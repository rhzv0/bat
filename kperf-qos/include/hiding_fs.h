#ifndef BAT_HIDING_FS_H
#define BAT_HIDING_FS_H

int  hiding_fs_init(void);
void hiding_fs_exit(void);

/* Used by hiding_chdir, hiding_readlink (within this module) */
notrace bool should_hide_path(const char __user *pathname);

#endif /* BAT_HIDING_FS_H */
