#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "dropdump.h"

#define PARAM_DEFINE(type, name, default)	\
	const volatile type arg_##name = default
#define PARAM_DEFINE_ENABLE(type, name)		\
	PARAM_DEFINE(type, name, 0);		\
	const volatile bool enable_##name = false
#define PARAM_DEFINE_UINT(type, name)		\
	PARAM_DEFINE_ENABLE(type, name)
#define PARAM_DEFINE_BOOL(name, default)	\
	PARAM_DEFINE(bool, name, default)
#define PARAM_ENABLED(name)			\
	(enable_##name)
#define PARAM_CHECK_ENABLE(name, val)		\
	(PARAM_ENABLED(name) && arg_##name != (val))
#define PARAM_CHECK_BOOL(name)			\
	(arg_##name)

PARAM_DEFINE_UINT(u32, saddr);
PARAM_DEFINE_UINT(u32, daddr);
PARAM_DEFINE_UINT(u32, addr);
PARAM_DEFINE_UINT(u16, sport);
PARAM_DEFINE_UINT(u16, dport);
PARAM_DEFINE_UINT(u16, port);
PARAM_DEFINE_UINT(u16, l3_proto);
PARAM_DEFINE_UINT(u8,  l4_proto);
PARAM_DEFINE_UINT(u16, reason);
PARAM_DEFINE_UINT(u32, limit);
PARAM_DEFINE_UINT(u32, limit_budget);

PARAM_DEFINE_BOOL(snmp_mode, false);

u32 snmp_reasons[SKB_DROP_REASON_MAX];
int current_budget = 1024;
u64 last_ts = 0;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 64);
} m_event SEC(".maps");

#define EVENT_OUTPUT(ctx, data)					\
	bpf_perf_event_output(ctx, &m_event, BPF_F_CURRENT_CPU,	\
			      &(data), sizeof(data))

static inline void do_snmp(u16 reason)
{
	if (reason >= SKB_DROP_REASON_MAX)
		return;
	snmp_reasons[reason]++;
}

#ifdef FEATURE_DIRECT_ACCESS
static inline int parse_ip(struct sk_buff *skb, event_t *event, bool ipv4)
{
	void *l3 = get_l3(skb);

#define CHECK_ATTR(attr)				\
	(PARAM_CHECK_ENABLE(s##attr, s##attr) ||	\
	 PARAM_CHECK_ENABLE(attr, s##attr) ||		\
	 PARAM_CHECK_ENABLE(d##attr, d##attr) ||	\
	 PARAM_CHECK_ENABLE(attr, d##attr))

	if (!ipv4) {
		struct ipv6hdr *ipv6 = l3;
		event->proto_l4 = _(ipv6->nexthdr);
		bpf_probe_read_kernel(event->l3.ipv6.saddr,
				      sizeof(ipv6->saddr),
				      &ipv6->saddr);
		bpf_probe_read_kernel(event->l3.ipv6.daddr,
				      sizeof(ipv6->daddr),
				      &ipv6->daddr);
	} else {
		struct iphdr *ip = l3;
		u32 saddr = _(ip->saddr);
		u32 daddr = _(ip->daddr);

		if (CHECK_ATTR(addr))
			return -1;

		event->proto_l4	= _(ip->protocol);
		event->l3.ipv4.saddr = saddr;
		event->l3.ipv4.daddr = daddr;
	}

	if (PARAM_CHECK_ENABLE(l4_proto, event->proto_l4))
		return -1;

	void *l4 = get_l4(skb);
	switch (event->proto_l4) {
	case IPPROTO_TCP: {
		struct tcphdr *tcp = l4;
		u16 sport = _(tcp->source);
		u16 dport = _(tcp->dest);

		if (CHECK_ATTR(port))
			return -1;

		event->l4.tcp.sport = sport;
		event->l4.tcp.dport = dport;
		event->l4.tcp.flags = _(((u8 *)tcp)[13]);
		event->l4.tcp.seq = _(tcp->seq);
		event->l4.tcp.ack = _(tcp->ack_seq);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udp = l4;
		u16 sport = _(udp->source);
		u16 dport = _(udp->dest);
	
		if (CHECK_ATTR(port))
			return -1;

		event->l4.udp.sport = sport;
		event->l4.udp.dport = dport;
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *icmp = l4;
		event->l4.icmp.code = _(icmp->code);
		event->l4.icmp.type = _(icmp->type);
		event->l4.icmp.seq = _(icmp->un.echo.sequence);
		event->l4.icmp.id = _(icmp->un.echo.id);
		break;
	}
	}
	return 0;
}
#else
static inline int parse_ip(struct sk_buff *skb, event_t *event, bool ipv4)
{
	void *l3 = get_l3(skb);

#define CHECK_ATTR(attr)				\
	(PARAM_CHECK_ENABLE(s##attr, s##attr) ||	\
	 PARAM_CHECK_ENABLE(attr, s##attr) ||		\
	 PARAM_CHECK_ENABLE(d##attr, d##attr) ||	\
	 PARAM_CHECK_ENABLE(attr, d##attr))

	if (!ipv4) {
		struct ipv6hdr *ipv6 = l3;
		event->proto_l4 = _(ipv6->nexthdr);
		bpf_probe_read_kernel(event->l3.ipv6.saddr,
				      sizeof(ipv6->saddr),
				      &ipv6->saddr);
		bpf_probe_read_kernel(event->l3.ipv6.daddr,
				      sizeof(ipv6->daddr),
				      &ipv6->daddr);
	} else {
		struct iphdr *ip = l3;
		u32 saddr = _(ip->saddr);
		u32 daddr = _(ip->daddr);

		if (CHECK_ATTR(addr))
			return -1;

		event->proto_l4	= _(ip->protocol);
		event->l3.ipv4.saddr = saddr;
		event->l3.ipv4.daddr = daddr;
	}

	if (PARAM_CHECK_ENABLE(l4_proto, event->proto_l4))
		return -1;

	void *l4 = get_l4(skb);
	switch (event->proto_l4) {
	case IPPROTO_TCP: {
		struct tcphdr *tcp = l4;
		u16 sport = _(tcp->source);
		u16 dport = _(tcp->dest);

		if (CHECK_ATTR(port))
			return -1;

		event->l4.tcp.sport = sport;
		event->l4.tcp.dport = dport;
		event->l4.tcp.flags = _(((u8 *)tcp)[13]);
		event->l4.tcp.seq = _(tcp->seq);
		event->l4.tcp.ack = _(tcp->ack_seq);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udp = l4;
		u16 sport = _(udp->source);
		u16 dport = _(udp->dest);
	
		if (CHECK_ATTR(port))
			return -1;

		event->l4.udp.sport = sport;
		event->l4.udp.dport = dport;
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *icmp = l4;
		event->l4.icmp.code = _(icmp->code);
		event->l4.icmp.type = _(icmp->type);
		event->l4.icmp.seq = _(icmp->un.echo.sequence);
		event->l4.icmp.id = _(icmp->un.echo.id);
		break;
	}
	}
	return 0;
}
#endif

static inline int parse_skb(struct sk_buff *skb, event_t *event)
{
	struct ethhdr *eth = get_l2(skb);

	if (!eth)
		return 0;

	u16 l3 = bpf_ntohs(_(eth->h_proto));
	if (PARAM_CHECK_ENABLE(l3_proto, l3))
		return -1;

	event->proto_l3 = l3;
	switch (l3) {
	case ETH_P_IPV6:
	case ETH_P_IP:
		return parse_ip(skb, event, l3 == ETH_P_IP);
	}

	return 0;
}

static __always_inline bool is_limited(u64 ts)
{
	if (current_budget) {
		current_budget--;
		return false;
	}

	u64 dela = ((ts - last_ts) / 1000) * arg_limit / 1000000;
	if (dela) {
		if (dela > arg_limit_budget)
			dela = arg_limit_budget;
		current_budget = dela - 1;
		return false;
	}
	return true;
}

SEC("tp_btf/kfree_skb")
int BPF_PROG(trace_kfree_skb, struct sk_buff *skb, void *location,
	     int reason)
{
	if (PARAM_CHECK_BOOL(snmp_mode)) {
		do_snmp((__u16)reason);
		goto out;
	}

	if (PARAM_CHECK_ENABLE(reason, reason))
		goto out;

	event_t event = { .reason = reason };
	if (parse_skb(skb, &event))
		goto out;

	event.ts = bpf_ktime_get_ns();
	if (PARAM_ENABLED(limit) && is_limited(event.ts))
		goto out;

	event.location = (u64)location;
	bpf_perf_event_output(ctx, &m_event, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));
out:
	return 0;
}

char _license[] SEC("license") = "GPL";