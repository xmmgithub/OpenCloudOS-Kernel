#include "bpf_base.h"
#include "dropdump_common.h"

#define _(P)						\
({							\
	typeof(P) tmp;					\
	bpf_probe_read_kernel(&tmp, sizeof(P), &(P));	\
	tmp;						\
})

typedef struct {
	u64 pad;
	u64 skb;
	u64 location;
	u16 prot;
	u32 reason;
} kfree_skb_t;

#define TCP_H_LEN	(sizeof(struct tcphdr))
#define UDP_H_LEN	(sizeof(struct udphdr))
#define IP_H_LEN	(sizeof(struct iphdr))

#define ETH_TOTAL_H_LEN	(sizeof(struct ethhdr))
#define IP_TOTAL_H_LEN	(ETH_TOTAL_H_LEN + IP_H_LEN)
#define TCP_TOTAL_H_LEN	(IP_TOTAL_H_LEN + TCP_H_LEN)
#define UDP_TOTAL_H_LEN	(IP_TOTAL_H_LEN + UDP_H_LEN)

static inline void *get_l2(struct sk_buff *skb)
{
	u16 mh = _(skb->mac_header);
	if (mh != (u16)~0U && mh)
		return _(skb->head) + mh;
	else
		return NULL;
}

static inline void *get_l3(struct sk_buff *skb)
{
	if (_(skb->network_header) > _(skb->mac_header))
		return _(skb->head) + _(skb->network_header);
	else if (get_l2(skb))
		return get_l2(skb) + ETH_HLEN;
	else
		return NULL;
}

static inline void *get_l3_send(struct sk_buff *skb)
{
	if (_(skb->network_header))
		return _(skb->head) + _(skb->network_header);
	else
		return NULL;
}

static inline bool skb_l4_was_set(const struct sk_buff *skb)
{
	return _(skb->transport_header) != 0xFFFF &&
	       _(skb->transport_header) > _(skb->network_header);
}

static __always_inline __u8 get_ip_header_len(__u8 h)
{
	__u8 len = (h & 0xF0) * 4;
	return len > IP_H_LEN ? len: IP_H_LEN;
}

static inline void *get_l4(struct sk_buff *skb)
{
	if (skb_l4_was_set(skb))
		return _(skb->head) + _(skb->transport_header);
	void *ip = get_l3(skb);
	if (!ip)
		return NULL;
	return ip + get_ip_header_len(_(((u8 *)ip)[0]));
}
