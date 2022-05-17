
#include <getopt.h>
#include <stdlib.h>
#include <asm-generic/int-ll64.h>
#include <linux/if_ether.h>
#include <unistd.h>

#include "reasons.h"
#include "utils.h"
#include "dropdump.lskel.h"
#include "progs/dropdump_common.h"
#include "parse_sym.h"

#define MAX_OUTPUT_LENGTH	256
#define MAX_ADDR_LENGTH		48
#define ROOT_PIN_PATH		"/sys/fs/bpf/droptrace/"
#define SNMP_PIN_PATH		ROOT_PIN_PATH"snmp"
#define TRACE_PIN_PATH		ROOT_PIN_PATH"trace"

u32 snmp_reasons[SKB_DROP_REASON_MAX];

static bool snmp_mode	= false,
	    ts_show	= false,
	    raw_sym	= false,
	    oneshot 	= false;

static void print_drop_packet(void *ctx, int cpu, void *data, __u32 size)
{
	char saddr[MAX_ADDR_LENGTH], daddr[MAX_ADDR_LENGTH];
	static char buf[MAX_OUTPUT_LENGTH] = {};
	char ts_str[32], raw_sym_desc[20];
	const char *reason_str, *ext_info;
	__u16 sport, dport, reason;
	struct sym_result *sym;
	char *sym_desc = NULL;
	event_t *e = data;
	__u64 ts;
	__u8 flags;

	reason = e->reason;
	if (reason >= SKB_DROP_REASON_MAX || reason <= 0) {
		printf("unknow drop reason: %d", reason);
		reason = SKB_DROP_REASON_NOT_SPECIFIED;
	}
	reason_str = drop_reasons[reason];
	if (!reason_str)
		printf("invalid reason found:%d\n", reason);
	if (!raw_sym) {
		sym = parse_sym(e->location);
		sym_desc = sym->desc;
	} else {
		sym_desc = raw_sym_desc;
		sprintf(sym_desc, "0x%llx", e->location);
	}

	if (ts_show) {
		ts = e->ts;
		sprintf(ts_str, "[%lu.%06lu] ", ts / 1000000000,
			ts % 1000000000 / 1000);
	} else {
		ts_str[0] = 0;
	}

	if (!e->proto_l3) {
		printf("%sunknow, reason: %s, %s\n", ts_str, reason_str,
		       sym_desc);
		return;
	}

	switch (e->proto_l3) {
	case ETH_P_IP:
		goto print_ip;
	case ETH_P_ARP:
		goto print_arp;
	default:
		break;
	}

	printf("%sether protocol: %u, reason: %s, %s\n", ts_str,
	       e->proto_l3, reason_str, sym_desc);
	return;

print_ip:
	i2ip(saddr, e->l3.ipv4.saddr);
	i2ip(daddr, e->l3.ipv4.daddr);

	switch (e->proto_l4) {
	case IPPROTO_TCP:
		sport = e->l4.tcp.sport;
		dport = e->l4.tcp.dport;
		flags = e->l4.tcp.flags;
#define CONVERT_FLAG(mask, name) ((flags & mask) ? name : "")
		sprintf(buf, "TCP seq:%u, ack:%u, flags:%s%s%s%s",
			e->l4.tcp.seq,
			e->l4.tcp.ack,
			CONVERT_FLAG(TCP_FLAGS_SYN, "S"),
			CONVERT_FLAG(TCP_FLAGS_ACK, "A"),
			CONVERT_FLAG(TCP_FLAGS_RST, "R"),
			CONVERT_FLAG(TCP_FLAGS_PSH, "P"));
		ext_info = buf;
		break;
	case IPPROTO_UDP:
		sport = e->l4.tcp.sport;
		dport = e->l4.tcp.dport;
		ext_info = "UDP";
		break;
	default:
		printf("%s%s -> %s, protocol: %u, reason: %s, %s\n",
		       ts_str, saddr, daddr, e->proto_l4,
		       reason_str, sym_desc);
		return;
	}

	printf("%s%s:%d -> %s:%d %s reason: %s, %s\n",
	       ts_str, saddr, htons(e->l4.tcp.sport),
	       daddr, htons(e->l4.tcp.dport),
	       ext_info, reason_str,
	       sym_desc);
	return;

print_arp:
}

static int do_drop_monitor(int map_fd)
{
	struct perf_buffer_opts pb_opts = {};
	struct perf_buffer *pb;
	struct dropdump *obj;
	int ret;

	pb_opts.sample_cb = print_drop_packet;
	pb = perf_buffer__new(map_fd, 8, &pb_opts);
	ret = libbpf_get_error(pb);
	if (ret) {
		printf("failed to setup perf_buffer: %d\n", ret);
		return -1;
	}

	while ((ret = perf_buffer__poll(pb, 1000)) >= 0) {
	}
	return 0;
}

static int do_stat_stop()
{
	if (access(SNMP_PIN_PATH, F_OK)) {
		printf("not loaded\n");
		goto err;
	}
	unlink(TRACE_PIN_PATH);
	unlink(SNMP_PIN_PATH);
	printf("stat stop successful!\n");
	return 0;

err:
	return -1;
}

static int parse_opts(int argc, char *argv[], struct dropdump *obj)
{
	static struct option long_opts[] = {
		{ "saddr",	required_argument,	0, 0 },
		{ "daddr",	required_argument,	0, 1 },
		{ "addr",	required_argument,	0, 2 },
		{ "sport",	required_argument,	0, 3 },
		{ "dport",	required_argument,	0, 4 },
		{ "port",	required_argument,	0, 5 },
		{ "raw-sym",	no_argument,		0, 6 },
		{ "oneshot",	no_argument,		0, 7 },
		{ "proto",	required_argument,	0, 'p' },
		{ "reason",	required_argument,	0, 'r' },
		{ "stat",	no_argument,		0, 's' },
		{ "stat-stop",	no_argument,		0, 8 },
		{ "limit",	required_argument,	0, 'l' },
		{ "limit-budget",	required_argument,	0, 9 },
		{ 0,		0,			0, 0 }
	};
	char *short_opts = "sp:htr:l:";
	int opt, err;
	__u32 addr;
	__u16 port;

#define S(name, value)				\
	obj->rodata->enable_##name = true;	\
	obj->rodata->arg_##name = value

	while ((opt = getopt_long(argc, argv, short_opts, long_opts,
				  NULL)) != -1) {
		switch (opt) {
		case 's':
			obj->rodata->arg_snmp_mode = true;
			snmp_mode = true;
			break;
		case 0:
			if (ip2i(optarg, &addr)) {
				printf("invalid ip address: %s\n", optarg);
				goto err;
			}
			S(saddr, addr);
			break;
		case 1:
			if (ip2i(optarg, &addr)) {
				printf("invalid ip address: %s\n", optarg);
				goto err;
			}
			S(daddr, addr);
			break;
		case 2:
			if (ip2i(optarg, &addr)) {
				printf("invalid ip address: %s\n", optarg);
				goto err;
			}
			S(addr, addr);
			break;
		case 3:
			port = atoi(optarg);
			S(sport, port);
			break;
		case 4:
			port = atoi(optarg);
			S(dport, port);
			break;
		case 5:
			port = atoi(optarg);
			S(port, port);
			break;
		case 6:
			raw_sym = true;
			break;
		case 7:
			oneshot = true;
			break;
		case 8:
			err = do_stat_stop();
			goto exit;
		case 9:
			int budget = atoi(optarg);
			if (budget <= 0) {
				printf("invalid budget: %s\n", optarg);
				goto err;
			}
			obj->data->current_budget = budget;
			S(limit_budget, budget);
			break;
		case 't':
			ts_show = true;
			break;
		case 'r':
			int reason = atoi(optarg);
			if (reason <= 0) {
				printf("invalid drop reason: %s\n", optarg);
				goto err;
			}
			S(reason, reason);
			break;
		case 'l':
			int limit = atoi(optarg);
			if (limit <= 0) {
				printf("invalid limitation: %s\n", optarg);
				goto err;
			}
			S(limit, limit);
			break;
		case 'h':
			goto usage;
		default:
			goto err;
		}
	}
#undef S
	return 0;
usage:
	printf("Usage:\n"
	       "    dropdump [--saddr] [--daddr] [--addr] [--sport]\n"
	       "             [--dport] [--port] [-p] [--proto] [-s]\n"
	       "\n"
	       "Examples:\n"
	       "    dropdump -s\n"
	       "    dropdump --saddr 192.168.122.1 --sport 9090\n");
	exit(0);
err:
	return -1;
exit:
	exit(err);
}

static void print_drop_stat(int fd)
{
	int key = 0, i = 1, count;

	if (bpf_map_lookup_elem(fd, &key, snmp_reasons)) {
		printf("failed to load data\n");
		return;
	}

	printf("packet statistics:\n");
	for (; i < SKB_DROP_REASON_MAX; i++) {
		count = snmp_reasons[i];
		printf("  %s: %d\n", drop_reasons[i], count);
	}
}

int main(int argc, char *argv[])
{
	struct dropdump *obj = NULL;
	int map_fd;

	if (!(obj = dropdump__open())) {
		printf("failed to open program\n");
		goto err;
	}

	if (parse_opts(argc, argv, obj))
		goto err;

	if (snmp_mode)
		goto do_snmp;

do_load:
	if (dropdump__load(obj)) {
		printf("failed to load program\n");
		goto err;
	}

	if (dropdump__attach(obj)) {
		printf("failed to attach kfree_skb event\n");
		goto err;
	}

	if (snmp_mode) {
		if (access(ROOT_PIN_PATH, F_OK) && mkdir(ROOT_PIN_PATH, 744)) {
			printf("failed to create bpf pin path\n");
			goto err;
		}
		if (bpf_obj_pin(obj->maps.bss.map_fd, SNMP_PIN_PATH)) {
			printf("failed to pin snmp map\n");
			goto err;
		}
		if (bpf_obj_pin(obj->links.trace_kfree_skb_fd, TRACE_PIN_PATH)) {
			printf("failed to pin program\n");
			unlink(SNMP_PIN_PATH);
			goto err;
		}
		goto do_snmp;
	} else {
		do_drop_monitor(obj->maps.m_event.map_fd);
	}

out:
	dropdump__destroy(obj);
	return 0;

err:
	dropdump__destroy(obj);
	return -1;

do_snmp:
	if (access(SNMP_PIN_PATH, F_OK))
		goto do_load;
	map_fd = bpf_obj_get(SNMP_PIN_PATH);
	if (map_fd < 0) {
		printf("failed to open snmp\n");
		return -1;
	}
	print_drop_stat(map_fd);
	goto out;
}
