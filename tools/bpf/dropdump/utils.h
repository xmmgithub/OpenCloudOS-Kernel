#include <unistd.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <asm-generic/int-ll64.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>

typedef __s8  s8;
typedef __u8  u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

static inline void i2ip(char *dest, __u32 ip)
{
	__u8 *t = (__u8 *)&ip;
	sprintf(dest, "%d.%d.%d.%d", t[0], t[1], t[2], t[3]);
}

static inline int ip2i(char *ip, __u32 *dest)
{
	__u32 t[4] = {};
	__u8 *c = (__u8 *)dest;
	if (sscanf(ip, "%u.%u.%u.%u", t, t + 1, t + 2, t + 3) != 4)
		return -EINVAL;

#define C(index) c[index] = t[index] 
	C(0);
	C(1);
	C(2);
	C(3);
#undef C
	return 0;
}
