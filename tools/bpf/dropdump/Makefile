
BPFTOOL = bpftool
CFLAGS += -I./

bpf: vmlinux
	clang -O2 -c -g -Wall -Wno-pointer-sign -emit-llvm $(CFLAGS) \
	-Wno-incompatible-pointer-types-discards-qualifiers \
	./progs/dropdump.c -Wno-unknown-attributes -o - | \
	llc -march=bpf -filetype=obj -o dropdump.o

vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux \
	format c > vmlinux.h

skb: vmlinux
	echo '#ifndef _H_SKB_DROP_REASON\n#define _H_SKB_DROP_REASON' > skb.h
	sed -e '/enum skb_drop_reason {/,/}/!d' vmlinux.h >> skb.h
	echo '\n#define __DEFINE_SKB_REASON(FN) \' >> skb.h
	cat skb.h | awk '/SKB_DROP_REASON_/{printf "	FN(%s) \\\n", substr($$1, 17)}' >> skb.h
	echo '\n#endif' >> skb.h

all: skb bpf
	$(BPFTOOL) gen skeleton -L dropdump.o name dropdump > dropdump.lskel.h
	gcc -g -O2 -static ./dropdump.c ./parse_sym.c -o dropdump $(CFLAGS) \
	-lbpf -lelf -lz

clean:
	rm -rf skb.h dropdump.lskel.h dropdump dropdump.o
