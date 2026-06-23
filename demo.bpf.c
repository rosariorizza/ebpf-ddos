// demo.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef INNER_ITERS
#define INNER_ITERS 100000
#endif

#ifndef OUTER_CALLS
#define OUTER_CALLS 8
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} counter_map SEC(".maps");


volatile __u64 inc = 1;

__attribute__((noinline))
int global_burn(void)
{
	__u32 key = 0;
	__u64 *counter = bpf_map_lookup_elem(&counter_map, &key);
	volatile __u64 *vcounter = counter;

	if (!counter)
		return 0;

#pragma clang loop unroll(disable)
	for (int i = 0; i < INNER_ITERS; i++)
		*vcounter += inc;
		#ifdef PRINTK
		bpf_printk("A");
		#endif

	return 0;
}

long burn_state;

SEC("tracepoint/syscalls/sys_enter_getpid")
int on_getpid(void *ctx)
{
	if (__sync_val_compare_and_swap(&burn_state, 0, 1) != 0)
		return 0;

#pragma unroll
	for (int i = 0; i < OUTER_CALLS; i++)
		global_burn();

	__sync_val_compare_and_swap(&burn_state, 1, 2);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
