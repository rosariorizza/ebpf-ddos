// user.c
#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

static volatile int done;

static void *trigger(void *arg)
{
	(void)arg;
	syscall(SYS_getpid);
	done = 1;
	return NULL;
}

int main(void)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link;
	pthread_t t;
	__u32 key = 0;
	__u64 zero = 0, prev = 0, cur = 0;
	int map_fd;


static char log_buf[256 * 1024 * 1024];

struct bpf_object_open_opts opts = {
	.sz = sizeof(opts),
	.kernel_log_buf = log_buf,
	.kernel_log_size = sizeof(log_buf),
	.kernel_log_level = 1,
};

obj = bpf_object__open_file("demo.bpf.o", &opts);
if (!obj) {
	fprintf(stderr, "open failed\n");
	return 1;
}

if (bpf_object__load(obj)) {
	fprintf(stderr, "load failed\n");
} else {
	fprintf(stderr, "load ok\n");
}

char *p = log_buf + strlen(log_buf);
int lines = 0;

while (p > log_buf && lines < 30) {
	p--;
	if (*p == '\n')
		lines++;
}

if (p != log_buf)
	p++;

printf("---- verifier log tail ----\n%s\n", p);

if (!strstr(log_buf, "processed ")) {
	fprintf(stderr, "no verifier summary found, try kernel_log_level = 2\n");
}


	prog = bpf_object__find_program_by_name(obj, "on_getpid");
	map_fd = bpf_object__find_map_fd_by_name(obj, "counter_map");

	bpf_map_update_elem(map_fd, &key, &zero, BPF_ANY);

	link = bpf_program__attach_tracepoint(
		prog, "syscalls", "sys_enter_getpid"
	);
	if (!link) {
		fprintf(stderr, "attach failed\n");
		return 1;
	}

	printf("attached. triggering getpid...\n");

	pthread_create(&t, NULL, trigger, NULL);

	for (;;) {
		sleep(1);

		bpf_map_lookup_elem(map_fd, &key, &cur);
		printf("counter=%llu delta=%lld%s\n",
		       (unsigned long long)cur,
		       (long long)(cur - prev),
		       done ? " done" : "");

		if (cur != 0 && cur == prev)
			break;

		prev = cur;
	}

	pthread_join(t, NULL);
	bpf_link__destroy(link);
	bpf_object__close(obj);

	return 0;
}
