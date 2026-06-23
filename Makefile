CLANG ?= clang
CC ?= gcc

INNER_ITERS ?= 100000
OUTER_CALLS ?= 90000

#PRINTK = 1
#INNER_ITERS ?= 80000
#OUTER_CALLS ?= 180000

ARCH := $(shell uname -m)
INCLUDE_ARCH := $(ARCH)-linux-gnu

BPF_CFLAGS := -O2 -g -target bpf \
	-I/usr/include/$(INCLUDE_ARCH) \
	-DINNER_ITERS=$(INNER_ITERS) \
	-DOUTER_CALLS=$(OUTER_CALLS)

USER_CFLAGS := -O2 -g -Wall -Wextra
USER_LDLIBS := -lbpf -lelf -lz -pthread

all: demo.bpf.o user

demo.bpf.o: demo.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

user: user.c
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDLIBS)

clean:
	rm -f demo.bpf.o user
