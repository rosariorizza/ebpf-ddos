# ebpf global functions ddos

Small eBPF experiment showing how long loops can be hidden behind global functions. The verifier checks the global function once, then the main program can call it many times, so the verified instruction count can stay under the 1M processed insntructions limit while the runtime work multiplies.

The userspace loader prints the verifier log tail, triggers the program, and polls the map counter incremented from inside the global function. Heavier loop bodies, for example with `bpf_printk`, make the cost jump quickly.
