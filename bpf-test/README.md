# BPF emulation against PCAP files

This r2pipe script takes a PCAP file and a bpf binary filter in input. Then it iterates all the packets in the PCAP file and run ESIL emulation on it.

This is meant to be a proof-of-concept and/or regression test for [bpf architecture plugin](https://github.com/mrmacete/r2scripts/tree/master/bpf), but can be easily generalized as a tool for developing and testing BPF filters, in platform independent fashion.

## Dependencies

Besides the obvious warning to install radare2 from latest git repository, there are the following deps:

```
pip install r2pipe
pip install pycapfile
```

And, of course, the Berkeley Packet Filter architecture radare2 plugin linked above.
