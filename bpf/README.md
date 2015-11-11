#BPF architecture for radare2

This is meant to add support for Berkeley Packet Filter in radare2, with full [ESIL](https://radare.gitbooks.io/radare2book/content/esil.html) emulation. The main purpose is to ease the analysis of existing filters encountered in reverse engineering, but can also aid filter development through ESIL emulation.

## Components

It is composed by three plugins:

* **asm_bpf** is the disassembler, i'm planning to add also assembler functionality, but for now it's only disassembler - it is mostly ripped from bpf_dbg.c in the Linux kernel
* **anal_bpf** this is the major contribution of this package, i.e. the analysis plugin which translates everything to ESIL and permits to emulate it completely
* **bin_bpf** is a placeholder, not sure if it's useful at all since there isn't a specific file format - i'm using it just to remember that data is represented big endian by enforcing this information

## Building

In unix system (tested on mac, but should work in Linux or *BSD out of the box) it should be as easy as doing:

```bash
make install
```

There are two known warnings:

* be sure to have the latest [radare2 from git](https://github.com/radare/radare2)
* on mac systems radare2 should be installed with sys/install.sh (and not sys/user.sh) because the Makefile relies on a properly working `pkg-config`

