# r2scripts
Collection of scripts for radare2
## [mipstring.py](https://github.com/mrmacete/r2scripts/tree/master/mipstring)
r2pipe script to add data reference to strings and corresponding comments in disassembly, targeted for MIPS arch.
## [esilstring.py](https://github.com/mrmacete/r2scripts/tree/master/esilstring)
r2pipe script which uses ESIL emulation to add non-obvious data reference to strings and corresponding comments in disassembly, targeted for MIPS arch - but potentially plaform independent.
## [esilburner.py](https://github.com/mrmacete/r2scripts/tree/master/esilburner)
MIPS-specific faster and more accurate version of esilstring.py, leverage r2's native analysis and emulation capabilities
## [BPF architecture](https://github.com/mrmacete/r2scripts/tree/master/bpf)
Plugin to support [Berkeley Packet Filter](https://www.kernel.org/doc/Documentation/networking/filter.txt) as a radare2 architecture, with full ESIL emulation.
