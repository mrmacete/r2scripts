# esilstring.py

r2pipe script which uses ESIL emulation to add non-obvious data reference to strings and corresponding comments in disassembly, targeted for MIPS arch - but potentially plaform independent.

In my intents it's roughly the same as using "e asm.emu=true" but adds persistent references and comments, so it's possible to analyze refences to strings.

The goal of all of this is to detect string references even in RISC architectures which requires pairs or longer sequences of instructions in order to forge an actual pointer to the data.

## usage

Example session:

```
$ r2 -i esilstring.py httpd
Canonical gp value: 0x462f40

emulating sym.AES_set_decrypt_key from 0x420b1c to 0x420e5c ...
emulating sym.AES_encrypt from 0x420e5c to 0x4212a8 ...
emulating sym.getCurrWanIp from 0x460340 to 0x460394 ...
emulating sym.acos_itoa from 0x45fa50 to 0x45faa4 ...
emulating sym.AES_cbc_encrypt from 0x422554 to 0x422a0c ...
emulating sym.AES_decrypt from 0x4214ec to 0x421938 ...
emulating sym.AES_set_encrypt_key from 0x420630 to 0x420648 ...
emulating sym.checkStringTblInMTD from 0x49d8ac to 0x49de5c ...
emulating sym._init from 0x406ba8 to 0x406c14 ...
emulating sym.abFirewallLoadServices from 0x447330 to 0x4476d0 ...
emulating sym.main from 0x411fd0 to 0x412690 ...

[...]


Found 9914 references.

 -- /dev/brain: No such file or directory.
[0x00491d88]> axt str.PageData
d 0x491d98 addiu a1, a1, -0x67b0
d 0x491ed4 addiu a1, a1, -0x67b0
d 0x4928a4 addiu a1, a1, -0x67b0
d 0x492a50 addiu a1, a1, -0x67b0
[0x00491d88]> pd 10 @ 0x491d98-24
│           0x00491d80    8fb0024c       lw s0, 0x24c(sp)
│           0x00491d84    03e00008       jr ra
│           0x00491d88    27bd0270       addiu sp, sp, 0x270
│           ; JMP XREF from 0x00491ccc (fcn.00491bc4)
│           0x00491d8c    8f9983c4       lw t9, -0x7c3c(gp)            ; [0x553c64:4]=0x413514 sym.websGetVar
│           0x00491d90    3c05004e       lui a1, 0x4e
│           0x00491d94    02e02021       move a0, s7
│           0x00491d98    24a59850       addiu a1, a1, -0x67b0         ; str.PageData
│           0x00491d9c    0320f809       jalr t9                       ;0x00000000() ; section..pdr
│           0x00491da0    02803021       move a2, s4
│           0x00491da4    8fbc0010       lw gp, 0x10(sp)

```

# what it does

The algorithm is:

* set a proper value for `gp` on MIPS arch
* let r2 analyze everything
* retrieve start address and length for each detected function (using r2 flags)
* emulate each function separately (using `aesl` command to step linearly)
* at each step, parse the destination register and read its emulated value
* lookup that value in the flags
* if a flag is hit, then add comment and `axd` a new reference to it
* if no flags are hit, try even with `psz` to extract potential null-terminated strings, if present then add comment and data reference to it
