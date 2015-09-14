# mipstring.py

r2pipe script to add data reference to strings and corresponding comments in disassembly, targeted for MIPS arch.

## usage

Example session:

```
$ r2 -i mipstring.py upnpd2
Canonical gp value: 0x462f40

searching for: "^lui [a-z0-9]{2}, \-?[0-9x]{3,4}$" ...
searching for: "^lw.*\(gp\)$" ...

Found 1527 string references.

 -- Are you still there?
[0x004236e0]> axt str.reboot
d 0x42dc5c addiu a0, a0, -0x7620
[0x004236e0]> s 0x42dc5c
```

The commented disassembly will look like this:

```
0x0042dc50   lui a0, 0x44
0x0042dc54   lw t9, -0x7ab0(gp)       ; [0x45b490:4]=0x42f640 sym.imp.system
0x0042dc58   jalr t9                  ;0x00000000() ; section..pdr
0x0042dc5c   addiu a0, a0, -0x7620    ; str.reboot
0x0042dc60   sw zero, -0x49dc(s0)
0x0042dc64   b 0x42d4bc                ; sym.sa_method_check+0x84
0x0042dc68   move v0, zero
0x0042dc6c   lw t9, -0x7e9c(gp)       ; [0x45b0a4:4]=0x42fcb0 sym.imp.acosNvramConfig_get
0x0042dc70   lui s2, 0x43
0x0042dc74   jalr t9                  ;0x00000000() ; section..pdr
0x0042dc78   addiu a0, s2, 0x9f4
0x0042dc7c   lw gp, 0x18(sp)
0x0042dc80   beqz v0, 0x42ddcc
0x0042dc84   move s3, v0
0x0042dc88   lb v0, (v0)
0x0042dc8c   beqz v0, 0x42ddd0
0x0042dc90   lw t9, -0x7ab0(gp)       ; [0x45b490:4]=0x42f640 sym.imp.system
0x0042dc94   lw t9, -0x7e9c(gp)       ; [0x45b0a4:4]=0x42fcb0 sym.imp.acosNvramConfig_get
0x0042dc98   lui a0, 0x43
0x0042dc9c   jalr t9                  ;0x00000000() ; section..pdr
0x0042dca0   addiu a0, a0, 0x2fc      ; str.lan_ipaddr
```

# what it does
Basically it searches for instruction pairs building addresses and then check for each of them if the address was flagged as string.

The heart of it is a linear search within disassembly using regular expression, which is both very effective and very slow.
