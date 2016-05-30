# esilburner.py

This script tries to reach the same goal of `esilstring.py` but is way faster and works better because leverages radare's native anlysis capabilities, which has improved a lot since my older attempt.

Basically, it works by letting `asm.emu` to perform the emulation, at function level, and then "burn" its result in real, persistent comments.

In this way it's possible to inspect the function using the `VV` command without caring for correct emulation context, because it will reuse the previous results - cached in comments.


# what it does

The algorithm is:

* set a proper value for `gp` on MIPS arch
* let r2 analyze everything (`aa`)
* try to maximize coverage by analyzing function by preludes using `aap` results (and setting `e anal.prelude=3c1c` this is the only part which is really MIPS specific here)
* emulate each function using the macro: `(pdfmips at,ar gp=loc._gp,af @$0,ar t9=$0,pdf @$0)`
* read the results and burn them in real comments
* optionally detect references to flags and add them using `axd` or `axC`

# warning

This is still pretty MIPS-specific, but should not be difficult to port it.