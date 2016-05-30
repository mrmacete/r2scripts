#!/usr/bin/python
# -*- coding: utf-8 -*-

import r2pipe
import json
import re
from cStringIO import StringIO

xtract = re.compile('^(0x[0-9a-fA-F]*)[^;]*;(.*)$')
blacks = re.compile('[><|]')
xtflag = re.compile('([a-z]{3}\.[^ ;]+)')


def iter_lines(foo):
    stri = StringIO(foo)
    while True:
        nl = stri.readline()
        if nl == '':
            break
        yield nl.strip('\n')


class EsilBurner:
    emulate_flags = ['sym.', 'fcn.']
    reference_flags = ['str.', 'obj.', 'sym.', 'fcn.']
    dump_commands = False
    auto_reference = False

    def __init__(self, r, options={}):
        self.r = r
        if 'emulate_flags' in options:
            self.emulate_flags = options['emulate_flags']
        if 'auto_reference' in options:
            self.auto_reference = options['auto_reference']

        self.initial_setup()

    def cmd(self, command):
        if self.dump_commands:
            print "dump> " + command
        return self.r.cmd(command)

    def cmdj(self, command):
        if self.dump_commands:
            print "dump> " + command
        return self.r.cmdj(command)

    def is_prelude(self, addr):
        pd = self.cmdj('pdj 1 @ ' + addr)
        if pd is not None and len(pd) > 0 and 'opcode' in pd[0]:
            return pd[0]['opcode'].startswith('lui gp')
        return False

    def maximize_coverage(self):
        self.cmd("e anal.prelude=3c1c")
        self.cmd("aap")

    def initial_setup(self):
        self.cmd("e anal.gp=`? (section..got+0x7ff0)~[1]`")
        self.cmd("f loc._gp=`? (section..got+0x7ff0)~[1]`")
        self.cmd("(pdfmips at,ar gp=loc._gp,af @$0,ar t9=$0,pdf @$0)")
        self.cmd("aa")
        self.cmd("e anal.prelude=3c1c") # mips prelude "lui gp, *"
        self.cmd("aap")
        print "code coverage: " + self.cmd('aai~percent[1]')


    def flags_to_emulate(self):
        raw = self.cmdj("fj")

        def flagtest(f):
            for tf in self.emulate_flags:
                if f.startswith(tf):
                    return True
            return False
        return [f for f in raw if flagtest(f['name'])]

    def sanitize_command(self, command):
        return re.sub(blacks, '_', command).replace(';', '')

    def add_auto_reference(self, addr, comment):
        m = re.findall(xtflag, comment)
        if m is not None:
            def flagtest(f):
                for tf in self.reference_flags:
                    if f.find(tf) == 0:
                        return True
                return False

            flags = [f for f in m if flagtest(f)]
            for f in flags:

                if f.startswith('sym.') or f.startswith('fcn.'):
                    self.cmd('axC ' + f + ' @ ' + addr)
                else:
                    self.cmd('axd ' + f + ' @ ' + addr)

    def burn_emu_lines(self, lines):
        for l in iter_lines(lines):
            m = re.match(xtract, l)
            if m is not None and len(m.groups()) == 2:
                addr, comment = m.groups()
                if self.auto_reference:
                    self.add_auto_reference(addr, comment)
                command = self.sanitize_command('CCu ' + comment.strip() + ' @ ' + addr)
                self.cmd(command)
                # print command

    def burn_emu_comments(self):
        self.cmd("e scr.color=false")
        self.cmd("e asm.fcnlines=false")
        self.cmd("e asm.lines=false")
        self.cmd("e asm.emu = true")
        self.cmd("e asm.emuwrite=true")
        self.cmd("aeim 0x100000 0x300000")

        for f in self.flags_to_emulate():
            print "emulating " + f['name'] + ' ...'
            lines = self.cmd(".(pdfmips " + f['name'] + ")")
            self.burn_emu_lines(lines)

        self.cmd("e scr.color=true")
        self.cmd("e asm.fcnlines=true")
        self.cmd("e asm.lines=true")
        self.cmd("e asm.emu = false")

        print "code coverage: " + self.cmd('aai~percent[1]')

if __name__ == '__main__':
    r = r2pipe.open("#!pipe")
    ms = EsilBurner(r, {
    	"auto_reference": True
    	})
    ms.burn_emu_comments()
