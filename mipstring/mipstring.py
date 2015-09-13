""" 

naive string extractor for MIPS executables 

author: mrmacete

Known limitations:
+ doesn't care about jumps (and control flow in general)
+ search window is fixed
+ only 2 heuristics implemented
+ regexp asm manual search is slow and quite dumb

note: requires r2pipe 0.6.5 and latest r2 from git

"""

import r2pipe
import json 
import re


def parseImmediate (immStr):
	try:
		if immStr.find("0x") >= 0:
			return int(immStr, 16)
		else:
			return int(immStr, 10)
	except:
		return None

class Opcode:
	def __init__(self, opstring):
		splitted = opstring.split(" ")

		self.src_reg = None
		self.src = None
		self.dst_reg = None
		self.operation = None
		self.immediate = None

		if len(splitted) == 1:
			self.operation = splitted[0]

		elif len(splitted) == 2:
			self.operation = splitted[0]
			self.immediate = parseImmediate(splitted[1])
			if self.immediate == None:
				self.src_reg = splitted[1]
			
		elif len(splitted) == 3:
			self.operation = splitted[0]
			self.dst_reg = splitted[1]
			self.immediate = parseImmediate(splitted[2])
			if self.immediate == None:
				self.src = splitted[2]

		elif len(splitted) == 4:
			self.operation = splitted[0]
			self.dst_reg = splitted[1]
			self.src_reg = splitted[2]
			self.immediate = parseImmediate(splitted[3])

		else:
			print "Ignoring opcode: " + opstring
			return

		if self.src != None and self.src.find("(") >= 0:
			sp = self.src.split("(")
			self.immediate = parseImmediate(sp[0])
			self.src_reg = sp[1].split(")")[0]

	def toString(self):
		return "\n".join(["operation: " + self.operation,
		"dst_reg: " + str(self.dst_reg),
		"src_reg: " + str(self.src_reg),
		"immediate: " + str(self.immediate),
		"src: " + str(self.src) ])


class MIPSString:

	dump_commands = False
	total_count = 0

	def __init__(self, r):
		self.r = r

	def cmd( self, command):
		if self.dump_commands:
			print "dump> " + command

		return self.r.cmd(command)

	def cmdj( self, command):
		if self.dump_commands:
			print "dump> " + command

		return self.r.cmdj(command)

	def init_gp( self ):
		self.cmd("aa")
		self.cmd("fs sections")
		self.cmd("e anal.gp=`? (section..got+0x7ff0)~[1]`")
		self.cmd("f gp=`? (section..got+0x7ff0)~[1]`")
		self.cmd("aa")
		print "Canonical gp value: " + self.cmd("?v gp")


	def get_str_flag( self, address ):
		try:
			dis = self.cmdj("pdj 1@" + hex(address) )
			return [f for f in dis[0]["flags"] if f.startswith("str.") ][0]
		except:
			return ""

	def rigid_asm_search_executable( self, asm_regex):

		results = []
		xsex = [s for s in self.cmdj("iSj") if s["flags"][3] == 'x']

		for sec in xsex:

			rr = self.rigid_asm_search(asm_regex, sec["addr"], sec["addr"]+sec["size"], None )
			results.extend(list(set(rr)))		


		return list(set(results))


	def rigid_asm_search( self, asm_regex, from_addr, to_addr, limit ):
		results = []

		ar = re.compile(asm_regex)

		for addr in xrange(from_addr, to_addr+1, 4):
			pdj = self.cmdj("pdj 1@" + hex(addr))
			if len(pdj) > 0:
				opcode = pdj[0]["opcode"]
				try:
					if ar.match(opcode) != None:
						results.append(addr)
						if limit != None and len(results) >= limit:
							return results
				except:
					pass

		return results


	def search_window_from( self, address, length = 128 ):
		self.cmd("e search.from="+ str(address))
		self.cmd("e search.to="+ str(address+length))


	def add_string_reference( self, string_address):
		
		string_flag = self.get_str_flag(string_address)

		if len(string_flag) > 0:
			self.cmd("CC " + string_flag)
			self.cmd("axd " + str(string_address))
			self.total_count += 1

	def sx_from_lui_to_addiu( self, address ):
		self.cmd("s " + str(address))
		self.search_window_from(address)

		opcode_lui = Opcode(self.cmdj("aoj")[0]["opcode"])

		reg = opcode_lui.dst_reg

		if reg == None or reg == 'zero' or reg == 'gp':
			return

		imm_lui = opcode_lui.immediate

		self.cmd("s/c addiu " + reg)

		aa = self.rigid_asm_search("^addiu " + reg +".*$", address+4, address+128, 1)

		if len(aa) == 0:
			return

		addiu_addr = aa[0]

		if addiu_addr == address or addiu_addr == 0:
			return

		self.cmd("s " + str(addiu_addr))

		opcode_addiu = Opcode(self.cmdj("aoj")[0]["opcode"])

		self.add_string_reference((imm_lui << 16) + opcode_addiu.immediate)

	def sx_from_lw_to_addiu( self, address ):

		self.cmd("s " + str(address))

		opcode_lw = Opcode(self.cmdj("aoj")[0]["opcode"])

		if opcode_lw.immediate == None:
			return

		ptr = opcode_lw.immediate + int(self.cmd("?v gp"), 16)

		self.cmd("f segp=`*" + str(ptr) + "`")
		segment = int(self.cmd("?v segp"), 16)
		self.cmd("f-segp")


		aa = self.rigid_asm_search("^addiu [a-z0-9]{2}, " + opcode_lw.dst_reg +".*$", address+4, address+128, 1)

		if len(aa) == 0:
			return

		addiu_addr = aa[0]

		if addiu_addr == address or addiu_addr == 0:
			return

		self.cmd("s " + str(addiu_addr))

		opcode_addiu = Opcode(self.cmdj("aoj")[0]["opcode"])

		self.add_string_reference(segment + opcode_addiu.immediate)

	def analyze( self ):
		self.total_count = 0
		self.init_gp()

		print "searching for: " + "\"^lui [a-z0-9]{2}, \-?[0-9x]{3,4}$\" ..."
		for plui in self.rigid_asm_search_executable("^lui [a-z0-9]{2}, \-?[0-9x]{3,4}$"):
			self.sx_from_lui_to_addiu(plui)

		print "searching for: " + "\"^lw.*\(gp\)$\" ..."
		for plw in self.rigid_asm_search_executable("^lw.*\(gp\)$"):
			self.sx_from_lw_to_addiu(plw)

		print "\nFound " + str(self.total_count) + " string references.\n"


r = r2pipe.open("#!pipe")
ms = MIPSString(r)
#ms.dump_commands = True
ms.analyze()

