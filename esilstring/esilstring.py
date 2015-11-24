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

def esil_parse_dst( esil ):
	es = esil.split(',')
	try:
		eq = (len(es)-1) - es[::-1].index('=')
		return es[eq-1]
	except:
		return False



class ESILString:

	dump_commands = False
	debug_log = True
	total_count = 0
	include_flagspaces = set(["str.", "sym."])
	exclude_flagspaces = set()

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

	def dlog( self, line ):
		if self.debug_log:
			print line

	def init_gp( self ):
		self.cmd("aaa")
		self.cmd("fs sections")
		self.cmd("e asm.relsub = true")
		self.cmd("e anal.gp=`? (section..got+0x7ff0)~[1]`")
		self.cmd("f gp=`? (section..got+0x7ff0)~[1]`")
		self.cmd("fs *")
		self.cmd("aaa")
		self.cmd("aae")
		self.gp = self.cmd("?v gp")
		print "Canonical gp value: " + self.gp


	def init_flags( self ):
		raw = self.cmdj("fj")
		
		self.flags = {}

		for f in raw:
			off = f["offset"]

			if off in self.flags:
				self.flags[off].append(f)
			else:
				self.flags[off] = [f]

	def merge_sections(self, xsex, tolerance):

		result = []
		current = None

		for sec in xsex:
			if current != None and (sec[0] - (current[0] + current[1])) <= tolerance:
				current[1] += (sec[0] - (current[0] + current[1])) + sec[1]
				current[2] = current[2] + "+" + sec[2]
			else:
				if current != None:
					result.append(current)
				current = list(sec)

		if current != None:
			result.append (current)

		return result

	def emulate_functions(self):

		flags = self.cmdj("fj")

		xsex = [(f["offset"], int(f["size"]), f["name"]) for f in flags if f["name"].startswith("fcn.") or f["name"].startswith("loc.") or (f["name"].startswith("sym.") and not f["name"].startswith("sym.imp."))]

		xsex.sort(key=lambda x: x[0])
		xsex = self.merge_sections(xsex, 0)

		for sec in xsex:
			self.emulate_from_to(sec[0], sec[0]+sec[1], sec[2])


	def emulate_from_to(self, from_addr , to_addr, name=None):

		inited = False
		if name != None:
			print "emulating " + name + " from " + hex(from_addr) + " to " + hex(to_addr) + " ..."
		else:
			print "emulating from " + hex(from_addr) + " to " + hex(to_addr) + " ..."

		addr = from_addr
		while addr < to_addr:
			self.cmd("s " + str(addr))
			
			o = self.cmdj("aoj")
			if o != None and len(o) > 0:

				if not inited:
					self.cmd("aei")
					self.cmd("aeip")
					self.cmd("aeim")
					inited = True

				self.cmd("aesl")

				if "esil" in o[0]:
					dst = esil_parse_dst(o[0]["esil"])
					if dst != False:
						regs = self.cmdj("arj")
						if dst in regs:
							val = regs[dst]
							self.add_flag_reference(val)
						else:
							self.dlog( "unknown register: " + dst )
				elif "opcode" in o[0]:
					self.dlog( "no esil for: " + o[0]["opcode"] )
				else:
					self.dlog( "no esil for this: " + str(o[0]))

				addr += o[0]["size"]
			else:

				self.dlog("skipping invalid at " + hex(addr))
				addr += 1

		if inited:
			self.cmd("aei-")
			self.cmd("aeim-")
			self.cmd("aek-")
			self.cmd("ar0")
			self.cmd("dr gp=" + self.gp)

		


	def add_flag_reference( self, offset):
		
		if offset in self.flags:

			flags = self.flags[offset]
			for flag in flags:
				include = False

				for toinclude in self.include_flagspaces:
					if flag["name"].startswith(toinclude):
						include = True
						break

				for toexclude in self.exclude_flagspaces:
					if flag["name"].startswith(toexclude):
						include = False
						break

				if not include:
					continue


				self.cmd("CC " + flag["name"])
				self.cmd("axd " + str(offset))
				self.total_count += 1

				self.dlog( "added reference to " + flag["name"] )
		else:

			# no flags, try to extract a nullterminated string

			psz = self.cmd("psz @ " + str(offset))

			if psz != None and len(psz.strip()) > 0:
				comment = "'"+self.normalize_str(psz)+"'"
				self.cmd("CC " + comment + " at " + hex(offset))
				self.cmd("axd " + str(offset))
				self.total_count += 1

	nrex = re.compile('[^a-zA-Z0-9%\-\+]')
	def normalize_str(self, astr):
		return re.sub(self.nrex, "_",astr.strip())

	def analyze( self ):
		self.total_count = 0
		self.init_gp()
		self.cmd("e io.cache=true")
		self.init_flags()

		self.emulate_functions()

		print "\nFound " + str(self.total_count) + " references.\n"


r = r2pipe.open("#!pipe")
ms = ESILString(r)
#ms.dump_commands = True
ms.analyze()

