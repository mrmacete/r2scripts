import re
from testeval import *
import bpftest
import binascii
import json

STATE_INIT, STATE_DESCR, STATE_INSN, STATE_FLAGS, STATE_DATA, STATE_TESTS, STATE_FRAG, STATE_PARSED = range(8)


def to_signed_32(n):
	n = n & 0xffffffff
	if n >> 31 == 1:
		return n - 0x100000000 
	return n

class BpfTestValue:	
	def __init__(self, rawtest):
		splitted = [e.strip("{ }\n\r") for e in rawtest.strip("{ }\n\r").split(",")]
	 	self.raw = splitted[1]
	 	self.len = int(splitted[0],0)
	 	try:
	 		self.parsed = to_signed_32(int(splitted[1],0))
	 	except:
	 		self.parsed = None

	 	if not self.parsed:
		 	try:
		 		self.parsed = to_signed_32(testeval(splitted[1]))
		 	except:
		 		self.parsed = None


	def __repr__(self):
		if self.parsed:
			return "Len %d -> %d (%s)" % (self.len, self.parsed, self.raw)
		else:
			return "Len %d -> (%s)" % (self.len, self.raw)


class BpfTest:

	_descr_extractor = re.compile ("\"([^\"]+)\"")
	_data_element_extractor = re.compile("([^\{\},]+)")
	_test_extractor = re.compile("(\{\s?[^{},]+,\s?[^{},]+\s?\})")
	_element_extractor = re.compile("\[([^]]+)]\s*=\s*(-?(?:0x)?[0-9a-fA-F]+)")

	def __init__(self):
		self.descr = ""
		self.instructions = []
		self.flags = []
		self.data = ['0'] * 128
		self.frag_data = ['0'] * 128
		self.data_len = 0
		self.frag_data_len = 0
		self.tests = []
		self._line_counter = -1
		self._state = STATE_INIT
		self.broken = False
		self.asm_test_func = None

	def feed_line(self, line):
		self._line_counter += 1
		if self._line_counter == 1:
			self.descr = re.search (self._descr_extractor, line).groups()[0]
			self._state = STATE_DESCR
		else:
			if self._state == STATE_DESCR:
				if line.strip ().find ('u.insns') >= 0:
					self._state = STATE_INSN
			elif self._state == STATE_INSN:
				if line.strip ().find ('},') >= 0:
					self._state = STATE_FLAGS
				else:
					insn = line.strip ().rstrip (',')
					if insn.find("SK") >= 0:
						self.broken = True
					self.instructions.append ( insn )
			elif self._state == STATE_FLAGS:
				self.flags = [ f.strip () for f in line.strip ().rstrip (',').split ("|") ]
				self._state = STATE_DATA
			elif self._state == STATE_DATA:
				m = re.findall (self._data_element_extractor, line.strip ())
				for el in m:
					els = el.strip ()
					if len(els) > 0:
						mm = re.findall (self._element_extractor, els)
						if len(mm) >0:
							self.data[int(mm[0][0],0)] = mm[0][1]
						else:
							self.data[self.data_len] = els
							self.data_len += 1
				if line.find("},") >= 0:
					self._state = STATE_TESTS
			elif self._state == STATE_TESTS:
				m = re.findall (self._test_extractor, line.strip ())
				for el in m:
					els = el.strip ()
					if len(els) > 0:
						self.tests.append (BpfTestValue(els))

				if line.strip().startswith("},") or line.find("} },") >= 0:
					self._state = STATE_FRAG
			elif self._state == STATE_FRAG:
				m = re.findall (self._data_element_extractor, line.strip ().replace(".frag_data =", ""))
				for el in m:
					els = el.strip ()
					if len(els) > 0:
						mm = re.findall (self._element_extractor, els)
						if len(mm) >0:
							self.frag_data[int(mm[0][0],0)] = mm[0][1]
						else:
							self.frag_data[self.frag_data_len] = els
							self.frag_data_len += 1
				if line.find("},") >= 0:
					self._state = STATE_PARSED



	
	def compile(self):
		
		self.compiled = []

		merged = None
		for ins in self.instructions:

			if len (ins) == 0:
				continue

			if merged != None:
				merged.append(ins)
				ins = ', '.join(merged)
				merged = None

			if ins[-1] != ')':
				merged = [ins]
			else:
				try:
					self.compiled.append ( testeval (ins) )
				except:
					print self.descr + " - ERROR COMPILING: " + ins
					return False


		return True

	def get_data_for_len(self, dlen):
		try:
			if dlen > 0:
				data = [int(x,0) for x in self.data[:dlen]]
			else:
				data = []

			if self.frag_data_len > 0:
				frag_data = [int(x,0) for x in self.frag_data[:self.frag_data_len]]
			else:
				frag_data = []
			return data + frag_data
		except:
			print self.descr + " - cannot parse data"
			return [0] * dlen

	def run(self):
		content = []
		try:
			for ins in self.compiled:
				content.append(ins.binarydata())
		except:
			print self.descr + " FAIL: error on code data"
			return False

		c = bpftest.Context(filename = "malloc://2048", filecontent = binascii.hexlify(b''.join(content)))
		for test in self.tests:
			d = self.get_data_for_len(test.len)
			if len(d) > 0:
				c.set_packet_data(binascii.hexlify(bytearray(d)))

			else:
				c.reset()
			val = c.emulate()[0]

			self.asm_test_func = c.r.cmdj("pdfj @ 0")

			if val != test.parsed:
				print self.descr + " CODE: " + binascii.hexlify(b''.join(content))
				print self.descr + " DATA: " + binascii.hexlify(bytearray(d))
				print c.r.cmd("e asm.emu = true")
				print c.r.cmd("pdf @ 0")

				print self.descr + " FAIL: " + str(val) + " != " + test.raw
				return False


		return True


	def gen_asm_test(self):

		content = []
		try:
			for ins in self.compiled:
				content.append(ins.binarydata())
		except:
			print self.descr + " FAIL: error on code data"
			return []


		if self.asm_test_func == None:
			return []

		tests = []
		for op in self.asm_test_func["ops"]:
			if op["opcode"].startswith("j"):
				continue
			tests.append((op["opcode"], op["bytes"]))

		return tests


def stripcomments(text):
    return re.sub('//.*?\n|/\*.*?\*/', '', text, re.S)

def parse_test_bpf_c(fileName):

	started = False
	start_marker = "static struct bpf_test tests[] = {"
	test_start_marker = "	{"
	test_end_marker = "	},"
	end_marker = "};"
	skipping_prepro = False
	tests = []
	current_test = None
	with open (fileName, 'r') as f:
		for line in f:
			if not started:
				if line.strip () == start_marker:
					started = True
				continue

			line = stripcomments (line)

			if line.find ('/*') >= 0 or line.find ('*/') >= 0 or line.strip ().startswith ('*'):
				continue

			if line.strip().startswith('#'):
				if line.strip() == "#else":
					skipping_prepro = True
				elif line.strip() == "#endif":
					skipping_prepro = False
				continue

			if skipping_prepro:
				continue

			if line.rstrip() == test_start_marker:
				if current_test != None:
					tests.append (current_test)
				current_test = BpfTest ()

			if current_test != None:
				current_test.feed_line (line)

			if line.rstrip() == end_marker:
				break

	return tests


def run_tests_with_flag(flag):
	all_tests = parse_test_bpf_c ("test_bpf.c")
	print "found %d tests" % len(all_tests)

	unsupported_values = set()

	broken_tests = []
	flagged_tests = []
	for test in all_tests:
		try:
			if test.flags.index(flag) >=0 :
				if test.broken:
					broken_tests += test.tests
				else:
					for tv in test.tests:
						if tv.parsed == None:
							unsupported_values.add(tv.raw)
						else:
							flagged_tests.append(test)
		except:
			pass

	print "WARNING: found %d unsupported test values:" % len(unsupported_values)
	print '\n'.join(['\t'+v for v in unsupported_values])
	print "running %d tests with flag \"%s\" ..." % (len(flagged_tests), flag)

	failed = 0
	succeed = 0
	for test in flagged_tests:
		if test.compile ():
			if test.run():
				succeed += 1
			else:
				failed += 1

	print "succeed: %d / %d" % (succeed, len(flagged_tests) + len(broken_tests))
	print "failed: %d / %d" % (failed, len(flagged_tests) + len(broken_tests))
	print "broken: %d / %d" % (len(broken_tests), len(flagged_tests) + len(broken_tests))

	return all_tests

def run_asm_tests_with_flag(flag, all_tests):
	flagged_tests = []
	for test in all_tests:
		try:
			if test.flags.index(flag) >=0 and not test.broken and not 'FLAG_EXPECTED_FAIL' in test.flags:
				if test.compile():
					flagged_tests += test.gen_asm_test()
		except ValueError:
			pass

	print "running %d tests with flag \"%s\" ..." % (len(flagged_tests), flag)

	failed = 0
	succeed = 0
	c = bpftest.Context("-")
	for test in flagged_tests:
		bytecode = c.r.cmd("\"pa " + test[0] + "\"")
		if bytecode.strip() == test[1]:
			succeed += 1
		else:
			print "\nFAILED: " + test[0] + " - " + bytecode.strip() + " != " + test[1] + "\n"
			failed += 1

	print "succeed: %d / %d" % (succeed, len(flagged_tests))
	print "failed: %d / %d" % (failed, len(flagged_tests))


if __name__ == "__main__":
	# run test_bpf.c emulation tests:
	all_tests = run_tests_with_flag("CLASSIC")

	# run "assemble the disassembled" above tests:
	run_asm_tests_with_flag("CLASSIC", all_tests)
