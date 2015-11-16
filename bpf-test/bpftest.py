import r2pipe
from pcapfile import savefile
import binascii
import json
import re
import time


class Context:
	Rejected, Accepted, Unknown = range(3)


	def __init__(self, filename, filecontent = None):
		self.r = r2pipe.open(filename)
		self.r.cmd("e io.cache = true")
		self.r.cmd("e asm.arch = bpf")
		if filecontent != None:
			self.filecontent = filecontent
			self.inject_filecontent()
		else:
			self.gp = self.r.cmdj("ij")["core"]["size"]
			self.filecontent = None

		self.r.cmd("e anal.gp = " + str(self.gp))
		self.r.cmd("e cfg.bigendian=true")
		self.r.cmd("aaa")

	def inject_filecontent(self):
		if self.filecontent != None:
			# filecontent must be hexlified
			clen = len(self.filecontent) / 2
			self.r.cmd("S %d %d %d %d code mrwx" % (0, 0, clen, clen))
			self.r.cmd("wx " + self.filecontent)
			self.gp = clen

	def reset(self):
		self.r.cmd("S-")
		self.r.cmd("s 0")
		self.inject_filecontent()

	def set_packet_data(self, packet):
		self.reset()
		dlen = len(packet)/2
		self.r.cmd("S %d %d %d %d data mrwx" % (self.gp, self.gp, dlen, dlen))
		self.r.cmd("s " + str(self.gp))
		self.r.cmd("wx " + packet)
		self.r.cmd("dr len=" + str(dlen))
		self.r.cmd("s 0")

	def emulate(self):
		self.r.cmd("aei-")
		self.r.cmd("s 0")

		result = self.r.cmd("aecu " + str(self.gp))
		irex = re.compile("BPF result: ([A-Z]+) value: (-?(?:0x)?[0-9a-fA-F]+)")
		for line in result.split("\n"):
			m = re.search(irex, line)
			if m != None and len(m.groups()) >= 2:

				val = int(m.group(2), 0)

				if m.group(1) == 'DROP':
					return (val, Context.Rejected)
				elif m.group(1) == 'ACCEPT':
					return (val, Context.Accepted)

		return (None, Context.Unknown)




def test_pcap(pcap_filename, bpf_filename):
	with open(pcap_filename, 'r') as testcap:
		capfile = savefile.load_savefile(testcap, layers=0, verbose=False)
		
		raw_packets = [pkt.raw() for pkt in capfile.packets]

		r = Context(bpf_filename)

		i = 1
		for rp in raw_packets:
			res = emulate_packet( r, binascii.hexlify(rp) )
			if res[1] == Context.Accepted:
				print "packet %d : accepted" % i
			elif res[1] == Context.Rejected:
				print "packet %d : rejected" % i
			else:
				print "packet %d : unknown" % i

			i+=1



def emulate_packet(r, packet):
	r.set_packet_data(packet)
	return r.emulate()



if __name__ == "__main__":
	test_pcap("crackme_mod.pcap", "bpf.bin")
