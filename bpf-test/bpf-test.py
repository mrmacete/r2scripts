import r2pipe
from pcapfile import savefile
import binascii
import json
import re


class Context:
	Rejected, Accepted, Unknown = range(3)


	def __init__(self, filename):
		self.r = r2pipe.open(filename)
		self.gp = self.r.cmdj("ij")["core"]["size"]
		self.r.cmd("e anal.gp = " + str(self.gp))
		self.r.cmd("e io.cache = true")
		self.r.cmd("e asm.arch = bpf")
		self.r.cmd("e cfg.bigendian=true")
		self.r.cmd("aaa")


	def reset(self):
		self.r.cmd("S-*")
		self.r.cmd("s 0")

	def set_packet_data(self, packet):
		self.reset()
		self.r.cmd("S %d %d %d %d packet mrwx" % (self.gp, self.gp, len(packet)/2, len(packet)/2))
		self.r.cmd("s " + str(self.gp))
		self.r.cmd("wx " + packet)
		self.r.cmd("s 0")

	def emulate(self):
		self.r.cmd("aei-")
		self.r.cmd("s 0")

		result = self.r.cmd("aecu " + str(self.gp))
		irex = re.compile("BPF result: ([A-Z]+)")
		for line in result.split("\n"):
			m = re.search(irex, line)
			if m != None and len(m.groups()):
				if m.group(1) == 'DROP':
					return Context.Rejected
				elif m.group(1) == 'ACCEPT':
					return Context.Accepted

		return Context.Unknown




def test_pcap(pcap_filename, bpf_filename):
	with open(pcap_filename, 'r') as testcap:
		capfile = savefile.load_savefile(testcap, layers=0, verbose=False)
		
		raw_packets = [pkt.raw() for pkt in capfile.packets]

		r = Context(bpf_filename)

		i = 1
		for rp in raw_packets:
			res = emulate_packet( r, binascii.hexlify(rp) )
			if res == Context.Accepted:
				print "packet %d : accepted" % i
			elif res == Context.Rejected:
				print "packet %d : rejected" % i
			i+=1


def emulate_packet(r, packet):
	r.set_packet_data(packet)
	return r.emulate()



if __name__ == "__main__":
	test_pcap("crackme_mod.pcap", "bpf.bin")
