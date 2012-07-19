#!/usr/bin/env python

import sys, os
import threading

#from ctypes import *
#cap = CDLL("pypcap.dylib")
#print "dosome", cap.some()

import pypcap, dpkt
print "interface:", pypcap.lookupdev()

class Tap:
	def __init__(self, d, vd, ip):
		self.vd = vd
		self.d = d
		self.ip = ip
		self.stop = False

	def start(self):
		self.vfd = pypcap.tunopen(self.vd)
		os.system("ifconfig vlan1 %s up" % self.ip)
		self.cap = pypcap.pcap(self.d)
		#self.cap.setfilter(" inbound and (arp or ip host %s)" % self.ip)
		self.cap.setfilter("ether[21] = 1 and arp")
		self.thread = threading.Thread( target=self.read ).start()

	def read(self):
		while self.stop == False:
			buf = os.read(self.vfd, 4096)
			print "<==",`dpkt.ethernet.Ethernet(buf)`
			self.cap.send(buf)
			

	def run(self):
		print("run ...")
		try:
			for t, p in self.cap:
				d = dpkt.ethernet.Ethernet(p)
				print "==>",`d`
				os.write(self.vfd,p)
		except Exception as r:
			print r
			print "wait thread ..."
			self.stop = True
		os.close(self.vfd)
		self.thread.join()
	
if __name__ == "__main__":
	t = Tap("eth2", "vlan1", "1.1.1.181")
	t.start()
	t.run()

