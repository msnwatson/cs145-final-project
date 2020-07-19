import sys
from scapy.all import *

class Tracking(Packet):
    name = "TrackingPacket"
    fields_desc=[BitField("enq_qdepth", 0, 19),
                 BitField("deq_qdepth", 0, 19),
                 BitField("hop_num", 0, 16),
                 BitField("sw_name", 0, 49),
				 BitField("final_hop", 0, 1)]

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print("usage: python tracertqueueing.py <host name>")
		print("\thost list: host IP address")
		exit()
		
	hostname = sys.argv[1]

	pkt = IP(dst=hostname, ttl=144) / UDP(dport=33434)
	pkt.proto += 1

	# Send the packet and get a reply
	reply = sr(pkt, multi=True, timeout=1)

	agg_data = []

	for _, resp in reply[0]:
		if not resp.haslayer(ICMP):
			track_info = Tracking(resp[Padding])
			hop_num = track_info.hop_num
			sw_name = hex(track_info.sw_name)[2:].decode('hex')
			enq_qdepth = track_info.enq_qdepth
			deq_qdepth = track_info.deq_qdepth
			final_hop = track_info.final_hop

			agg_data.append([hop_num, sw_name, enq_qdepth, deq_qdepth, final_hop])

	for row in sorted(agg_data):
		print("%s: enq_qdepth = %d, deq_qdepth = %d\n" % (row[1], row[2], row[3]))

	if agg_data[-1][4] == 1:
		print("Final hop was reached! :D")
	else:
		print("Final hop not reached, destination inaccessible :(")
