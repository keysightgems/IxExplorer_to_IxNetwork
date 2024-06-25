from ixia_defines import IxiaPktGenerator, IxiaPortClass
from traffic_gen import IxiaTe
# from ixia import IXIA
import time

"""
import ixnetwork-restpy
"""
from scapy.all import Ether, IP, TCP, Raw
stream_list = []
class Stream:
    def __init__(self,port_name, stream_id: int, pkt_size, pkt, traffic_rate, pkt_limit=0, randomize_packet_size=False, rand_range=[-80, 80], imix_packet_size=False):
        self.port_name              = port_name
        self.stream_id              = stream_id
        self.pkt_size               = pkt_size
        self.pkt                    = pkt
        self.traffic_rate           = traffic_rate
        self.pkt_limit              = pkt_limit
        self.randomize_packet_size  = randomize_packet_size
        self.rand_range             = rand_range
        self.imix_packet_size       = imix_packet_size

def addStream(port_name, stream_id: int, pkt_size, pkt, traffic_rate):
    # obj = Stream(port_name, stream_id: int, pkt_size, pkt, traffic_rate, pkt_limit=0, randomize_packet_size=False, rand_range=[-80, 80], imix_packet_size=False)
    obj = Stream(port_name, stream_id, pkt_size, pkt, traffic_rate)
    stream_list.append(obj)



packet = Ether(dst='00:00:00:11:11:11', src='00:00:00:22:22:22', type=0xf8ff)/IP(ihl=None, tos=0, id=102, frag=0, ttl=64, src='192.168.0.1', dst='10.0.0.1')/TCP(sport=1234, dport=80, flags=2)/Raw(load=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-')

for i in range(0,1000):
    port_name = "2/9"
    stream_id = i
    pkt_size = 128
    pkt = packet
    traffic_rate = 20
    addStream(port_name, stream_id, pkt_size, pkt, traffic_rate)
#<Ether  dst=00:00:00:00:00:00 src=00:00:00:00:00:00 type=0x1df4 |<Raw  load=b'\x04\x00\x000\x0f\xe0\x00\x00\x00\x00\x04 \x00\x00\x00\x00`\x02#\xff\xff\xf3\xff\xff\xf3\xff\xff\xf3\xff\xff\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x04' |>>
apiServerIp = "127.0.0.1" #(Windows/Linux IP)
# apiServerIp = "10.39.70.237"
# ixChassisIp  = ["10.39.64.137"]
# ixChassisIp  = ["10.39.64.169"]
ixChassisIp  = ["10.39.65.156"]
#osPlatform = 'linux'
ixia_te = IxiaTe(ip_addr="10.39.65.156", usr_name="Mohan", debug=False, server_ip=apiServerIp, port='11009', session_name='IxNetwork Test 150', clear_config=False)
#The below line port/session_name params are optional
# ixia_te = IxiaTe(ip_addr="10.39.65.156", usr_name="admin", debug=True, server_ip=apiServerIp, port='443', session_name='IxNetwork Test 1')

ixia_te.reserve_ports("2/1", "1", portLoop=False)
ixia_te.reserve_ports("2/2", "2", portLoop=True)
# import pdb;pdb.set_trace()
seconds = time.time()
local_time = time.ctime(seconds)
ixia_te.add_stream(stream_list)
seconds1 = time.time()
local_time1 = time.ctime(seconds1)
print("Start time:", local_time)
print("End time:", local_time1)
import pdb;pdb.set_trace()
# ixia_te.reserve_ports("2/11", "10")
# ixia_te.reserve_ports("2/12", "10")
# pkt=ixia_te.scapy_packet_to_layers(packet)
# for i in range(5):
# seconds = time.time()
# local_time = time.ctime(seconds)
# ixia_te.add_stream("2/9", 1, 128, packet, 10)
# ixia_te.add_stream("2/10", 1, 128, packet, 10)
# seconds1 = time.time()
# local_time1 = time.ctime(seconds1)
# print("Start time:", local_time)
# print("End time:", local_time1)
# import pdb;pdb.set_trace()
# import pdb;pdb.set_trace()
# for i in range(2):
# ixia_te.add_stream("2/10", 2, 512, packet, 100)
# import pdb;pdb.set_trace()
# ixia_te.add_modifier("2/9", 1, 128, 64, 1050, "random")
# ixia_te.change_traffic_mac(1, "ff:ff:ff:ff:ff:ee", 2)
# ixia_te.add_stream("2/10", 1, 128, packet, 10)
# ixia_te.add_modifier("2/9", 1, "random", 64, 128, "True")
# import pdb;pdb.set_trace()
ixia_te.enable_stream("2/9", 1)

ixia_te.disable_stream("2/9", 2)
import pdb;pdb.set_trace()
# ixia_te.add_stream_layer_start(1, 30, 128, "00:0c:29:68:05:14", "00:0c:29:68:05:1E", 100, 1,etype=0x0800,gid=0)
ixia_te.clear_port_statistics("2/9")
# ixia_te.enable_capture("2/9", True)
ixia_te.start_traffic("2/9")
time.sleep(20)
ixia_te.enable_capture("2/9", False)
ixia_te.get_capture("2/9")
ixia_te.stop_traffic("2/9")
# # ixia_te.get_rx_statistic(1,1)
ixia_te.get_port_statistics("2/9")
# ixia_te.get_stream_statistics("2/9", 1)
# ixia_te.teardown_session()

#, session_name='IxNetwork Test 150'
# ixia_te.add_port("2/9")
# ixia_te.add_port("2/10")
# import pdb;pdb.set_trace()
# ixia_te.add_stream_layer_start(1, 30, 128, "00:0c:29:68:05:14", "00:0c:29:68:05:1E", 100, 1,etype=0x0800,gid=0)
# ixia_te.clear_statistic()
# ixia_te.enable_capture(True)
# ixia_te.start_traffic()
# import pdb;pdb.set_trace()
# ixia_te.clear_statistic()

# time.sleep(20)
# ixia_te.enable_capture(False)
# ixia_te.get_packets()
# ixia_te.stop_traffic()
# # ixia_te.get_rx_statistic(1,1)
# ixia_te.get_statistic()

# ixia_te = IxiaTe(ip_addr="10.39.64.169", usr_name="Mohan", debug=True, server_ip=apiServerIp, port='443', session_name='IxNetwork Test 150')
# ixia_te.reserve_ports("2/9", 1)
# ixia_te.reserve_ports("2/10", 2)
# import pdb;pdb.set_trace()
# ixia_te.enable_stream("2/9", 1)

