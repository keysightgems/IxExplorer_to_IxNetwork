import ixia_defines
import logging
from binascii import hexlify, unhexlify
from ixnetwork_restpy.testplatform.testplatform import TestPlatform
from ixnetwork_restpy.assistants.statistics.statviewassistant import StatViewAssistant
from ixnetwork_restpy import SessionAssistant
trafficData = []
portList = []
class IxiaTe():

    def __init__(self, ip_addr, usr_name, debug, **kwargs):
        self.server_ip = kwargs.get('server_ip', None)
        self.port = kwargs.get('port', 443)
        self.session_name = kwargs.get('session_name', None)
        self.pkt_gen = ixia_defines.IxiaPktGenerator(ip_addr, usr_name, debug, server_ip=self.server_ip, port=self.port, session_name=self.session_name)
        self.gid = 0
        self.ports = {}
        self.streams = {}
        self.card_id = 2
        self.port_id = 9
        # super().__init__(te_type='ixia_te', ip=ip_addr)

    def reserve_ports(self, port_name, connected_port, speed=100, portLoop=False):        
        if portLoop:
            portList.append(port_name)
            self.ports[port_name] = self.pkt_gen.add_port(portList)                
            # super().reserve_ports(port_name, connected_port, speed)
            return self.ports[port_name]
        else:
            portList.append(port_name)

    def start_traffic(self, port_name):
        self.ports[port_name].start_traffic(port_name)
        # for vportObj in self.pkt_gen.Vport.find():            
        #     if port_name.replace("/", ":") in vportObj.AssignedTo:
        #         vportObj.StartStatelessTraffic()
        #         break

    def stop_traffic(self, port_name):
        self.ports[port_name].stop_traffic(port_name)
        # for vportObj in self.pkt_gen.Vport.find():            
        #     if port_name.replace("/", ":") in vportObj.AssignedTo:
        #         vportObj.StopStatelessTraffic()
        #         break

    def reset_port(self, port_name):
        super().reset_port(port_name)
        self.ports[port_name].reset(port_name)

    def enable_capture(self, port_name, enable):
        # super().enable_capture(port_name, enable)
        self.ports[port_name].enable_capture(enable, port_name)
        # for vportObj in self.pkt_gen.Vport.find():            
        #     if port_name.replace("/", ":") in vportObj.AssignedTo:
        #         vportObj.Capture.find().Start()
        #         break

    def get_capture(self, port_name):
        return self.ports[port_name].get_packets(port_name)
        # for vportObj in self.pkt_gen.Vport.find():            
        #     if port_name.replace("/", ":") in vportObj.AssignedTo:
        #         return vportObj.Capture.find().read()                

    # Enable pkt payload checksum error in TE
    def enable_payload_checksum(self, port_name, payload_cs_offset):
        # TODO
        pass

    def scapy_packet_to_layers(self, pkt):
        counter = 0
        header_size = 0
        layers = []
        is_gre = False
        while True:
            layer = pkt.getlayer(counter)
            if layer is None:
                break
            if self.scapy_layer_name_to_ixia(layer.name) == 'Unsupported':
                print(
                    "Ixia stream has unsupported scapy layer type:{0}, default to add_stream_layer2".format(layer.name))
                layers = []
                break
            if self.scapy_layer_name_to_ixia(layer.name) == 'GRE':
                is_gre = True
            layers.append(layer)
            header_size += self.scapy_layer_header_size(layer.name)
            counter += 1
        # import pdb;pdb.set_trace()
        return layers, header_size, is_gre

    def scapy_layer_name_to_ixia(self, name):
        # import pdb;pdb.set_trace()
        return {
            'Ethernet': 'Ethernet',
            'IP': 'IP',
            '802.1Q': 'VLAN',  # header size are different
            'MPLS': 'MPLS',
            'IPv6': 'IPv6',
            'TCP': 'TCP',
            'UDP': 'UDP',
            'GRE': 'GRE',
            'VXLAN': 'VXLAN',
            'Raw': 'RAW',
        }.get(name, 'Unsupported')

    def scapy_layer_header_size(self, name):
        # return each supported scapy layer header size
        return {
            'Ethernet': 14,
            'IP': 20,
            '802.1Q': 4,
            'MPLS': 4,
            'IPv6': 40,
            'TCP': 20,
            'UDP': 8,
            'GRE': 4,
            'VXLAN': 8,
            'Raw': 0,
        }.get(name, 0)

    def set_packet_size_mix(self, port_name, packet_mix_type):
        self.ports[port_name].set_packet_size_mix(packet_mix_type)

    # ixia now use layered API to create stream if possible, o.w. it will default
    # to old way of create stream, i.e. add_stream_layer2
    def add_stream(self, stream_list):
        stream_data_list = []
        for st in stream_list:
            stream_data_dict = {}
            (layers, hdr_size, is_gre) = self.scapy_packet_to_layers(st.pkt)
            # import pdb;pdb.set_trace()
            if len(layers) == 0:
                print('ERROR: shouldnt come here')
                return               

            # if we come here, we'll use layered API to create the Ixia packet stream
            stats_offset = 0
            if not (st.randomize_packet_size or st.imix_packet_size):
                # this is really unfortunate, we would love to use pre-calculate hdr_size
                # as each stream stats offset, this works really well if test only contains
                # streams with same type of packets. A single test with multiple streams
                # of different type packets can't use hdr_size as stream stats offset
                # anymore, as Ixia requires all streams on the TG port must share the
                # stats offset value, since most tests's stream size are fixed, we switch
                # to packet_size to figure out stats offset towards the end of packet.
                # instead.
                # The only exception for this assumption is when randomized packet size
                # stream is used in test, where every packet may have different pkt_size,
                # such test will only use single type of packet, i.e. layer2, therefore,
                # we can use hdr_size as stats offset value.
                stats_offset = st.pkt_size - 20
            elif st.randomize_packet_size:
                stats_offset = st.pkt_size + st.rand_range[0] - 20
            elif st.imix_packet_size:
                # Ixia only support predefined IMIX1, i.e. IMIX packet starts from 64B
                st.pkt_size = 64
                stats_offset = st.pkt_size - 20
                print("predefined Ixia IMIX1 packet hdr_size:{0}".format(stats_offset))

            seq_check = True
            if (hdr_size + 4) > stats_offset:
                seq_check = False
                print("packet size not big enough, disable sequence check")

            stream = None
            outer_vlan = 1
            inner_vlan = 0
            mpls_tag_no = 0
            last_mpls_tag = False
            ip_header_cnt = 0
            is_ipv4 = False
            layer_cnt = 0
            gre_stack = []
            for layer in layers:                
                l_name = self.scapy_layer_name_to_ixia(layer.name)
                if l_name == 'Ethernet':      
                    port_session = ixia_defines.IxiaPortClass(self.pkt_gen.sg, st.port_name)    
                    self.ports[st.port_name] = port_session
                    stream_data_dict["port_name"], stream_data_dict["stream_id"], stream_data_dict["traffic_rate"], stream_data_dict["pkt_size"], stream_data_dict["frame_type"], stream_data_dict["eth_src_mac"], stream_data_dict["eth_dst_mac"], stream_data_dict["statsOffset"], stream_data_dict["etype"] = st.port_name, st.stream_id, st.traffic_rate, st.pkt_size, "fixed", layer.src, layer.dst, stats_offset, hex(layer.type)
                    
                elif l_name == 'VLAN':
                    if outer_vlan:
                        inner_vlan = layer.vlan
                        stream_data_dict["Vlan"], stream_data_dict["outer_vlan"], stream_data_dict["inner_vlan"] = True, outer_vlan, inner_vlan
                    elif len(layers) > (layer_cnt + 1) and layers[layer_cnt + 1].name == 'VLAN':
                        # seeing Q-in-Q vlan tag, parse the outer_vlan, and let it continue
                        outer_vlan = layer.vlan
                    else:
                        # seeing single dot1q vlan tag
                        stream_data_dict["Vlan"], stream_data_dict["vlan_id"], stream_data_dict["vlan_priority"] = True, layer.vlan, layer.prio
                elif l_name == 'MPLS':
                    if len(layers) > (layer_cnt + 1) and layers[layer_cnt + 1].name == 'MPLS':
                        last_mpls_tag = False
                    else:
                        last_mpls_tag = True
                    mpls_tag_no += 1
                    stream_data_dict["Mpls"], stream_data_dict["mpls_tag_no"], stream_data_dict["mpls_label"], stream_data_dict["mpls_ttl"], stream_data_dict["mpls_last_tag"] = True, mpls_tag_no, layer.label, layer.ttl, last_mpls_tag
                elif l_name == 'IP':
                    is_ipv4 = True
                    # GRE workaround, outer IP must be configured after inner IP payload
                    if ip_header_cnt == 0 and is_gre:
                        gre_stack.append(layer)
                        ip_header_cnt += 1
                        layer_cnt += 1
                        continue
                    ip_header_cnt += 1
                    stream_data_dict["Ipv4"], stream_data_dict["ipv4_ttl"], stream_data_dict["ipv4_src"], stream_data_dict["ipv4_dst"] = True, layer.ttl, layer.src, layer.dst
                elif l_name == 'IPv6':
                    stream_data_dict["Ipv6"], stream_data_dict["ipv6_hop_limit"], stream_data_dict["ipv6_src"], stream_data_dict["ipv6_dst"] = True, layer.hlim, layer.src, layer.dst
                elif l_name == 'TCP':
                    stream_data_dict["Tcp"], stream_data_dict["tcp_src_port"], stream_data_dict["tcp_dst_port"], stream_data_dict["tcp_seq_no"] = True, layer.sport, layer.dport, layer.seq
                elif l_name == 'UDP':
                    stream_data_dict["Udp"], stream_data_dict["udp_src_port"], stream_data_dict["udp_dst_port"] = True, layer.sport, layer.dport
                elif l_name == 'GRE':
                    # GRE workaround, GRE header must be configured after inner IP payload
                    gre_stack.append(layer)
                    layer_cnt += 1
                    continue
                elif l_name == 'VXLAN':
                    # Ixia doesnt' support VXLAN protocol yet, the workaround is to
                    # use protocolPad to support VXLAN header, so that VXLAN header
                    # and its content (inner Ether/Ip/Tcp) is treated as fixed pattern,
                    # while the rest payload as random pattern (emulate random VXLAN
                    # payload) stream signature offset is calculated with the consideration
                    # of VXLAN hdr + inner payload hdr (Ether/IP/TCP etc), just to
                    # make sure it won't accidentally override VXLAN inner payload
                    # header
                    # payload = hexlify(bytes(layer)).decode('ascii')
                    payload = " ".join(payload[i:i + 2] for i in range(0, len(payload), 2))
                    stream_data_dict["Vxlan"], stream_data_dict["vxlan_payload"] = True, payload
                    # VXLAN payload is last layer, no need to continue
                    break
                elif l_name == 'RAW':
                    # if see RAW payload, need to take the payload as dataPattern,
                    # first 6 bytes of RAW payload will still be overriden as stream
                    # signature.
                    payload = hexlify(bytes(layer)).decode('ascii')
                    payloadlen = len(payload)
                    stream_data_dict["Custom"], stream_data_dict["custom_length"], stream_data_dict["custom_data"] = True, payloadlen, payload
                    # RAW payload is last layer, no need to continue
                    break
                else:
                    assert ("Unsupported scapy packet layer:{0}".format(l_name))
                layer_cnt += 1           

            # GRE workaround for Ixia, after inner IP payload is configured, then
            # we configure GRE header and outer IP header
            if is_gre:
                gre_hdr = gre_stack.pop()
                outer_ip = gre_stack.pop()
                stream_data_dict["Gre"], stream_data_dict["gre_version"], stream_data_dict["gre_ttl"], stream_data_dict["gre_src"], stream_data_dict["gre_dst"] = True, gre_hdr.version, outer_ip.ttl, outer_ip.src, outer_ip.dst

            # push layered Tcl script to Ixia
            if seq_check:
                seqcheck_mode = "interleaved"
            else:
                seqcheck_mode = "interleaved"
            stream_data_dict["tracking_offset"], stream_data_dict["traffic_mode"] = stats_offset, seqcheck_mode
            if st.randomize_packet_size:
                # reset stream size, only if specified as random range
                stream_data_dict["frame_type"], stream_data_dict["frame_min"],stream_data_dict["frame_max"] = "random", st.pkt_size + st.rand_range[0], st.pkt_size + st.rand_range[1]
            elif st.imix_packet_size:
                # reset stream random size type as IMIX
                stream_data_dict["frame_type"] = "IMIX"
            # if specific amount of packets were requested, then
            # the stream will be reconfigured as a burst mode.
            if st.pkt_limit > 0:
                stream_data_dict["fixed_frame_type"], stream_data_dict["fixed_frame_count"] = "fixedFrameCount", st.pkt_limit
            stream_data_list.append(stream_data_dict)            
        port_session = ixia_defines.IxiaPortClass(self.pkt_gen.sg, st.port_name) 
        self.streams = port_session.add_stream_layer_start(stream_data_list)  
        return self.streams

    # this is the default way to handle stream creation, we treat everything as
    # layer2 packet, it's the simple way, but has its own limitation, for now,
    # we try to switch to layered API to create stream, if we are not able to handle
    # via layered API, we'll default to old layer2 API.
    def add_stream_layer2(self, port_name, stream_id: int, pkt_size, pkt, traffic_rate,
                          pkt_limit=0, randomize_packet_size=False, rand_range=[-80, 80], imix_packet_size=False):
        # A quick hack for Ixia TG sending all-0 payload, until we figure out RANDOM payload type...
        if pkt_size <= 1000:
            pkt = pkt / Raw(RandString(size=pkt_size))
        else:
            pkt = pkt / Raw(RandString(size=1000))
        layer = pkt.getlayer(0)
        bytes_str = hexlify(bytes(layer)).decode('ascii')
        mac_da = bytes_str[0:12]
        mac_da = " ".join(mac_da[i:i + 2] for i in range(0, len(mac_da), 2))
        mac_sa = bytes_str[12:24]
        mac_sa = " ".join(mac_sa[i:i + 2] for i in range(0, len(mac_sa), 2))
        payload = bytes_str[24:]
        payload = " ".join(payload[i:i + 2] for i in range(0, len(payload), 2))

        stream = self.ports[port_name].add_stream_layer2(stream_id, traffic_rate, pkt_size, mac_sa, mac_da, payload,
                                                         pkt, port_name)
        stream.set_rate_percentage(traffic_rate)
        # if specific amount of packets were requested, then
        # the stream will be reconfigured as a burst mode.
        if pkt_limit > 0:
            stream.set_packet_limit(pkt_limit)
        stream.enable_traffic()
        self.streams[port_name, stream_id] = stream
        return stream
    
    def add_stream_json(self, stream_list):
        pass

    def change_traffic_mac(self, sid, mask=None, init=None, macDa=False, count=None, step=None, action=None, field_size=None, value_type="nonRepeatableRandom", udf=False, byte_offset=None):
        """
        Internal method to update the random values.
        :param sid (str)
        :param mask (str)
        :param init (int)
        availableValueTypes: "singleValue", "valueList", "increment", "decrement", "random", "nonRepeatableRandom", "repeatableRandomRange"
        """
        print("Changing Mac Parameters for Traffic Item/Items")
        # import pdb;pdb.set_trace()
        self.sg=self.pkt_gen.sg
        for trafficObj in self.sg.Traffic.TrafficItem.find().HighLevelStream.find():
            if 'highLevelStream/' + str(sid) in trafficObj.href:
                frameType = trafficObj.FrameSize.find()
                frameType.FixedSize = field_size
                if action == "random":
                    action = "random"
                else:
                    if action:
                        if "inc" in action.lower():
                            direction = "increment"
                        else:
                            direction = "decrement"
                        action = "counter"
                if udf:                    
                    trafficObj.Udf.add(ByteOffset=byte_offset, Enabled=True, Type=action)
                    if action == "counter":
                        trafficObj.Udf.find().counter.add(Count=count, Direction=direction)
                    for stack in trafficObj.Stack.find():
                        fieldNames = [fieldObj.DisplayName for fieldObj in stack[0].Field.find()]
                        for fieldName in fieldNames:                        
                            if fieldName == "Destination MAC Address":
                                field = stack[0].Field.find(DisplayName=fieldName)
                                field.ValueType, field.RandomMask, field.Seed = value_type, mask, init
                                if step:
                                    field.Step, field.Count = step, count
                            if fieldName == "Source MAC Address":
                                field.ValueType, field.RandomMask, field.Seed = value_type, mask, init
                                if step:
                                    field.Step, field.Count = step, count
                else:
                    if action:
                        frameType = trafficObj.FrameSize.find()
                        frameType.FixedSize = field_size
                        # frameType.RandomMin= min
                        # frameType.RandomMax= max
                    for stack in trafficObj.Stack.find():
                        fieldNames = [fieldObj.DisplayName for fieldObj in stack[0].Field.find()]
                        for fieldName in fieldNames:                        
                            if fieldName == "Destination MAC Address" and macDa:
                                field = stack[0].Field.find(DisplayName=fieldName)
                                field.ValueType, field.RandomMask, field.Seed = value_type, mask, init
                            if fieldName == "Source MAC Address" and not macDa:
                                field = stack[0].Field.find(DisplayName=fieldName)
                                # import pdb;pdb.set_trace()
                                field.ValueType, field.RandomMask, field.Seed = value_type, mask, init
                            
        print("Mac updated in Traffic Items")
        return True
    
    def add_modifier(self, port_name, stream_id: int,
                     field, min_bit_pos, max_bit_pos, action, lower_range=-1, higher_range=-1,
                     force_modifier_index=-1, use_extended_modifier=0, step=1):
        print("AMIT:*****************add_modifier***********is called port_name {} stream_id{} field {} min_bit_pos {} max_bit_pos {} action {}".format(port_name, stream_id, field, min_bit_pos, max_bit_pos, action))
        # import pdb;pdb.set_trace()
        strm = self.streams[port_name, stream_id]
        strm.add_modifier(field, min_bit_pos, max_bit_pos, action,
                          lower_range, higher_range, force_modifier_index, use_extended_modifier)

    def get_modifier_reference(self, port_name, stream_id, header_idx, field):
        # ixia only supports offset based modifier, not field based modifier.
        pass

    def remove_stream(self, port_name, stream_id):
        pass

    def enable_stream(self, port_name, stream_id):    
        self.streams[port_name, stream_id].enable_traffic(stream_id)         
        # self.pkt_gen.enable_traffic()
        # self.pkt_gen.disable_traffic()
       
    def disable_stream(self, port_name, stream_id):
        self.streams[port_name, stream_id].disable_traffic(stream_id)

    def get_port_statistics(self, port_name):
        return self.ports[port_name].get_statistic(port_name)

    def get_stream_statistics(self, port_name, stream_id):
        return self.streams[port_name, stream_id].get_statistic()

    def get_all_ports_stream_statistics(self, stream_id):
        ports_statistics = Counter({})
        for port_name in self.ports.keys():
            port_stat = Counter(self.streams[port_name, stream_id].get_statistic())
            ports_statistics.update(port_stat)
        return dict(ports_statistics)

    def get_stream_rate_percentage(self, port_name, stream_id):
        return self.streams[port_name, stream_id].get_rate_percentage()

    def clear_port_statistics(self, port_name):
        self.ports[port_name].clear_statistic()

    def teardown_session(self):
        self.pkt_gen.__del__()

    def disable_checksum_insertion(self, port_name, stream_id: int):
        pass

    def enable_checksum_insertion(self, port_name, stream_id: int):
        pass
    def get_statistic(self, view_name="Port Statistics"):
        """
        Get the statistics based on the view name.
        :param view_name (str)
        """
        statistics = {}
        ixia_stats = {}
        if len(str(self.card_id)) > 1:
            cardId = "Card" + str(self.card_id)
        else:
            cardId = "Card" + '0' + str(self.card_id)
        if len(str(self.port_id)) > 1:
            portId = "Port" + str(self.port_id)
        else:
            portId = "Port" + '0' + str(self.port_id)
        logging.info('\ngetStats: %s' % (view_name))
        TrafficItemStats = StatViewAssistant(self.pkt_gen.sg, view_name)
        columnCaptions = TrafficItemStats.ColumnHeaders
        for rowNumber, stat in enumerate(TrafficItemStats.Rows):
            statsDict = {}
            for column in columnCaptions:
                statsDict[column] = stat[column]
            ixia_stats[rowNumber + 1] = statsDict
        for key, value in ixia_stats.items():
            if cardId + '/' + portId in value['Stat Name']:
                statistics = value
                break
        for stat_key, stat_value in statistics.items():
            if 'Rate' in stat_key:
                statistics[stat_key] = float(statistics[stat_key]) 
            elif 'Frames' in stat_key or 'Bytes' in stat_key or 'Bits' in stat_key:
                statistics[stat_key] = int(statistics[stat_key]) 
            else:
                pass
        # import pdb;pdb.set_trace()
        # (frameReceived, bytesReceived, rx_pps, rx_bps, misOrdered, framesSent, tx_pps, bytesSent, tx_bps) = \
        #     self.sg.streamStatsGet(self.card_id, self.port_id, self.sid)
        statistics['tx_bps']     = 0
        statistics['tx_pps']     = statistics['Frames Tx.']
        statistics['tx_bytes']   = 0
        statistics['tx_packets'] = statistics['Frames Tx.']

        statistics['rx_bps']     = 0
        statistics['rx_pps']     = 0
        statistics['rx_bytes']   = statistics['Bytes Rx.']
        statistics['rx_packets'] = statistics['Valid Frames Rx.']

        statistics['lost_packets']   = statistics['tx_packets'] - statistics['rx_packets']
        # statistics['misordered']     = misOrdered
        statistics['misordered']     = 0
        statistics['payload_errors'] = 0
        statistics['latency']        = 0

        logging.debug("stream get_statistic, tx_packets:{0} rx_packets:{1} lost_packets:{2} misordered_packets:{3}".format(
            statistics['tx_packets'], statistics['rx_packets'], statistics['lost_packets'], statistics['misordered']))
        
        return statistics

    def get_tx_statistic(self, view_name="Port Statistics"):
        """
        Get the tx statistics based on the view name.
        :param view_name (str)
        """
        statistics = {}
        ixia_stats = {}
        if len(str(self.card_id)) > 1:
            cardId = "Card" + str(self.card_id)
        else:
            cardId = "Card" + '0' + str(self.card_id)
        if len(str(self.port_id)) > 1:
            portId = "Port" + str(self.port_id)
        else:
            portId = "Port" + '0' + str(self.port_id)
        logging.info('\ngetStats: %s' % (view_name))
        TrafficItemStats = StatViewAssistant(self.pkt_gen.sg, view_name)
        columnCaptions = TrafficItemStats.ColumnHeaders
        for rowNumber, stat in enumerate(TrafficItemStats.Rows):
            statsDict = {}
            for column in columnCaptions:
                statsDict[column] = stat[column]
            ixia_stats[rowNumber + 1] = statsDict
        for key, value in ixia_stats.items():
            if cardId + '/' + portId in value['Stat Name']:
                statistics = value
                break
        for stat_key, stat_value in statistics.items():
            if 'Rate' in stat_key:
                statistics[stat_key] = float(statistics[stat_key]) 
            elif 'Frames' in stat_key or 'Bytes' in stat_key or 'Bits' in stat_key:
                statistics[stat_key] = int(statistics[stat_key]) 
            else:
                pass
        # import pdb;pdb.set_trace()
        #print('Calling streamTxStatsGet with port_id {} sid {}'.format(self.port_id, self.sid))
        # (framesSent, tx_pps) = self.sg.streamTxStatsGet(self.card_id, self.port_id, self.sid)
        statistics['tx_bps']     = 0
        statistics['tx_pps']     = statistics['Frames Tx.']
        statistics['tx_bytes']   = 0
        statistics['tx_packets'] = statistics['Frames Tx.']
        
        return statistics
    
    def get_rx_statistic(self,sid,gid, view_name="Flow Statistics"):
        """
        Method to get the RX Statistics
        :param view_name: view_name options (case sensitive):
                "Port Statistics",
                "Tx-Rx Frame Rate Statistics",
                "Port CPU Statistics",
                "Global Protocol Statistics",
                "Protocols Summary",
                "Port Summary",
                "OSPFv2-RTR Drill Down",
                "OSPFv2-RTR Per Port",
                "IPv4 Drill Down",
                "L2-L3 Test Summary Statistics",
                "Flow Statistics",
                "Traffic Item Statistics", \n
                Note: Not all of the view_names are listed here. You have to get the
                exact names from the IxNetwork GUI in statistics based on your
                protocol(s)
        :return:  A dictionary of RX stats: 
        """
        statistics = {}
        ixia_stats = {}        
        logging.info('\ngetStats: %s' % (view_name))
        TrafficItemStats = StatViewAssistant(self.pkt_gen.sg, view_name)
        # trafficItemStatsDict = {}
        columnCaptions = TrafficItemStats.ColumnHeaders
        for rowNumber, stat in enumerate(TrafficItemStats.Rows):
            statsDict = {}
            for column in columnCaptions:
                statsDict[column] = stat[column]
            ixia_stats[rowNumber + 1] = statsDict
        for key, value in ixia_stats.items():
            if sid == key:
                statistics = value
                break
        for stat_key, stat_value in statistics.items():
            if 'Rate' in stat_key:
                statistics[stat_key] = float(statistics[stat_key]) 
            elif 'Frames' in stat_key or 'Bytes' in stat_key or 'Bits' in stat_key:
                statistics[stat_key] = int(statistics[stat_key]) 
            else:
                pass
        # The convertion is not required in IxNetwork
        # rx_bps = self.convert_to_l1rate(statistics['byteRate'],statistics['frameRate'])
        statistics     = ixia_stats
        # import pdb;pdb.set_trace()
        statistics['rx_bps']     = statistics['Rx L1 Rate (bps)']
        statistics['rx_pps']     = statistics['Rx Frame Rate']
        statistics['rx_bytes']   = statistics['Rx Bytes']
        statistics['rx_packets'] = statistics['Rx Frames']
        
        return statistics
    
    def get_statistic1(self, view_name="Flow Statistics"):
        """
        Get the port statistics.
        :param view_name: view_name options (case sensitive):
                "Port Statistics",
                "Tx-Rx Frame Rate Statistics",
                "Port CPU Statistics",
                "Global Protocol Statistics",
                "Protocols Summary",
                "Port Summary",
                "OSPFv2-RTR Drill Down",
                "OSPFv2-RTR Per Port",
                "IPv4 Drill Down",
                "L2-L3 Test Summary Statistics",
                "Flow Statistics",
                "Traffic Item Statistics", \n
                Note: Not all of the view_names are listed here. You have to get the
                exact names from the IxNetwork GUI in statistics based on your
                protocol(s)
        :return:  A dictionary of RX stats: 
        """        
        # get total port statistics
        statistics = {}
        ixia_stats = {}
        if len(str(self.card_id)) > 1:
            cardId = "Card" + str(self.card_id)
        else:
            cardId = "Card" + '0' + str(self.card_id)
        if len(str(self.port_id)) > 1:
            portId = "Port" + str(self.port_id)
        else:
            portId = "Port" + '0' + str(self.port_id)
        logging.info('\ngetStats: %s' % (view_name))
        TrafficItemStats1 = StatViewAssistant(self.pkt_gen.sg, view_name)
        TrafficItemStats2 = StatViewAssistant(self.pkt_gen.sg, "Port Statistics")
        # (bytesSent, framesSent, bytesReceived, frameReceived, dataIntegrityFrames,dataIntegrityErrors, rxPPS, txPPS, rxGbps, txGbps) = self.sg.portStatsGet(self.card_id, self.port_id)
        #(bytesSent, framesSent, bytesReceived, frameReceived, rxPPS, txPPS, rxGbps, txGbps) = self.sg.portStatsGet(self.card_id, self.port_id)
        # rxGbps = self.convert_to_l1rate(rxGbps,rxPPS)
        # txGbps = self.convert_to_l1rate(txGbps,txPPS)
        for TrafficItemStats in [TrafficItemStats1, TrafficItemStats2]:
            columnCaptions = TrafficItemStats.ColumnHeaders
            for rowNumber, stat in enumerate(TrafficItemStats.Rows):
                statsDict = {}
                for column in columnCaptions:
                    statsDict[column] = stat[column]
                ixia_stats[rowNumber + 1] = statsDict
            for key, value in ixia_stats.items():
                if cardId + '/' + portId in value['Stat Name']:
                    statistics = value
                    break
            for stat_key, stat_value in statistics.items():
                if 'Rate' in stat_key:
                    statistics[stat_key] = float(statistics[stat_key]) 
                elif 'Frames' in stat_key or 'Bytes' in stat_key or 'Bits' in stat_key:
                    statistics[stat_key] = int(statistics[stat_key]) 
                else:
                    pass
        # import pdb;pdb.set_trace()
        statistics['tx_bps']     = statistics['Tx L1 Rate (bps)']  # TODO
        statistics['tx_pps']     = statistics['Tx Frames']
        statistics['tx_bytes']   = statistics['Bytes Tx.']
        statistics['tx_packets'] = statistics['Tx Frames']

        statistics['rx_bps']     = statistics['Rx L1 Rate (bps)']  # TODO
        statistics['rx_pps']     = statistics['Rx Frame Rate']
        statistics['rx_bytes']   = statistics['Bytes Rx.']
        statistics['rx_packets'] = statistics['Rx Frames']
        statistics['rx_integrity_frames'] = statistics['Data Integrity Frames Rx.']
        statistics['rx_integrity_errors'] = statistics['Data Integrity Errors']

        # TODO
        statistics['rx_no_test_payload_bytes']   = 0
        statistics['rx_no_test_payload_packets'] = 0
        statistics['error_count']                = 0

        output_str = f"get_port_stats, card:{self.card_id} port:{self.port_id} tx_bytes:{statistics['tx_bytes']} " \
                     f"tx_packets:{statistics['tx_packets']} rx_bytes:{statistics['rx_bytes']} rx_packets:{statistics['rx_packets']} "\
                     f"rx_pps:{statistics['rx_pps']} tx_pps:{statistics['tx_pps']}"
        logging.debug(output_str)
        
        return statistics