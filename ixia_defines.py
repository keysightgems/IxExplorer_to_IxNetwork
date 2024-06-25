import time, re, json
import logging
# from traffic_gen import trafficData, portList
from binascii import hexlify, unhexlify
# import binascii
from ixnetwork_restpy.testplatform.testplatform import TestPlatform
from ixnetwork_restpy.assistants.statistics.statviewassistant import StatViewAssistant
from ixnetwork_restpy import SessionAssistant
class IxiaConfigException(Exception):
    """
    IXIA config exception
    """
    pass

class IxiaOperationException(Exception):
    """
    IXIA operation exception
    """
    pass

class IxiaStatsException(Exception):
    """
    IXIA stats exception
    """
    pass

class IxiaPktGenerator:
    def __init__(self, ip, usr_name, debug, login="fishnet", **kwargs):
        """
        IxNetwork version should be 8.0 or above for REST api's to work.
        Create the IxNetwork session
        :param ip_addr (str): API server IP address
        :param usr_name (str): user name
        :param debug (bool): if True, enable debug print statements
        :param server_ip (str): IxNetwork TCL server IP
        :param kwargs (session_name (str), etc): session name for linux API server        
        """
        self.serverIP = kwargs.get('server_ip', None)
        self.chassis_ip_addr = ip
        self.tgn_server_user = kwargs.get('tgn_server_user', 'admin')
        # self.tgn_server_pw = kwargs.get('tgn_server_pw', 'Ciscoixia123#')
        self.tgn_server_pw = kwargs.get('tgn_server_pw', 'admin')
        self.session_name = kwargs.get('session_name', None)
        self.session_id = kwargs.get('session_id', None)
        self.apikey = kwargs.get('apikey', None)
        self.clear_config = kwargs.get('clear_config', True)
        ##self.login = login
        ##self.debug = 0
        ##self.halt = 0
        self.enable_signature = 'true' 
        self.enable_fc_hdr = False
        self.enable_data_pattern = False
        self.pattern_type = 'patternTypeRandom' 
        self.preamble = '55 55 55 55 55 55 d5'
        #self.pattern_type = 'incrByte' 
        #self.tcl = tkinter.Tcl().tk
        self.session_established = False
        
        #if not debug:
        #    self.log_level = 'debug'
        #else:
        #    self.log_level = 'info'
        if debug:
            #'LOGLEVEL_ALL', 'LOGLEVEL_INFO', 'LOGLEVEL_NONE', 'LOGLEVEL_REQUEST', 'LOGLEVEL_REQUEST_RESPONSE', 'LOGLEVEL_WARNING'
            self.log_level = SessionAssistant.LOGLEVEL_ALL
        else:
            self.log_level = SessionAssistant.LOGLEVEL_INFO        
        self.port = kwargs.get('port', 443)
        self.session = SessionAssistant(IpAddress=self.serverIP, RestPort=self.port, UserName=self.tgn_server_user, Password=self.tgn_server_pw, 
                                        SessionName=self.session_name, SessionId=self.session_id, ApiKey=self.apikey, ClearConfig=True, LogLevel=self.log_level, LogFilename='restpy.log')
        self.ports = {}        
        if self.session_name is None:
            self.session_name = self.session.Session.Name
        self.sg = self.session.Ixnetwork
    def connect_to_chassis(self, chassis_ip_list=None):
        """
        Connect to IXIA Chassis
        :param chassis_ip_list: list of chassis' IPs to which session has to connect
        :return: True if successful
        :Example: connect_to_chassis(["10.39.60.120"])
        """
        logging.info("Connection to the Chassis")
        if chassis_ip_list is None:
            chassis_ip_list = [self.chassis_ip_addr]
        for chassisIp in chassis_ip_list:
            self.sg.AvailableHardware.Chassis.add(Hostname=chassisIp)
            time.sleep(5)
            for counter in range(1, 100):                        
                if self.sg.AvailableHardware.Chassis.find(Hostname=chassisIp).State == 'ready':
                    break
                else:
                    time.sleep(1)
                if counter <= 99:
                    raise IxiaConfigException('Connect Chassis: Connecting to chassis {0} failed'.format(chassisIp))
        return True
    def add_port(self, port_name):
        """
        Adding ports and verify assigned or not.
        :param port_name: ["chassisIP/card/port", "chassisIP/card/port",..]
        """
        if type(port_name) is str:
            if self.chassis_ip_addr not in port_name:
                portName = self.chassis_ip_addr + '/' + port_name
            else:
                portName = [portName.split('/')]
        else:            
            portName = [(self.chassis_ip_addr + '/' + port).split('/') for port in port_name if self.chassis_ip_addr not in port_name]
            if not portName:
                portName = [port.split('/') for port in port_name]
        chassis_list = [self.chassis_ip_addr]
        forceTakePortOwnership = True
        testPorts = []       
        vportList = self.sg.Vport.add()                
        for port in portName:
            testPorts.append(dict(Arg1=port[0], Arg2=port[1], Arg3=port[2]))        
        reserve_port = IxiaPortClass(self.sg, port_name)
        reserve_port.reserve(testPorts, vportList, forceTakePortOwnership)   
        for port in port_name:   
            self.ports[port] = reserve_port
        return self.ports    
    def __del__(self, session_name=None): 
        """
        Delete the existing session.
        :param session_name (str): IxNetwork session name
        """
        if session_name:
            self.testPlatform.Sessions.find(Name=session_name).remove()
            self.sg = None
class IxiaPortClass:
    def __init__(self, sg, port_name):
        """
        Using IxiaPktGenerator session and reserve, clear ports, add streams, get stats.
        :param sg (str): IxNetwork session
        :param port_name (str): Port name ("2/9")
        """
        self.sg = sg 
        # [self.card_id, self.port_id] = list(map(int, port_name.split('/')))
        self.portList = port_name
        self.streams = {}
        self.trafficItemList = []
    def reserve(self, testPorts=None, vportList=None, forceTakePortOwnership=False):
        """
        Assign ports with the valid input.
        :param testPorts (list): List of ports.
        :param vportList (list): List of ports objects.
        :param forceTakePortOwnership (bool): True/False
        """
        # logging.debug("reserve_port_ownership, card:{0} port:{1}".format(self.card_id, self.port_id))      
        self.sg.AssignPorts(testPorts, [], vportList, forceTakePortOwnership)
        
    def clear(self, port_list=None):
        """
        Clear/Release ports
        :param port_list: list of port names\n
               port_list can be port_list = ['10.30.20.140/1/5','10.30.20.140/1/6']
               port_list = ['Ethernet 01' , Ethernet 02']\n
               port_list = [[ixChassisIp, 1, 2], [ixChassisIp, 1, 3], ...]          
        """
        logging.info("Releasing Ports")
        if port_list is None:
            try:
                for vport in self.sg.Vport.find():
                    vport.ResetPortCpu()
                    time.sleep(5)
                    vport.ReleasePort()
                    vport.remove()
            except:
                pass
        else:
            vportNames = []
            for port in port_list:
                regexString = ''
                if isinstance(port, list):
                    # Construct the regex string format = '(1.1.1.1:2:3)'
                    regexString = regexString + '(' + str(port[0]) + ':' + str(port[1]) + ':' + str(port[2]) + ')'
                elif isinstance(port, str):
                    if '.' in port:
                        regexString = port.replace('/',':')
                    else:
                        try:
                            regexString = self.sg.Vport.find(Name=port).AssignedTo
                        except:
                            raise IxiaConfigException("Port not configured or Failed to release")
                vport = self.sg.Vport.find(AssignedTo=regexString)
                if vport:
                    vportNames.append(vport.Name)
                    logging.info('\nReleasing port: {0}:{1}'.format(port, vport.href))
                    vport.ReleasePort()
            for vport in self.sg.Vport.find():                
                if vport.ConnectionStatus != 'Port Released':
                    msg = 'Release Port "%s" not Successful' % (vport.Name)
                    raise IxiaOperationException(msg)
                else:
                    vport.remove()
    def reset(self, port_name, traffic_item_list=None):        
        """
        API to deleted traffic items
        :param traffic_item_list: list of traffic items to be deleted. if None, delete all
        :return: True
        """
        card_id, port_id = map(int, port_name.split('/'))
        # reset Ixia port to factory default will automatically clear all streams
        logging.debug("reset_port_to_factory_default, card:{0} port:{1}".format(card_id, port_id))
        if traffic_item_list:
            if isinstance(traffic_item_list, list):
                try:
                    for trafficName in traffic_item_list:
                        trafficName = trafficName.replace('+', '\+').replace('*', '\*')
                        self.sg.Traffic.TrafficItem.find(Name='^'+trafficName+'$').remove()
                except:
                    raise IxiaOperationException("Not able to find the TrafficItem to Delete")
            elif isinstance(traffic_item_list, str):
                try:
                    self.sg.Traffic.TrafficItem.find(Name='^'+traffic_item_list+'$').remove()
                except:
                    raise IxiaOperationException("Not able to find the TrafficItem to Delete")
        else:
            trafficItems = self.sg.Traffic.TrafficItem.find()
            trafficItems.remove()
        logging.debug("Traffic Item/Items Deleted Successfully")        
        # streams collections will be GC
        self.streams = {}
    def set_loopback(self, port_name):
        """
        Set Ixia port to internal loopback mode, to force the TG port link up.
        """
        card_id, port_id = map(int, port_name.split('/'))
        logging.debug("enable_port_loopback, card:{0} port:{1}".format(card_id, port_id))        
        for vportObj in self.sg.Vport.find():
            if str(card_id) + ":" + str(port_id) in vportObj.AssignedTo:                
                vportType = (vportObj.Type)[0].upper() + (vportObj.Type)[1:]     
                cardTypeObj = eval('vportObj.L1Config.'+vportType)
                cardTypeObj.LoopbackMode = "internalLoopback" 
                break
    def set_packet_size_mix(self, packet_mix_type):
        """
        Set packet size mix.
        :param packet_mix_type (str)
        """
        # logging.debug("set_packet_size_mix, card:{0} port:{1} mix_type:{2}".format(self.card_id,
        #                                                                           self.port_id,
        #                                                                           packet_mix_type))
        logging.debug("Ixia Tcl only supports predefined IMIX1 distribution")
    def _get_src_dst_vport_objects(self, port_name=None):
        """
        Internal method to get src/dst endpoint using the vport protocols object.
        :param port_name (str)
        """
        protocolEndpoint = []
        if port_name:
            for portName in port_name:
                protocolEndpoint.append(self.sg.Vport.find(Name=portName).href + "/protocols")
        else:
            for vportObj in self.sg.Vport.find():
                protocolEndpoint.append(vportObj.href + "/protocols")
        return protocolEndpoint
    
    def _stream_stacks_update(self, highLevelObj, protocol_stack, protocol_stack_values):
        """
        Internal method to update the protocol values based on the stack.
        :param protocol_stack (str): Ipv4/Ipv6/Tcp
        :param protocol_stack_values (dict)
        """
        configElement = highLevelObj
        if protocol_stack.lower() == "vlan" or protocol_stack.lower() == "vxlan":
            stackObj = configElement.Stack.find(StackTypeId='^ethernet$')
        elif protocol_stack.lower() == "ipv4" or protocol_stack.lower() == "ipv6": 
            if configElement.Stack.find(StackTypeId='^vlan$').index != -1:
                stackObj = configElement.Stack.find(StackTypeId='^vlan$')
            else:
                stackObj = configElement.Stack.find(StackTypeId='^ethernet$')
        elif protocol_stack.lower() == "mpls":
            if configElement.Stack.find(StackTypeId='^vlan$').index != -1:
                stackObj = configElement.Stack.find(StackTypeId='^vlan$')
            else:
                stackObj = configElement.Stack.find(StackTypeId='^ethernet$')
        elif protocol_stack.lower() == "gre":
            stackObj = configElement.Stack.find(StackTypeId='^ipv4$')
        elif protocol_stack.lower() == "tcp":
            stackObj = configElement.Stack.find(StackTypeId='^ipv4$')
        elif protocol_stack.lower() == "udp":
            stackObj = configElement.Stack.find(StackTypeId='^ipv6$')
        else:
            stackObj = configElement.Stack.find(StackTypeId='^ethernet$')                
        if protocol_stack.lower() == "vlan" or protocol_stack.lower() == "vxlan":
            vlanTemplate = self.sg.Traffic.ProtocolTemplate.find(StackTypeId="^"+protocol_stack.lower()+"$")
            configElement.Stack.read(stackObj.AppendProtocol(vlanTemplate))     
            protocolStackObj = configElement.Stack.find(DisplayName=protocol_stack)                
        else:
            if protocol_stack.lower == "gre":
                protocolTemplate = self.sg.Traffic.ProtocolTemplate.find(DisplayName="GRE")
                stackObj.Append(Arg2=protocolTemplate)
                protocolStackObj = configElement.Stack.find(DisplayName="IPv4")
            else:   
                protocolTemplate = self.sg.Traffic.ProtocolTemplate.find(DisplayName=protocol_stack)
                stackObj.Append(Arg2=protocolTemplate)
                protocolStackObj = configElement.Stack.find(DisplayName=protocol_stack)
        for key, value in protocol_stack_values.items():
                    protocolStackObj.Field.find(DisplayName=key).SingleValue = value

    def _add_stream_layer_end(self, stats_offset, seq_check=True):
        """"
        Update existing stream offset and sequence check.
        :param stats_offset (int)
        :param seq_check (bool)
        """
        for trafficObj in self.sg.Traffic.TrafficItem.find():
            if seq_check:
                #trafficObj.TransmitMode="sequential"
                trafficObj.TransmitMode="interleaved"
            for trackingObj in trafficObj.Tracking.find():
                if trackingObj.TrackBy:
                    trackOptions = trackingObj.TrackBy
                    if 'customOverride' not in trackOptions:
                        trackOptions.append('customOverride')
                else:
                    trackingObj.TrackBy = ['customOverride']
                trackingObj.Offset = stats_offset

    def _get_src_dst_endpoint(self, port_name):
        card_id, port_id = map(int, port_name.split('/'))
        srcPortNameList = []
        # import pdb;pdb.set_trace()        
        # pattern = r'/api/v1/sessions\[1\]/ixnetwork(\S+)'
        pattern = re.compile(r'/vport\[\d+\]/protocols')
        # portNameList = [re.search(pattern, re.sub(r'/(\d+)', r'[\1]', (vportObj.href + '/protocols'))).group(1) for vportObj in self.sg.Vport.find()]
        portNameList = [re.sub(r'/(\d+)', r'[\1]', (vportObj.href + '/protocols')) for vportObj in self.sg.Vport.find()]
        endpointList = []
        for item in portNameList:
            endpointList.append(pattern.search(item).group())
        for vportObj in self.sg.Vport.find():
            if str(card_id)+":"+str(port_id) in vportObj.AssignedTo:
                # srcPortNameList.append(re.search(pattern, re.sub(r'/(\d+)', r'[\1]', (vportObj.href + '/protocols'))).group(1))
                href = re.sub(r'/(\d+)', r'[\1]', (vportObj.href + '/protocols'))
                srcPortNameList.append(pattern.search(href).group())
                # srcPortNameList.append(re.sub(r'/(\d+)', r'[\1]', (vportObj.href + '/protocols')))
        # srcPortNameList = [vportObj.Name for vportObj in self.sg.Vport.find() if str(card_id)+":"+str(port_id) in vportObj.AssignedTo]
        # portNameList.remove(srcPortNameList[0])
        # import pdb;pdb.set_trace()
        # srcPortNameList = [portNameList[0]]
        # import pdb;pdb.set_trace() 
        dstPortNameList = endpointList     
        return [srcPortNameList, dstPortNameList]
    
    def _get_fields_data(self, stream_id, field_type, stackIndex, field_header, field_value):
        if field_type == "mpls":
            return {"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(stream_id) + "]" + "/stack[@alias = " + field_type +"-" + str(stackIndex) +"']/field[@alias = '" + field_type + "."+ field_header + "']",
                                                                            "singleValue": field_value,
                                                                            # "fieldValue": 'Default',
                                                                            # "stepValue": "1",
                                                                            "valueType": "singleValue", "auto": False}
                                                                            # "startValue": field_value,
                                                                            # "countValue": "1"}
        else:
            return {"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(stream_id) + "]" + "/stack[@alias = " + field_type +"-" + str(stackIndex) +"']/field[@alias = '" + field_type + ".header."+ field_header + "']",
                                                                        "singleValue": field_value,
                                                                        # "fieldValue": 'Default',
                                                                        # "stepValue": "1",
                                                                        "valueType": "singleVlaue", "auto": False}
                                                                        # "startValue": field_value,
                                                                        # "countValue": "1"}

    def add_stream_layer_start(self, stream_data_list):
        """
        Add stream based on the input provided by the user.
        :param sid (int): stream ID
        :param rate (int): Frame rate
        :param size (int): Frame size
        :param macSa (str): Source Mac
        :param macDa (str): Destination Mac
        :param pkt (str): pkt
        :param stats_offset (int): offset
        :param etype (str): Ehternet Type
        :param gid (int): group ID
        """
        trafficItemList = []
        endpointSetList = []
        highlevelObjList = []
        portName = ""
        endpointSrcDst = []
        streamObjdict = {}
        for streamData in stream_data_list:    
            stackIndex = 1                   
            stackObjList = []
            frameSizeDict = {}
            frameRateDict = {}
            streamId = streamData['stream_id'] + 1
            if streamData['stream_id'] not in self.streams:
                card_id, port_id = map(int, streamData['port_name'].split('/'))
                # First time create new Ixia stream
                stream = IxiaStreamClass(self.sg, card_id, port_id, streamData['stream_id'])
                # add new streams into dictionary
                self.streams[streamData['stream_id']] = stream    
            if portName != streamData['port_name']:
                endpointSrcDst = self._get_src_dst_endpoint(streamData['port_name'])
                portName = streamData['port_name']

            endpointSetList.append(
                                {"xpath": "/traffic/trafficItem[1]/endpointSet[" + str(streamId) + "]",
                                 "name": "EndpointSet" + str(streamId),
                                 "sources": endpointSrcDst[0],
                                 "destinations": endpointSrcDst[1]
                                 })            
            if 'eth_src_mac' in streamData and streamData['eth_src_mac']:
                fieldList = []
                stackIndex = 1                                
                fieldList.append(self._get_fields_data(streamId, "ethernet", stackIndex, "sourceAddress-2", streamData['eth_src_mac'])) 
                fieldList.append(self._get_fields_data(streamId, "ethernet", stackIndex, "destinationAddress-1", streamData['eth_dst_mac']))
                fieldList.append(self._get_fields_data(streamId, "ethernet", stackIndex, "etherType-3", streamData['etype']))
                stackObjList.append({"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]" + "/stack[@alias = 'ethernet-" + str(stackIndex) + "']",
                                     "field": fieldList})              
                
            if 'Vlan' in streamData and streamData['Vlan']:
                fieldList = []
                stackIndex = stackIndex + 1
                if 'outer_vlan' in streamData and streamData['outer_vlan']:
                    stackObjList.append({"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]" + "/stack[@alias = 'vlan-"+ str(stackIndex) + "']",
                                        "field": fieldList})
                    stackIndex = stackIndex + 1
                    stackObjList.append({"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]" + "/stack[@alias = 'vlan-"+ str(stackIndex) + "']",
                                        "field": fieldList})
                if 'vlan_id' in streamData and streamData['vlan_id']:                    
                    fieldList.append(self._get_fields_data(streamId, "vlan", stackIndex, "vlanTag.vlanID-3", streamData['vlan_id']))                
                    fieldList.append(self._get_fields_data(streamId, "vlan", stackIndex, "vlanTag.vlanUserPriority-1", streamData['vlan_priority']))
                    stackObjList.append({"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]" + "/stack[@alias = 'vlan-"+ str(stackIndex) + "']",
                                            "field": fieldList})
            if 'Vxlan' in streamData and streamData['Vxlan']:
                fieldList = []
                stackIndex = stackIndex + 1
                stackObjList.append({"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]" + "/stack[@alias = 'vxlan-"+ str(stackIndex) + "']",
                                        "field": fieldList})
            if 'Ipv4' in streamData and streamData['Ipv4']:
                fieldList = []
                stackIndex = stackIndex + 1
                ipv4StackIndex = stackIndex                
                fieldList.append(self._get_fields_data(streamId, "ipv4", stackIndex, "ttl-24", streamData['ipv4_ttl']))
                fieldList.append(self._get_fields_data(streamId, "ipv4", stackIndex, "srcIp-27", streamData['ipv4_src']))
                fieldList.append(self._get_fields_data(streamId, "ipv4", stackIndex, "dstIp-28", streamData['ipv4_dst']))
                stackObjList.append({"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]" + "/stack[@alias = 'ipv4-"+ str(stackIndex) + "']",
                                        "field": fieldList})
            if 'Ipv6' in streamData and streamData['Ipv6']:
                fieldList = []
                stackIndex = stackIndex + 1                
                fieldList.append(self._get_fields_data(streamId, "ipv6", stackIndex, "hopLimit-6", streamData['ipv6_hop_limit']))
                fieldList.append(self._get_fields_data(streamId, "ipv6", stackIndex, "srcIP-7", streamData['ipv6_src']))
                fieldList.append(self._get_fields_data(streamId, "ipv6", stackIndex, "dstIp-8", streamData['ipv6_dst']))
                stackObjList.append({"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]" + "/stack[@alias = 'ipv6-"+ str(stackIndex) + "']",
                                        "field": fieldList})
            if 'Tcp' in streamData and streamData['Tcp']:
                fieldList = []
                stackIndex = stackIndex + 1                
                fieldList.append(self._get_fields_data(streamId, "tcp", stackIndex, "srcPort-1", streamData['tcp_src_port']))
                fieldList.append(self._get_fields_data(streamId, "tcp", stackIndex, "dstPort-2", streamData['tcp_dst_port']))
                fieldList.append(self._get_fields_data(streamId, "tcp", stackIndex, "sequenceNumber-3", streamData['tcp_seq_no']))
                stackObjList.append({"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]" + "/stack[@alias = 'tcp-"+ str(stackIndex) + "']",
                                        "field": fieldList})
            if 'Udp' in streamData and streamData['Udp']:
                fieldList = []
                stackIndex = stackIndex + 1                
                fieldList.append(self._get_fields_data(streamId, "udp", stackIndex, "srcPort-1", streamData['udp_src_port']))
                fieldList.append(self._get_fields_data(streamId, "udp", stackIndex, "dstPort-2", streamData['udp_dst_port']))
                stackObjList.append({"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]" + "/stack[@alias = 'udp-"+ str(stackIndex) + "']",
                                        "field": fieldList})
            if 'Mpls' in streamData and streamData['Mpls']:
                fieldList = []
                stackIndex = stackIndex + 1                
                fieldList.append(self._get_fields_data(streamId, "mpls", stackIndex, "label.value-1", streamData['mpls_label']))
                fieldList.append(self._get_fields_data(streamId, "mpls", stackIndex, "label.ttl-4", streamData['mpls_ttl']))
                fieldList.append(self._get_fields_data(streamId, "mpls", stackIndex, "label.experimental-2", streamData['mpls_tag_no']))
                fieldList.append(self._get_fields_data(streamId, "mpls", stackIndex, "label.bottomOfStack-3", streamData['mpls_last_tag']))
                stackObjList.append({"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]" + "/stack[@alias = 'mpls-"+ str(stackIndex) + "']",
                                        "field": fieldList})
            if 'Gre' in streamData and streamData['Gre']:
                fieldList = []
                stackIndex = stackIndex + 1                
                fieldList.append(self._get_fields_data(streamId, "gre", stackIndex, "version-6", streamData['gre_version']))
                stackObjList.append({"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]" + "/stack[@alias = 'gre-"+ str(stackIndex) + "']",
                                        "field": fieldList})                
                fieldList.append(self._get_fields_data(streamId, "ipv4", ipv4StackIndex, "ttl-24", streamData['ipv4_ttl']))
                fieldList.append(self._get_fields_data(streamId, "ipv4", ipv4StackIndex, "srcIp-27", streamData['ipv4_src']))
                fieldList.append(self._get_fields_data(streamId, "ipv4", ipv4StackIndex, "dstIp-28", streamData['ipv4_dst']))
                stackObjList.append({"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]" + "/stack[@alias = 'ipv4-"+ str(ipv4StackIndex) + "']",
                                        "field": fieldList})
            
            if 'Custom' in streamData and streamData['Custom']:
                fieldList = []
                customLength = streamData['custom_length'] * 4
                stackIndex = stackIndex + 1                
                fieldList.append(self._get_fields_data(streamId, "custom", stackIndex, "length-1", customLength))
                fieldList.append(self._get_fields_data(streamId, "custom", stackIndex, "data-2", streamData['custom_data']))
                stackObjList.append({"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]" + "/stack[@alias = 'custom-"+ str(stackIndex) + "']",
                                        "field": fieldList})
            if 'pkt_size' in streamData and streamData['pkt_size']:
                frameSizeDict = {"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]" + "/frameSize", "type": streamData['frame_type'], 
                                 "fixedSize": streamData['pkt_size']}
            if 'frame_min' in streamData and streamData['frame_min']:
                frameSizeDict = {"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]" + "/frameSize", "type": streamData['frame_type'], 
                                 "incrementFrom": streamData['frame_min'], "incrementTo": streamData['frame_max']}
            if 'traffic_rate' in streamData and streamData['traffic_rate']:
                frameRateDict = {"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]" + "/frameRate", "rate": streamData['traffic_rate']}
            highlevelObjList.append({"xpath": "/traffic/trafficItem[1]/highLevelStream[" + str(streamId) + "]",
                                     "enabled": True,"stack": stackObjList, "frameSize": frameSizeDict, "frameRate": frameRateDict})
            # if not trafficItemList:
            #     trafficItemList.append({"xpath": "/traffic/trafficItem[1]",
            #                                   "trafficItemType": "quick", "trafficType": "ethernetVlan", "endpointSet": endpointSetList, "highLevelStream": highlevelObjList})
            streamObjdict[streamData['port_name'],  streamData['stream_id']] = self.streams[streamData['stream_id']]
        tracking = [{"xpath": "/traffic/trafficItem[1]/tracking", "trackBy": ["customOverride"]}]
        trafficItemList.append({"xpath": "/traffic/trafficItem[1]",
                                              "trafficItemType": "quick", "trafficType": "ethernetVlan", "transmitMode": "interleaved", "endpointSet": endpointSetList, "highLevelStream": highlevelObjList, 
                                              "tracking": tracking})
        # import pdb;pdb.set_trace()
        with open('data.json', 'w', encoding='utf-8') as f:
            json.dump(json.dumps(trafficItemList), f, ensure_ascii=False, indent=4)
        self.sg.ResourceManager.ImportConfig(json.dumps(trafficItemList), False)        
        return streamObjdict
        # streamObjdict = {}
        # for stream_data in stream_data_list:
        #     # card_id, port_id = list(map(int, stream_data['port_name'].split('/')))
        #     card_id, port_id = map(int, stream_data['port_name'].split('/'))
        #     # Ixia stream id is 1 based, 1-off from 0 based traffic_gen stream_id input
        #     stream_data['stream_id'] = stream_data['stream_id'] + 1        
        #     if stream_data['stream_id'] not in self.streams:
        #         # First time create new Ixia stream
        #         stream = IxiaStreamClass(self.sg, card_id, port_id, stream_data['stream_id'])
        #         # add new streams into dictionary
        #         self.streams[stream_data['stream_id']] = stream            
        #     # # update the pkt connected for each add_stream invocation
        #     # self.streams[sid].pkt = stream_data['pkt']
        #     logging.info("Adding New Traffic Stream")             
        #     # srcPortNameList = []
        #     # portNameList = [vportObj.Name for vportObj in self.sg.Vport.find()]
        #     # for vportObj in self.sg.Vport.find():
        #     #     if str(card_id)+":"+str(port_id) in vportObj.AssignedTo:
        #     #         srcPortNameList.append(vportObj.Name)
        #     # # srcPortNameList = [vportObj.Name for vportObj in self.sg.Vport.find() if str(card_id)+":"+str(port_id) in vportObj.AssignedTo]
        #     # portNameList.remove(srcPortNameList[0])
        #     # dstPortNameList = portNameList        
        #     srcPortNameList = ["2/9"]
        #     dstPortNameList = ["2/9", "2/10"]
        #     self.sg.Traffic.UseRfc5952 = True
        #     self.sg.Traffic.Statistics.PacketLossDuration.Enabled = True
        #     if not self.sg.Traffic.TrafficItem.find():
        #         rawTrafficItemObj = self.sg.Traffic.TrafficItem.add(BiDirectional=False, TrafficType='ethernetVlan', TrafficItemType='quick')
        #         #rawTrafficItemObj = self.sg.Traffic.TrafficItem.add(BiDirectional=False, TrafficType='raw', TrafficItemType='quick')
        #     else:
        #         rawTrafficItemObj = self.sg.Traffic.TrafficItem.find()
        #     rawTrafficItemObj.Tracking.find().TrackBy = []
        #     srcEndpoint = self._get_src_dst_vport_objects(port_name=srcPortNameList)
        #     dstEndpoint = self._get_src_dst_vport_objects(port_name=dstPortNameList)
        #     rawTrafficItemObj.EndpointSet.add(Sources=srcEndpoint, Destinations=dstEndpoint)
        #     endpointIndex = len([end for end in rawTrafficItemObj.EndpointSet.find()])
        #     highlevelObj = rawTrafficItemObj.HighLevelStream.find(EndpointSetId=endpointIndex)
        #     if stream_data['frame_type'].lower() == "random":
        #         highlevelObj.FrameSize.Type = stream_data['frame_type'].lower()
        #         highlevelObj.FrameSize.RandomMin = stream_data['frame_min']
        #         highlevelObj.FrameSize.RandomMax = stream_data['frame_max']
        #     elif stream_data['frame_type'].lower() == "imix":
        #         highlevelObj.FrameSize.Type = stream_data['frame_type'].lower()
        #     else:
        #         highlevelObj.FrameSize.Type = stream_data['frame_type'].lower()
        #         highlevelObj.FrameSize.FixedSize = stream_data["pkt_size"]
        #     highlevelObj.FrameRate.Rate = stream_data["traffic_rate"]
        #     # highlevelObj.FrameSize.FixedSize = size            
        #     ethernetStackObj = highlevelObj.Stack.find(StackTypeId='^ethernet$')
        #     if 'eth_src_mac' in stream_data or 'eth_dst_mac' in stream_data:
        #         for key, value in {"Destination MAC Address":stream_data['eth_dst_mac'], "Source MAC Address":stream_data['eth_src_mac'], "Ethernet-Type":stream_data['etype']}.items():
        #             ethernetStackObj.Field.find(DisplayName=key).Auto = False
        #             ethernetStackObj.Field.find(DisplayName=key).ValueType = "singleValue"
        #             ethernetStackObj.Field.find(DisplayName=key).SingleValue = value
        #     if "Vlan" in stream_data and "outer_vlan" in stream_data:
        #         for vlanType in [stream_data['outer_vlan'], stream_data['inner_vlan']]:
        #             vlanStack = highlevelObj.Stack.find(StackTypeId='^vlan$')
        #             if ethernetStackObj and not vlanStack:
        #                 vlanTemplate = self.sg.Traffic.ProtocolTemplate.find(StackTypeId="^vlan$")
        #                 highlevelObj.Stack.read(ethernetStackObj.AppendProtocol(vlanTemplate)) 
        #                 vlanStackObj = highlevelObj.Stack.find(DisplayName="VLAN")[0]
        #             else:
        #                 vlanTemplate = self.sg.Traffic.ProtocolTemplate.find(StackTypeId="^vlan$")
        #                 highlevelObj.Stack.read(vlanStack.AppendProtocol(vlanTemplate))       
        #                 vlanStackObj = highlevelObj.Stack.find(DisplayName="VLAN")[1]
        #             vlanStackObj.Field.find(DisplayName="VLAN").SingleValue = vlanType 
        #     if "Vlan" in stream_data and "vlan_id" in stream_data:
        #         self._stream_stacks_update(highlevelObj, "VLAN", {"VLAN-ID":stream_data["vlan_id"], "VLAN Priority":stream_data["vlan_priority"]})
        #     if "Vxlan" in stream_data:
        #         vlanTemplate = self.sg.Traffic.ProtocolTemplate.find(StackTypeId="^"+"vxlan"+"$")
        #         highlevelObj.Stack.read(ethernetStackObj.AppendProtocol(vlanTemplate))     
        #         protocolStackObj = highlevelObj.Stack.find(DisplayName="VXLAN")    
        #     if "Ipv4" in stream_data:
        #         self._stream_stacks_update(highlevelObj, "IPv4", {"TTL":stream_data["ipv4_ttl"], "Source Address":stream_data["ipv4_src"], "Destination Address":stream_data["ipv4_dst"]})
                
        #     if "Ipv6" in stream_data:
        #         self._stream_stacks_update(highlevelObj, "IPv6", {"Hop Limit":stream_data["ipv6_hop_limit"], "Source Address":stream_data["ipv6_src"], "Destination Address":stream_data["ipv6_dst"]})
                            
        #     if "Mpls" in stream_data:
        #         self._stream_stacks_update(highlevelObj, "MPLS", {"Label Value":stream_data["mpls_label"], "Time To Live": stream_data["mpls_ttl"], "MPLS Exp": stream_data["mpls_tag_no"], "Last Tag": stream_data["mpls_last_tag"]})
        #     if "Tcp" in stream_data:
        #         self._stream_stacks_update(highlevelObj, "TCP", {"TCP-Source-Port":stream_data["tcp_src_port"], "TCP-Dest-Port":stream_data["tcp_dst_port"], "Sequence Number":stream_data["tcp_seq_no"]})
        #     if "Udp" in stream_data:
        #         self._stream_stacks_update(highlevelObj, "UDP", {"UDP-Source-Port":stream_data["udp_src_port"], "UDP-Dest-Port":stream_data["udp_dst_port"]})
        #     if "Gre" in stream_data:
        #         self._stream_stacks_update(highlevelObj, "GRE", {"Version": stream_data["gre_version"], "TTL":stream_data["gre_ttl"], "Source Address":stream_data["gre_src"], "Destination Address":stream_data["gre_dst"]})
        #     if "tracking_offset" in stream_data:
        #         self._add_stream_layer_end(stream_data["tracking_offset"])
        #     streamObjdict[stream_data['port_name'],  stream_data['stream_id']] = highlevelObj   
        # return streamObjdict
    
    def add_stream_layer2(self, sid, rate, size, macSa, macDa, payload, pkt, port_name):
        # Ixia stream id is 1 based, 1-off from 0 based traffic_gen stream_id input
        # ixia_sid = sid + 1
        card_id, port_id = map(int, port_name.split('/'))
        ixia_sid = sid
        logging.debug("add_stream_layer2, sid:{0} rate:{1} size:{2} macSa:{3} macDa:{4}".
                     format(ixia_sid, rate, size, macSa, macDa))
        if sid not in self.streams:
            # First time create new Ixia stream
            stream = IxiaStreamClass(self.sg, card_id, port_id, ixia_sid)
            # add new streams into dictionary
            self.streams[sid] = stream
        self.streams[sid].pkt = pkt
        logging.info("Adding New Traffic Stream")
        portName = {}
        for vportObj in self.sg.Vport.find():            
            if str(card_id)+":"+str(port_id) in vportObj.AssignedTo:
                if 'srcPortName' not in portName:
                    portName['srcPortName'] = [vportObj.Name]
                else:
                    portName['srcPortName'].append(vportObj.Name)
            else:
                if 'dstPortName' not in portName:
                    portName['dstPortName'] = [vportObj.Name]
                else:
                    portName['dstPortName'].append(vportObj.Name)        
        self.sg.Traffic.UseRfc5952 = True
        self.sg.Traffic.Statistics.PacketLossDuration.Enabled = True        
        if not self.sg.Traffic.TrafficItem.find():
            rawTrafficItemObj = self.sg.Traffic.TrafficItem.add(BiDirectional=False, TrafficType='raw', TrafficItemType='quick')
        else:
            rawTrafficItemObj = self.sg.Traffic.TrafficItem.find()
        srcEndpoint = self._get_src_dst_vport_objects(port_name=portName['srcPortName'])
        dstEndpoint = self._get_src_dst_vport_objects(port_name=portName['dstPortName'])
        rawTrafficItemObj.EndpointSet.add(Sources=srcEndpoint, Destinations=dstEndpoint)
        endpointIndex = len([end for end in rawTrafficItemObj.EndpointSet.find()])
        highlevelObj = rawTrafficItemObj.HighLevelStream.find(EndpointSetId=endpointIndex)
        highlevelObj.FrameSize.FixedSize = size
        highlevelObj.FrameSize.FixedSize = rate
        highlevelObj.FrameSize.FixedSize = size
        ethernetStackObj = highlevelObj.Stack.find(StackTypeId='^ethernet$')
        for key, value in {"Destination MAC Address":macDa, "Source MAC Address":macSa, "Ethernet-Type":etype}.items():
            #ethernetStackObj.Field.find(DisplayName=key).SingleValue = value  
            ethernetStackObj.Field.find(DisplayName=key).Auto = False
            ethernetStackObj.Field.find(DisplayName=key).ValueType = "singleValue"
            ethernetStackObj.Field.find(DisplayName=key).SingleValue = value
        return self.streams[sid]
    def _regenerate_traffic(self):
        """
        Regenerate all traffic items
        :return: True else Raise IxiaOperationException if failed        
        """
        try:
            logging.info('Regenerating Traffic Items')
            if self.sg.Traffic.State == 'started':
                pass
            else:
                trafficItem = self.sg.Traffic.TrafficItem.find()
                trafficItem.Generate()
        except:
            raise IxiaOperationException("Failed to Re-Generate Traffic")
        return True
    def _apply_traffic(self):
        """
        API to apply the traffic        
        """
        self.sg.Traffic.Apply()
        globals = self.sg.Globals
        apperrors = globals.AppErrors.find()
        for error in apperrors.Error.find():
            if "One or more destination MACs or VPNs are invalid" in error.Description:
                raise IxiaOperationException("Failed to apply traffic as packets are not generated properly")   
    def start_traffic(self, port_name):
        """
        This method used to start the traffic.
        """
        card_id, port_id = map(int, port_name.split('/'))
        logging.debug("start_traffic, card:{0} port:{1}".format(card_id, port_id))
        #self.sg.Traffic.TrafficItem.find().Tracking.find().TrackBy = ['trackingenabled0']
        if self.sg.Traffic.State not in ['stopped','stoppedWaitingForStats','unapplied']:
            self.stop_traffic() 
        if self.sg.Traffic.State in ['unapplied']:
           self.sg.Traffic.TrafficItem.find().Tracking.find().TrackBy = ['trackingenabled0']
           self._regenerate_traffic()
           self._apply_traffic()
        for vportObj in self.sg.Vport.find():            
            if str(card_id)+":"+str(port_id) in vportObj.AssignedTo:
                vportObj.StartStatelessTraffic()
                break  
    # def start_traffic(self):
    #     """
    #     This method used to start the traffic.
    #     """
    #     if self.sg.Traffic.State not in ['stopped','stoppedWaitingForStats','unapplied']:
    #         self.stop_traffic()        
    #     self._regenerate_traffic()
    #     self._apply_traffic() 
    #     try:
    #         for trafficObj in self.sg.Traffic.TrafficItem.find():
    #             trafficObj.StartStatelessTraffic()
    #     except:
    #         for trafficObj in self.sg.Traffic.TrafficItem.find():       
    #             trafficObj.HighLevelStream.find().StartStatelessTraffic()        
    def stop_traffic(self, port_name):
        """
        This method used to stop the traffic.
        """
        card_id, port_id = map(int, port_name.split('/'))
        logging.debug("stop_traffic, card:{0} port:{1}".format(card_id, port_id))
        for vportObj in self.sg.Vport.find():
            if str(card_id)+":"+str(port_id) in vportObj.AssignedTo:
                vportObj.StopStatelessTraffic()
                break 
    def convert_to_l1rate(self,byte_rate,frate):
        """
        Convert to l1rate with the byte/frame rate.
        :param byte_rate (int)
        :param frate (int)
        """
        l1rate = byte_rate*8+(frate*20*8)
        return l1rate
    def get_rx_statistic(self,sid,gid,counter, view_name="Flow Statistics"):
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
        # if len(str(self.card_id)) > 1:
        #     cardId = "Card" + str(self.card_id)
        # else:
        #     cardId = "Card" + '0' + str(self.card_id)
        # if len(str(self.port_id)) > 1:
        #     portId = "Port" + str(self.port_id)
        # else:
        #     portId = "Port" + '0' + str(self.port_id)   
        logging.info('\ngetStats: %s' % (view_name))
        TrafficItemStats = StatViewAssistant(self.sg, view_name)
        # trafficItemStatsDict = {}
        columnCaptions = TrafficItemStats.ColumnHeaders
        for rowNumber, stat in enumerate(TrafficItemStats.Rows):
            statsDict = {}
            for column in columnCaptions:
                statsDict[column] = stat[column]
            ixia_stats[rowNumber + 1] = statsDict
        for key, value in ixia_stats.items():
            #if cardId + '/' + portId in value['Stat Name']:
            #sid = 0
            if (counter + 1) == key:
                    statistics = value
                    break
        for stat_key, stat_value in statistics.items():
            if 'Rate' in stat_key:
                statistics[stat_key] = float(statistics[stat_key])
            elif 'Frames' in stat_key or 'Bytes' in stat_key or 'Bits' in stat_key:
                statistics[stat_key] = int(statistics[stat_key])
            else:
                pass
        #['Stat Name', 'Port Name', 'Line Speed', 'Link State', 'Frames Tx.', 'Valid Frames Rx.', 'Frames Tx. Rate', 'Valid Frames Rx. Rate', 'Data Integrity Frames Rx.', 'Data Integrity Errors', 'Bytes Tx.', 'Bytes Rx.', 'Bits Sent', 'Bits Received', 'Bytes Tx. Rate', 'Tx. Rate (bps)', 'Tx. Rate (Kbps)', 'Tx. Rate (Mbps)', 'Bytes Rx. Rate', 'Rx. Rate (bps)', 'Rx. Rate (Kbps)', 'Rx. Rate (Mbps)', 'Scheduled Frames Tx.', 'Scheduled Frames Tx. Rate', 'Control Frames Tx', 'Control Frames Rx', 'Ethernet OAM Information PDUs Sent', 'Ethernet OAM Information PDUs Received', 'Ethernet OAM Event Notification PDUs Received', 'Ethernet OAM Loopback Control PDUs Received', 'Ethernet OAM Organisation PDUs Received', 'Ethernet OAM Variable Request PDUs Received', 'Ethernet OAM Variable Response Received', 'Ethernet OAM Unsupported PDUs Received', 'Rx Pause Priority Group 0 Frames', 'Rx Pause Priority Group 1 Frames', 'Rx Pause Priority Group 2 Frames', 'Rx Pause Priority Group 3 Frames', 'Rx Pause Priority Group 4 Frames', 'Rx Pause Priority Group 5 Frames', 'Rx Pause Priority Group 6 Frames', 'Rx Pause Priority Group 7 Frames', 'Misdirected Packet Count', 'CRC Errors', 'Fragments', 'Undersize', 'Oversize', 'FEC Frame Loss Ratio', 'pre FEC Bit Error Rate']
        #{1: {'Stat Name': '10.106.148.81/4.1', 'Port Name': 'Ethernet - 001', 'Line Speed': '50GE', 'Link State': 'Link Up', 'Frames Tx.': '336664120', 'Valid Frames Rx.': '336661727', 'Frames Tx. Rate': '4788314', 'Valid Frames Rx. Rate': '4788325', 'Data Integrity Frames Rx.': '336661726', 'Data Integrity Errors': '0', 'Bytes Tx.': '286164502608', 'Bytes Rx.': '286162467950', 'Bits Sent': '2289316020864', 'Bits Received': '2289299743600', 'Bytes Tx. Rate': '4070068273', 'Tx. Rate (bps)': '32560546184.000', 'Tx. Rate (Kbps)': '32560546.184', 'Tx. Rate (Mbps)': '32560.546', 'Bytes Rx. Rate': '4070076554', 'Rx. Rate (bps)': '32560612432.000', 'Rx. Rate (Kbps)': '32560612.432', 'Rx. Rate (Mbps)': '32560.612', 'Scheduled Frames Tx.': '336664120', 'Scheduled Frames Tx. Rate': '4788314', 'Control Frames Tx': '0', 'Control Frames Rx': '0', 'Ethernet OAM Information PDUs Sent': '0', 'Ethernet OAM Information PDUs Received': '0', 'Ethernet OAM Event Notification PDUs Received': '0', 'Ethernet OAM Loopback Control PDUs Received': '0', 'Ethernet OAM Organisation PDUs Received': '0', 'Ethernet OAM Variable Request PDUs Received': '0', 'Ethernet OAM Variable Response Received': '0', 'Ethernet OAM Unsupported PDUs Received': '0', 'Rx Pause Priority Group 0 Frames': '0', 'Rx Pause Priority Group 1 Frames': '0', 'Rx Pause Priority Group 2 Frames': '0', 'Rx Pause Priority Group 3 Frames': '0', 'Rx Pause Priority Group 4 Frames': '0', 'Rx Pause Priority Group 5 Frames': '0', 'Rx Pause Priority Group 6 Frames': '0', 'Rx Pause Priority Group 7 Frames': '0', 'Misdirected Packet Count': '0', 'CRC Errors': '0', 'Fragments': '0', 'Undersize': '0', 'Oversize': '0', 'FEC Frame Loss Ratio': '0.000', 'pre FEC Bit Error Rate': '0.000'}}
        #
        # The convertion is not required in IxNetwork
        # rx_bps = self.convert_to_l1rate(statistics['byteRate'],statistics['frameRate'])
        # statistics = ixia_stats
        rx_bps = self.convert_to_l1rate(statistics['Rx Rate (bps)'],statistics['Rx Frame Rate'])
        statistics['rx_bps']     = rx_bps
        statistics['rx_pps']     = statistics['Rx Frame Rate']
        statistics['rx_bytes']   = statistics['Rx Bytes']
        statistics['rx_packets'] = statistics['Rx Frames']              
        return statistics
    
    def get_statistic(self, port_name, view_name="Port Statistics"):
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
        card_id, port_id = map(int, port_name.split('/'))
        # get total port statistics
        statistics = {}
        ixia_stats = {}
        portname = None
        logging.info('\ngetStats: %s' % (view_name))
        for vport in self.sg.Vport.find():
            if str(card_id) == (vport.AssignedTo).split(":")[1] and str(port_id) == (vport.AssignedTo).split(":")[2]:
                portname = vport.Name            
                break
        TrafficItemStats = StatViewAssistant(self.sg, view_name)
        # TrafficItemStats2 = StatViewAssistant(self.sg, "Port Statistics")
        # (bytesSent, framesSent, bytesReceived, frameReceived, dataIntegrityFrames,dataIntegrityErrors, rxPPS, txPPS, rxGbps, txGbps) = self.sg.portStatsGet(self.card_id, self.port_id)
        #(bytesSent, framesSent, bytesReceived, frameReceived, rxPPS, txPPS, rxGbps, txGbps) = self.sg.portStatsGet(self.card_id, self.port_id)
        # rxGbps = self.convert_to_l1rate(rxGbps,rxPPS)
        # txGbps = self.convert_to_l1rate(txGbps,txPPS)        
        columnCaptions = TrafficItemStats.ColumnHeaders
        
        for rowNumber, stat in enumerate(TrafficItemStats.Rows):
            statsDict = {}
            for column in columnCaptions:
                statsDict[column] = stat[column]
            ixia_stats[rowNumber + 1] = statsDict
        for key, value in ixia_stats.items():
            if portname and portname == value['Port Name']:
                statistics = value
                break
            else:
                raise IxiaConfigException('Failed to find the port name with the portId {}'.format(self.port_id))            
            
        for stat_key, stat_value in statistics.items():
            if 'Rate' in stat_key:
                statistics[stat_key] = float(statistics[stat_key]) 
            elif 'Frames' in stat_key or 'Bytes' in stat_key or 'Bits' in stat_key:
                statistics[stat_key] = int(statistics[stat_key]) 
            else:
                pass
        rxGbps = self.convert_to_l1rate(statistics['Rx. Rate (bps)'],statistics['Valid Frames Rx. Rate'])
        txGbps = self.convert_to_l1rate(statistics['Tx. Rate (bps)'],statistics['Frames Tx. Rate'])  
        statistics['tx_bps']     = txGbps  # TODO
        statistics['tx_pps']     = statistics['Frames Tx. Rate']
        statistics['tx_bytes']   = statistics['Bytes Tx.']
        statistics['tx_packets'] = statistics['Frames Tx.']

        statistics['rx_bps']     = rxGbps  # TODO
        statistics['rx_pps']     = statistics['Valid Frames Rx. Rate']
        statistics['rx_bytes']   = statistics['Bytes Rx.']
        statistics['rx_packets'] = statistics['Valid Frames Rx.']
        statistics['rx_integrity_frames'] = statistics['Data Integrity Frames Rx.']
        statistics['rx_integrity_errors'] = statistics['Data Integrity Errors']

        # TODO
        statistics['rx_no_test_payload_bytes']   = 0
        statistics['rx_no_test_payload_packets'] = 0
        statistics['error_count']                = 0

        output_str = f"get_port_stats, card:{card_id} port:{port_id} tx_bytes:{statistics['tx_bytes']} " \
                     f"tx_packets:{statistics['tx_packets']} rx_bytes:{statistics['rx_bytes']} rx_packets:{statistics['rx_packets']} "\
                     f"rx_pps:{statistics['rx_pps']} tx_pps:{statistics['tx_pps']}"
        logging.debug(output_str)
        return statistics   
    
    def get_tid_statistic(self, sid):
        """
        Get statistics based on the stream ID.
        :param sid (int): Stream ID
        """
        # logging.debug("get_stream_stats, card:{0} port:{1} sid:{2}".format(self.card_id, self.port_id, sid))
        return self.streams[sid].get_statistic()
    def clear_statistic(self):
        """
        Clear the statistics.
        """
        # logging.debug("clear_port_stats, card:{0} port:{1}".format(self.card_id, self.port_id))
        try:
            self.sg.ClearStats(Arg1=["waitForTrafficStatsRefresh"])
        except:
            pass
        return True
    def enable_capture(self, enable, port_name, data_plane=True, control_plane=True):
        """
        Enable the capture.
        :param enable (bool)
        :param data_plane (bool)
        :param control_plane (bool)
        """    
        card_id, port_id = map(int, port_name.split('/'))    
        # logging.debug("starting capture... card:{0} port:{1}".format(self.card_id, self.port_id))
        for vportObj in self.sg.Vport.find():      
            if str(card_id)+":"+str(port_id) in vportObj.AssignedTo: 
                capObj = vportObj.Capture.find()
                capObj.HardwareEnabled = data_plane
                capObj.SoftwareEnabled = control_plane
            else:
                vportObj.Capture.find().SoftwareEnabled = control_plane
                vportObj.Capture.find().HardwareEnabled = data_plane
        if enable:
            capObj.Start()
        else:
            capObj.Stop()            
    def get_packets(self, port_name):
        """
        Get list of packets sent.
        """
        card_id, port_id = map(int, port_name.split('/'))
        packets = []
        logging.debug("Capture returned {0} (packets) card:{1} port:{2}".format(len(packets), card_id, port_id))        
        for vportObj in self.sg.Vport.find():      
            if str(card_id)+":"+str(port_id) in vportObj.AssignedTo:      
                for capObj in vportObj.Capture.find():
                    if capObj.DataCapturedPacketCounter:
                        for stackObj in capObj.CurrentPacket.find().Stack.find():
                            if "Frame" == stackObj.DisplayName:
                                for fieldObj in stackObj.Field.find():
                                    packets.append((fieldObj.DisplayName,fieldObj.FieldValue))                             
        return packets
    def checksum_offset(self):
        # TODO
        pass
class IxiaStreamClass:
    def __init__(self, sg, card_id, port_id, sid):
        """
        Using IxiaPktGenerator session execute the below methods.
        :param sg (str): IxNetwork session
        :param card_id (str)
        :param port_id (str)
        :param sid (int): stream ID
        """
        self.sg = sg
        self.card_id = card_id
        self.port_id = port_id
        self.sid = sid
        self.raw_byte_size = ""
        self.modifier_count = 0
        self.udf_count = 0
        self.pkt = ""

    def set_payload_type(self, payload_type):
        # TODO
        pass

    def get_statistic(self, view_name="Port Statistics"):
        """
        Get the statistics based on the view name.
        :param view_name (str)
        """
        statistics = {}
        ixia_stats = {}
        logging.info('\ngetStats: %s' % (view_name))
        portname = None
        for vport in self.sg.Vport.find():
            if str(self.card_id) == (vport.AssignedTo).split(":")[1] and str(self.port_id) == (vport.AssignedTo).split(":")[2]:
                portname = vport.Name            
                break        
        TrafficItemStats = StatViewAssistant(self.sg, view_name)
        # TrafficItemStats.AddRowFilter("Port Name", StatViewAssistant.REGEX, "Port 1$")
        columnCaptions = TrafficItemStats.ColumnHeaders
        for rowNumber, stat in enumerate(TrafficItemStats.Rows):
            statsDict = {}
            for column in columnCaptions:
                statsDict[column] = stat[column]
            ixia_stats[rowNumber + 1] = statsDict
        for key, value in ixia_stats.items():
            if portname and portname == value['Port Name']:
                statistics = value
                break
            else:
                raise IxiaConfigException('Failed to find the port name with the portId {}'.format(self.port_id))          
        for stat_key, stat_value in statistics.items():
            if 'Rate' in stat_key:
                statistics[stat_key] = float(statistics[stat_key]) 
            elif 'Frames' in stat_key or 'Bytes' in stat_key or 'Bits' in stat_key:
                statistics[stat_key] = int(statistics[stat_key]) 
            else:
                pass
        # (frameReceived, bytesReceived, rx_pps, rx_bps, misOrdered, framesSent, tx_pps, bytesSent, tx_bps) = \
        #     self.sg.streamStatsGet(self.card_id, self.port_id, self.sid)
        
        statistics['tx_bps']     = 0
        statistics['tx_pps']     = statistics['Frames Tx. Rate']
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

    def get_tx_statistic(self, counter, view_name="Flow Statistics"):
        """
        Get the tx statistics based on the view name.
        :param view_name (str)
        """
        statistics = {}
        ixia_stats = {}
        # if len(str(self.card_id)) > 1:
        #     cardId = "Card" + str(self.card_id)
        # else:
        #     cardId = "Card" + '0' + str(self.card_id)
        # if len(str(self.port_id)) > 1:
        #     portId = "Port" + str(self.port_id)
        # else:
        #     portId = "Port" + '0' + str(self.port_id)
        logging.info('\ngetStats: %s' % (view_name))
        TrafficItemStats = StatViewAssistant(self.sg, view_name)
        columnCaptions = TrafficItemStats.ColumnHeaders
        for rowNumber, stat in enumerate(TrafficItemStats.Rows):
            statsDict = {}
            for column in columnCaptions:
                statsDict[column] = stat[column]
            ixia_stats[rowNumber + 1] = statsDict
        for key, value in ixia_stats.items():
            #if cardId + '/' + portId in value['Stat Name']:
            #sid = 0
            if (counter + 1) == key:
                statistics = value
                break
        for stat_key, stat_value in statistics.items():
            if 'Rate' in stat_key:
                statistics[stat_key] = float(statistics[stat_key])
            elif 'Frames' in stat_key or 'Bytes' in stat_key or 'Bits' in stat_key:
                statistics[stat_key] = int(statistics[stat_key])
            else:
                pass
        #print('Calling streamTxStatsGet with port_id {} sid {}'.format(self.port_id, self.sid))
        # (framesSent, tx_pps) = self.sg.streamTxStatsGet(self.card_id, self.port_id, self.sid)       
        statistics['tx_bps']     = 0
        statistics['tx_pps']     = statistics['Tx Frame Rate']
        statistics['tx_bytes']   = 0
        statistics['tx_packets'] = statistics['Tx Frames']
        return statistics
    
    def stream_stacks_update(self, protocol_stack, protocol_stack_values):
        """
        Internal method to update the protocol values based on the stack.
        :param protocol_stack (str): Ipv4/Ipv6/Tcp
        :param protocol_stack_values (dict)
        """
        configElement = self.sg.Traffic.TrafficItem.find().HighLevelStream.find()
        if protocol_stack.lower() == "vlan" or protocol_stack.lower() == "vxlan":
            stackObj = configElement.Stack.find(StackTypeId='^ethernet$')
        elif protocol_stack.lower() == "ipv4" or protocol_stack.lower() == "ipv6": 
            if configElement.Stack.find(StackTypeId='^vlan$').index != -1:
                stackObj = configElement.Stack.find(StackTypeId='^vlan$')
            else:
                stackObj = configElement.Stack.find(StackTypeId='^ethernet$')
        elif protocol_stack.lower() == "gre":
            stackObj = configElement.Stack.find(StackTypeId='^ipv4$')
        elif protocol_stack.lower() == "tcp":
            stackObj = configElement.Stack.find(StackTypeId='^ipv4$')
        elif protocol_stack.lower() == "udp":
            stackObj = configElement.Stack.find(StackTypeId='^ipv6$')
        else:
            stackObj = configElement.Stack.find(StackTypeId='^ethernet$')                
        if protocol_stack.lower() == "vlan" or protocol_stack.lower() == "vxlan":
            vlanTemplate = self.sg.Traffic.ProtocolTemplate.find(StackTypeId="^"+protocol_stack.lower()+"$")
            configElement.Stack.read(stackObj.AppendProtocol(vlanTemplate))     
            protocolStackObj = configElement.Stack.find(DisplayName=protocol_stack)                
        else:
            if protocol_stack.lower == "gre":
                protocolTemplate = self.sg.Traffic.ProtocolTemplate.find(DisplayName="GRE")
                stackObj.Append(Arg2=protocolTemplate)
                protocolStackObj = configElement.Stack.find(DisplayName="IPv4")
            else:   
                protocolTemplate = self.sg.Traffic.ProtocolTemplate.find(DisplayName=protocol_stack)
                stackObj.Append(Arg2=protocolTemplate)
                protocolStackObj = configElement.Stack.find(DisplayName=protocol_stack)
        for key, value in protocol_stack_values.items():
                    protocolStackObj.Field.find(DisplayName=key).SingleValue = value
    def add_dot1q_layer(self, vlan,prio=0):
        """
        Add dot1q Vlan stack and update vlan id and priority
        :param vlan (int): vlan ID
        :param prio (int): Priority
        """
        logging.debug("add_dot1q_layer, vlan:{0}".format(vlan))
        # self.sg.dot1QVlanAdd(vlan,prio)        
        self.stream_stacks_update("VLAN", {"VLAN-ID":vlan, "VLAN Priority":prio})
    def add_qinq_layer(self, outer_vlan, inner_vlan):
        """
        Add qinq Vlan stack using outer/inner vlan.
        :param outer_vlan (int)
        :param inner_vlan (int)
        """
        logging.debug("add_qinq_layer, outer_vlan:{0} inner_vlan:{1}".format(outer_vlan, inner_vlan))
        # self.sg.qinQVlanAdd(outer_vlan, inner_vlan) 
        for trafficObj in self.sg.Traffic.TrafficItem.find().HighLevelStream.find():
            if 'highLevelStream/' + str(self.sid) in trafficObj.href:       
                configElement = trafficObj        
                ethernetStack = configElement.Stack.find(StackTypeId='^ethernet$')                
                for vlanType in [outer_vlan, inner_vlan]:
                    vlanStack = configElement.Stack.find(StackTypeId='^vlan$')
                    if ethernetStack and not vlanStack:
                        vlanTemplate = self.sg.Traffic.ProtocolTemplate.find(StackTypeId="^vlan$")
                        configElement.Stack.read(ethernetStack.AppendProtocol(vlanTemplate)) 
                        protocolStackObj = configElement.Stack.find(DisplayName="VLAN")[0]
                    else:
                        vlanTemplate = self.sg.Traffic.ProtocolTemplate.find(StackTypeId="^vlan$")
                        configElement.Stack.read(vlanStack.AppendProtocol(vlanTemplate))       
                        protocolStackObj = configElement.Stack.find(DisplayName="VLAN")[1]
                    protocolStackObj.Field.find(DisplayName="VLAN").SingleValue = vlanType   
    def add_mpls_layer(self, tag_no, label, ttl, last_tag):
        """
        Add mpls stack 
        :param tag_no (int)
        :param label (int)
        :param ttl (int)
        :param lats_tag (int)
        """
        logging.debug("add_mpls_layer, tag_no:{0} label:{1} ttl:{2} last_tag:{3}"
                     .format(tag_no, label, ttl, last_tag))
        # self.sg.mplsAdd(tag_no, label, ttl, last_tag)
        self.stream_stacks_update("MPLS", {"Label Value":label, "Time To Live": ttl, "MPLS Exp": tag_no, "Lats Tag": last_tag})
    def add_ip_layer(self, outer_ip, ttl, ipsa, ipda):
        """
        Add IP stack
        :param outer_ip (str)
        :param ttl (int)
        :param ipsa (str)
        :param ipda (str)
        """
        logging.debug("add_ip_layer, outer_ip:{0} ttl:{1} ipsa:{2} ipda:{3}".format(outer_ip, ttl, ipsa, ipda))        
        self.stream_stacks_update("IPv4", {"TTL":ttl, "Source Address":ipsa, "Destination Address":ipda})
    def add_ipv6_layer(self, hlim, v6_sip, v6_dip):
        """
        Add Ipv6 stack
        :param hlim (int): Hop limit
        :param v6_sip (str)
        :param v6_dip (str)
        """
        logging.debug("add_ipv6_layer, hlim:{0} v6_sip:{1} v6_dip:{2}".format(hlim, v6_sip, v6_dip))
        # self.sg.ipv6Add(hlim, v6_sip, v6_dip)
        self.stream_stacks_update("IPv6", {"Hop Limit":hlim, "Source Address":v6_sip, "Destination Address":v6_dip})
    def add_tcp_layer(self, is_ipv4, sport, dport, seq_no):
        """
        Add Tcp stack
        :param is_ipv4 (bool)
        :param sport (int)
        :param dport (int)
        :param seq_no (int)
        """
        logging.debug("add_tcp_layer, is_ipv4:{0} sport:{1} dport:{2} seq_no:{3}".format(is_ipv4, sport, dport, seq_no))
        # self.sg.tcpAdd(is_ipv4, sport, dport, seq_no)
        self.stream_stacks_update("TCP", {"TCP-Source-Port":sport, "TCP-Dest-Port":dport, "Sequence Number":seq_no})
    def add_udp_layer(self, is_ipv4, sport, dport):
        """
        Add Udp stack
        :param is_ipv4 (bool)
        :param sport (int)
        :param dport (int)
        """
        logging.debug("add_udp_layer, is_ipv4:{0} sport:{1} dport:{2}".format(is_ipv4, sport, dport))
        # self.sg.udpAdd(is_ipv4, sport, dport)
        self.stream_stacks_update("UDP", {"UDP-Source-Port":sport, "UDP-Dest-Port":dport})
    def add_gre_and_outer_ip_layer(self, version, ttl, ipsa, ipda):
        """
        Add Gre stack
        :param version (int)
        :param ttl (int)
        :param ipsa (str)
        :param ipda (str)
        """
        logging.debug("add_gre_and_outer_ip_layer, version:{0} ttl:{1} ipsa:{2} ipda:{3}".format(version, ttl, ipsa, ipda))
        # self.sg.greOuterIpAdd(version, ttl, ipsa, ipda)
        self.stream_stacks_update("GRE", {"Version": version, "TTL":ttl, "Source Address":ipsa, "Destination Address":ipda})
    def add_vxlan_layer(self, payload):
        """
        Add Vxlan stack
        :param payload (str)
        """
        logging.debug("add_vxlan_layer, payload:{0}".format(payload))
        # self.sg.vxlanAdd(payload)
        self.stream_stacks_update("VXLAN",{})
    def add_raw_layer(self, payload):
        """
        Add Raw stack
        :param payload (str)
        """
        logging.debug("add_raw_layer, payload:{0}".format(payload))
        # self.sg.rawAdd(payload)
        #highLevelObj = self.sg.Traffic.TrafficItem.find().HighLevelStream.find(EndpointSetId=self.sid)
        highlevelObjLen = len(self.sg.Traffic.TrafficItem.find().EndpointSet.find())
        highLevelObj = self.sg.Traffic.TrafficItem.find().HighLevelStream.find(EndpointSetId=highlevelObjLen)
        payloadlen = len(payload)        
        if highLevelObj.Stack.find(StackTypeId='^udp$'):
            stackObj = highLevelObj.Stack.find(StackTypeId='^udp$')
        elif highLevelObj.Stack.find(StackTypeId='^tcp$'):
            stackObj = highLevelObj.Stack.find(StackTypeId='^tcp$')
        elif highLevelObj.Stack.find(StackTypeId='^ipv6$'):
            stackObj = highLevelObj.Stack.find(StackTypeId='^ipv6$')
        elif highLevelObj.Stack.find(StackTypeId='^ipv4$'):
            stackObj = highLevelObj.Stack.find(StackTypeId='^ipv4$')
        else:
            stackObj = highLevelObj.Stack.find(StackTypeId='^ethernet$')
        protocolTemplate = self.sg.Traffic.ProtocolTemplate.find(StackTypeId="^custom$")
        stackObj.Append(Arg2=protocolTemplate)
        protocolStackObj = highLevelObj.Stack.find(StackTypeId="^custom$")
        protocolStackObj.Field.find(Name="Length").SingleValue = payloadlen * 4
        protocolStackObj.Field.find(Name="Data").SingleValue = payload
        #protocolTemplate = self.sg.Traffic.ProtocolTemplate.find(DisplayName="Custom")
        #stackObj.Append(Arg2=protocolTemplate)
        #protocolStackObj = highLevelObj.Stack.find(DisplayName="Custom")
        #import pdb; pdb.set_trace()
        #protocolStackObj.Field.find(Name="Length").SingleValue = payloadlen
        #protocolStackObj.Field.find(Name="Data").SingleValue = payload
        #highLevelObj = self.sg.Traffic.TrafficItem.find().HighLevelStream.find(EndpointSetId=self.sid)
        #highLevelObj.FramePayload.Type = "custom"
        #highLevelObj.FramePayload.CustomPattern = payload
    def add_stream_layer_end(self, stats_offset, seq_check=True):
        """"
        Update existing stream offset and sequence check.
        :param stats_offset (int)
        :param seq_check (bool)
        """
        logging.debug("add_stream_layer_end, stats_offset:{0}, seq_check:{1}".format(stats_offset, seq_check))
        # self.sg.streamAddLayerEnd(stats_offset, seq_check)
        for trafficObj in self.sg.Traffic.TrafficItem.find():
            if seq_check:
                #trafficObj.TransmitMode="sequential"
                trafficObj.TransmitMode="interleaved"
            for trackingObj in trafficObj.Tracking.find():
                if trackingObj.TrackBy:
                    trackOptions = trackingObj.TrackBy
                    if 'customOverride' not in trackOptions:
                        trackOptions.append('customOverride')
                else:
                    trackingObj.TrackBy = ['customOverride']
                trackingObj.Offset = stats_offset
    def change_traffic_mac(self, sid, mask=None, init=None, macDa=False, count=None, step=None, action=None, field_size=None, value_type="nonRepeatableRandom", udf=False, byte_offset=None):
        """
        Internal method to update the random values.
        :param sid (str)
        :param mask (str)
        :param init (int)
        availableValueTypes: "singleValue", "valueList", "increment", "decrement", "random", "nonRepeatableRandom", "repeatableRandomRange"
        """
        logging.info("Changing Mac Parameters for Traffic Item/Items")
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
                                field.ValueType, field.RandomMask, field.Seed = value_type, mask, init
        logging.info("Mac updated in Traffic Items")
        return True
    def add_modifier(
            self,
            field,
            min,
            max,
            action,
            lower_range = -1,
            higher_range = -1,
            force_modifier_index=-1,
            use_extended_modifier=0):
        logging.debug("add_modifier, field:{0} min:{1} max:{2} action:{3} lower_range:{4} higher_range:{5} "
                     "force_modifier_index:{6} use_extended_modifier:{7}".format(field, min, max, action,
                                                                                 lower_range, higher_range,
                                                                                 force_modifier_index,
                                                                                 use_extended_modifier))
        print("******************AMIT******************")
        print("add_modifier, field:{0} min:{1} max:{2} action:{3} lower_range:{4} higher_range:{5} "
                     "force_modifier_index:{6} use_extended_modifier:{7}".format(field, min, max, action,
                                                                                 lower_range, higher_range,
                                                                                 force_modifier_index,
                                                                                 use_extended_modifier))
        byte_offset = (min // 8)
        relevant_bits_for_field = (max - min + 1)
        action = self.modifier_mode_to_ixia(action)
        # macSa/macDa field modifier.
        if byte_offset < 12:
            # random modifier for macSa/macDa
            if action == 'random':
                # for Mac random modifier, always contruct entire 6 bytes length of
                # mask and init, i.e. mask off those bits in the bit range...
                is_macDa = True if (byte_offset < 6) else False
                layer = self.pkt.getlayer(0)
                init = bytes(layer)[0:6] if is_macDa else bytes(layer)[6:12]
                logging.debug("mac{0} random modifier, init_without_mask:{1}".format("Da" if is_macDa else "Sa",
                                                                                    [bin(x) for x in init]))
                mask = bytearray()
                mask_start_byte = ((1 << (7 - (min % 8) + 1)) - 1)
                mask_end_byte = (((1 << (7 - (max % 8))) - 1) ^ 0xff)
                if (min // 8) == (max // 8):
                    # bit-range fit within in single byte boundary
                    mask.append(mask_start_byte & mask_end_byte)
                else:
                    # figure out how many mid mask bytes are needed
                    mask_mid_bytes = [0xff] * ((max // 8) - (min // 8) - 1)
                    mask.append(mask_start_byte)
                    [mask.append(x) for x in mask_mid_bytes]
                    mask.append(mask_end_byte)
                if is_macDa:
                    for i in range(min // 8):
                        mask.insert(0, 0x0)
                    for i in range((max // 8), 5):
                        mask.append(0x0)
                else:
                    for i in range(6, (min // 8)):
                        mask.insert(0, 0x0)
                    for i in range((max // 8), 11):
                        mask.append(0x0)
                logging.debug("mac{0} random modifier, init_mask:{1}".format("Da" if is_macDa else "Sa",
                                                                            [bin(x) for x in mask]))
                # reverse the mask for byte ranges, for mask off purpose
                mask = [(x ^ 0xff) for x in mask]
                logging.debug("mac{0} random modifier, reverse init_mask:{1}".format("Da" if is_macDa else "Sa",
                                                                                    [bin(x) for x in mask]))
                # apply mask on init value, i.e. so to mask off bit-range value.
                init = [x & y for x, y in zip(mask, init)]
                logging.debug("mac{0} random modifier, init_apply_mask:{1}".format("Da" if is_macDa else "Sa",
                                                                                  [bin(x) for x in init]))
                # use this init seed string to configure random Mac modifier
                init = hexlify(bytes(init)).decode('ascii')
                init = " ".join(init[i:i + 2] for i in range(0, len(init), 2))
                # the reverse mask is needed to configure random Mac modifier
                mask = hexlify(bytes(mask)).decode('ascii')
                mask = " ".join(mask[i:i + 2] for i in range(0, len(mask), 2))
                if is_macDa:
                    # macDa random modifier
                    self.change_traffic_mac(self.sid, mask, init, macDa=True)
                else:
                    # macSa random modifier
                    self.change_traffic_mac(self.sid, mask, init)                    
                return
            # Non-random modifier for macSa/macDa
            if relevant_bits_for_field > 48:
                raise Exception('Error: invalid modifier for macDa/macSa, field bit length large:{}'
                                .format(relevant_bits_for_field))
                return
            if relevant_bits_for_field == 48:
                # (contIncr/contDecr) modifier for macSa/macDa
                # simple continuous modifier apply to entire MacDa or MacSa field
                mac_action = "Increment" if action == "uuuu" else "Decrement"
                if byte_offset == 0:
                    # macDa field modifier
                    self.change_traffic_mac(self.sid, value_type=mac_action, macDa=True)
                    # self.sg.streamMacDaContModifier(self.card_id, self.port_id, self.sid, mac_action)
                    logging.debug("macDa cont modifier, sid:{0} action:{1}".format(self.port_id, mac_action))
                elif byte_offset == 6:
                    # macSa field modifier
                    self.change_traffic_mac(self.sid, value_type=mac_action)
                    # self.sg.streamMacSaContModifier(self.card_id, self.port_id, self.sid, mac_action)
                    logging.debug("macSa cont modifier, sid:{0} action:{1}".format(self.port_id, mac_action))
                else:
                    raise Exception('Error: invalid continuous modifier for macDa/macSa, byte_offset:{}'
                                    .format(byte_offset))
                    return
            else:
                # (range increment/decrement) modifier for macSa/macDa
                # range based modifier apply to specific range of MacDa or MacSa field
                mac_action = "increment" if action == "uuuu" else "decrement"
                repeat = higher_range + 1 if higher_range != -1 else (1 << relevant_bits_for_field)
                if byte_offset < 6:
                    # macDa field modifier
                    step = 1 << (47 - (max % 48))
                    self.change_traffic_mac(self.sid, value_type=mac_action, count=repeat, step=step, macDa=True)
                    # self.sg.streamMacDaRangeModifier(self.card_id, self.port_id, self.sid, mac_action, repeat, step)
                    logging.debug("macDa range modifier, sid:{0} action:{1} repeat:{2} step:{3}"
                                 .format(self.sid, mac_action, repeat, step))
                elif byte_offset < 12:
                    # macSa field modifier
                    step = 1 << (95 - (max % 96))
                    self.change_traffic_mac(self.sid, value_type=mac_action, count=repeat, step=step)
                    # self.sg.streamMacSaRangeModifier(self.card_id, self.port_id, self.sid, mac_action, repeat, step)
                    logging.debug("macSa range modifier, sid:{0} action:{1} repeat:{2} step:{3}"
                                 .format(self.sid, mac_action, repeat, step))
                else:
                    raise Exception('Error: invalid range modifier for macDa/macSa, byte_offset:{}'.
                                    format(byte_offset))
                    return
        else:
            # UDF modifier:
            # modifier bit range [min, max] not enough to cover higher range,
            # error out as Ixia UDF can't support it.
            if higher_range != -1 and (1 << relevant_bits_for_field) < (higher_range + 1):
                raise Exception(
                    'Error: invalid udf modifier, bit range less than higher range, min:{0}, max:{1}, higher range:{2}'.format(
                        min, max, higher_range))
                return
            # init seed needs to consider [min, max] mask, i.e. whatever the original
            # packet value, with [min, max] bit ranges all masked out
            layer = self.pkt.getlayer(0)
            init = bytes(layer)[byte_offset:(max // 8 + 1)]
            logging.debug("udf modifier, init_without_mask:{0}".format([bin(x) for x in init]))
            print("AMIT: 1. udf modifier, init_without_mask:{0}".format([bin(x) for x in init]))
            mask = bytearray()
            mask_start_byte = ((1 << (7 - (min % 8) + 1)) - 1)
            mask_end_byte = (((1 << (7 - (max % 8))) - 1) ^ 0xff)
            if (min // 8) == (max // 8):
                # bit-range fit within in single byte boundary
                mask.append(mask_start_byte & mask_end_byte)
            else:
                # figure out how many mid mask bytes are needed
                mask_mid_bytes = [0xff] * ((max // 8) - (min // 8) - 1)
                mask.append(mask_start_byte)
                [mask.append(x) for x in mask_mid_bytes]
                mask.append(mask_end_byte)
            logging.debug("udf modifier, init_mask:{0}".format([bin(x) for x in mask]))
            print("AMIT: 2. udf modifier, init_mask:{0}".format([bin(x) for x in mask]))
            if field == 'BYPASS_INIT':
               pass
            else :
               # reverse the mask for byte ranges, for mask off purpose
               mask = [(x ^ 0xff) for x in mask]
               logging.debug("udf modifier, reverse init_mask:{0}".format([bin(x) for x in mask]))
               print("AMIT: 3. udf modifier, init_mask:{0}".format([bin(x) for x in mask]))
               # apply mask on init value, i.e. so to mask off bit-range value.
               init = [x & y for x, y in zip(mask, init)]
               logging.debug("udf modifier, init_apply_mask:{0}".format([bin(x) for x in init]))
               print("AMIT: 4. udf modifier, init_without_mask:{0}".format([bin(x) for x in init]))
            # use this init seed string to configure Ixia UDF modifier
            init = hexlify(bytes(init)).decode('ascii')
            init = " ".join(init[i:i + 2] for i in range(0, len(init), 2))
            print("AMIT: 5. udf modifier, init_without_mask:{0}".format(init))
            # reverse mask is needed to configure random UDF modifier
            mask = hexlify(bytes(mask)).decode('ascii')
            mask = " ".join(mask[i:i + 2] for i in range(0, len(mask), 2))
            if action == "random":
                # random UDF modifier
                if (max // 8  - byte_offset) > 3:
                    # modifier bit range [min, max] span across more than 4 bytes field,
                    # error out as Ixia UDF can't support it.
                    raise Exception(
                        'Error: invalid udf random modifier, field length over 4 bytes, min:{0}, max:{1}'.format(
                            min, max))
                    return
                logging.debug("udf random modifier, sid:{0} udf_id:{1} byte_offset:{2} field_size:{3} reverse_mask:{4} "
                             "init:{5}".format(self.sid, self.udf_count + 1, byte_offset,
                                               (max // 8  - byte_offset + 1) * 8, mask, init))
                print("AMIT udf random modifier, sid:{0} udf_id:{1} byte_offset:{2} field_size:{3} reverse_mask:{4} "
                             "init:{5}".format(self.sid, self.udf_count + 1, byte_offset,
                                               (max // 8  - byte_offset + 1) * 8, mask, init))
                self.change_traffic_mac(self.sid, mask, init, byte_offset, action=action, field_size=(max // 8  - byte_offset + 1) * 8, udf=True)

            elif (min % 8 == 0 and
                  relevant_bits_for_field in [8, 16, 24, 32]):
                # none random action, i.e. action = INC/DEC...
                # Ixia supports upto 4 bytes of UDF modifier with bit_offset as 0, i.e.
                # when bit range is byte aligned
                logging.debug("udf modifier, sid:{0} udf_id:{1} byte_offset:{2} field_size:{3} action:{4} repeat:{5} "
                             "step:{6} init:{7}".format(self.sid, self.udf_count + 1, byte_offset, relevant_bits_for_field, action,
                                                        higher_range + 1 if higher_range != -1 else (1 << relevant_bits_for_field),
                                                        1, init))
                self.change_traffic_mac(self.sid, mask, init, byte_offset, action=action, field_size=relevant_bits_for_field, step=1, repeat=higher_range + 1 if higher_range != -1 else (1 << relevant_bits_for_field), udf=True)
                
            else:
                # none random action, i.e. action = INC/DEC...
                if (max // 8  - byte_offset) > 3:
                    # modifier bit range [min, max] span across more than 4 bytes field,
                    # error out as Ixia UDF can't support it.
                    raise Exception('Error: invalid udf modifier, field length over 4 bytes, min:{0}, max:{1}'.format(min, max))
                    return
                # [min, max] span within 4 bytes field, so Ixia UDF should be able to support:
                # - field size => [min, max]
                # - step => bit_offset => max
                # - upperlimit => higher range
                logging.debug("udf modifier, sid:{0} udf_id:{1} byte_offset:{2} field_size:{3} action:{4} repeat:{5} "
                             "step:{6} init:{7}".format(self.sid, self.udf_count + 1, byte_offset,
                                                        (max // 8  - byte_offset + 1) * 8, action,
                                                        higher_range + 1 if higher_range != -1 else (1 << relevant_bits_for_field),
                                                        1 << (7 - (max % 8)), init))
                self.change_traffic_mac(self.sid, mask, init, byte_offset, action=action, field_size=(max // 8  - byte_offset + 1) * 8, step=1 << (7 - (max % 8)), repeat=higher_range + 1 if higher_range != -1 else (1 << relevant_bits_for_field), udf=True)
                
        # keep track of how many modifiers being added for the stream
        self.udf_count += 1
        self.modifier_count += 1
    def modifier_mode_to_ixia(self, action):
        # convert to Ixia UDF modifier action string representation
        return {
            'INC': 'uuuu',
            'DEC': 'duuu',
            'RANDOM': 'random',
        }.get(action, 'uuuu')
    def get_packet_size(self):
        # TODO
        pass
    # set continuous stream packet rate, once set, the packet duration mode is also
    # changed to continuos mode
    def set_rate_percentage(self, rate_perc):
        """
        Update/set stream rate percentage.
        :param rate_perc (int)
        """
        logging.debug("set_rate_percentage, card:{0} port:{1} sid:{2} rate:{3}".
                     format(self.card_id, self.port_id, self.sid, rate_perc))
        # self.sg.streamRateSet(self.card_id, self.port_id, self.sid, rate_perc)
        for trafficObj in self.sg.Traffic.TrafficItem.find():
            for configObj in trafficObj.ConfigElement.find():
                if str(self.sid) in trafficObj.href and str(self.sid) in configObj.href:
                    for frameRate in configObj.FrameRate.find():
                        frameRate.Rate = rate_perc
                    break
    def get_rate_percentage(self):
        """
        Get stream rate percentage.
        """
        logging.debug("get_rate_percentage, card:{0} port:{1} sid:{2}".format(self.card_id, self.port_id, self.sid))
        # return self.sg.streamRateGet(self.card_id, self.port_id, self.sid)
        self.sg.Traffic.TrafficItem.find()
        for trafficObj in self.sg.Traffic.TrafficItem.find():
            for configObj in trafficObj.ConfigElement.find():
                if str(self.sid) in trafficObj.href and str(self.sid) in configObj.href:
                    return configObj.FrameRate.find().Rate
    def set_rate_mpps(self, rate_Mpps):
        # TODO
        pass
    def get_rate_mpps(self):
        # TODO
        pass
    # set burst stream packet limit, once set, the packet duration mode is also
    # changed to burst mode.
    def set_packet_limit(self, packet_limit):
        """
        Update/Set packet limit 
        :param packet_limit (int)
        """
        logging.debug("set_packet_limit, card:{0} port:{1} sid:{2} limit:{3}".
                     format(self.card_id, self.port_id, self.sid, packet_limit))
        # self.sg.streamPktLimitSet(self.card_id, self.port_id, self.sid, packet_limit)
        for trafficObj in self.sg.Traffic.TrafficItem.find().HighLevelStream.find():
            if 'highLevelStream/' + str(self.sid) in trafficObj.href:
                configElement = trafficObj
                configElement.TransmissionControl.find().Type="fixedFrameCount"
                configElement.TransmissionControl.find().FrameCount=packet_limit       
                break   
    # get burst stream packet limit
    def get_packet_limit(self):
        """
        Get packet limit
        """
        logging.debug("get_packet_limit, card:{0} port:{1} sid:{2}".format(self.card_id, self.port_id, self.sid))
        # return self.sg.streamPktLimitGet(self.card_id, self.port_id, self.sid)
        for trafficObj in self.sg.Traffic.TrafficItem.find().HighLevelStream.find():
            if 'highLevelStream/' + str(self.sid) in trafficObj.href:
                configElement = trafficObj
                return configElement.TransmissionControl.find().FrameCount               
    # enable a particular stream
    def enable_traffic(self, stream_id):
        """
        Enable the traffic stream based on the stream ID.
        """
        # logging.debug("enable_stream, card:{0} port:{1} sid:{2}".format(self.card_id, self.port_id, self.sid))
        # self.sg.streamEnable(self.card_id, self.port_id, self.sid)
        # self.sg.Traffic.TrafficItem.find()
        highLevelObjList = [highLevelObj for highLevelObj in self.sg.Traffic.TrafficItem.find().HighLevelStream.find()]
        highLevelObjList[stream_id-1].Enabled = True
        # self.sg.Traffic.TrafficItem.find().HighLevelStream.find(EndpointSetId=stream_id).Enabled = True
        # for trafficObj in self.sg.Traffic.TrafficItem.find().HighLevelStream.find():
        #     import pdb;pdb.set_trace()
        #     if 'highLevelStream/' + str(self.sid) in trafficObj.href:
        #         trafficObj.Enabled = True
        #         break
    # disable a particular stream
    def disable_traffic(self,stream_id):
        """
        Disable the traffic stream based on the stream ID.
        """
        # logging.debug("disable_stream, card:{0} port:{1} sid:{2}".format(self.card_id, self.port_id, self.sid))
        # self.sg.streamDisable(self.card_id, self.port_id, self.sid)
        highLevelObjList = [highLevelObj for highLevelObj in self.sg.Traffic.TrafficItem.find().HighLevelStream.find()]
        highLevelObjList[stream_id-1].Enabled = False
        # for trafficObj in self.sg.Traffic.TrafficItem.find().HighLevelStream.find():
        #     import pdb;pdb.set_trace()
        #     if 'highLevelStream/' + str(self.sid) in trafficObj.href:
        #         trafficObj.Enabled = False
        #         break

