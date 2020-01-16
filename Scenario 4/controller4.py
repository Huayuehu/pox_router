from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.lib.addresses as adr
from  pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str
log = core.getLogger()



class Controller4 (object):
  def __init__ (self, connection):
    self.connection = connection
    connection.addListeners(self)

    # mac address match port number
    self.mac_to_port1 = {}
    self.mac_to_port2 = {}
    self.mac_to_port3 = {}

    self.routing_table1 = {
        "10.0.1.4":[1, '00:00:00:00:00:01'], 
        "10.0.1.5":[2, '00:00:00:00:00:02'],
        "10.0.1.6":[3, '00:00:00:00:00:03']
        }
    
    self.routing_table2 = {
        "10.0.2.7":[1, '00:00:00:00:00:04'], 
        "10.0.2.8":[2, '00:00:00:00:00:05'],
        "10.0.2.9":[3, '00:00:00:00:00:06']
        }
    
    self.routing_table3 = {
        "10.0.3.10":[1, '00:00:00:00:00:07'], 
        "10.0.3.11":[2, '00:00:00:00:00:08'],
        "10.0.3.12":[3, '00:00:00:00:00:09']
        }

  def send_packet (self, packet_in, port_out):
    msg = of.ofp_packet_out()
    msg.data = packet_in
    action = of.ofp_action_output(port=port_out)
    msg.actions.append(action)
    self.connection.send(msg)


  def switch1 (self, packet, packet_in):
    # record the src mac_address with its port number
    self.mac_to_port1[packet.src] = packet_in.in_port

    if packet.dst not in self.mac_to_port1:
        self.send_packet(packet_in, of.OFPP_ALL)
    else:
        self.send_packet(packet_in, self.mac_to_port1[packet.dst])

  def switch2 (self, packet, packet_in):
    # record the src mac_address with its port number
    self.mac_to_port2[packet.src] = packet_in.in_port

    if packet.dst not in self.mac_to_port2:
        self.send_packet(packet_in, of.OFPP_ALL) 
    else:
        self.send_packet(packet_in, self.mac_to_port2[packet.dst])

  def switch3 (self, packet, packet_in):
    # record the src mac_address with its port number
    self.mac_to_port3[packet.src] = packet_in.in_port

    if packet.dst not in self.mac_to_port3:
        self.send_packet(packet_in, of.OFPP_ALL) 
    else:
        self.send_packet(packet_in, self.mac_to_port3[packet.dst])
      

  # ref: https://openflow.stanford.edu/display/ONL/POX+Wiki.html#POXWiki-Example%3AARPmessages
  def arp_request1(self, packet, packet_in):
      arp_packet = packet.payload
      if arp_packet.opcode == pkt.arp.REQUEST:
          if str(arp_packet.protodst) == "10.0.1.1":  # network1
              # packet: arp packet
              arp_reply = pkt.arp()
              arp_reply.hwsrc = adr.EthAddr("11:11:11:11:11:11")
              arp_reply.hwdst = arp_packet.hwsrc
              arp_reply.opcode = pkt.arp.REPLY
              arp_reply.protosrc = arp_packet.protodst
              arp_reply.protodst = arp_packet.protosrc
              # ethernet packet
              eth_packet = pkt.ethernet()
              eth_packet.type = pkt.ethernet.ARP_TYPE
              eth_packet.dst = packet.src
              eth_packet.src = adr.EthAddr("11:11:11:11:11:11")
              eth_packet.payload = arp_reply

              msg = of.ofp_packet_out()
              msg.data = eth_packet.pack()

              action = of.ofp_action_output(port = packet_in.in_port)
              msg.actions.append(action)
              self.connection.send(msg)

              self.mac_to_port1[packet.src] = packet_in.in_port
              log.debug(self.mac_to_port1)
          
          else:
              find_ip = 0
              for ip in self.routing_table1.keys():
                  if ip == str(arp_packet.protodst):
                      find_ip = ip
              if find_ip != 0:
                  self.switch1(packet,packet_in)
      
      elif arp_packet.opcode == pkt.arp.REPLY:
          log.debug("Received arp REPLY")
          self.mac_to_port1[packet.src] = packet_in.in_port
          self.switch1(packet, packet_in)
    
  # ref: https://openflow.stanford.edu/display/ONL/POX+Wiki.html#POXWiki-Example%3AARPmessages
  def arp_request2(self,packet, packet_in):
      arp_packet = packet.payload
      if arp_packet.opcode == pkt.arp.REQUEST:
          if str(arp_packet.protodst) == "10.0.2.1":  # network2
              arp_reply = pkt.arp()
              arp_reply.hwsrc = adr.EthAddr("22:22:22:22:22:22")
              arp_reply.hwdst = arp_packet.hwsrc
              arp_reply.opcode = pkt.arp.REPLY
              arp_reply.protosrc = arp_packet.protodst
              arp_reply.protodst = arp_packet.protosrc
              
              eth_packet = pkt.ethernet()
              eth_packet.type = pkt.ethernet.ARP_TYPE
              eth_packet.dst = packet.src
              eth_packet.src = adr.EthAddr("22:22:22:22:22:22")
              eth_packet.payload = arp_reply

              msg = of.ofp_packet_out()
              msg.data = eth_packet.pack()

              action = of.ofp_action_output(port = packet_in.in_port)
              msg.actions.append(action)
              self.connection.send(msg)

              self.mac_to_port2[packet.src] = packet_in.in_port
              log.debug(self.mac_to_port2)
          
          else:
              find_ip = 0
              for ip in self.routing_table2.keys():
                  if ip == str(arp_packet.protodst):
                      find_ip = ip
              if find_ip != 0:
                  self.switch2(packet,packet_in)

      elif arp_packet.opcode == pkt.arp.REPLY:
          log.debug("Received arp REPLY")
          self.mac_to_port2[packet.src] = packet_in.in_port
          self.switch2(packet,packet_in) 

  # ref: https://openflow.stanford.edu/display/ONL/POX+Wiki.html#POXWiki-Example%3AARPmessages
  def arp_request3(self,packet, packet_in):
      arp_packet = packet.payload

      if arp_packet.opcode == pkt.arp.REQUEST:
          if str(arp_packet.protodst) == "10.0.3.1":
              arp_reply = pkt.arp()
              arp_reply.hwsrc = adr.EthAddr("33:33:33:33:33:33")
              arp_reply.hwdst = arp_packet.hwsrc
              arp_reply.opcode = pkt.arp.REPLY
              arp_reply.protosrc = arp_packet.protodst
              arp_reply.protodst = arp_packet.protosrc
              
              eth_packet = pkt.ethernet()
              eth_packet.type = pkt.ethernet.ARP_TYPE
              eth_packet.dst = packet.src
              eth_packet.src = adr.EthAddr("33:33:33:33:33:33")
              eth_packet.payload = arp_reply

              msg = of.ofp_packet_out()
              msg.data = eth_packet.pack()

              action = of.ofp_action_output(port = packet_in.in_port)
              msg.actions.append(action)
              self.connection.send(msg)

              self.mac_to_port3[packet.src] = packet_in.in_port
              log.debug(self.mac_to_port3)
          
          else:
              find_ip = 0
              for ip in self.routing_table3.keys():
                  if ip == str(arp_packet.protodst):
                      find_ip = ip
              if find_ip != 0:
                  self.switch3(packet,packet_in)

      elif arp_packet.opcode == pkt.arp.REPLY:
          log.debug("Received arp REPLY")
          self.mac_to_port3[packet.src] = packet_in.in_port
          self.switch3(packet,packet_in) 


  def handle_reachable(self, packet, packet_in):
      # echo
      echo = pkt.echo()
      echo.seq = packet.payload.payload.payload.seq + 1
      echo.id = packet.payload.payload.payload.id
      # icmp pakcet
      icmp_packet = pkt.icmp()
      icmp_packet.type = pkt.TYPE_ECHO_REPLY
      icmp_packet.payload = echo
      # ip packet
      ip_packet = pkt.ipv4()
      ip_packet.srcip = packet.payload.dstip
      ip_packet.dstip = packet.payload.srcip
      ip_packet.protocol = pkt.ipv4.ICMP_PROTOCOL
      ip_packet.payload = icmp_packet
      # ethernet packet
      ether_packet = pkt.ethernet()
      ether_packet.type = pkt.ethernet.IP_TYPE
      ether_packet.dst = packet.src
      ether_packet.src = packet.dst
      ether_packet.payload = ip_packet

      msg = of.ofp_packet_out()
      msg.data = ether_packet.pack()
      
      action = of.ofp_action_output(port=packet_in.in_port)
      msg.actions.append(action)
      self.connection.send(msg)

  def handle_unreachable(self,packet,packet_in):
      packet_unreachable = pkt.unreach()
      packet_unreachable.payload = packet.payload

      icmp_packet = pkt.icmp()
      icmp_packet.type = pkt.TYPE_DEST_UNREACH
      icmp_packet.payload = packet_unreachable

      ip_packet = pkt.ipv4()
      ip_packet.srcip = packet.payload.dstip
      ip_packet.dstip = packet.payload.srcip 
      ip_packet.protocol = pkt.ipv4.ICMP_PROTOCOL
      ip_packet.payload = icmp_packet

      ether_packet = pkt.ethernet()
      ether_packet.type = pkt.ethernet.IP_TYPE
      ether_packet.dst = packet.src
      ether_packet.src = packet.dst
      ether_packet.payload = ip_packet
      
      msg = of.ofp_packet_out()
      msg.data = ether_packet.pack()
      action = of.ofp_action_output(port=packet_in.in_port)
      msg.actions.append(action)
      self.connection.send(msg)

  # https://github.com/Chuansssss/Mininet-Openflow-exercise 
  def handle_ip1(self, packet, packet_in):
      log.debug("Send ip packet, src ip: %r ,dest ip: %r" % (packet.payload.srcip,packet.payload.dstip))
      dest_ip = packet.payload.dstip
      src_ip = packet.payload.srcip
      if str(dest_ip) in self.routing_table1:
          if str(src_ip) in self.routing_table1:
              log.debug("ip packet is sent in local network1")
              msg = of.ofp_flow_mod()
              msg.match.dl_type = pkt.ethernet.IP_TYPE
              msg.match.dl_src = packet.src
              msg.match.dl_dst = packet.dst  
              msg.match.nw_src = packet.payload.srcip
              msg.match.nw_dst = packet.payload.dstip
              msg.match.in_port = packet_in.in_port
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=self.routing_table1[str(dest_ip)][0]))
              self.connection.send(msg)
          elif str(src_ip) in self.routing_table2:
              packet.src = packet.dst
              packet.dst = EthAddr(self.routing_table1[str(dest_ip)][1])
              msg = of.ofp_packet_out()
              msg.data = packet.pack()
              action = of.ofp_action_output(port = self.routing_table1[str(dest_ip)][0])
              msg.actions.append(action)
              self.connection.send(msg)
              log.debug("ip packet move to host in network1")
          elif str(src_ip) in self.routing_table3:
              packet.src = packet.dst
              packet.dst = EthAddr(self.routing_table1[str(dest_ip)][1])
              msg = of.ofp_packet_out()
              msg.data = packet.pack()
              action = of.ofp_action_output(port = self.routing_table1[str(dest_ip)][0])
              msg.actions.append(action)
              self.connection.send(msg)
              log.debug("ip packet move to host in network1")              
          else:
              log.debug("ip packet is unreachable in this network")
          
      elif str(dest_ip) in self.routing_table2:
          log.debug("packet move from %r to %r" % (packet.payload.srcip, packet.payload.dstip))
          packet.src = packet.dst
          packet.dst = adr.EthAddr("22:22:22:22:22:22")
          msg = of.ofp_packet_out()
          msg.data = packet.pack()
          action = of.ofp_action_output(port=4)
          msg.actions.append(action)
          self.connection.send(msg)
          log.debug("ip packet move to Router2")

      elif str(dest_ip) in self.routing_table3:
          log.debug("packet move from %r to %r" % (packet.payload.srcip, packet.payload.dstip))
          packet.src = packet.dst
          packet.dst = adr.EthAddr("33:33:33:33:33:33")
          msg = of.ofp_packet_out()
          msg.data = packet.pack()
          action = of.ofp_action_output(port=5)
          msg.actions.append(action)
          self.connection.send(msg)
          log.debug("ip packet move to Router3")          
      else:
          log.debug("ip packet is unreachable in this network")

  # handle_ip2 is very similar with handle_ip1
  def handle_ip2(self, packet, packet_in):
      log.debug("Send ip packet, src ip: %r ,dest ip: %r" % (packet.payload.srcip,packet.payload.dstip))
      dest_ip = packet.payload.dstip
      src_ip = packet.payload.srcip
      if str(dest_ip) in self.routing_table2:
          if str(src_ip) in self.routing_table2:
              log.debug("ip packet is sent in local network2")
              msg = of.ofp_flow_mod()
              msg.match.dl_type = pkt.ethernet.IP_TYPE
              msg.match.dl_src = packet.src
              msg.match.dl_dst = packet.dst  
              msg.match.nw_src = packet.payload.srcip
              msg.match.nw_dst = packet.payload.dstip
              msg.match.in_port = packet_in.in_port
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port = self.routing_table2[str(dest_ip)][0]))
              self.connection.send(msg)
          elif str(src_ip) in self.routing_table1:
              packet.src = packet.dst
              packet.dst = EthAddr(self.routing_table2[str(dest_ip)][1])
              msg = of.ofp_packet_out()
              msg.data = packet.pack()
              action = of.ofp_action_output(port=self.routing_table2[str(dest_ip)][0])
              msg.actions.append(action)
              self.connection.send(msg)
              log.debug("ip packet move to host in network2")
          elif str(src_ip) in self.routing_table3:
              packet.src = packet.dst
              packet.dst = EthAddr(self.routing_table2[str(dest_ip)][1])
              msg = of.ofp_packet_out()
              msg.data = packet.pack()
              action = of.ofp_action_output(port = self.routing_table2[str(dest_ip)][0])
              msg.actions.append(action)
              self.connection.send(msg)
              log.debug("ip packet move to host in network2")
          else:
              log.debug("ip packet is unreachable in this network")
          
      elif str(dest_ip) in self.routing_table1:
          log.debug("packet move from %r to %r" % (packet.payload.srcip, packet.payload.dstip))
          packet.src = packet.dst
          packet.dst = adr.EthAddr("11:11:11:11:11:11")
          msg = of.ofp_packet_out()
          msg.data = packet.pack()
          action = of.ofp_action_output(port=4)
          msg.actions.append(action)
          self.connection.send(msg)
          log.debug("ip packet move to Router1")
      
      elif str(dest_ip) in self.routing_table3:
          log.debug("packet move from %r to %r" % (packet.payload.srcip, packet.payload.dstip))
          packet.src = packet.dst
          packet.dst = adr.EthAddr("33:33:33:33:33:33")
          msg = of.ofp_packet_out()
          msg.data = packet.pack()
          action = of.ofp_action_output(port=5)
          msg.actions.append(action)
          self.connection.send(msg)
          log.debug("ip packet move to Router3")
      else:
          log.debug("ip packet is unreachable in this network")

  # handle_ip3 is very similar with handle_ip1
  def handle_ip3(self, packet, packet_in):
      log.debug("Send ip packet, src ip: %r ,dest ip: %r" % (packet.payload.srcip,packet.payload.dstip))
      dest_ip = packet.payload.dstip
      src_ip = packet.payload.srcip
      if str(dest_ip) in self.routing_table3:
          if str(src_ip) in self.routing_table3:
              log.debug("ip packet is sent in local network3")
              msg = of.ofp_flow_mod()
              msg.match.dl_type = pkt.ethernet.IP_TYPE
              msg.match.dl_src = packet.src
              msg.match.dl_dst = packet.dst  
              msg.match.nw_src = packet.payload.srcip
              msg.match.nw_dst = packet.payload.dstip
              msg.match.in_port = packet_in.in_port
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=self.routing_table3[str(dest_ip)][0]))
              self.connection.send(msg)
          elif str(src_ip) in self.routing_table1:
              packet.src = packet.dst
              packet.dst = EthAddr(self.routing_table3[str(dest_ip)][1])
              msg = of.ofp_packet_out()
              msg.data = packet.pack()
              action = of.ofp_action_output(port = self.routing_table3[str(dest_ip)][0])
              msg.actions.append(action)
              self.connection.send(msg)
              log.debug("ip packet move to host in network3")
          elif str(src_ip) in self.routing_table2:
              packet.src = packet.dst
              packet.dst = EthAddr(self.routing_table3[str(dest_ip)][1])
              msg = of.ofp_packet_out()
              msg.data = packet.pack()
              action = of.ofp_action_output(port = self.routing_table3[str(dest_ip)][0])
              msg.actions.append(action)
              self.connection.send(msg)
              log.debug("ip packet move to host in network3")
          else:
              log.debug("ip packet is unreachable in this network")
          
      elif str(dest_ip) in self.routing_table1:
          log.debug("packet move from %r to %r" % (packet.payload.srcip, packet.payload.dstip))
          packet.src = packet.dst
          packet.dst = adr.EthAddr("11:11:11:11:11:11")
          msg = of.ofp_packet_out()
          msg.data = packet.pack()
          action = of.ofp_action_output(port=4)
          msg.actions.append(action)
          self.connection.send(msg)
          log.debug("ip packet move to Router1")
      
      elif str(dest_ip) in self.routing_table2:
          log.debug("packet move from %r to %r" % (packet.payload.srcip, packet.payload.dstip))
          packet.src = packet.dst
          packet.dst = adr.EthAddr("22:22:22:22:22:22")
          msg = of.ofp_packet_out()
          msg.data = packet.pack()
          action = of.ofp_action_output(port=5)
          msg.actions.append(action)
          self.connection.send(msg)
          log.debug("ip packet move to Router2")
      else:
          log.debug("ip packet is unreachable in this network")


  # https://github.com/Chuansssss/Mininet-Openflow-exercise/blob/master/bonus_flow_mod
  def act_like_router(self,event,packet_in):
      # Router 1
      if dpid_to_str(event.dpid) == "00-00-00-00-00-01":
          log.debug("Router1")
          packet = event.parsed
          # if this is arp packet
          if event.parsed.type == pkt.ethernet.ARP_TYPE:
              self.arp_request1(event.parsed, packet_in)

          # if this is ipv4 packet
          elif packet.type == pkt.ethernet.IP_TYPE:
              log.debug("Receiced ip packet, src ip: %r ,dest ip: %r" % (packet.payload.srcip, packet.payload.dstip))
              ipPkt = packet.payload
              ipDstAddr = ipPkt.dstip 
              ipSrcAddr = ipPkt.srcip

              # if this is icmp packet
              if ipPkt.protocol == pkt.ipv4.ICMP_PROTOCOL:
                  icmpPacket = ipPkt.payload   
                  if ipDstAddr.inNetwork("10.0.1.0/24"):
                      log.debug("Destination ip comes from the same network Router1")      
                      if ipSrcAddr.inNetwork("10.0.1.0/24"):
                          log.debug("In 10.0.1.0/24 network, act_like_switch")
                          self.switch1(packet,packet_in)
                      
                      elif ipSrcAddr.inNetwork("10.0.2.0/24"):
                          if str(ipDstAddr) in self.routing_table1:
                              packet.src = packet.dst
                              packet.dst = EthAddr(self.routing_table1[str(ipDstAddr)][1])
                              msg = of.ofp_packet_out()
                              msg.data = packet.pack()

                              action = of.ofp_action_output(port = self.routing_table1[str(ipDstAddr)][0])
                              msg.actions.append(action)
                              self.connection.send(msg)

                              log.debug("icmp move to host in network1")
                          elif str(ipDstAddr) in self.routing_table3:
                              packet.src = packet.dst
                              packet.dst = EthAddr(self.routing_table3[str(ipDstAddr)][1])
                              msg = of.ofp_packet_out()
                              msg.data = packet.pack()

                              action = of.ofp_action_output(port = self.routing_table3[str(ipDstAddr)][0])
                              msg.actions.append(action)
                              self.connection.send(msg)

                              log.debug("icmp move to host in network3")
                      
                      elif ipSrcAddr.inNetwork("10.0.3.0/24"):
                          if str(ipDstAddr) in self.routing_table1:
                              packet.src = packet.dst
                              packet.dst = EthAddr(self.routing_table1[str(ipDstAddr)][1])
                              msg = of.ofp_packet_out()
                              msg.data = packet.pack()

                              action = of.ofp_action_output(port = self.routing_table1[str(ipDstAddr)][0])
                              msg.actions.append(action)
                              self.connection.send(msg)

                              log.debug("icmp move to host in network1")
                          elif str(ipDstAddr) in self.routing_table2:
                              packet.src = packet.dst
                              packet.dst = EthAddr(self.routing_table2[str(ipDstAddr)][1])
                              msg = of.ofp_packet_out()
                              msg.data = packet.pack()

                              action = of.ofp_action_output(port = self.routing_table2[str(ipDstAddr)][0])
                              msg.actions.append(action)
                              self.connection.send(msg)

                              log.debug("icmp move to host in network2")                                                           
                          else:
                              self.handle_unreachable(packet, packet_in)
                              log.debug("Unreachable to host")

                      elif ipDstAddr == "10.0.1.1":
                          log.debug("icmp packet move to Router1")
                          if icmpPacket.type == pkt.TYPE_ECHO_REQUEST:
                              log.debug("Received icmp packet REQUEST")
                              log.debug("Destination ip: %r" % (ipDstAddr))
                              if str(ipSrcAddr) in self.routing_table1:
                                  log.debug("Reachable, icmp reply")
                                  self.handle_reachable(packet, packet_in)
                              elif str(ipSrcAddr) in self.routing_table2:
                                  log.debug("icmp packet REQUEST move to Router2")
                                  self.handle_reachable(packet, packet_in)
                              elif str(ipSrcAddr) in self.routing_table3:
                                  log.debug("icmp packet REQUEST move to Router3")
                                  self.handle_reachable(packet, packet_in)
                              else:
                                  log.debug("Unreachable")
                                  self.handle_unreachable(packet, packet_in)       

                  elif ipDstAddr.inNetwork("10.0.2.0/24"):
                      if ipSrcAddr.inNetwork("10.0.1.0/24"):
                          packet.src = packet.dst
                          packet.dst = adr.EthAddr("22:22:22:22:22:22")

                          msg = of.ofp_packet_out()
                          msg.data = packet.pack()

                          action = of.ofp_action_output(port = 4)
                          msg.actions.append(action)
                          self.connection.send(msg)
                          log.debug("packet move to Router2")
                      elif ipSrcAddr.inNetwork("10.0.3.0/24"):
                          packet.src = packet.dst
                          packet.dst = adr.EthAddr("22:22:22:22:22:22")

                          msg = of.ofp_packet_out()
                          msg.data = packet.pack()

                          action = of.ofp_action_output(port = 5)
                          msg.actions.append(action)
                          self.connection.send(msg)
                          log.debug("packet move to Router2")                        

                  elif ipDstAddr.inNetwork("10.0.3.0/24"):
                      if ipSrcAddr.inNetwork("10.0.1.0/24"):
                          packet.src = packet.dst
                          packet.dst = adr.EthAddr("33:33:33:33:33:33")

                          msg = of.ofp_packet_out()
                          msg.data = packet.pack()

                          action = of.ofp_action_output(port = 5)
                          msg.actions.append(action)
                          self.connection.send(msg)
                          log.debug("packet move to Router2")
                      elif ipSrcAddr.inNetwork("10.0.2.0/24"):
                          packet.src = packet.dst
                          packet.dst = adr.EthAddr("33:33:33:33:33:33")

                          msg = of.ofp_packet_out()
                          msg.data = packet.pack()

                          action = of.ofp_action_output(port = 5)
                          msg.actions.append(action)
                          self.connection.send(msg)
                          log.debug("packet move to Router3")                        
             
                  else:
                      self.handle_unreachable(packet, packet_in)
                      log.debug("Unreachable this network")
              else:
                  log.debug("not ICMP packet, it is a packet need to forward")
                  self.handle_ip1(packet, packet_in)                           
      # Router2
      elif dpid_to_str(event.dpid) == "00-00-00-00-00-02":
          log.debug("Router2")
          packet = event.parsed
          # if this is arp packet
          if event.parsed.type == pkt.ethernet.ARP_TYPE:
              self.arp_request2(event.parsed, packet_in)
          # if this is ipv4 packet
          elif packet.type == pkt.ethernet.IP_TYPE:
              log.debug("Received ipv4 packet, src ip: %r ,dest ip: %r" % (packet.payload.srcip, packet.payload.dstip))
              ipPkt = packet.payload
              ipDstAddr = ipPkt.dstip
              ipSrcAddr = ipPkt.srcip
              # if this is icmp packet
              if ipPkt.protocol == pkt.ipv4.ICMP_PROTOCOL:
                  icmpPacket = ipPkt.payload   
                  if ipDstAddr.inNetwork("10.0.2.0/24"):
                      log.debug("Destination ip comes from the same network of Router2")
                  
                      if ipSrcAddr.inNetwork("10.0.2.0/24"):
                          log.debug("In 10.0.2.0/24 network, act_like_switch")
                          self.switch2(packet,packet_in)
                      elif ipSrcAddr.inNetwork("10.0.1.0/24"):
                          if str(ipDstAddr) in self.routing_table2:
                              packet.src = packet.dst
                              packet.dst = EthAddr(self.routing_table2[str(ipDstAddr)][1])
                              log.debug("icmp REQUEST from Router1, ip address: %r" % (ipDstAddr))
                              log.debug("icmp REQUEST from Router1, mac address: %r" % (self.routing_table2[str(ipDstAddr)][1]))
                              msg = of.ofp_packet_out()
                              msg.data = packet.pack()

                              action = of.ofp_action_output(port = self.routing_table2[str(ipDstAddr)][0])
                              msg.actions.append(action)
                              self.connection.send(msg)

                              log.debug("icmp move to host in network2")
                          elif str(ipDstAddr) in self.routing_table3:
                              packet.src = packet.dst
                              packet.dst = EthAddr(self.routing_table3[str(ipDstAddr)][1])
                              log.debug("icmp REQUEST from Router1, ip address: %r" % (ipDstAddr))
                              log.debug("icmp REQUEST from Router1, mac address: %r" % (self.routing_table3[str(ipDstAddr)][1]))
                              msg = of.ofp_packet_out()
                              msg.data = packet.pack()

                              action = of.ofp_action_output(port = self.routing_table3[str(ipDstAddr)][0])
                              msg.actions.append(action)
                              self.connection.send(msg)

                              log.debug("icmp move to host in network3")
                      elif ipSrcAddr.inNetwork("10.0.3.0/24"):
                          if str(ipDstAddr) in self.routing_table1:
                              packet.src = packet.dst
                              packet.dst = EthAddr(self.routing_table1[str(ipDstAddr)][1])
                              log.debug("icmp REQUEST from Router1, ip address: %r" % (ipDstAddr))
                              log.debug("icmp REQUEST from Router1, mac address: %r" % (self.routing_table1[str(ipDstAddr)][1]))
                              msg = of.ofp_packet_out()
                              msg.data = packet.pack()

                              action = of.ofp_action_output(port = self.routing_table1[str(ipDstAddr)][0])
                              msg.actions.append(action)
                              self.connection.send(msg)

                              log.debug("icmp move to host in network1")
                          elif str(ipDstAddr) in self.routing_table2:
                              packet.src = packet.dst
                              packet.dst = EthAddr(self.routing_table2[str(ipDstAddr)][1])
                              log.debug("icmp REQUEST from Router1, ip address: %r" % (ipDstAddr))
                              log.debug("icmp REQUEST from Router1, mac address: %r" % (self.routing_table2[str(ipDstAddr)][1]))
                              msg = of.ofp_packet_out()
                              msg.data = packet.pack()

                              action = of.ofp_action_output(port = self.routing_table2[str(ipDstAddr)][0])
                              msg.actions.append(action)
                              self.connection.send(msg)

                              log.debug("icmp move to host in network2")                                                          
                          else:
                              self.handle_unreachable(packet, packet_in)
                              log.debug("Unreachable host in network2")
                      
                      elif ipDstAddr == "10.0.2.1":
                          log.debug("icmp packet move to Router2")
                          if icmpPacket.type == pkt.TYPE_ECHO_REQUEST:
                              log.debug("Received icmp packet REQUEST")
                              log.debug("Destination ip is %r"%(ipDstAddr))
                              if str(ipSrcAddr) in self.routing_table2:
                                  log.debug("Reachable, icmp reply")
                                  self.handle_reachable(packet, packet_in)
                              elif str(ipSrcAddr) in self.routing_table1:
                                  log.debug("icmp packet REQUEST move to Router1")
                                  self.handle_reachable(packet, packet_in)
                              elif str(ipSrcAddr) in self.routing_table3:
                                  log.debug("icmp packet REQUEST move to Router3")
                                  self.handle_reachable(packet, packet_in)
                              else:
                                  log.debug("Unreachable")
                                  self.handle_unreachable(packet, packet_in)

                  elif ipDstAddr.inNetwork("10.0.1.0/24"):
                      if ipSrcAddr.inNetwork("10.0.2.0/24"):
                          packet.src = packet.dst
                          packet.dst = adr.EthAddr("11:11:11:11:11:11")

                          msg = of.ofp_packet_out()
                          msg.data = packet.pack()

                          action = of.ofp_action_output(port = 4)
                          msg.actions.append(action)
                          self.connection.send(msg)
                          log.debug("packet move to Router1")
                      elif ipSrcAddr.inNetwork("10.0.3.0/24"):
                          packet.src = packet.dst
                          packet.dst = adr.EthAddr("11:11:11:11:11:11")

                          msg = of.ofp_packet_out()
                          msg.data = packet.pack()

                          action = of.ofp_action_output(port = 4)
                          msg.actions.append(action)
                          self.connection.send(msg)
                          log.debug("packet move to Router1")
                      else:
                          pass
                  elif ipDstAddr.inNetwork("10.0.3.0/24"):
                      if ipSrcAddr.inNetwork("10.0.1.0/24"):
                          packet.src = packet.dst
                          packet.dst = adr.EthAddr("33:33:33:33:33:33")

                          msg = of.ofp_packet_out()
                          msg.data = packet.pack()

                          action = of.ofp_action_output(port = 5)
                          msg.actions.append(action)
                          self.connection.send(msg)
                          log.debug("packet move to Router2")
                      elif ipSrcAddr.inNetwork("10.0.2.0/24"):
                          packet.src = packet.dst
                          packet.dst = adr.EthAddr("33:33:33:33:33:33")

                          msg = of.ofp_packet_out()
                          msg.data = packet.pack()

                          action = of.ofp_action_output(port = 5)
                          msg.actions.append(action)
                          self.connection.send(msg)                                           
                  else:
                      self.handle_unreachable(packet, packet_in)
                      log.debug("Unreachable network")
              else:
                  self.handle_ip2(packet, packet_in)         
      # Router 3
      elif dpid_to_str(event.dpid) == "00-00-00-00-00-03":
          log.debug("Router3")
          packet = event.parsed
          # if this is arp packet
          if event.parsed.type == pkt.ethernet.ARP_TYPE:
              self.arp_request3(event.parsed, packet_in)
          # if this is ipv4 packet
          elif packet.type == pkt.ethernet.IP_TYPE:
              log.debug("Received ipv4 packet, src ip: %r ,dest ip: %r" % (packet.payload.srcip, packet.payload.dstip))
              ipPkt = packet.payload
              ipDstAddr = ipPkt.dstip
              ipSrcAddr = ipPkt.srcip
              # if this is icmp packet
              if ipPkt.protocol == pkt.ipv4.ICMP_PROTOCOL:
                  icmpPacket = ipPkt.payload   
                  if ipDstAddr.inNetwork("10.0.3.0/24"):
                      log.debug("Destination ip comes from the same network of Router3")
                                        
                      if ipSrcAddr.inNetwork("10.0.3.0/24"):
                          log.debug("in 10.0.3.0/24 network, act_like_switch")
                          self.switch3(packet,packet_in)

                      elif ipSrcAddr.inNetwork("10.0.1.0/24"):
                          if str(ipDstAddr) in self.routing_table2:
                              packet.src = packet.dst
                              packet.dst = EthAddr(self.routing_table2[str(ipDstAddr)][1])
                              log.debug("icmp REQUEST from Router1, ip address: %r" % (ipDstAddr))
                              log.debug("icmp REQUEST from Router1, mac address: %r" % (self.routing_table2[str(ipDstAddr)][1]))
                              msg = of.ofp_packet_out()
                              msg.data = packet.pack()

                              action = of.ofp_action_output(port = self.routing_table2[str(ipDstAddr)][0])
                              msg.actions.append(action)
                              self.connection.send(msg)

                              log.debug("icmp packet move to host in network2")
                          elif str(ipDstAddr) in self.routing_table3:
                              packet.src = packet.dst
                              packet.dst = EthAddr(self.routing_table3[str(ipDstAddr)][1])
                              log.debug("icmp REQUEST from Router1, ip address: %r" % (ipDstAddr))
                              log.debug("icmp REQUEST from Router1, mac address: %r" % (self.routing_table3[str(ipDstAddr)][1]))
                              msg = of.ofp_packet_out()
                              msg.data = packet.pack()

                              action = of.ofp_action_output(port = self.routing_table3[str(ipDstAddr)][0])
                              msg.actions.append(action)
                              self.connection.send(msg)

                              log.debug("icmp packet move to host in network3")
                      elif ipSrcAddr.inNetwork("10.0.2.0/24"):
                          if str(ipDstAddr) in self.routing_table1:
                              packet.src = packet.dst
                              packet.dst = EthAddr(self.routing_table1[str(ipDstAddr)][1])
                              log.debug("icmp REQUEST from Router1, ip address: %r" % (ipDstAddr))
                              log.debug("icmp REQUEST from Router1, mac address: %r" % (self.routing_table1[str(ipDstAddr)][1]))
                              msg = of.ofp_packet_out()
                              msg.data = packet.pack()

                              action = of.ofp_action_output(port = self.routing_table1[str(ipDstAddr)][0])
                              msg.actions.append(action)
                              self.connection.send(msg)

                              log.debug("icmp packet move to host in network1")
                          elif str(ipDstAddr) in self.routing_table3:
                              packet.src = packet.dst
                              packet.dst = EthAddr(self.routing_table3[str(ipDstAddr)][1])
                              log.debug("icmp REQUEST from Router1, ip address: %r" % (ipDstAddr))
                              log.debug("icmp REQUEST from Router1, mac address: %r" % (self.routing_table3[str(ipDstAddr)][1]))
                              msg = of.ofp_packet_out()
                              msg.data = packet.pack()

                              action = of.ofp_action_output(port = self.routing_table3[str(ipDstAddr)][0])
                              msg.actions.append(action)
                              self.connection.send(msg)

                              log.debug("icmp packet move to host in network3")                                                          
                          else:
                              self.handle_unreachable(packet, packet_in)
                              log.debug("Unreachable")

                      elif ipDstAddr == "10.0.3.1":
                          log.debug("icmp packet move to Router3")
                          if icmpPacket.type == pkt.TYPE_ECHO_REQUEST:
                              log.debug("Received icmp packet REQUEST")
                              log.debug("Destination ip is %r" % (ipDstAddr))
                              if str(ipSrcAddr) in self.routing_table3:
                                  log.debug("Reachable, icmp reply")
                                  self.handle_reachable(packet, packet_in)
                              elif str(ipSrcAddr) in self.routing_table1:
                                  log.debug("icmp packet REQUEST move to Router1")
                                  self.handle_reachable(packet, packet_in)
                              elif str(ipSrcAddr) in self.routing_table2:
                                  log.debug("icmp packet REQUEST move to Router3")
                                  self.handle_reachable(packet, packet_in)
                              else:
                                  log.debug("Unreachable")
                                  self.handle_unreachable(packet, packet_in)

                  elif ipDstAddr.inNetwork("10.0.1.0/24"):
                      if ipSrcAddr.inNetwork("10.0.2.0/24"):
                          packet.src = packet.dst
                          packet.dst = adr.EthAddr("11:11:11:11:11:11")

                          msg = of.ofp_packet_out()
                          msg.data = packet.pack()

                          action = of.ofp_action_output(port = 4)
                          msg.actions.append(action)
                          self.connection.send(msg)
                      elif ipSrcAddr.inNetwork("10.0.3.0/24"):
                          packet.src = packet.dst
                          packet.dst = adr.EthAddr("11:11:11:11:11:11")

                          msg = of.ofp_packet_out()
                          msg.data = packet.pack()

                          action = of.ofp_action_output(port = 4)
                          msg.actions.append(action)
                          self.connection.send(msg)

                  elif ipDstAddr.inNetwork("10.0.2.0/24"):
                      if ipSrcAddr.inNetwork("10.0.1.0/24"):
                          packet.src = packet.dst
                          packet.dst = adr.EthAddr("22:22:22:22:22:22")

                          msg = of.ofp_packet_out()
                          msg.data = packet.pack()

                          action = of.ofp_action_output(port = 4)
                          msg.actions.append(action)
                          self.connection.send(msg)
                      elif ipSrcAddr.inNetwork("10.0.3.0/24"):
                          packet.src = packet.dst
                          packet.dst = adr.EthAddr("22:22:22:22:22:22")

                          msg = of.ofp_packet_out()
                          msg.data = packet.pack()

                          action = of.ofp_action_output(port = 5)
                          msg.actions.append(action)
                          self.connection.send(msg)                       
                  
                  else:
                      self.handle_unreachable(packet, packet_in)
                      log.debug("Unreachable network")
              else:
                  self.handle_ip2(packet, packet_in)                               
          

  def _handle_PacketIn (self, event):
      packet = event.parsed
      if not packet.parsed:
          log.warning("Ignoring incomplete packet")
          return
      packet_in = event.ofp
      self.act_like_router(event,packet_in)


def launch ():
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Controller4(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)