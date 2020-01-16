from pox.core import core
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import struct

log = core.getLogger()
Valid_IP = ['10.0.1.1', '10.0.1.100', '10.0.2.1', '10.0.2.100', '10.0.3.1', '10.0.3.100']

class Controller (object):
    
    def __init__ (self, connection):
        self.connection = connection
        connection.addListeners(self)
        self.interface = [IPAddr('10.0.1.1'), IPAddr('10.0.2.1'), IPAddr('10.0.3.1')]
        self.routingtable = {} # map IP to port
        self.arptable = {}
        self.arpwait = {}
     
    """
    This function is to create an ethernet packet
    """
    def create_eth_packet (self, packet_type, src, dst, payload):
        eth_pkt = pkt.ethernet()
        eth_pkt.type = packet_type
        eth_pkt.src = src
        eth_pkt.dst = dst
        eth_pkt.payload = payload
        return eth_pkt 

    """
    This function is to create an IP packet
    """
    def create_ip_packet (self, src, dst, icmp_pkt):
        ip_pkt = pkt.ipv4()
        ip_pkt.srcip = src
        ip_pkt.dstip = dst
        ip_pkt.protocol = pkt.ipv4.ICMP_PROTOCOL
        ip_pkt.payload = icmp_pkt
        return ip_pkt
 
    """
    This function is to create an ICMP packet
    """
    def create_icmp_packet (self, icmp_type, payload):
        icmp_pkt = pkt.icmp()
        icmp_pkt.type = icmp_type
        icmp_pkt.payload = payload
        return icmp_pkt

    """
    This function is to handle ICMP request, and send out the reply to router
    """
    def send_icmp_request (self, icmp_type, packet, srcip, dstip):
        if icmp_type == pkt.TYPE_ECHO_REPLY:
            icmp_pkt = self.create_icmp_packet(icmp_type, packet.find('icmp').payload)
        elif icmp_type == pkt.TYPE_DEST_UNREACH:
            orig_ip = packet.find('ipv4')
            icmp_payload = orig_ip.pack()
            icmp_payload = icmp_payload[:orig_ip.hl * 4 + 8]
            icmp_payload = struct.pack("!HH", 0, 0) + icmp_payload
            icmp_pkt = self.create_icmp_packet(pkt.TYPE_DEST_UNREACH, icmp_payload)

        ip_pkt = self.create_ip_packet(dstip, srcip, icmp_pkt)
        eth_pkt = self.create_eth_packet(pkt.ethernet.IP_TYPE, packet.dst, packet.src, ip_pkt)
        msg = of.ofp_packet_out()
        msg.match = of.ofp_match.from_packet(eth_pkt)
        msg.data = packet.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.in_port = self.routingtable[srcip]
        self.connection.send(msg)
        log.debug('IP %s pings router at %s, sending ICMP reply'% (str(srcip), str(dstip)))
        return


    """
    This function is to handle ARP request and when it not belongs to the subnet then forward it to the next hop
    """
    def forward_arp_request (self, packet, packet_in, arp_pkt):
        # Read ARP packets
        rt = pkt.arp()
        rt.hwtype = rt.HW_TYPE_ETHERNET
        rt.hwlen = 6
        rt.hwsrc = packet.src
        rt.hwdst = ETHER_BROADCAST
        rt.prototype = rt.PROTO_TYPE_IP
        rt.opcode = rt.REQUEST
        rt.protolen = rt.protolen
        rt.protosrc = self.interface[packet_in.in_port - 1]
        rt.protodst = arp_pkt.dstip
        
        # Examine ARP packets paths and send out request
        eth_pkt = self.create_eth_packet(pkt.ethernet.ARP_TYPE, packet.src, ETHER_BROADCAST, rt)
        log.debug('ARP request: From port %d, sending out ARP request for IP %s from %s' % (packet_in.in_port, str(rt.protodst), str(rt.protosrc)))
        msg = of.ofp_packet_out()
        msg.data = eth_pkt.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connection.send(msg)


    """
    This function is to send an ARP reply to the ARP request packet
    """
    def send_arp_reply (self, arp_pkt, packet_in):
        rt = arp()
        rt.hwtype = arp_pkt.hwtype
        rt.hwlen = arp_pkt.hwlen
        rt.hwdst = arp_pkt.hwsrc
        rt.hwsrc = self.arptable[arp_pkt.protodst]
        rt.opcode = arp.REPLY
        rt.prototype = arp_pkt.prototype
        rt.protolen = arp_pkt.protolen
        rt.protodst = arp_pkt.protosrc
        rt.protosrc = arp_pkt.protodst

        eth_pkt = self.create_eth_packet(pkt.ethernet.ARP_TYPE, self.arptable[arp_pkt.protodst], arp_pkt.hwsrc, rt)
        log.debug('ARP reply: From port %d, replying for ARP request from %s: MAC for IP %s is %s' % (packet_in.in_port, str(arp_pkt.protosrc), str(arp_pkt.protodst), str(self.arptable[arp_pkt.protodst])))
        msg = of.ofp_packet_out()
        msg.data = eth_pkt.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.in_port = packet_in.in_port
        self.connection.send(msg)


    """
    This function is to form a waitlist for ARP packets
    when dst MAC is known, sending a packet out
    """
    def handle_arp_wait (self, srcip):
        log.debug('Pending ARP packet for IP %s in ARP waitlist' % (str(srcip)))
        while len(self.arpwait[srcip]) > 0:
            (b_id, in_port) = self.arpwait[srcip][0]
            msg = of.ofp_packet_out(buffer_id = b_id, in_port = in_port)
            msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arptable[srcip]))
            out_port = self.routingtable[srcip]
            msg.actions.append(of.ofp_action_output(port = out_port))
            self.connection.send(msg)
            log.debug("Sending waiting ARP packet, destination IP: %s, destination MAC: %s, output port: %d" % (str(srcip), str(self.arptable[srcip]), self.routingtable[srcip]))
            del self.arpwait[srcip][0]


    """
    This function is to handle ARP packet
    """
    def handle_arp_packet (self, arp_pkt, packet_in):
        log.debug("Receive ARP packet from port %d, ARP from IP %s to %s" %(packet_in.in_port, str(arp_pkt.protosrc), str(arp_pkt.protodst)))
        if arp_pkt.prototype == arp.PROTO_TYPE_IP:
            if (arp_pkt.hwtype == arp.HW_TYPE_ETHERNET) and (arp_pkt.protosrc != 0):
                if arp_pkt.protosrc not in self.arptable:
                    # Add to arptable if no in record
                    self.arptable[arp_pkt.protosrc] = arp_pkt.hwsrc
                    log.debug('Added to arptable: IP %s, MAC %s' % (str(arp_pkt.protosrc), str(arp_pkt.hwsrc)))
                # Waiting line is not empty
                if (arp_pkt.protosrc in self.arpwait) and (len(self.arpwait[arp_pkt.protosrc]) != 0):   
                    self.handle_arp_wait(arp_pkt.protosrc)
                if (arp_pkt.opcode == arp.REQUEST) and (arp_pkt.protodst in self.interface): 
                    self.send_arp_reply(arp_pkt, packet_in)
        else:
            log.error("Invalid ARP request")
        return

    # Reference: https://github.com/noxrepo/pox/blob/carp/pox/forwarding/l3_learning.py
    def handle_ip_packet (self, packet, ip_pkt, packet_in):
        # if the packet is destined to router
        if ip_pkt.dstip in self.interface:
            if (ip_pkt.next.type == pkt.TYPE_ECHO_REQUEST):
                log.debug('ICMP packet to router')
                self.send_icmp_request(pkt.TYPE_ECHO_REPLY, packet, ip_pkt.srcip, ip_pkt.dstip)
        else:
            # if not in record, cache the packet into arp waitlist and broadcast ARP request
            if (ip_pkt.dstip not in self.routingtable) or (ip_pkt.dstip not in self.arptable):
                if ip_pkt.dstip not in self.arpwait:
                    self.arpwait[ip_pkt.dstip] = []
                entry = (packet_in.buffer_id, packet_in.in_port)
                self.arpwait[ip_pkt.dstip].append(entry)
                log.debug('Packet %s to %s, add in ARP waitlist and send broadcast' % (str(ip_pkt.srcip), str(ip_pkt.dstip)))
                self.forward_arp_request(packet, packet_in, ip_pkt)
            else:
                msg = of.ofp_packet_out(buffer_id = packet_in.buffer_id, in_port = packet_in.in_port)
                msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arptable[ip_pkt.dstip]))
                msg.actions.append(of.ofp_action_output(port = self.routingtable[ip_pkt.dstip]))
                self.connection.send(msg)
                log.debug('Packet %s to %s through port %d'% (str(ip_pkt.srcip), str(ip_pkt.dstip), self.routingtable[ip_pkt.dstip]))
                msg = of.ofp_flow_mod()
                msg.match.dl_type = 0x800
                msg.match.nw_dst = ip_pkt.dstip
                msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arptable[ip_pkt.dstip]))
                msg.actions.append(of.ofp_action_output(port = self.routingtable[ip_pkt.dstip]))
                self.connection.send(msg)

    """
    This function is used to define the rules of layer-3 switch
    """
    def act_like_router (self, packet, packet_in):
        # ARP packet  
        if isinstance(packet.next, arp):
            arp_pkt = packet.next
            # add to routingtable if not in record
            if arp_pkt.protosrc not in self.routingtable:
                self.routingtable[arp_pkt.protosrc] = packet_in.in_port
                log.debug('Added IP %s, port %d into routingtable' % (str(arp_pkt.protosrc), packet_in.in_port))

            if arp_pkt.protodst not in Valid_IP:
                # if dest ip is not within the network scope
                log.warning("IP address %s is invalid" % arp_pkt.protodst)
                self.send_icmp_request(pkt.TYPE_DEST_UNREACH, packet, arp_pkt.protosrc, arp_pkt.protodst)
                return
            self.handle_arp_packet(arp_pkt, packet_in)

        # IP packet        
        elif isinstance(packet.next, ipv4):
            ip_pkt = packet.next
            log.debug("Received IPv4 packet from %s trying to reach %s" % (ip_pkt.srcip, ip_pkt.dstip))
            # add to routingtable if not in record
            if ip_pkt.srcip not in self.routingtable:
                self.routingtable[ip_pkt.srcip] = packet_in.in_port
                log.debug('Added IP %s, port %d into routingtable' % (str(ip_pkt.srcip), packet_in.in_port))

            if ip_pkt.dstip not in Valid_IP:
                # if dest ip is not within the network scope
                log.warning("IP address %s is invalid" % ip_pkt.dstip)
                self.send_icmp_request(pkt.TYPE_DEST_UNREACH, packet, ip_pkt.srcip, ip_pkt.dstip)
                return
            self.handle_ip_packet(packet, ip_pkt, packet_in)
            


    """
    This function is used to handle packets in messages from layer-3 switch
    Reference: https://github.com/Chuansssss/Mininet-Openflow-exercise
    """                    
    def _handle_PacketIn (self, event):
        packet_in = event.ofp # The actual ofp_packet_in message.
        packet = event.parsed # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Incomplete packet")
            return

        # Generate MAC address for each interface of layer-3 switch
        for i in self.interface:
            self.arptable[i] = EthAddr("%012x" % (event.dpid & 0xffffffffffff | 0x0000000000f0,))
      
        self.act_like_router(packet, packet_in)
          

def launch ():
    """
    Starts the component
    """
    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        Controller(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
