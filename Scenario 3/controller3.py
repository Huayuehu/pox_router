from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, EthAddr
import struct
import time

log = core.getLogger()
DEFAULT_GATEWAY = 1
Valid_IP = [IPAddr('10.0.1.1'), IPAddr('10.0.1.2'), IPAddr('10.0.1.3'), IPAddr('10.0.2.1'), IPAddr('10.0.2.2')]
subnet1 = ['10.0.1.1', '10.0.1.2', '10.0.1.3']
subnet2 = ['10.0.2.1', '10.0.2.2']

class Controller (object):
    def __init__(self):
        log.debug('Router registered')
        self.arptable = {}
        self.arpwait = {}
        self.routingtable = {}
        self.connections = {}
        self.routerIP = {}
        core.openflow.addListeners(self)

    def _handle_GoingUpEvent(self, event):
        self.listenTo(core.openflow)
        log.debug("Router up")

    def _handle_ConnectionUp(self, event):
        log.debug("Connection %d is up" % event.dpid)
        dpid = event.dpid
        if dpid not in self.connections:
            self.connections[dpid] = event.connection
        if dpid not in self.arptable:
            self.arptable[dpid] = {}
        if dpid not in self.routingtable:
            self.routingtable[dpid] = {}
        if dpid not in self.arpwait:
            self.arpwait[dpid] = {}
        ip = IPAddr('10.0.%d.1' % dpid)
        mac = EthAddr("%012x" % (event.dpid & 0xffffffffffff | 0x0000000000f0,))
        self.routerIP[dpid] = ip
        self.arptable[dpid][ip] = mac
        log.debug("Router %d: adding MAC %s, IP %s as router" % (dpid, mac, ip))
        if len(self.routerIP) == 2:
            self.forward_arp_request(ip, IPAddr('10.0.%d.1' %(3 - event.dpid)), mac, of.OFPP_FLOOD, dpid)

    def _handle_ConnectionDown(self, event):
        log.debug("Connection %d is down" % event.dpid)
        if event.dpid in self.arptable:
            del self.arptable[event.dpid]
        if event.dpid in self.routingtable:
            del self.routingtable[event.dpid]
        if event.dpid in self.connections:
            del self.connections[event.dpid]
        if event.dpid in self.arpwait:
            del self.arpwait[event.dpid]
        if event.dpid in self.routerIP:
            del self.routerIP[event.dpid]

    def send_packet(self, dpid, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port = out_port)
        msg.actions.append(action)
        self.connections[dpid].send(msg)

    def create_ip_packet (self, src, dst, icmp_pkt):
        ip_pkt = pkt.ipv4()
        ip_pkt.srcip = src
        ip_pkt.dstip = dst
        ip_pkt.protocol = pkt.ipv4.ICMP_PROTOCOL
        ip_pkt.payload = icmp_pkt
        return ip_pkt
 
    def create_echo_reply (self, icmp_payload):       
        echo = pkt.echo()
        echo.seq = icmp_payload.seq + 1
        echo.id = icmp_payload.id
        return echo
    
    def create_echo_unreach (self, icmp_payload):       
        echo = pkt.unreach()
        echo.payload = icmp_payload
        return echo

    def create_icmp_packet (self, icmp_type, payload):
        icmp_pkt = pkt.icmp()
        icmp_pkt.type = icmp_type
        icmp_pkt.payload = payload
        return icmp_pkt

    def send_icmp_request(self, dpid, p, srcip, dstip, icmp_type): 
        ip_pkt = p.next
        if icmp_type == pkt.TYPE_ECHO_REPLY:
            echo_reply = self.create_echo_reply(ip_pkt.payload.payload)
            icmp_pkt = self.create_icmp_packet(pkt.TYPE_ECHO_REPLY, echo_reply)
        elif icmp_type == pkt.TYPE_DEST_UNREACH:
            echo_unreach = self.create_echo_unreach(ip_pkt.payload.payload)
            icmp_pkt = self.create_icmp_packet(pkt.TYPE_DEST_UNREACH, echo_unreach)

        e = ethernet()
        e.src = p.dst    
        ip_req = self.create_ip_packet(dstip, srcip, icmp_pkt)
        if (srcip in subnet1 and self.routerIP[dpid] in subnet1) or (srcip in subnet2 and self.routerIP[dpid] in subnet2):
            e.dst = p.src
        else:
            gatewayip = IPAddr('10.0.%d.1' % (3 - dpid))
            e.dst = self.arptable[dpid][gatewayip]
        e.type = e.IP_TYPE
        ip_req.payload = icmp_pkt
        e.payload = ip_req

        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.data = e.pack()
        msg.in_port = self.routingtable[dpid][srcip]
        self.connections[dpid].send(msg)
        log.debug("Router %d: IP %s pings router at %s, sending ICMP reply" % (dpid, str(srcip), str(dstip)))

    def handle_arp_wait(self, protosrc, dpid):
        log.debug("Router %d: Processing ARP packet for IP %s in ARP waitlist" % (dpid, str(protosrc)))
        while len(self.arpwait[dpid][protosrc]) > 0:
            (b_id, inport) = self.arpwait[dpid][protosrc][0]
            msg = of.ofp_packet_out(buffer_id = b_id, in_port = inport)
            msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arptable[dpid][protosrc]))
            msg.actions.append(of.ofp_action_output(port = self.routingtable[dpid][protosrc]))
            self.connections[dpid].send(msg)
            log.debug("Router %d: Sending waiting ARP packet to IP: %s, MAC: %s" % (dpid, str(protosrc), str(self.arptable[dpid][protosrc])))
            del self.arpwait[dpid][protosrc][0]

    def send_arp_reply(self, arp_pkt, inport, dpid):
        rt = arp()
        rt.hwtype = arp_pkt.hwtype
        rt.hwlen = arp_pkt.hwlen
        rt.hwdst = arp_pkt.hwsrc
        rt.hwsrc = self.arptable[dpid][arp_pkt.protodst]
        rt.opcode = arp.REPLY
        rt.prototype = arp_pkt.prototype
        rt.protolen = arp_pkt.protolen
        rt.protodst = arp_pkt.protosrc
        rt.protosrc = arp_pkt.protodst

        e = ethernet(type = ethernet.ARP_TYPE, src = self.arptable[dpid][arp_pkt.protodst], dst = arp_pkt.hwsrc)
        e.set_payload(rt)
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.in_port = inport
        log.debug("Router %d: replying for ARP request from %s: MAC for IP %s is %s" % (dpid, str(arp_pkt.protosrc), str(rt.protosrc), str(rt.hwsrc)))
        self.connections[dpid].send(msg)

    def forward_arp_request(self, srcip, dstip, srcmac, inport, dpid):
        rt = arp()
        rt.hwtype = rt.HW_TYPE_ETHERNET
        rt.hwlen = 6
        rt.hwsrc = srcmac
        rt.hwdst = ETHER_BROADCAST
        rt.opcode = rt.REQUEST
        rt.prototype = rt.PROTO_TYPE_IP
        rt.protolen = rt.protolen
        rt.protosrc = srcip 
        rt.protodst = dstip
        
        e = ethernet(type = ethernet.ARP_TYPE, src = srcmac, dst = ETHER_BROADCAST)
        e.set_payload(rt)
        log.debug("Router %d: Sending out ARP request for IP %s from %s, port %d," % (dpid, str(rt.protodst), str(rt.protosrc), inport))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connections[dpid].send(msg)

    def handle_arp_packet(self, a, inport, dpid, packet_in):
        log.debug("Router %d: ARP packet, inport %d, ARP from IP %s to %s" % (dpid, inport, str(a.protosrc), str(a.protodst)))
        if a.prototype == arp.PROTO_TYPE_IP:
            if (a.hwtype == arp.HW_TYPE_ETHERNET) and (a.protosrc != 0):
                if a.protosrc not in self.arptable[dpid]:
                    self.arptable[dpid][a.protosrc] = a.hwsrc
                    log.debug("Router %d: Added IP %s, MAC %s into arptable" % (dpid, str(a.protosrc), str(a.hwsrc)))
                    if (a.protosrc in self.arpwait[dpid]) and (len(self.arpwait[dpid][a.protosrc]) > 0):
                        self.handle_arp_wait(a.protosrc, dpid)
                if a.opcode == arp.REQUEST:
                    if str(a.protodst) == str(self.routerIP[dpid]):
                        self.send_arp_reply(a, inport, dpid)
                    else:
                        self.send_packet(dpid, packet_in, of.OFPP_FLOOD)
                elif a.opcode == arp.REPLY and a.protodst != IPAddr('10.0.%d.1' % (dpid)):
                    self.send_packet(dpid, packet_in, self.routingtable[dpid][a.protodst])
        else:
            log.debug("Router %d: Unkown ARP request, flooding")
            self.send_packet(dpid, packet_in, of.OFPP_FLOOD)   

    # Reference: https://github.com/noxrepo/pox/blob/carp/pox/forwarding/l3_learning.py
    def handle_ip_packet (self, packet, ip_pkt, inport, dpid, packet_in):
        # if dst ip is not within the network scope
            if ip_pkt.dstip not in Valid_IP:
                log.error("IP address %s is invalid" % ip_pkt.dstip)
                self.send_icmp_request(dpid, packet, ip_pkt.srcip, ip_pkt.dstip, pkt.TYPE_DEST_UNREACH)
                return
            # if the packet is destined to router in the same subnet
            if str(ip_pkt.dstip) == str(self.routerIP[dpid]):
                if isinstance(ip_pkt.next, icmp):
                    log.debug("ICMP packet to router")
                    if ip_pkt.next.type == pkt.TYPE_ECHO_REQUEST:
                        self.send_icmp_request(dpid, packet, ip_pkt.srcip, ip_pkt.dstip, pkt.TYPE_ECHO_REPLY)
            # if src and dst are in different subnets: forward to next switch
            elif (ip_pkt.dstip in subnet1 and self.routerIP[dpid] in subnet2) or (ip_pkt.dstip in subnet2 and self.routerIP[dpid] in subnet1):
                nextip = IPAddr('10.0.%d.1' % (3 - dpid))
                nextMAC = self.arptable[dpid][nextip]
                msg = of.ofp_packet_out(buffer_id = packet_in.buffer_id, in_port = inport)
                msg.actions.append(of.ofp_action_dl_addr.set_dst(nextMAC))
                msg.actions.append(of.ofp_action_output(port = 1))
                self.connections[dpid].send(msg)
                log.debug('Router %d: Packet from %s to %s, different subnet, send to port %d' % (dpid, str(ip_pkt.srcip),str(ip_pkt.dstip), 1))

                msg = of.ofp_flow_mod()
                msg.match.dl_type = 0x800
                msg.match.nw_dst = ip_pkt.dstip
                msg.actions.append(of.ofp_action_dl_addr.set_dst(nextMAC))
                msg.actions.append(of.ofp_action_output(port = 1))
                self.connections[dpid].send(msg)
            # if src and dst are in the same subnet
            else:
                # unknown dstip: FLOOD ARP request to ask
                if ip_pkt.dstip not in self.routingtable[dpid] or ip_pkt.dstip not in self.arptable[dpid]:
                    if ip_pkt.dstip not in self.arpwait[dpid]:
                        self.arpwait[dpid][ip_pkt.dstip] = []
                    entry = (packet_in.buffer_id, inport)
                    self.arpwait[dpid][ip_pkt.dstip].append(entry)
                    log.debug("Router %d: Packet from %s to %s, added to arpwait, broadcast ARP request" % (dpid, str(ip_pkt.srcip), str(ip_pkt.dstip)))
                    self.forward_arp_request(ip_pkt.srcip, ip_pkt.dstip, packet.src, inport, dpid)
                # known dstip
                else:
                    msg = of.ofp_packet_out(buffer_id = packet_in.buffer_id, in_port = inport)
                    msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arptable[dpid][ip_pkt.dstip]))
                    msg.actions.append(of.ofp_action_output(port = self.routingtable[dpid][ip_pkt.dstip]))
                    self.connections[dpid].send(msg)
                    log.debug('Router %d: Packet from %s to %s, same subnet, send to port %d' % (dpid, str(ip_pkt.srcip),str(ip_pkt.dstip), self.routingtable[dpid][ip_pkt.dstip]))

                    msg = of.ofp_flow_mod()
                    msg.match.dl_type = 0x800
                    msg.match.nw_dst = ip_pkt.dstip
                    msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arptable[dpid][ip_pkt.dstip]))
                    msg.actions.append(of.ofp_action_output(port = self.routingtable[dpid][ip_pkt.dstip]))
                    self.connections[dpid].send(msg)


    def act_like_router (self, packet, packet_in, inport, dpid):
        # IP packet 
        if isinstance(packet.next, ipv4):
            ip_pkt = packet.next
            log.debug("Router %d: Receive IPv4 packet from %s trying to reach %s" % (dpid, packet.next.srcip, packet.next.dstip))
            if ip_pkt.srcip not in self.routingtable[dpid]:
                self.routingtable[dpid][ip_pkt.srcip] = inport
                log.debug('Router %d: Added IP %s, port %d into routingtable' % (dpid, str(ip_pkt.srcip), inport))
            else:
                log.debug('Router %d: IP %s, port %d already exists in routingtabe' % (dpid, str(ip_pkt.srcip), inport))
            self.handle_ip_packet (packet, ip_pkt, inport, dpid, packet_in)
        # ARP packet 
        elif isinstance(packet.next, arp):
            arp_pkt = packet.next
            if arp_pkt.protosrc not in self.routingtable[dpid]:
                self.routingtable[dpid][arp_pkt.protosrc] = inport
                log.debug('Router %d: Added IP %s, port %d into routingtable' % (dpid, str(arp_pkt.protosrc), inport))
            else:
                log.debug('Router %d: IP %s, put port %d already exists in routingtabe' % (dpid, str(arp_pkt.protosrc), inport))
            self.handle_arp_packet(arp_pkt, inport, dpid, packet_in)

    # Reference: https://github.com/Chuansssss/Mininet-Openflow-exercise
    def _handle_PacketIn (self, event):
        packet = event.parsed
        packet_in = event.ofp
        dpid = event.connection.dpid
        inport = event.port

        # if packet is not the right version
        if not packet.parsed:
            log.error("Incomplete packet")
            return    

        self.act_like_router(packet, packet_in, inport, dpid)


def launch():
    core.registerNew(Controller)