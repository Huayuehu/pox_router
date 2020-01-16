# Topology for scenario 2

from mininet.topo import Topo

class topology2(Topo):

	def __init__(self):

		# Initialize topology
		Topo.__init__(self)

		# Add hosts and switch
		host1 = self.addHost('h1', ip="10.0.1.100/24", defaultRoute = "via 10.0.1.1")
		host2 = self.addHost('h2', ip="10.0.2.100/24", defaultRoute = "via 10.0.2.1")
		host3 = self.addHost('h3', ip="10.0.3.100/24", defaultRoute = "via 10.0.3.1")
		switch = self.addSwitch('s1')
		
		# Add links
		self.addLink(host1, switch)
		self.addLink(host2, switch)
		self.addLink(host3, switch)


topos = {'topology2' : (lambda : topology2())}