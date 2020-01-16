from mininet.topo import Topo

class MyTopo( Topo ):
    
    def __init__( self ):
        
        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches

        host4 = self.addHost( 'h4', ip="10.0.1.4/24", defaultRoute = "via 10.0.1.1" )
        host5 = self.addHost( 'h5', ip="10.0.1.5/24", defaultRoute = "via 10.0.1.1" )
        host6 = self.addHost('h6', ip="10.0.1.6/24", defaultRoute = "via 10.0.1.1")
        
        host7 = self.addHost( 'h7', ip="10.0.2.7/24", defaultRoute = "via 10.0.2.1" )
        host8 = self.addHost( 'h8', ip="10.0.2.8/24", defaultRoute = "via 10.0.2.1" )
        host9 = self.addHost( 'h9', ip="10.0.2.9/24", defaultRoute = "via 10.0.2.1" )
        
        host10 = self.addHost( 'h10', ip="10.0.3.10/24", defaultRoute = "via 10.0.3.1" )
        host11 = self.addHost( 'h11', ip="10.0.3.11/24", defaultRoute = "via 10.0.3.1" )
        host12 = self.addHost( 'h12', ip="10.0.3.12/24", defaultRoute = "via 10.0.3.1" )

        switch1 = self.addSwitch( 's1' )
        switch2 = self.addSwitch( 's2' )
        switch3 = self.addSwitch( 's3' )
        

        # Add links
        self.addLink( host4, switch1 )
        self.addLink( host5, switch1 )
        self.addLink( host6, switch1 )
        
        self.addLink( host7, switch2 )
        self.addLink( host8, switch2 )
        self.addLink( host9, switch2 )

        self.addLink( host10, switch3)
        self.addLink( host11, switch3)
        self.addLink( host12, switch3)
        
        self.addLink( switch1, switch2 )
        self.addLink( switch1, switch3 )
        self.addLink( switch2, switch3 )

topos = { 'mytopo': ( lambda: MyTopo() ) }
