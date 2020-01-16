++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
			EE555 - Fall 2019 - Major Project - Design of OpenFlow controller using Python POX Library

							README File
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

+++++
TEAM
+++++
[Huayue Hua    huayuehu@usc.edu]
[Mengdi Yuan   mengdiyu@usc.edu]

+++++++++++++++++++++++++++++++
Files Submitted in the package
+++++++++++++++++++++++++++++++
Folder		Files
Scenario 1	of_tutorial.py

Scenario 2	controller2.py
		topology2.py

Scenario 3	controller3.py
		topology3.py

Scenario 4	controller4.py
		topology4.py

Bonus Scenario	controller5.py
		topology5.py


++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
							Scenario 1
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
[List of files that are to be used to execute scenario 1]

++++++++++++++++++++++
Location to copy files
++++++++++++++++++++++
<of_tutorial.py> - <~/pox/pox/misc/>

++++++++++++++++
Commands to Run:
++++++++++++++++
open two SSH terminal for Mininet
(1) In the first terminal, run:
$ sudo killall controller
$ sudo mn -c
$ sudo mn --topo single,3 --mac --controller remote --switch ovsk
(2) In the second terminal, run:
$ cd pox
$ ./pox.py log.level --DEBUG misc.of_tutorial

+++++++++++++++++++++++++++++++++
Special Notes or any observations
+++++++++++++++++++++++++++++++++
[Any special notes or observations that we need to take care while evaluating scenario 1]

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
							Scenario 2
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
[List of files that are to be used to execute scenario 2]
controller2.py
topology2.py

++++++++++++++++++++++
Location to copy files
++++++++++++++++++++++
<controller2.py> - <~/pox/pox/misc/>
<topology2.py> - <~/mininet/custom/>


++++++++++++++++
Commands to Run:
++++++++++++++++
open two SSH terminal for Mininet
(1) In the first terminal, run:
$ sudo killall controller
$ sudo mn -c
$ sudo mn --custom topology2.py --topo topology2 --mac --controller=remote,ip=127.0.0.1,port=6633
(2) In the second terminal, run:
$ cd pox
$ sudo ./pox.py log.level --DEBUG misc.controller2 misc.full_payload

+++++++++++++++++++++++++++++++++
Special Notes or any observations
+++++++++++++++++++++++++++++++++
Note:
host1: ip=10.0.1.100, mac=00:00:00:00:00:00, defaultRoute = "via 10.0.1.1"
host2: ip=10.0.2.100, mac=00:00:00:00:00:00, defaultRoute = "via 10.0.2.1"
host3: ip=10.0.3.100, mac=00:00:00:00:00:00, defaultRoute = "via 10.0.3.1"


++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
							Scenario 3
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
[List of files that are to be used to execute scenario 3]
controller3.py
topology3.py

++++++++++++++++++++++
Location to copy files
++++++++++++++++++++++
<controller3.py> - <~/pox/pox/misc/>
<topology3.py> - <~/mininet/custom/>

++++++++++++++++
Commands to Run:
++++++++++++++++
open two SSH terminal for Mininet
(1) In the first terminal, run:
$ sudo killall controller
$ sudo mn -c
$ sudo mn --custom topology3.py --topo topology3 --mac --controller=remote,ip=127.0.0.1,port=6633
(2) In the second terminal, run:
$ cd pox
$ sudo ./pox.py log.level --DEBUG misc.controller3 misc.full_payload

+++++++++++++++++++++++++++++++++
Special Notes or any observations
+++++++++++++++++++++++++++++++++
Note:
host3: ip=10.0.1.4, mac=00:00:00:00:00:01
host4: ip=10.0.1.5, mac=00:00:00:00:00:02
host5: ip=10.0.1.6, mac=00:00:00:00:00:03

switch1: ip=10.0.1.1, mac=00:00:00:00:00:f1
switch2: ip=10.0.2.1, mac=00:00:00:00:00:f2

Link(host3, switch1, port1 = 1, port2 = 2)
Link(host4, switch1, port1 = 1, port2 = 3)
Link(host5, switch2, port1 = 1, port2 = 2)
Link(switch1, switch2, port1 = 1, port2 = 1)

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
							Scenario 4
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
[List of files that are to be used to execute scenario 4]
controller4.py
topology4.py

++++++++++++++++++++++
Location to copy files
++++++++++++++++++++++
<controller4.py> - <~/pox/pox/misc/>
<topology4.py> - <~/mininet/custom/>

++++++++++++++++
Commands to Run:
++++++++++++++++
open two SSH terminal for Mininet
(1) In the first terminal, run:
$ sudo killall controller
$ sudo mn -c
$ sudo mn --custom topology4.py --topo mytopo --mac --controller=remote,ip=127.0.0.1,port=6633
(2) In the second terminal, run:
$ cd pox
$ sudo ./pox.py log.level --DEBUG misc.controller4 misc.full_payload

+++++++++++++++++++++++++++++++++
Special Notes or any observations
+++++++++++++++++++++++++++++++++
Note: 
host4: ip=10.0.1.4, port=1, mac=00:00:00:00:00:01
host5: ip=10.0.1.5, port=2, mac=00:00:00:00:00:02
host6: ip=10.0.1.6, port=3, mac=00:00:00:00:00:03

host7: ip=10.0.2.7, port=1, mac=00:00:00:00:00:04
host8: ip=10.0.2.8, port=2, mac=00:00:00:00:00:05
host9: ip=10.0.2.9, port=3, mac=00:00:00:00:00:06

host10: ip=10.0.3.10, port=1, mac=00:00:00:00:00:07
host11: ip=10.0.3.11, port=2, mac=00:00:00:00:00:08
host12: ip=10.0.3.12, port=3, mac=00:00:00:00:00:09

switch1: ip=10.0.1.1
switch2: ip=10.0.2.1
switch3: ip=10.0.3.1

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
							Bonus Scenario
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
[List of files that are to be used to execute Bonus Scenario]
topology5.py
controller5.py

++++++++++++++++++++++
Location to copy files
++++++++++++++++++++++
<controller5.py> - <~/pox/pox/misc/>
<topology5.py> - <~/mininet/custom/>

++++++++++++++++
Commands to Run:
++++++++++++++++
open two SSH terminal for Mininet
(1) Firstly, in the first terminal, run:
$ cd pox
$ sudo ./pox.py log.level --DEBUG misc.controller4 misc.full_payload
(2) Then, in the second terminal, run:
$ sudo mn -c
$ sudo mn --custom topology4.py --topo mytopo --mac --controller=remote,ip=127.0.0.1,port=6633

+++++++++++++++++++++++++++++++++
Special Notes or any observations
+++++++++++++++++++++++++++++++++
for Bonus part, we write the topology file, but the controller5.py file, we are still in processing ...
[Any special notes or observations that we need to take care while evaluating Bonus Scenario]