# CS241 Operating Systems and Computer Networks

## Packet Sniffer using Threadpool Model to detect Syn, Arp, and Blacklisted URL attacks

Coursework for cs241 module.
Grade 86%

To run:
```
-bash-4.1$ /courses/cs241/coursework-multi &
Creating COW file for courseworkFormatting...
```
To start the following server:
```
SSH server will start on port <portno>, to connect use:
    ssh -p <portno> root@localhost

VNC server will start on port <N>, to connect use ( password= <sessionpassword> )
    vncviewer localhost:<N>
```
Then to connect to the VNC session log in using:
```
-bash-4.1$ vncviewer
```
Finally to make the files run
```
../build/idsniff -i <interface> 

```
Replace `<interface>` with the name of the interface on which you wish to capture packets. If the -ioption is not used, i.e., no interface name is specified, then the program will assume the default interface name eth0 for the interface. (You can use the command ifconfig to see the details of the network interfaces used by a machine.)
You can also use run the skeleton with the -v option to set the verbose flag to 1 or 0 as shown below

To attack the program with the syn packets use:
```
hping3 -c 100 -d 120 -S -w 64 -p 80 -i u100 --rand-source localhost
```
To do the same with Arp poisoning run:
```
arp-poison.py
```
Finally to execute the blacklisted URLs the command is:
```
wget www.google.co.uk
```
This should return an intrusion detection report like the one below:
```
Intrusion Detection Report:
100 SYN packets detected from 10 different IPs (syn attack)
4 ARP responses (cache poisoning)
5 URL Blacklist violations
```

