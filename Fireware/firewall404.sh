#!/bin/sh
# Homework Number: 07
# Name: Tingzhang Li
# ECN Login: li3402
# Due Date: 3/10/2022

# 1. Remove all previous rules or chains
sudo iptables -t filter -F
sudo iptables -t filter -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t raw -F
sudo iptables -t raw -X

# 2. Change source of outgoing packet to my ip address. eth1 is the Internet interface on my machine
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE

# 3. Block all new packets come from yahoo.com
iptables -A INPUT -s yahoo.com -j REJECT

# 4. Block the computer from being pinged by all other hosts
iptables -A INPUT -p icmp --icmp-type echo-request -j REJECT

# 5. Set up port-forwarding from an unused port of my choice(port 2411) to port 22
#    First command enable connection on port 2411
#    Second command enable forwarding to port 22   
#    Third command forward the data to port 22, 
#    assumming the IP address is typical class C private IP address 
iptables -A INPUT -p tcp --dport 2411 -j ACCEPT
iptables -A FORWARD -p tcp --dport 22 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 2411 -j REDIRECT --to-port 22

# 6. Allow for SSH access (port 22) to the machine from only the engineering.purdue.edu domain
#    First command accept the connection from engineering.purdue.edu using SSH
#    Second command reject all other connection from port 22
iptables -A INPUT -s engineering.purdue.edu -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j REJECT

# 7. Limit connection requests to 30 per min after 60 connection
iptables -A FORWARD -p tcp --syn -m limit --limit 30/minute --limit-burst 60 -j ACCEPT

# 8. Drop any other packets if they are not caught by the above rules
iptables -A INPUT -p all -j REJECT --reject-with icmp-host-prohibited