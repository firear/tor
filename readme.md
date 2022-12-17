tunnel on raw简称tor

通过rawsocket建立可靠通信通道。

底层协议支持UDP/ICMP/FakeTCP,自动重发请求(ARQ)采用KCP算法。

OSI模型如下：

```
UDP/TCP
----------------
compression
-----------------------------     
KCP                 |
----------------    |
encryption|块加密   |  传输层
----------------    |
udp/icmp/faketcp    |
-----------------------------
IP                  |  网络层
-----------------------------
```


windows使用npcap,linux使用libpcap,android使用vpn框架和socket实现(只支持ICMP)。

1.pcaploop thread
2.workthread






## faketcp
### server:
iptables -A OUTPUT -p tcp --tcp-flags RST RST  -j DROP


### client:
* linux:
```
serverip=192.168.0.2
serverport=10087
sudo iptables -A INPUT  -s $serverip -p tcp -m tcp --sport $serverport  -j DROP

sudo iptables -nL --line-numbers
sudo iptables -D INPUT 1
```

