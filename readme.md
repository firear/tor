tun on raw简称tor

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


windows使用npcap,linux使用libpcap,android使用vpn框架。

1.pcaploop thread
2.workthread
