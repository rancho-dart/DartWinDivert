<title>DART WinDivert</title>
<description>DART WinDivert</description>
<author>DART Team</author>
<copyright>Copyright (c) 2015 DART Team</copyright>
<url>https://github.com/rancho-dart/DartWinDivert</url>
<license>MIT</license>
<version>1.0.0</version>
<tags>DART, WinDivert, DART-Ready</tags>


DART WinDivert Introduction
===========================
DART WinDivert is an implementation of the DART protocol on Windows systems. When a Windows host runs DART WinDivert, the host behaves externally as a DART-Ready device.
This program, as one of the components of the DART protocol prototype system, is used to demonstrate the implementation of the DART protocol under Windows.

Functions of DART WinDivert
===========================
1. Indicate support for the DART protocol externally
   DART WinDivert achieves this function by intercepting DHCP REQUEST packets.
   For DHCP REQUEST packets sent by this machine, DART WinDivert inserts Option 224 into them, thereby informing the DHCP server that the terminal requesting an IP address is a DART-Ready device.
   When the program starts, it automatically triggers the Windows system to send out a DHCP REQUEST.

2. NAT-DART-4 Functionality
   This function implements bidirectional conversion between DART encapsulation and IPv4-Only encapsulation.
   
   2.1 DART WinDivert intercepts DNS response packets
       For DNS response packets received by the terminal, DART WinDivert checks the DNS records in the packet. If the remote host supports the DART protocol, it allocates a pseudo address from the pseudo address pool, records the mapping between the pseudo address and the queried remote host, and modifies the DNS record in the DNS response packet.
       
   2.2 DART WinDivert intercepts packets sent to pseudo addresses
       Subsequently, applications will send packets to this pseudo address. DART WinDivert intercepts all packets discovered by the host. It extracts the destination address from these packets. If the destination address is a pseudo address, DART WinDivert checks the mapping in the pseudo address allocation table for that pseudo address and identifies the corresponding remote host. Then it inserts a DART header, modifies the destination address in the IP header to the real IP address of the remote host, and sends out the packet.
       
   2.3 DART WinDivert intercepts received DART-encapsulated packets
       Find the corresponding pseudo address from the pseudo address allocation table, modify the source address in the IP header to the pseudo address, remove the DART header, and send out the packet.

Design Concept of DART WinDivert
================================
1. DART WinDivert is designed to run either as a standalone application or as a service in the Windows system.
2. If designed as a Windows driver, it should have higher efficiency. However, this program is only intended to verify the DART protocol (and the NAT-DART-4 mechanism), so it currently implements this using WinDivert in user mode.

Compilation of DART WinDivert
=============================
1. Obtain WinDivert
   Get the binary package of WinDivert and copy the DLL/LIB/SYS files from it into the DART WinDivert directory.
   Download URL: https://reqrypt.org/windivert.html

2. Compile DART WinDivert
   Open the DartWinDivert directory and compile DartWinDivert.sln in Visual Studio.
   After successful compilation, DartWinDivert.exe and the installation package DartWinDivertSetup.msi will be generated. The installation package will automatically register DartWinDivert as a system service during installation.

Running DART WinDivert
======================
1. Run as a standalone application
   DartWinDivert.exe must be run with administrator privileges. DartWinDivert will open a debug window where necessary debugging information can be observed.
   
2. Run as a service
   If installed via the installation package, DartWinDivert will automatically register as a system service.

When DartWinDivert works properly, resolving a domain name of a host that supports the DART protocol (e.g., www.dart-proto.cn) will yield an IP address within the 198.19.0.0/16 network segment.

Conclusion
==========
You are welcome to try DART WinDivert, and we encourage you to develop better DART protocol support programs.




DART WinDivert简介
==================
DART WinDivert是Windows系统中DART协议的实现。Windows主机运行DART WinDivert后，主机对外就表现为一台DART-Ready设备。
本程序作为DART协议原型系统的组件之一，用以证明DART协议在Windows下的实现。

DART WinDivert的功能
===================
1. 对外表明自己支持DART协议
    DART WinDivert通过截获DHCP REQUEST数据包来实现这个功能。
    对于本机发出的DHCP REQUEST数据包，DART WinDivert会在其中插入Option 224，以此向DHCP服务器表明：正在请求IP地址的终端是DART-Ready设备。
    程序启动时，会自动触发Windows系统发出DHCP REQUEST请求。
2. NAT-DART-4 功能
    此功能实现DART封装与IPv4-Only封装的双向转换。
2.1 DART WinDivert截获DNS应答数据包
    对于终端收到的DNS应答数据包，DART WinDivert会检查DNS应答数据包中的DNS记录。如果远程主机支持DART协议，那么就在伪地址池中分配一个伪地址，记录伪地址与被查询的远程主机的映射，并修改DNS应答数据包中的DNS记录。
2.2 DART WinDivert截获发送到伪地址的报文
    随后应用程序会发送报文到该伪地址。DART WinDivert会截获主机发现的所有报文，从中取出目标地址。如果目标地址是伪地址，那么DART WinDivert会检查伪地址分配表中该伪地址的映射，并找出对应的远程主机。然后插入DART头，并修改IP头中的目标地址为远程主机的真实IP地址，将报文发出。
2.3 DART WinDivert截获收到的DART封装的报文
    从伪地址分配表中找出对应的伪地址，并修改IP头中的源地址为伪地址，删除DART头，将报文发出。


DART WinDivert设计思路
=====================
1. DART WinDivert被设计为可以作为独立的应用程序运行，也可以作为Windows系统的的服务运行。
2. 如果设计为Windows的驱动，应该可以有更高的效率。但本程序只为验证DART协议（以及NAT-DART-4机制），所以目前利用WinDivert在用户态模式下实现。

DART WinDivert的编译
===================
1. 获取WinDivert
    获取WinDivert的二进制包，并复制其中的DLL/LIB/SYS文件到DART WinDivert的目录下。
    下载地址：https://reqrypt.org/windivert.html

2. 编译DART WinDivert
    打开DartWinDivert的目录，在Visual Studio中编译DartWinDivert.sln。
    编译成功后，会生成DartWinDivert.exe和安装包DartWinDivertSetup.msi。安装包在安装时会自动将DartWinDivert注册为系统的服务。

DART WinDivert的运行
==================
1. 作为独立的应用程序运行
    必须以管理员权限运行DartWinDivert.exe。DartWinDivert会打开一个调试窗口，从中可以观察到必要的调试信息。
2. 作为服务运行
    如果是执行安装包安装，那么DartWinDivert会自动注册为系统服务。

DartWinDivert正常工作时，解析一个支持DART协议的主机域名（譬如www.dart-proto.cn），会得到198.19.0.0/16网段内的IP地址。


结语
====
欢迎您尝试DART WinDivert，也鼓励您开发出更优秀的DART协议支持程序。


