# DART WinDivert简介

DART WinDivert是Windows系统中DART协议的实现。Windows主机运行DART WinDivert后，主机对外就表现为一台DART-Ready设备。
本程序作为DART协议原型系统的组件之一，用以证明DART协议在Windows下的实现。

## DART WinDivert的功能

### 1.对外表明自己支持DART协议

DART WinDivert通过截获DHCP REQUEST数据包来实现这个功能。

对于本机发出的DHCP REQUEST数据包，DART WinDivert会在其中插入Option 224，以此向DHCP服务器表明：正在请求IP地址的终端是DART-Ready设备。

程序启动时，会自动触发Windows系统发出DHCP REQUEST请求。

### 2.NAT-DART-4 功能
    
此功能实现DART封装与IPv4-Only封装的双向转换。

#### 2.1 DART WinDivert截获DNS应答数据包
    
对于终端收到的DNS应答数据包，DART WinDivert会检查DNS应答数据包中的DNS记录。如果远程主机支持DART协议，那么就在伪地址池中分配一个伪地址，记录伪地址与被查询的远程主机的映射，并修改DNS应答数据包中的DNS记录。

#### 2.2 DART WinDivert截获发送到伪地址的报文
随后应用程序会发送报文到该伪地址。DART WinDivert会截获主机发送的所有报文，从中取出目标地址。如果目标地址是伪地址，那么DART WinDivert会检查伪地址分配表中该伪地址的映射，并找出对应的远程主机。然后插入DART头，并修改IP头中的目标地址为远程主机的真实IP地址，将报文发出。

#### 2.3 DART WinDivert截获收到的DART封装的报文
    
从伪地址分配表中找出对应的伪地址，并修改IP头中的源地址为伪地址，删除DART头，将报文发出。


## DART WinDivert设计思路

1. DART WinDivert被设计为可以作为独立的应用程序运行，也可以作为Windows系统的的服务运行。
2. 如果设计为Windows的驱动，应该可以有更高的效率。但本程序只为验证DART协议（以及NAT-DART-4机制），所以目前利用WinDivert在用户态模式下实现。

## DART WinDivert的编译
1. 获取WinDivert
    
    获取WinDivert的二进制包，并复制其中的DLL/LIB/SYS文件到DART WinDivert的目录下。
    
    下载地址：https://reqrypt.org/windivert.html
    
    注：当前库中已经包含WinDivert 2.2.2版本的文件。

2. 编译DART WinDivert
    
    打开DartWinDivert的目录，在Visual Studio中编译DartWinDivert.sln。
    
    编译成功后，会生成DartWinDivert.exe和安装包DartWinDivertSetup.msi。安装包在安装时会自动将DartWinDivert注册为系统服务。

## DART WinDivert的运行

1. 作为独立的应用程序运行
    
    必须以管理员权限运行DartWinDivert.exe。DartWinDivert会打开一个Console窗口，从中可以观察到必要的调试信息。

2. 作为服务运行
    
    如果是执行安装包安装，那么DartWinDivert会自动注册为系统服务。

DartWinDivert正常工作时，解析一个支持DART协议的主机域名（譬如www.dart-proto.cn），会得到198.19.0.0/16网段内的IP地址。如果没有，尝试刷新一下DNS:
    ```
    ipconfig /flushdns
    ```


## 结语
欢迎您尝试DART WinDivert，也鼓励您开发出更优秀的DART协议支持程序。


