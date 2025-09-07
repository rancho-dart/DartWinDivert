# DART WinDivert Introduction
DART WinDivert is an implementation of the DART protocol on Windows systems. When a Windows host runs DART WinDivert, the host behaves externally as a DART-Ready device.

This program, as one of the components of the DART protocol prototype system, is used to demonstrate the implementation of the DART protocol under Windows.

## Functions of DART WinDivert

### 1. Indicate support for the DART protocol externally
   
   DART WinDivert achieves this function by intercepting DHCP REQUEST packets.

   For DHCP REQUEST packets sent by this machine, DART WinDivert inserts Option 224 into them, thereby informing the DHCP server that the terminal requesting an IP address is a DART-Ready device.

   When the program starts, it automatically trhttps://github.com/rancho-dart/DartWinDivertiggers the Windows system to send out a DHCP REQUEST.

### 2. NAT-DART-4 Functionality

   This function implements bidirectional conversion between DART encapsulation and IPv4-Only encapsulation.
   
#### 2.1 DART WinDivert intercepts DNS response packets
For DNS response packets received by the terminal, DART WinDivert checks the DNS records in the packet. If the remote host supports the DART protocol, it allocates a pseudo address from the pseudo address pool, records the mapping between the pseudo address and the queried remote host, and modifies the DNS record in the DNS response packet.
       
#### 2.2 DART WinDivert intercepts packets sent to pseudo addresses
Subsequently, applications will send packets to this pseudo address. DART WinDivert intercepts all packets discovered by the host. It extracts the destination address from these packets. If the destination address is a pseudo address, DART WinDivert checks the mapping in the pseudo address allocation table for that pseudo address and identifies the corresponding remote host. Then it inserts a DART header, modifies the destination address in the IP header to the real IP address of the remote host, and sends out the packet.
       
#### 2.3 DART WinDivert intercepts received DART-encapsulated packets
Find the corresponding pseudo address from the pseudo address allocation table, modify the source address in the IP header to the pseudo address, remove the DART header, and send out the packet.

## Design Concept of DART WinDivert

1. DART WinDivert is designed to run either as a standalone application or as a service in the Windows system.
1. If designed as a Windows driver, it should have higher efficiency. However, this program is only intended to verify the DART protocol (and the NAT-DART-4 mechanism), so it currently implements this using WinDivert in user mode.

## Compilation of DART WinDivert

1. Obtain WinDivert

   Get the binary package of WinDivert and copy the DLL/LIB/SYS files from it into the DART WinDivert directory.

   Download URL: https://reqrypt.org/windivert.html
 
   Note: The current library already includes files for WinDivert version 2.2.2.

1. Compile DART WinDivert
   
   Open the DartWinDivert directory and compile DartWinDivert.sln in Visual Studio.
   
   After successful compilation, DartWinDivert.exe and the installation package DartWinDivertSetup.msi will be generated. The installation package will automatically register DartWinDivert as a system service during installation.

## Running DART WinDivert

1. Run as a standalone application
   
   DartWinDivert.exe must be run with administrator privileges. DartWinDivert will open a debug window where necessary debugging information can be observed.
   
1. Run as a service
   
   If installed via the installation package, DartWinDivert will automatically register as a system service.

When DartWinDivert works properly, resolving a domain name of a host that supports the DART protocol (e.g., www.dart-proto.cn) will yield an IP address within the 198.19.0.0/16 network segment.

## Conclusion
You are welcome to try DART WinDivert, and we encourage you to develop better DART protocol support programs.
