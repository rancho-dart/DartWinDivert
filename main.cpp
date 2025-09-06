#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <windns.h>
#include <string>
#include <vector>
#include <locale>
#include <codecvt>
#include <winhttp.h>
#include <cstdio>
#include <iostream>
#include <stdint.h>
#include <stddef.h>
#include "include/DartHeader.h"
#include "include/pseudoip.h"
#include "include/windivert.h"
#include <winreg.h>


#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "winhttp.lib")

const UINT DEFAULT_MTU = 1500;


// Read PMTU from registry, default to 1500 if not found or error
UINT ReadPMTUFromRegistry() {
    HKEY hKey;
    DWORD mtu = DEFAULT_MTU;
    DWORD dwType = REG_DWORD;
    DWORD dwSize = sizeof(mtu);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\DartWinDivert", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "PMTU", NULL, &dwType, (LPBYTE)&mtu, &dwSize) != ERROR_SUCCESS || dwType != REG_DWORD) {
			mtu = DEFAULT_MTU;
        }
        RegCloseKey(hKey);
    }
    return mtu;
}

// Replace const UINT MTU with global variable
UINT g_MTU = DEFAULT_MTU;

volatile bool g_Running = true;
static std::string g_resolvable_domain;

static int renew_DHCP_ifce() {
	DWORD ret;
	ULONG len;

	// Step 1: Get IP_INTERFACE_INFO (for IpRenewAddress)
	IP_INTERFACE_INFO* pIfInfo = NULL;
	len = 0;
	GetInterfaceInfo(NULL, &len); // Estimate length
	pIfInfo = (IP_INTERFACE_INFO*)malloc(len);
	if ((ret = GetInterfaceInfo(pIfInfo, &len)) != NO_ERROR) {
		printf("GetInterfaceInfo failed: %lu\n", ret);
		return 1;
	}

	// Step 2: Get IP_ADAPTER_INFO (for checking DHCP)
	IP_ADAPTER_INFO* pAdInfo = NULL, * pAdapter;
	len = 0;
	GetAdaptersInfo(NULL, &len);
	pAdInfo = (IP_ADAPTER_INFO*)malloc(len);
	if ((ret = GetAdaptersInfo(pAdInfo, &len)) != NO_ERROR) {
		printf("GetAdaptersInfo failed: %lu\n", ret);
		free(pIfInfo);
		return 1;
	}

	// Step 3: Loop through adapters and renew those with DHCP enabled
	pAdapter = pAdInfo;
	while (pAdapter) {
		if (pAdapter->DhcpEnabled) {
			printf("Interface with DHCP enabled: %s (Index: %lu)\n",
				pAdapter->AdapterName, pAdapter->Index);

			// Find IP_ADAPTER_INDEX_MAP in pIfInfo with matching Index
			for (int i = 0; i < pIfInfo->NumAdapters; ++i) {
				if (pIfInfo->Adapter[i].Index == pAdapter->Index) {
					IP_ADAPTER_INDEX_MAP* map = &pIfInfo->Adapter[i];
					DWORD res = IpRenewAddress(map);
					if (res == NO_ERROR) {
						printf("  -> DHCP renew request sent successfully.\n");
					}
					else {
						printf("  -> IpRenewAddress failed: %lu\n", res);
					}
					break;
				}
			}
		}
		pAdapter = pAdapter->Next;
	}

	free(pIfInfo);
	free(pAdInfo);
	return 0;
}

uint16_t checksum(const uint8_t* data, size_t len) {
	uint32_t sum = 0;

	// Accumulate every two bytes (16 bits) as one unit
	for (size_t i = 0; i + 1 < len; i += 2) {
		sum += (data[i] << 8) | data[i + 1];
	}

	// If odd length, handle the last byte
	if (len & 1) {
		sum += data[len - 1] << 8;
	}

	// Fold carry until 16 bits
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	// Take one's complement to get the final checksum
	return (uint16_t)(~sum);
}


// Helper function: Read DNS name (handle compression pointer), return new offset
static int dns_read_name(UINT8* dns_base, UINT8* ptr, UINT8* end, char* out_name, size_t out_size, UINT8** out_next_ptr) {
	char name[256] = { 0 };
	int name_len = 0;
	int jumped = 0;
	UINT8* orig_ptr = ptr;
	UINT8* next_ptr = NULL;

	while (ptr < end && name_len < 255) {
		if ((*ptr & 0xC0) == 0xC0) { // Compression pointer
			if (ptr + 1 >= end) return -1;
			int offset = ((ptr[0] & 0x3F) << 8) | ptr[1];
			if (!jumped && !next_ptr) next_ptr = ptr + 2;
			ptr = dns_base + offset;
			jumped = 1;
		}
		else if (*ptr == 0) {
			if (!jumped && !next_ptr) next_ptr = ptr + 1;
			break;
		}
		else {
			int label_len = *ptr++;
			if (ptr + label_len > end) return -1;
			if (name_len && name_len < 255) name[name_len++] = '.';
			for (int i = 0; i < label_len && name_len < 255; ++i) {
				name[name_len++] = *ptr++;
			}
		}
	}

	name[name_len] = 0;
	strncpy_s(out_name, out_size, name, out_size - 1);

	if (out_next_ptr) {
		*out_next_ptr = next_ptr ? next_ptr : ptr + 1;
	}

	return 0;
}


std::string ip_to_arpa(const std::string& ip) {
	struct in_addr addr;
	if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
		return "";
	}
	unsigned char* bytes = reinterpret_cast<unsigned char*>(&addr);
	char arpa[64];
	snprintf(arpa, sizeof(arpa), "%d.%d.%d.%d.in-addr.arpa", bytes[3], bytes[2], bytes[1], bytes[0]);
	return arpa;
}

std::string resolve_ptr(const std::string& ip) {
	std::string query_name = ip_to_arpa(ip);
	if (query_name.empty()) {
		return "";
	}

	PDNS_RECORD pRecord = nullptr;
	DNS_STATUS status = DnsQuery_A(
		query_name.c_str(),
		DNS_TYPE_PTR,
		DNS_QUERY_BYPASS_CACHE, // Bypass cache to get latest result
		nullptr,                // Do not use specific DNS server
		&pRecord,
		nullptr
	);

	if (status != ERROR_SUCCESS || !pRecord) {
		if (pRecord) {
			DnsRecordListFree(pRecord, DnsFreeRecordList);
		}
		return "";
	}

	std::string result;
	for (PDNS_RECORD ptr = pRecord; ptr != nullptr; ptr = ptr->pNext) {
		if (ptr->wType == DNS_TYPE_PTR && ptr->Data.PTR.pNameHost) {
			// Convert wide string to multibyte string
			std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
			result = converter.to_bytes(ptr->Data.PTR.pNameHost);
			break; // Return the first valid PTR record found
		}
	}

	DnsRecordListFree(pRecord, DnsFreeRecordList);
	return result;
}

// IP address to ARPA domain (for IPv4 PTR query)
std::wstring ip_to_arpa_w(const std::string& ip) {
	in_addr addr;
	if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return L"";

	BYTE* bytes = (BYTE*)&addr;
	wchar_t arpa[100];
	swprintf(arpa, 100, L"%d.%d.%d.%d.in-addr.arpa.",
		bytes[3], bytes[2], bytes[1], bytes[0]);

	return std::wstring(arpa);
}

std::string get_first_ipv4_and_resolvable_name() {
	ULONG bufLen = 15 * 1024;
	std::vector<BYTE> buf(bufLen);
	IP_ADAPTER_ADDRESSES* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());

	if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST, nullptr, adapters, &bufLen) != NO_ERROR) {
		return "";
	}

	for (IP_ADAPTER_ADDRESSES* adapter = adapters; adapter; adapter = adapter->Next) {
		if (adapter->OperStatus != IfOperStatusUp) continue;
		if (!adapter->FirstDnsServerAddress) continue;

		// Get the first DNS address of the interface
		SOCKADDR* dns_sa = adapter->FirstDnsServerAddress->Address.lpSockaddr;
		if (dns_sa->sa_family != AF_INET) continue;

		// Extract DNS IP address (IPv4)
		IP4_ARRAY dnsServers;
		dnsServers.AddrCount = 1;
		dnsServers.AddrArray[0] = ((sockaddr_in*)dns_sa)->sin_addr.S_un.S_addr;

		// Traverse all IPv4 addresses of the interface
		for (IP_ADAPTER_UNICAST_ADDRESS* ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
			SOCKADDR* sa = ua->Address.lpSockaddr;
			if (sa->sa_family != AF_INET) continue;

			char ipstr[INET_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET, &((sockaddr_in*)sa)->sin_addr, ipstr, INET_ADDRSTRLEN);

			std::wstring query_name = ip_to_arpa_w(ipstr);
			if (query_name.empty()) continue;

			PDNS_RECORDW pRecord = nullptr;

			DNS_STATUS status = DnsQuery_W(
				query_name.c_str(),
				DNS_TYPE_PTR,
				DNS_QUERY_BYPASS_CACHE,
				&dnsServers,
				&pRecord,
				nullptr
			);

			std::string result;
			if (status == ERROR_SUCCESS && pRecord) {
				for (PDNS_RECORDW ptr = pRecord; ptr != nullptr; ptr = ptr->pNext) {
					if (ptr->wType == DNS_TYPE_PTR && ptr->Data.PTR.pNameHost) {
						std::wstring hostname(ptr->Data.PTR.pNameHost);
						std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
						result = converter.to_bytes(hostname);
						break;
					}
				}
				DnsRecordListFree(pRecord, DnsFreeRecordList);
			}

			if (!result.empty()) return result;
		}
	}

	return "";
}

std::string get_public_ip() {
	HINTERNET hSession = WinHttpOpen(L"MyApp", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
	if (!hSession) return "";

	HINTERNET hConnect = WinHttpConnect(hSession, L"ifconfig.me", INTERNET_DEFAULT_HTTP_PORT, 0);
	if (!hConnect) {
		WinHttpCloseHandle(hSession);
		return "";
	}

	HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", nullptr, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
	if (!hRequest) {
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return "";
	}

	// Set User-Agent and Accept headers
	LPCWSTR userAgent = L"User-Agent: curl/7.85.0\r\n";
	LPCWSTR accept = L"Accept: */*\r\n";
	std::wstring headers = userAgent;
	headers += accept;

	BOOL result = WinHttpAddRequestHeaders(hRequest, headers.c_str(), (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
	result = result && WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0)
		&& WinHttpReceiveResponse(hRequest, nullptr);
	if (!result) {
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return "";
	}

	DWORD size = 0;
	std::string response;
	do {
		DWORD downloaded = 0;
		char buffer[512];
		if (!WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &downloaded) || downloaded == 0) break;
		response.append(buffer, downloaded);
	} while (true);

	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);

	// Format as [A-B-C-D]
	for (auto& c : response) if (c == '.') c = '-';
	return "[" + response + "]";
}

static std::string get_resolvable_domain() {
	if (!g_resolvable_domain.empty()) return g_resolvable_domain;
	std::string fqdn = get_first_ipv4_and_resolvable_name();
	if (!fqdn.empty()) {
		// Replace the hostname part with "dart-gateway"
		size_t dot = fqdn.find('.');
		std::string new_domain;
		if (dot != std::string::npos) {
			new_domain = "dart-gateway" + fqdn.substr(dot);

			// Query if the new domain can be resolved to IP
			struct addrinfo hints = {};
			hints.ai_family = AF_INET;
			struct addrinfo* res = nullptr;
			int ret = getaddrinfo(new_domain.c_str(), nullptr, &hints, &res);
			if (ret == 0 && res != nullptr) {
				freeaddrinfo(res);
				// make sure fqdn ends with '.'
				if (fqdn.back() != '.') fqdn += '.';
				
				g_resolvable_domain = fqdn; // Use the original FQDN found by PTR query

				return g_resolvable_domain;
			}
		}
		// Otherwise fallthrough to get_public_ip
	}
	//g_resolvable_domain = get_public_ip();
	g_resolvable_domain += "[--------]"; // Placeholder to avoid empty domain, will be replaced by the recipient
	return g_resolvable_domain;
}


// Handle inbound DNS packet
static void handle_inbound_dns(char* packet, UINT packetLen, WINDIVERT_ADDRESS* addr, PWINDIVERT_IPHDR ip_header, PWINDIVERT_UDPHDR udp_header, UINT8* udp_payload, UINT udp_payload_len) {
	//printf("[INBOUND][DNS] Received DNS packet (%d bytes)\n", packetLen);

	// 1. Skip IP and UDP headers, locate DNS data
	if (!ip_header || !udp_header || !udp_payload) {
		printf("Invalid DNS packet\n");
		return;
	}

	// 2. Parse DNS header
	if (udp_payload_len < 12) return; // DNS header is 12 bytes
	UINT8* dns = udp_payload;
	UINT16 qdcount = (dns[4] << 8) | dns[5];
	UINT16 ancount = (dns[6] << 8) | dns[7];
	UINT8* p = dns + 12;
	UINT8* end = dns + udp_payload_len;

	// 3. Skip all question sections (QNAME/QTYPE/QCLASS)
	for (int i = 0; i < qdcount; ++i) {
		// Skip QNAME
		while (p < end && *p != 0) {
			if ((*p & 0xC0) == 0xC0) { // Pointer
				p += 2;
				break;
			}
			p += (*p) + 1;
		}
		if (p < end && *p == 0) ++p; // Skip 0
		if (p + 4 > end) return; // QTYPE(2) + QCLASS(2)
		p += 4;
	}

	// 4. Traverse Answer section
	// Main logic: traverse Answer section
	char first_name[256] = { 0 };
	bool first_record = true;

	for (int i = 0; i < ancount; ++i) {
		if (p >= end) break;

		char name[256] = { 0 };
		UINT8* next_ptr = NULL;

		if (dns_read_name(dns, p, end, name, sizeof(name), &next_ptr) < 0) {
			printf("Failed to parse answer name\n");
			break;
		}

		p = next_ptr;
		if (p + 10 > end) break;

		UINT16 type = (p[0] << 8) | p[1];
		UINT16 class_ = (p[2] << 8) | p[3];
		UINT32 ttl = (p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7];
		UINT16 rdlength = (p[8] << 8) | p[9];
		p += 10;

		if (p + rdlength > end) break;

		if (first_record) {
			strncpy_s(first_name, sizeof(first_name), name, sizeof(first_name) - 1);
			first_record = false;
		}

		if (type == 1 && class_ == 1 && rdlength == 4) { // A record
			if (strncmp(name, "dart-gateway.", 13) != 0 && strncmp(name, "dart-host.", 10) != 0) {
				p += rdlength;
				continue;
			}

			uint32_t real_ip = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
			uint32_t pseudo_ip = allocate_pseudoip(first_name, real_ip, DART_PORT);
			if (pseudo_ip != 0) {
				p[0] = (pseudo_ip >> 24) & 0xFF;
				p[1] = (pseudo_ip >> 16) & 0xFF;
				p[2] = (pseudo_ip >> 8) & 0xFF;
				p[3] = (pseudo_ip) & 0xFF;
				printf("A record: %s, real IP: %u.%u.%u.%u -> pseudo IP: %u.%u.%u.%u (pseudo domain: %s)\n",
					name,
					(real_ip >> 24) & 0xFF, (real_ip >> 16) & 0xFF, (real_ip >> 8) & 0xFF, real_ip & 0xFF,
					(pseudo_ip >> 24) & 0xFF, (pseudo_ip >> 16) & 0xFF, (pseudo_ip >> 8) & 0xFF, pseudo_ip & 0xFF,
					first_name
				);
			}

			p += 4;
		}
		else {
			p += rdlength; // Skip non-A record data
		}
	}

}


void hex_dump(char* packet, UINT packetLen) {
	// Print packet content in hexadecimal, and printable characters on the right
	const size_t bytes_per_line = 16;
	for (UINT i = 0; i < packetLen; i += bytes_per_line) {
		// Print offset
		printf("%04X  ", i);

		// Print 16 bytes in hexadecimal
		for (size_t j = 0; j < bytes_per_line; ++j) {
			if (i + j < packetLen) {
				printf("%02X ", (unsigned char)packet[i + j]);
			}
			else {
				printf("   ");
			}
		}

		printf(" ");

		// Print printable characters
		for (size_t j = 0; j < bytes_per_line; ++j) {
			if (i + j < packetLen) {
				unsigned char c = (unsigned char)packet[i + j];
				if (c >= 32 && c <= 126) {
					printf("%c", c);
				}
				else {
					printf(".");
				}
			}
		}
		printf("\n");
	}
}

// Handle inbound UDP port 55847 (DART protocol) packet
static void handle_inbound_dart(char* packet, UINT& packetLen, WINDIVERT_ADDRESS* addr, PWINDIVERT_IPHDR ip_header, PWINDIVERT_UDPHDR udp_header, UINT8* dart_packet_data, UINT dart_packet_len) {
	//printf("[INBOUND][UDP 55847] Received UDP 55847 packet (%d bytes)\n", packetLen);

	// 1. Parse IP and UDP headers, locate DART payload
	if (!ip_header || !udp_header || !dart_packet_data) {
		printf("Invalid DART packet\n");
		return;
	}

	// 2. Check DART packet integrity
	// Because now we are using a test udp port, sometimes non-DART packets may use this port and be passed here. we do a little simple check here.
	// If it is not DART packet, just return. 
	if (dart_packet_len < sizeof(DartHeader)) {
		//printf("DART header too short\n");
		return;
	}

	DartHeader* dart = (DartHeader*)dart_packet_data;
	if (dart->version != 1) {
		//printf("Unsupported DART version: %d\n", dart->version);
		return;
	}

	if (dart->protocol != 6 && dart->protocol != 17 && dart->protocol != 1) { 
		//printf("Only TCP/UDP/ICMP supported.\n");
		return;
	}
	
	uint16_t dart_header_len = DartHeaderLength(dart); // Remember the total header length, we will need it later while calculating desired MSS
	if (dart_packet_len < dart_header_len){
		//printf("DART address fields too short\n"); 
		return;
	}
	//UINT8* dart_payload = dart_packet_data + sizeof(DartHeader);

	// 3. Parse variable-length address fields
	const char* dst_addr = (const char*)(dart_packet_data + sizeof(DartHeader));
	const char* src_addr = dst_addr + dart->dst_addr_len;
	// DART payload start
	UINT8* dart_data = (UINT8*)(src_addr + dart->src_addr_len);
	UINT dart_data_len = static_cast<UINT>(dart_packet_len - (dart_data - dart_packet_data));

	// Extract source and destination addresses as std::string
	std::string dst_addr_str(dst_addr, dart->dst_addr_len);
	std::string src_addr_str(src_addr, dart->src_addr_len);

	// Query pseudo address
	// Source IP is the source IP of UDP packet
	uint32_t src_ip = ntohl(ip_header->SrcAddr);
	uint32_t pseudo_ip = allocate_pseudoip(src_addr_str, src_ip, ntohs(udp_header->SrcPort));
	if (pseudo_ip == 0) {
		printf("Pseudo IP pool exhausted or allocation failed\n");
		return;
	}

	// Print
	printf("DART src_addr: %.*s, dst_addr: %.*s\n",
		dart->src_addr_len, src_addr,
		dart->dst_addr_len, dst_addr);

	// 5. Construct new IP packet (overwrite original packet memory)
	// Move dart_data after UDP header, overwrite original UDP payload
	size_t ip_header_len = sizeof(WINDIVERT_IPHDR);
	size_t new_payload_len = dart_data_len;
	size_t new_packet_len = ip_header_len + new_payload_len;

	// Modify IP header
	ip_header = (PWINDIVERT_IPHDR)packet;
	ip_header->SrcAddr = htonl(pseudo_ip);
	ip_header->Protocol = dart->protocol;
	ip_header->Length = htons((USHORT)(ip_header_len + new_payload_len));
	//ip_header->Checksum = checksum((uint8_t*)packet, packetLen);
	ip_header->Checksum = 0;

	// Only keep IP header, followed directly by DART payload
	memmove(packet + ip_header_len, dart_data, dart_data_len);

	// Update packet length, for main loop to send
	packetLen = (UINT)new_packet_len;


    // 检查是否为TCP SYN报文，并调整MSS
	if (ip_header->Protocol == 6) { // TCP协议号为6
		PWINDIVERT_TCPHDR tcp_header = NULL;
		UINT8* tcp_payload = NULL;
		UINT tcp_payload_len = 0;
		bool parsed = WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL, NULL, NULL, NULL, &tcp_header, NULL, (PVOID*)&tcp_payload, &tcp_payload_len, NULL, NULL);
		if (parsed && tcp_header && tcp_header->Syn) {
			// TCP头长度（单位：字节）
			uint16_t tcp_hdr_len = tcp_header->HdrLength * 4;
			uint8_t* options = (uint8_t*)tcp_header + sizeof(WINDIVERT_TCPHDR);
			size_t options_len = tcp_hdr_len > sizeof(WINDIVERT_TCPHDR) ? (tcp_hdr_len - sizeof(WINDIVERT_TCPHDR)) : 0;

			// 扫描TCP选项，查找MSS（kind=2, len=4）
			size_t i = 0;
			while (i + 3 < options_len) {
				uint8_t kind = options[i];
				if (kind == 0) break; // 选项结束
				if (kind == 1) { i++; continue; } // NOP
				uint8_t len = options[i + 1];
				if (len < 2 || i + len > options_len) break;
				if (kind == 2 && len == 4) {
					// MSS选项
					uint16_t mss_val = (options[i + 2] << 8) | options[i + 3];
					// 本地MSS = g_MTU - IP头 - TCP头 -UDP头(8字节) - DART头
					uint16_t local_mss = (uint16_t)(g_MTU - sizeof(WINDIVERT_IPHDR) - tcp_hdr_len - 8 - dart_header_len);
					if (mss_val > local_mss) {
						options[i + 2] = (local_mss >> 8) & 0xFF;
						options[i + 3] = local_mss & 0xFF;
						printf("TCP SYN: MSS %u -> %u\n", mss_val, local_mss);
						WinDivertHelperCalcChecksums(packet, packetLen, NULL, 0);
					}
					break;
				}
				i += len;
			}
		}
	}


	WinDivertHelperCalcChecksums(packet, packetLen, NULL, 0); // Calculate checksum (automatically calculates IP, TCP/UDP/ICMP header checksums)

	//hex_dump(packet, packetLen);
	char srcAddrStr[INET_ADDRSTRLEN];
	char dstAddrStr[INET_ADDRSTRLEN];

	// Convert the source and destination addresses to strings  
	inet_ntop(AF_INET, &(ip_header->SrcAddr), srcAddrStr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_header->DstAddr), dstAddrStr, INET_ADDRSTRLEN);

	// Use the converted strings in printf  
	printf("[INBOUND]: %s to %s\n", srcAddrStr, dstAddrStr);

}

// Handle outbound DHCP packet
static void handle_outbound_dhcp(char* packet, UINT& packetLen, WINDIVERT_ADDRESS* addr, PWINDIVERT_IPHDR ip_header, PWINDIVERT_UDPHDR udp_header, UINT8* udp_payload = NULL, UINT udp_payload_len = 0) {
	//printf("[OUTBOUND][DHCP] DHCP packet captured (%d bytes)\n", packetLen);

	// 1. Parse IP and UDP headers, locate DHCP data
	if (!ip_header || !udp_header || !udp_payload) {
		printf("Invalid DHCP packet\n");
		return;
	}

	// 2. Check minimum DHCP packet length (BOOTP fixed part)
	if (udp_payload_len < 240) return; // 236 bytes BOOTP + 4 bytes Magic Cookie

	UINT8* dhcp = udp_payload;
	UINT8* options = dhcp + 240;
	UINT options_len = udp_payload_len - 240;

	// 3. Find DHCP Message Type
	UINT8 dhcp_type = 0;
	UINT8* opt = options;
	UINT8* end = options + options_len;
	while (opt < end && *opt != 0xFF) { // 0xFF is option end
		UINT8 code = *opt++;
		if (code == 0) continue; // Pad
		if (opt >= end) break;
		UINT8 len = *opt++;
		if (opt + len > end) break;
		if (code == 53 && len == 1) { // DHCP Message Type
			dhcp_type = opt[0];
			break;
		}
		opt += len;
	}

	// 4. Only handle DHCP Discover(1) and Request(3)
	if (dhcp_type != 1 && dhcp_type != 3) return;

	// 5. Check if Option 224 already exists
	opt = options;
	bool has_224 = false;
	while (opt < end && *opt != 0xFF) {
		UINT8 code = *opt++;
		if (code == 0) continue;
		if (opt >= end) break;
		UINT8 len = *opt++;
		if (opt + len > end) break;
		if (code == 224) {
			has_224 = true;
			break;
		}
		opt += len;
	}
	if (has_224) return; // Option 224 already exists, no need to add

	// 6. Add Option 224 ("Dart:v1"), insert before 0xFF end
	const char dart_val[] = "Dart:v1";
	const UINT8 dart_opt_code = 224;
	const UINT8 dart_opt_len = sizeof(dart_val) - 1; // Exclude \0
	UINT8 extra[2 + sizeof(dart_val) - 1 + 1]; // code+len+value+end
	extra[0] = dart_opt_code;
	extra[1] = dart_opt_len;
	memcpy(extra + 2, dart_val, dart_opt_len);
	extra[2 + dart_opt_len] = 0xFF; // End

	// Find 0xFF end
	UINT8* ff = options;
	while (ff < end && *ff != 0xFF) {
		if (*ff == 0) { ff++; continue; }
		if (ff + 1 >= end) break;
		ff += 2 + ff[1];
	}
	if (ff >= end) return; // End not found

	// Calculate new packet length
	size_t before_ff = ff - udp_payload;
	size_t after_ff = udp_payload_len - before_ff - 1; // payload_len is DHCP payload length
	size_t new_len = before_ff + 2 + dart_opt_len + 1 + after_ff;

	// Move subsequent data to make room for Option 224
	memmove(udp_payload + before_ff + 2 + dart_opt_len + 1, udp_payload + before_ff + 1, after_ff);
	// Insert Option 224 and end
	memcpy(udp_payload + before_ff, extra, 2 + dart_opt_len + 1);

	// Update packet length
	packetLen += (2 + dart_opt_len); // Added Option length

	// Update IP and UDP length fields
	if (ip_header) ip_header->Length = htons((USHORT)(packetLen));
	if (udp_header) udp_header->Length = htons((USHORT)(packetLen - sizeof(WINDIVERT_IPHDR)));

	printf("DHCP Option 224 (Dart:v1) appended to DHCP REQUEST.\n");
}

static void handle_exceed_mtu_packets(const char* packet, const WINDIVERT_IPHDR* ip_header, uint16_t suggested_mut, const WINDIVERT_ADDRESS* addr) {
	const int ICMP_PAYLOAD_LEN = sizeof(WINDIVERT_IPHDR) + 8;
	char icmp_pkt[sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_ICMPHDR) + ICMP_PAYLOAD_LEN] = { 0 };

	auto* ip = (PWINDIVERT_IPHDR)icmp_pkt;
	auto* icmp = (PWINDIVERT_ICMPHDR)(icmp_pkt + sizeof(WINDIVERT_IPHDR));
	uint8_t* icmp_data = (uint8_t*)(icmp + 1);

	// Fill IP header
	*ip = *ip_header;
	ip->SrcAddr = ip_header->DstAddr;
	ip->DstAddr = ip_header->SrcAddr;
	ip->Protocol = 1; // ICMP
	ip->HdrLength = 5;
	ip->Length = htons(sizeof(icmp_pkt));
	ip->Checksum = 0;

	// Fill ICMP header
	icmp->Type = 3;
	icmp->Code = 4;
	icmp->Checksum = 0;
	uint8_t* unused = (uint8_t*)(&icmp->Checksum + 1);
	uint8_t* length = unused + 1;
	uint16_t* mtu = (uint16_t*)(length + 1);

	*mtu = htons(suggested_mut); // Next-Hop MTU

	// Copy original IP header + 8 bytes data
	int copy_len = suggested_mut > ICMP_PAYLOAD_LEN ? ICMP_PAYLOAD_LEN : suggested_mut;
	memcpy(icmp_data, packet, copy_len);
	*length = copy_len + 8;

	// Prepare send address
	WINDIVERT_ADDRESS fake_addr = *addr;
	fake_addr.Outbound = 0;
	fake_addr.Impostor = 1;

	WinDivertHelperCalcChecksums(icmp_pkt, sizeof(icmp_pkt), NULL, 0);
	//hex_dump(icmp_pkt, sizeof(icmp_pkt));

	HANDLE h = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);
	if (h != INVALID_HANDLE_VALUE) {
		WinDivertSend(h, icmp_pkt, sizeof(icmp_pkt), NULL, &fake_addr);
		WinDivertClose(h);
	}
}



// Handle outbound IP packet to 198.18.0.0/15
static void handle_outbound_to_pseudo_addr(char* packet, UINT& packetLen, WINDIVERT_ADDRESS* addr, PWINDIVERT_IPHDR ip_header, UINT8 protocol, PWINDIVERT_ICMPHDR icmp_header, PWINDIVERT_UDPHDR udp_header, PWINDIVERT_TCPHDR tcp_header, UINT8* payload, UINT payload_len) {
	//printf("[OUTBOUND][198.18.0.0/15] Sent IP packet to 198.18.0.0/15 (%d bytes)\n", packetLen);

	// Convert the unsigned int IP addresses to strings using inet_ntoa or similar function before passing to printf.  
	char srcAddrStr[INET_ADDRSTRLEN];
	char dstAddrStr[INET_ADDRSTRLEN];

	// Convert the source and destination addresses to strings  
	inet_ntop(AF_INET, &(ip_header->SrcAddr), srcAddrStr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_header->DstAddr), dstAddrStr, INET_ADDRSTRLEN);

	// Use the converted strings in printf  
	printf("[OUTBOUND]: %s to %s\n", srcAddrStr, dstAddrStr);

	uint32_t pseudo_ip = ntohl(ip_header->DstAddr);

	// 1. Find domain and real IP corresponding to pseudo address
	std::string dst_fqdn;
	uint16_t udpPort = 0;
	uint32_t real_ip = 0;
	if (!query_by_pseudoip(pseudo_ip, dst_fqdn, real_ip, udpPort)) {
		printf("Pseudo IP not found in mapping table\n");
		return;
	}

	// 2. Get local FQDN as source address
	std::string local_fqdn = get_resolvable_domain();

	// 3. Construct DART header
	DartHeader dart_hdr;
	dart_hdr.version = 1;
	dart_hdr.protocol = ip_header->Protocol;
	dart_hdr.dst_addr_len = (uint8_t)dst_fqdn.size();
	dart_hdr.src_addr_len = (uint8_t)local_fqdn.size();

	// 4. Shink the TCP MSS option if needed
	if (tcp_header && (tcp_header->Syn)) {
		// TCP header length in bytes
		uint16_t tcp_hdr_len = tcp_header->HdrLength * 4;
		// TCP options start after the fixed header
		uint8_t* options = (uint8_t*)tcp_header + sizeof(WINDIVERT_TCPHDR);
		size_t options_len = tcp_hdr_len > sizeof(WINDIVERT_TCPHDR) ? (tcp_hdr_len - sizeof(WINDIVERT_TCPHDR)) : 0;

		// Scan TCP options for MSS (kind=2, len=4)
		size_t i = 0;
		while (i + 3 < options_len) {
			uint8_t kind = options[i];
			if (kind == 0) break; // End of options
			if (kind == 1) { i++; continue; } // NOP
			if (i + 1 >= options_len) break;
			uint8_t len = options[i + 1];
			if (len < 2 || i + len > options_len) break;
			if (kind == 2 && len == 4) {
				// MSS option found, set to (MTU - IP header - TCP header - UDP header - DART header)
				uint16_t desiredMSS = (uint16_t)(g_MTU - sizeof(WINDIVERT_IPHDR) - tcp_hdr_len - 8 - DartHeaderLength(&dart_hdr));
				options[i + 2] = (desiredMSS >> 8) & 0xFF;
				options[i + 3] = desiredMSS & 0xFF;
				printf("TCP SYN: MSS modified to %u\n", desiredMSS);
				break;
			}
			i += len;
		}
	}


	// 5. Calculate new packet length
	uint16_t ip_header_len = sizeof(WINDIVERT_IPHDR);
	uint16_t udp_header_len = sizeof(WINDIVERT_UDPHDR);
	//size_t dart_header_len = sizeof(DartHeader) + domain.size() + local_fqdn.size();
	uint16_t dart_header_len = DartHeaderLength(&dart_hdr);
	uint16_t old_ip_payload_len = packetLen - ip_header_len;
	uint16_t new_ip_payload_len = udp_header_len + dart_header_len + old_ip_payload_len;
	uint16_t new_packet_len = ip_header_len + new_ip_payload_len;

	if (new_packet_len > MAX_PACKET_SIZE) {
		printf("Packet too large after DART encapsulation\n");
		return;
	}

	// 6. If larger than MTU, send the ICMP packet 'PACKET TOO BIG'
	bool df_set = (ip_header->FragOff0 & 0x40) != 0; // DF bit is bit6 of FragOff0 field in IP header
	if (new_packet_len > g_MTU && df_set) {
		uint16_t suggested_mtu = g_MTU - (8 + DartHeaderLength(&dart_hdr));
		handle_exceed_mtu_packets(packet, ip_header, suggested_mtu, addr);
		packetLen = 0;
		return;
	}

	// 7. Move original ip payload backwards to make room for UDP header & DART header
	char *orig_ip_payload_ptr = packet + ip_header_len;
	char *dart_payload_ptr = orig_ip_payload_ptr + udp_header_len + dart_header_len;
	memmove(dart_payload_ptr, orig_ip_payload_ptr, old_ip_payload_len);

	// 8. Construct UDP header
	PWINDIVERT_UDPHDR udp_header_before_dart = (PWINDIVERT_UDPHDR)(packet + ip_header_len);
	udp_header_before_dart->SrcPort = htons(DART_PORT);
	udp_header_before_dart->DstPort = htons(udpPort);
	udp_header_before_dart->Length = htons((USHORT)(udp_header_len + dart_header_len + old_ip_payload_len));
	udp_header_before_dart->Checksum = checksum((uint8_t*)packet, packetLen);

	// 9. Construct DART header and addresses
	DartHeader* dart_header_ptr = (DartHeader*)(udp_header_before_dart + 1);
	memcpy(dart_header_ptr, &dart_hdr, sizeof(DartHeader));

	char* dst_fqdn_ptr = (char*)(dart_header_ptr + 1);
	if (dart_hdr.dst_addr_len > 0) {
		memcpy(dst_fqdn_ptr, dst_fqdn.data(), dart_hdr.dst_addr_len);
	}
	char* src_fqdn_ptr = dst_fqdn_ptr + dart_hdr.dst_addr_len;
	if (dart_hdr.src_addr_len > 0) {
		memcpy(src_fqdn_ptr, local_fqdn.data(), dart_hdr.src_addr_len);
	}


	// 10. Modify IP header
	ip_header = (PWINDIVERT_IPHDR)packet;
	ip_header->DstAddr = htonl(real_ip);
	ip_header->Protocol = 17; // UDP
	ip_header->Length = htons((USHORT)new_packet_len);
	ip_header->Checksum = 0;

	WinDivertHelperCalcChecksums(packet, new_packet_len, NULL, 0);

	// 11. Update packet length
	packetLen = (UINT)new_packet_len;

}


static void divert_loop() {
	HANDLE handle =
		WinDivertOpen(
			// Filter inbound DNS, inbound UDP 55847, outbound UDP 67/68 (DHCP), outbound 198.18.0.0/15
			"(inbound and udp.DstPort == 55847) or "										// Inbound DART, need NAT: DART->4 conversion
			"(outbound and ip.DstAddr >= 198.18.0.0 and ip.DstAddr <= 198.19.255.255) or "	// Outbound to pseudo address, need NAT: 4->DART conversion
			"(inbound and udp.SrcPort == 53) or "											// Inbound DNS, perform pseudo address replacement
			"(outbound and udp.SrcPort == 68 and udp.DstPort == 67)",						// Outbound DHCP, need to add OPTION 224
			WINDIVERT_LAYER_NETWORK, 0, 0);

	if (handle == INVALID_HANDLE_VALUE) {
		int error = GetLastError();
		switch (error) {
		case ERROR_ACCESS_DENIED:
			printf("WinDivertOpen failed: Access denied. Please run as administrator.\n");
			break;
		case ERROR_INVALID_PARAMETER:
			printf("WinDivertOpen failed: Invalid parameter. Please check the filter syntax.\n");
			break;
		case ERROR_INVALID_IMAGE_HASH:
			printf("WinDivertOpen failed: Driver unsigned or blocked by security policy. Please check driver signature.\n");
			break;
		default:
			printf("WinDivertOpen failed with error code: %d\n", error);
			break;
		}

		WSACleanup();
		return;
	}

	printf("WinDivert opened successfully!\n");

	// Set receive timeout (milliseconds)
	UINT64 timeout = 1000; // 1 second
	WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, timeout);

	char* packet = (char*)malloc(MAX_PACKET_SIZE);
	if (!packet) {
		printf("Allocate memory failed\n");
		if (packet) free(packet);
		return;
	}

	UINT packetLen;
	WINDIVERT_ADDRESS addr;

	PWINDIVERT_IPHDR ip_header = NULL;
	UINT8 protocol = 0;
	PWINDIVERT_ICMPHDR icmp_header = NULL;
	PWINDIVERT_UDPHDR udp_header = NULL;
	PWINDIVERT_TCPHDR tcp_header = NULL;
	UINT8* payload = NULL;
	UINT payload_len = 0;

	while (g_Running) {
		if (!WinDivertRecv(handle, packet, MAX_PACKET_SIZE, &packetLen, &addr)) {
			printf("WinDivertRecv failed: %d\n", GetLastError());
			continue;
		}

		bool ok =
			WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL, &protocol, &icmp_header, NULL, &tcp_header, &udp_header, (PVOID*)&payload, &payload_len, NULL, NULL);

		if (ok) {
			if (addr.Outbound) {
				if (udp_header && ntohs(udp_header->SrcPort) == 68 && ntohs(udp_header->DstPort) == 67) { // If is a DHCP REQUEST or DISCOVER packet
					// Insert DHCP Option 224, to inform DHCP server: this is a Dart protocol capable device
					handle_outbound_dhcp(packet, packetLen, &addr, ip_header, udp_header, payload, payload_len);  // Here the payload is UDP payload
				}
				else if (ip_header && is_pseudoip(ntohl(ip_header->DstAddr))) { // If is an outbound packet heading to a pseudo IP address
					// NAT: 4->DART conversion
					handle_outbound_to_pseudo_addr(packet, packetLen, &addr, ip_header, protocol, icmp_header, udp_header, tcp_header, payload, payload_len); // Here the payload depends on protocol
				}
				else {
					// Other outbound packets are passed through directly
				}
			}
			else {
				if (udp_header && ntohs(udp_header->DstPort) == 55847) { // If is an inbound DART packet heading to UDP port 55847
					// NAT: DART->4 conversion
					handle_inbound_dart(packet, packetLen, &addr, ip_header, udp_header, payload, payload_len);
				}
				else if (udp_header && ntohs(udp_header->SrcPort) == 53) { // If is a DNS response packet
					// Replace the A record to a pseduo address if the queried host is DART-ready
					handle_inbound_dns(packet, packetLen, &addr, ip_header, udp_header, payload, payload_len);
				}
				else {
					// Other inbound packets are passed through directly
				}
			}
		}

		// Send the packet
		if (!WinDivertSend(handle, packet, packetLen, NULL, &addr)) {
			printf("WinDivertSend failed: %d\n", GetLastError());
		}
	}

	free(packet);

	WinDivertClose(handle);
}

int AppMain() {

	// Initialize Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("WSAStartup failed\n");
		return -1;
	}

	// Read PMTU from registry
	g_MTU = ReadPMTUFromRegistry();

	// Get resolvable domain (if any)
	get_resolvable_domain();

	// Start pseudo IP cleanup thread
	start_pseudoip_cleanup_thread();

	// Start background thread to handle WinDivert loop
	std::thread divertThread(divert_loop);

	// Wait for thread to start
	Sleep(1000);

	// Main thread performs DHCP renewal. WinDivert will handle packets in the background, adding Option 224 to tell the DHCP server this is a Dart protocol capable device
	renew_DHCP_ifce();

	// Wait for background thread to finish (if needed)
	divertThread.join();

	WSACleanup(); // Cleanup when program ends

	return 0;
}


// Register program as Windows service

SERVICE_STATUS        g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
void WINAPI ServiceCtrlHandler(DWORD);

int main(int argc, char* argv[]) {
	SERVICE_TABLE_ENTRY ServiceTable[] = {
        { (LPWSTR)L"DartWinDivertService", (LPSERVICE_MAIN_FUNCTION)ServiceMain },
		{ NULL, NULL }
	};
	if (!StartServiceCtrlDispatcher(ServiceTable)) {
		// If not started as a service, run main logic directly here
		AppMain(); 
        // Convert the string literal to a wide string (LPCWSTR) using the L prefix  
	}
	return 0;
}

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
	while (!IsDebuggerPresent()) Sleep(100);
	// Or
	// DebugBreak(); // Directly pop up debugger selection window

	g_StatusHandle = RegisterServiceCtrlHandler(L"DartWinDivertService", ServiceCtrlHandler);
	if (!g_StatusHandle) return;

	g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

	g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (g_ServiceStopEvent == NULL) {
		g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
		return;
	}

	// Initialize Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
		return;
	}

	// Read PMTU from registry
	g_MTU = ReadPMTUFromRegistry();

	// Other initialization
	get_resolvable_domain();
	start_pseudoip_cleanup_thread();

	std::thread divertThread(divert_loop);
	
	Sleep(1000);
	renew_DHCP_ifce();

	g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

	// Wait for service stop signal
	WaitForSingleObject(g_ServiceStopEvent, INFINITE);

	// Cleanup
	// Notify background thread to exit (if needed, can use global variable or event)
	// Here assume divert_loop can respond to exit signal
	divertThread.join();
	WSACleanup();

	g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

void WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
	switch (CtrlCode) {
	case SERVICE_CONTROL_STOP:
		g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
		g_Running = false; // Stop main loop
		SetEvent(g_ServiceStopEvent);
		break;
	default:
		break;
	}
}

