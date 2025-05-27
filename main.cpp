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
#include "DartHeader.h"
#include "pseudoip.h"
#include "windivert.h"


#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "winhttp.lib")

const UINT MTU = 1500;
static std::string g_resolvable_domain;

static int renew_DHCP_ifce() {
	DWORD ret;
	ULONG len;

	// Step 1: Get IP_INTERFACE_INFO (for IpRenewAddress)
	IP_INTERFACE_INFO* pIfInfo = NULL;
	len = 0;
	GetInterfaceInfo(NULL, &len); // Ԥ������
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

			// �� pIfInfo �в��� Index ƥ��� IP_ADAPTER_INDEX_MAP
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

	// �ۼ�ÿ�����ֽڣ�16 λ��Ϊһ����λ
	for (size_t i = 0; i + 1 < len; i += 2) {
		sum += (data[i] << 8) | data[i + 1];
	}

	// ������������ȣ��������һ���ֽ�
	if (len & 1) {
		sum += data[len - 1] << 8;
	}

	// �۵���λֱ�� 16 λ
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	// ȡ���õ�����У���
	return (uint16_t)(~sum);
}


// ������������ȡ DNS ���ƣ�����ѹ��ָ�룩��������λ��ƫ��
static int dns_read_name(UINT8* dns_base, UINT8* ptr, UINT8* end, char* out_name, size_t out_size, UINT8** out_next_ptr) {
	char name[256] = { 0 };
	int name_len = 0;
	int jumped = 0;
	UINT8* orig_ptr = ptr;
	UINT8* next_ptr = NULL;

	while (ptr < end && name_len < 255) {
		if ((*ptr & 0xC0) == 0xC0) { // ѹ��ָ��
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
		DNS_QUERY_BYPASS_CACHE, // �ƹ������ȡ���½��
		nullptr,                // ��ʹ���ض���DNS������
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
			// �����ַ�ת��Ϊ���ֽ��ַ���
			std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
			result = converter.to_bytes(ptr->Data.PTR.pNameHost);
			break; // �ҵ���һ����Ч��PTR��¼�ͷ���
		}
	}

	DnsRecordListFree(pRecord, DnsFreeRecordList);
	return result;
}



// IP ��ַת��Ϊ ARPA ������IPv4 PTR ��ѯ�ã�
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

		// ��ȡ�ӿڵ��׸� DNS ��ַ
		SOCKADDR* dns_sa = adapter->FirstDnsServerAddress->Address.lpSockaddr;
		if (dns_sa->sa_family != AF_INET) continue;

		// ��ȡ DNS IP ��ַ��IPv4��
		IP4_ARRAY dnsServers;
		dnsServers.AddrCount = 1;
		dnsServers.AddrArray[0] = ((sockaddr_in*)dns_sa)->sin_addr.S_un.S_addr;

		// �����ӿ����� IPv4 ��ַ
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

	// ����User-Agent��Acceptͷ
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

	// ��ʽ��Ϊ [A-B-C-D]
	for (auto& c : response) if (c == '.') c = '-';
	return "[" + response + "]";
}

static std::string get_resolvable_domain() {
	if (!g_resolvable_domain.empty()) return g_resolvable_domain;
	std::string fqdn = get_first_ipv4_and_resolvable_name();
	if (!fqdn.empty()) {
		// �������������滻Ϊ"dart-gateway"
		size_t dot = fqdn.find('.');
		std::string new_domain;
		if (dot != std::string::npos) {
			new_domain = "dart-gateway" + fqdn.substr(dot);

			// ��ѯ�������ܷ������IP
			struct addrinfo hints = {};
			hints.ai_family = AF_INET;
			struct addrinfo* res = nullptr;
			int ret = getaddrinfo(new_domain.c_str(), nullptr, &hints, &res);
			if (ret == 0 && res != nullptr) {
				freeaddrinfo(res);
				g_resolvable_domain = fqdn; // ʹ��PTR��ѯ����ԭʼFQDN
				return g_resolvable_domain;
			}
		}
		// ���� fallthrough �� get_public_ip
	}
	g_resolvable_domain = get_public_ip();
	return g_resolvable_domain;
}


// ������վDNS����
static void handle_inbound_dns(char* packet, UINT packetLen, WINDIVERT_ADDRESS* addr) {
	//printf("[INBOUND][DNS] Received DNS packet (%d bytes)\n", packetLen);

	// 1. ����IP��UDPͷ������λDNS����
	PWINDIVERT_IPHDR ip_header = NULL;
	PWINDIVERT_UDPHDR udp_header = NULL;
	UINT8* payload = NULL;
	UINT payload_len = 0;
	if (!WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL, NULL, NULL, NULL, NULL, &udp_header, (PVOID*)&payload, &payload_len, NULL, NULL)) {
		printf("Failed to parse packet headers\n");
		return;
	}
	if (!ip_header || !udp_header || !payload) {
		printf("Invalid DNS packet\n");
		return;
	}

	// 2. ����DNSͷ��
	if (payload_len < 12) return; // DNSͷ��12�ֽ�
	UINT8* dns = payload;
	UINT16 qdcount = (dns[4] << 8) | dns[5];
	UINT16 ancount = (dns[6] << 8) | dns[7];
	UINT8* p = dns + 12;
	UINT8* end = dns + payload_len;

	// 3. ��������������(QNAME/QTYPE/QCLASS)
	for (int i = 0; i < qdcount; ++i) {
		// ����QNAME
		while (p < end && *p != 0) {
			if ((*p & 0xC0) == 0xC0) { // ָ��
				p += 2;
				break;
			}
			p += (*p) + 1;
		}
		if (p < end && *p == 0) ++p; // ����0
		if (p + 4 > end) return; // QTYPE(2) + QCLASS(2)
		p += 4;
	}

	// 4. ����Answer��
	// ���߼�������Answer��
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

		if (type == 1 && class_ == 1 && rdlength == 4) { // A��¼
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
			p += rdlength; // ������ A ��¼������
		}
	}

}


void hex_dump(char* packet, UINT packetLen) {
	// ��16������ʽ��ӡ�������ݣ��������Ҳ��ӡ�ɴ�ӡ�ַ�
	const size_t bytes_per_line = 16;
	for (UINT i = 0; i < packetLen; i += bytes_per_line) {
		// ��ӡƫ��
		printf("%04X  ", i);

		// ��ӡ16�ֽڵ�16����
		for (size_t j = 0; j < bytes_per_line; ++j) {
			if (i + j < packetLen) {
				printf("%02X ", (unsigned char)packet[i + j]);
			}
			else {
				printf("   ");
			}
		}

		printf(" ");

		// ��ӡ�ɴ�ӡ�ַ�
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

// ������վUDP 55847�˿ڣ�DARTЭ�飩����
static void handle_inbound_dart(char* packet, UINT& packetLen, WINDIVERT_ADDRESS* addr, PWINDIVERT_IPHDR ip_header, PWINDIVERT_UDPHDR udp_header, UINT8* payload, UINT payload_len) {
	//printf("[INBOUND][UDP 55847] Received UDP 55847 packet (%d bytes)\n", packetLen);

	// 1. ����IP��UDPͷ������λDART����
	if (!WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL, NULL, NULL, NULL, NULL, &udp_header, (PVOID*)&payload, &payload_len, NULL, NULL)) {
		printf("Failed to parse packet headers\n");
		return;
	}
	if (!ip_header || !udp_header || !payload) {
		printf("Invalid DART packet\n");
		return;
	}

	// 2. ���DARTͷ������
	if (payload_len < sizeof(DartHeader)) {
		printf("DART header too short\n");
		return;
	}
	DartHeader* dart = (DartHeader*)payload;
	UINT8* dart_payload = payload + sizeof(DartHeader);

	// 3. �����䳤��ַ�ֶ�
	if (payload_len < sizeof(DartHeader) + dart->dst_addr_len + dart->src_addr_len) {
		printf("DART address fields too short\n");
		return;
	}
	const char* dst_addr = (const char*)(payload + sizeof(DartHeader));
	const char* src_addr = dst_addr + dart->dst_addr_len;
	// DART������ʼ
	UINT8* dart_data = (UINT8*)(src_addr + dart->src_addr_len);
	UINT dart_data_len = static_cast<UINT>(payload_len - (dart_data - payload));

	// ��ȡԴ��ַ��Ŀ���ַΪstd::string
	std::string dst_addr_str(dst_addr, dart->dst_addr_len);
	std::string src_addr_str(src_addr, dart->src_addr_len);

	// ��ѯα��ַ
	// ԴIPΪUDP����ԴIP
	uint32_t src_ip = ntohl(ip_header->SrcAddr);
	uint32_t pseudo_ip = allocate_pseudoip(src_addr_str, src_ip, ntohs(udp_header->SrcPort));
	if (pseudo_ip == 0) {
		printf("Pseudo IP pool exhausted or allocation failed\n");
		return;
	}

	// ��ӡʱ
	printf("DART src_addr: %.*s, dst_addr: %.*s\n",
		dart->src_addr_len, src_addr,
		dart->dst_addr_len, dst_addr);

	// 5. �����µ�IP��������ԭʼ���ڴ棩
	// �ƶ�dart_data��UDPͷ�󣬸���ԭUDP����
	size_t ip_header_len = sizeof(WINDIVERT_IPHDR);
	size_t new_payload_len = dart_data_len;
	size_t new_packet_len = ip_header_len + new_payload_len;

	// �޸�IPͷ
	ip_header = (PWINDIVERT_IPHDR)packet;
	ip_header->SrcAddr = htonl(pseudo_ip);
	ip_header->Protocol = dart->protocol;
	ip_header->Length = htons((USHORT)(ip_header_len + new_payload_len));
	//ip_header->Checksum = checksum((uint8_t*)packet, packetLen);
	ip_header->Checksum = 0;

	// ֻ����IPͷ������ֱ�Ӹ�DART����
	memmove(packet + ip_header_len, dart_data, dart_data_len);

	// ���°����ȣ�����ѭ��ͳһ����
	packetLen = (UINT)new_packet_len;

	// ��鱨�ģ������TCP����UDP,������У���
	PWINDIVERT_TCPHDR TcpHdr;
	PWINDIVERT_UDPHDR UdpHer;
	PWINDIVERT_ICMPHDR IcmpHdr;

	WinDivertHelperCalcChecksums(packet, packetLen, NULL, 0); // ����У���(�����Զ�����IPͷ��TCP/UDP/ICMPͷ��У���)

	//hex_dump(packet, packetLen);
	char srcAddrStr[INET_ADDRSTRLEN];
	char dstAddrStr[INET_ADDRSTRLEN];

	// Convert the source and destination addresses to strings  
	inet_ntop(AF_INET, &(ip_header->SrcAddr), srcAddrStr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_header->DstAddr), dstAddrStr, INET_ADDRSTRLEN);

	// Use the converted strings in printf  
	printf("[INBOUND]: %s to %s\n", srcAddrStr, dstAddrStr);

}

// �����վDHCP����
static void handle_outbound_dhcp(char* packet, UINT& packetLen, WINDIVERT_ADDRESS* addr) {
	printf("[OUTBOUND][DHCP] Sent DHCP packet (%d bytes)\n", packetLen);

	// 1. ����IP��UDPͷ������λDHCP����
	PWINDIVERT_IPHDR ip_header = NULL;
	PWINDIVERT_UDPHDR udp_header = NULL;
	UINT8* payload = NULL;
	UINT payload_len = 0;
	if (!WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL, NULL, NULL, NULL, NULL, &udp_header, (PVOID*)&payload, &payload_len, NULL, NULL)) {
		printf("Failed to parse packet headers\n");
		return;
	}
	if (!ip_header || !udp_header || !payload) {
		printf("Invalid DHCP packet\n");
		return;
	}

	// 2. ���DHCP������С���ȣ�BOOTP�̶����֣�
	if (payload_len < 240) return; // 236�ֽ�BOOTP + 4�ֽ�Magic Cookie

	UINT8* dhcp = payload;
	UINT8* options = dhcp + 240;
	UINT options_len = payload_len - 240;

	// 3. ����DHCP Message Type
	UINT8 dhcp_type = 0;
	UINT8* opt = options;
	UINT8* end = options + options_len;
	while (opt < end && *opt != 0xFF) { // 0xFFΪoption����
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

	// 4. ������DHCP Discover(1)��Request(3)
	if (dhcp_type != 1 && dhcp_type != 3) return;

	// 5. ����Ƿ��Ѵ���Option 224
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
	if (has_224) return; // ����Option 224���������

	// 6. ���Option 224��"Dart:v1"�������뵽0xFF������ǰ
	const char dart_val[] = "Dart:v1";
	const UINT8 dart_opt_code = 224;
	const UINT8 dart_opt_len = sizeof(dart_val) - 1; // ����\0
	UINT8 extra[2 + sizeof(dart_val) - 1 + 1]; // code+len+value+end
	extra[0] = dart_opt_code;
	extra[1] = dart_opt_len;
	memcpy(extra + 2, dart_val, dart_opt_len);
	extra[2 + dart_opt_len] = 0xFF; // ������

	// �ҵ�0xFF������
	UINT8* ff = options;
	while (ff < end && *ff != 0xFF) {
		if (*ff == 0) { ff++; continue; }
		if (ff + 1 >= end) break;
		ff += 2 + ff[1];
	}
	if (ff >= end) return; // û���ҵ�������

	// �����°�����
	size_t before_ff = ff - payload;
	size_t after_ff = payload_len - before_ff - 1; // payload_len �� DHCP ���س���
	size_t new_len = before_ff + 2 + dart_opt_len + 1 + after_ff;

	// �ƶ��������ݣ�ΪOption 224�ڳ��ռ�
	memmove(payload + before_ff + 2 + dart_opt_len + 1, payload + before_ff + 1, after_ff);
	// ����Option 224�ͽ�����
	memcpy(payload + before_ff, extra, 2 + dart_opt_len + 1);

	// ���°�����
	packetLen += (2 + dart_opt_len); // ������Option����

	// ����IP��UDP�����ֶ�
	if (ip_header) ip_header->Length = htons((USHORT)(packetLen));
	if (udp_header) udp_header->Length = htons((USHORT)(packetLen - sizeof(WINDIVERT_IPHDR)));

	printf("DHCP Option 224 (Dart:v1) added.\n");
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



// �����վĿ��Ϊ198.18.0.0/15��IP����
static void handle_outbound_to_pseudo_addr(char* packet, UINT& packetLen, WINDIVERT_ADDRESS* addr, PWINDIVERT_IPHDR ip_header) {
	//printf("[OUTBOUND][198.18.0.0/15] Sent IP packet to 198.18.0.0/15 (%d bytes)\n", packetLen);

	// 1. ����IPͷ
	//PWINDIVERT_IPHDR ip_header = NULL;
	//WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	//if (!ip_header) {
	//	printf("Invalid IP header\n");
	//	return;
	//}

	// Convert the unsigned int IP addresses to strings using inet_ntoa or similar function before passing to printf.  

	char srcAddrStr[INET_ADDRSTRLEN];
	char dstAddrStr[INET_ADDRSTRLEN];

	// Convert the source and destination addresses to strings  
	inet_ntop(AF_INET, &(ip_header->SrcAddr), srcAddrStr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_header->DstAddr), dstAddrStr, INET_ADDRSTRLEN);

	// Use the converted strings in printf  
	printf("[OUTBOUND]: %s to %s\n", srcAddrStr, dstAddrStr);

	uint32_t pseudo_ip = ntohl(ip_header->DstAddr);

	// 1.1 ����α��ַ��Ӧ����������ʵIP
	std::string domain;
	uint16_t udpPort = 0;
	uint32_t real_ip = 0;
	if (!query_by_pseudoip(pseudo_ip, domain, real_ip, udpPort)) {
		printf("Pseudo IP not found in mapping table\n");
		return;
	}

	// 2. ��ȡ����FQDN��ΪԴ��ַ
	std::string local_fqdn = get_resolvable_domain();

	// 3. ����DARTͷ
	DartHeader dart_hdr;
	dart_hdr.version = 1;
	dart_hdr.protocol = ip_header->Protocol;
	dart_hdr.dst_addr_len = (uint8_t)domain.size();
	dart_hdr.src_addr_len = (uint8_t)local_fqdn.size();

	// 4. �����°�����
	size_t ip_header_len = sizeof(WINDIVERT_IPHDR);
	size_t udp_header_len = sizeof(WINDIVERT_UDPHDR);
	size_t dart_header_len = sizeof(DartHeader) + domain.size() + local_fqdn.size();
	size_t orig_payload_len = packetLen - ip_header_len;
	size_t new_payload_len = udp_header_len + dart_header_len + orig_payload_len;
	size_t new_packet_len = ip_header_len + new_payload_len;

	if (new_packet_len > 0xFFFF) {
		printf("Packet too large after DART encapsulation\n");
		return;
	}

	bool df_set = (ip_header->FragOff0 & 0x40) != 0; // DFλ��IPͷ��FragOff0�ֶ�bit6
	if (new_packet_len > MTU && df_set) {
		int suggested_mtu = MTU - (8 + DartHeaderLength(&dart_hdr));
		handle_exceed_mtu_packets(packet, ip_header, suggested_mtu, addr);
		packetLen = 0;
		return;
	}


	// 5. �ƶ�ԭʼ���أ�ΪUDPͷ+DARTͷ�ڳ��ռ�
	memmove(packet + ip_header_len + udp_header_len + dart_header_len,
		packet + ip_header_len,
		orig_payload_len);

	// 6. ����UDPͷ
	PWINDIVERT_UDPHDR udp_header = (PWINDIVERT_UDPHDR)(packet + ip_header_len);
	udp_header->SrcPort = htons(DART_PORT);
	udp_header->DstPort = htons(udpPort);
	udp_header->Length = htons((USHORT)(udp_header_len + dart_header_len + orig_payload_len));
	udp_header->Checksum = checksum((uint8_t*)packet, packetLen);

	// 7. ����DARTͷ�͵�ַ
	UINT8* dart_ptr = (UINT8*)(packet + ip_header_len + udp_header_len);
	memcpy(dart_ptr, &dart_hdr, sizeof(DartHeader));
	dart_ptr += sizeof(DartHeader);
	if (domain.size() > 0) {
		memcpy(dart_ptr, domain.data(), domain.size());
		dart_ptr += domain.size();
	}
	if (local_fqdn.size() > 0) {
		memcpy(dart_ptr, local_fqdn.data(), local_fqdn.size());
		dart_ptr += local_fqdn.size();
	}


	// 8. �޸�IPͷ
	ip_header = (PWINDIVERT_IPHDR)packet;
	ip_header->DstAddr = htonl(real_ip);
	ip_header->Protocol = 17; // UDP
	ip_header->Length = htons((USHORT)new_packet_len);
	ip_header->Checksum = 0;

	WinDivertHelperCalcChecksums(packet, new_packet_len, NULL, 0);

	// 9. ���°�����
	packetLen = (UINT)new_packet_len;

}

static void divert_loop() {
	HANDLE handle = WinDivertOpen(
		// ������վDNS����վUDP 55847����վUDP 67/68��DHCP������վ198.18.0.0/15������ȫ��
		"(inbound and udp.DstPort == 55847) or " // ��վDART����Ҫ����NAT:DART->4ת��
		"(outbound and ip.DstAddr >= 198.18.0.0 and ip.DstAddr <= 198.19.255.255) or " // ��վ��α��ַ����Ҫ����NAT:4->DARTת��
		"(inbound and udp.SrcPort == 53) or " // ��վDNS������α��ַ�滻
		"(outbound and udp.SrcPort == 68 and udp.DstPort == 67)", // ��վDHCP����Ҫ���OPTION 224
		WINDIVERT_LAYER_NETWORK, 0, 0);
	if (handle == INVALID_HANDLE_VALUE) {
		printf("WinDivertOpen failed: %d\n", GetLastError());
		WSACleanup();
		return;
	}
	printf("WinDivert open successful!\n");

	char packet[MAX_PACKET_SIZE];
	UINT packetLen;
	WINDIVERT_ADDRESS addr;

	while (TRUE) {
		if (!WinDivertRecv(handle, packet, sizeof(packet), &packetLen, &addr)) {
			printf("WinDivertRecv failed: %d\n", GetLastError());
			continue;
		}

		PWINDIVERT_IPHDR ip_header = NULL;
		PWINDIVERT_UDPHDR udp_header = NULL;
		UINT8* payload = NULL;
		UINT payload_len = 0;

		WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL, NULL, NULL, NULL, NULL, &udp_header, (PVOID*)&payload, &payload_len, NULL, NULL);

		if (addr.Outbound) {
			if (udp_header && ntohs(udp_header->SrcPort) == 68 && ntohs(udp_header->DstPort) == 67) {
				handle_outbound_dhcp(packet, packetLen, &addr);
			}
			else if (ip_header && is_pseudoip(ntohl(ip_header->DstAddr))) {
				handle_outbound_to_pseudo_addr(packet, packetLen, &addr, ip_header);
			}
			else {
				// ������վ����ֱ�ӷ���
			}
		}
		else {
			if (udp_header && ntohs(udp_header->DstPort) == 55847) {
				handle_inbound_dart(packet, packetLen, &addr, ip_header, udp_header, payload, payload_len);
			}
			else if (udp_header && ntohs(udp_header->SrcPort) == 53) {
				handle_inbound_dns(packet, packetLen, &addr);
			}
			else {
				// ������վ����ֱ�ӷ���
			}
		}


		// �������б���
		if (!WinDivertSend(handle, packet, packetLen, NULL, &addr)) {
			printf("WinDivertSend failed: %d\n", GetLastError());
		}
	}

	WinDivertClose(handle);

}

int main() {
	// ��ʼ�� Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("WSAStartup failed\n");
		return -1;
	}

	// ��ȡ�ɽ���������������У�
	get_resolvable_domain();

	// ����αIP�����߳�
	start_pseudoip_cleanup_thread();

	// ������̨�̴߳���WinDivertѭ��
	std::thread divertThread(divert_loop);

	// �ȴ��߳�����
	Sleep(1000);

	// ���߳�ִ��DHCP���⡣WinDivert���ں�̨�����ģ�����Option 224���� DHCP ����������һ̨֧��DartЭ����豸
	renew_DHCP_ifce();

	// �ȴ���̨�߳̽����������Ҫ��
	divertThread.join();

	WSACleanup(); // �������ʱ����
	return 0;
}





