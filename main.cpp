#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <windns.h>
#include <windows.h>
#include <iphlpapi.h>
#include <windns.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <locale>
#include <codecvt>
#include <winhttp.h>
#include <string>
#include <vector>
#include <cstdio>
#include <iostream>
#include "DartHeader.h"
#include "pseudoip.h"
#include "windivert.h"
#include <locale>
#include <codecvt>


#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "winhttp.lib")

static std::string g_resolvable_domain;

// 辅助函数：读取 DNS 名称（处理压缩指针），返回新位置偏移
int dns_read_name(UINT8* dns_base, UINT8* ptr, UINT8* end, char* out_name, size_t out_size, UINT8** out_next_ptr) {
	char name[256] = { 0 };
	int name_len = 0;
	int jumped = 0;
	UINT8* orig_ptr = ptr;
	UINT8* next_ptr = NULL;

	while (ptr < end && name_len < 255) {
		if ((*ptr & 0xC0) == 0xC0) { // 压缩指针
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
		DNS_QUERY_BYPASS_CACHE, // 绕过缓存获取最新结果
		nullptr,                // 不使用特定的DNS服务器
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
			// 将宽字符转换为多字节字符串
			std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
			result = converter.to_bytes(ptr->Data.PTR.pNameHost);
			break; // 找到第一个有效的PTR记录就返回
		}
	}

	DnsRecordListFree(pRecord, DnsFreeRecordList);
	return result;
}



// IP 地址转换为 ARPA 域名（IPv4 PTR 查询用）
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

		// 获取接口的首个 DNS 地址
		SOCKADDR* dns_sa = adapter->FirstDnsServerAddress->Address.lpSockaddr;
		if (dns_sa->sa_family != AF_INET) continue;

		// 提取 DNS IP 地址（IPv4）
		IP4_ARRAY dnsServers;
		dnsServers.AddrCount = 1;
		dnsServers.AddrArray[0] = ((sockaddr_in*)dns_sa)->sin_addr.S_un.S_addr;

		// 遍历接口所有 IPv4 地址
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

	// 设置User-Agent和Accept头
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

	// 格式化为 [A-B-C-D]
	for (auto& c : response) if (c == '.') c = '-';
	return "[" + response + "]";
}

std::string get_resolvable_domain() {
	if (!g_resolvable_domain.empty()) return g_resolvable_domain;
	std::string fqdn = get_first_ipv4_and_resolvable_name();
	if (!fqdn.empty()) {
		// 将主机名部分替换为"dart-gateway"
		size_t dot = fqdn.find('.');
		std::string new_domain;
		if (dot != std::string::npos) {
			new_domain = "dart-gateway" + fqdn.substr(dot);

			// 查询新域名能否解析到IP
			struct addrinfo hints = {};
			hints.ai_family = AF_INET;
			struct addrinfo* res = nullptr;
			int ret = getaddrinfo(new_domain.c_str(), nullptr, &hints, &res);
			if (ret == 0 && res != nullptr) {
				freeaddrinfo(res);
				g_resolvable_domain = fqdn; // 使用PTR查询到的原始FQDN
				return g_resolvable_domain;
			}
		}
		// 否则 fallthrough 到 get_public_ip
	}
	g_resolvable_domain = get_public_ip();
	return g_resolvable_domain;
}


// 处理入站DNS报文
void handle_inbound_dns(char* packet, UINT packetLen, WINDIVERT_ADDRESS* addr) {
	printf("[INBOUND][DNS] Received DNS packet (%d bytes)\n", packetLen);

	// 1. 跳过IP和UDP头部，定位DNS数据
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

	// 2. 解析DNS头部
	if (payload_len < 12) return; // DNS头部12字节
	UINT8* dns = payload;
	UINT16 qdcount = (dns[4] << 8) | dns[5];
	UINT16 ancount = (dns[6] << 8) | dns[7];
	UINT8* p = dns + 12;
	UINT8* end = dns + payload_len;

	// 3. 跳过所有问题区(QNAME/QTYPE/QCLASS)
	for (int i = 0; i < qdcount; ++i) {
		// 跳过QNAME
		while (p < end && *p != 0) {
			if ((*p & 0xC0) == 0xC0) { // 指针
				p += 2;
				break;
			}
			p += (*p) + 1;
		}
		if (p < end && *p == 0) ++p; // 跳过0
		if (p + 4 > end) return; // QTYPE(2) + QCLASS(2)
		p += 4;
	}

	// 4. 遍历Answer区
	// 主逻辑：遍历Answer区
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

		if (type == 1 && class_ == 1 && rdlength == 4) { // A记录
			if (strncmp(name, "dart-gateway.", 13) != 0 && strncmp(name, "dart-host.", 10) != 0) {
				p += rdlength;
				continue;
			}

			uint32_t real_ip = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
			uint32_t pseudo_ip = allocate_pseudoip(first_name, real_ip);
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
			p += rdlength; // 跳过非 A 记录的数据
		}
	}

}


void hex_dump(char* packet, UINT packetLen) {
	// 以16进制形式打印报文内容，并且在右侧打印可打印字符
	const size_t bytes_per_line = 16;
	for (UINT i = 0; i < packetLen; i += bytes_per_line) {
		// 打印偏移
		printf("%04X  ", i);

		// 打印16字节的16进制
		for (size_t j = 0; j < bytes_per_line; ++j) {
			if (i + j < packetLen) {
				printf("%02X ", (unsigned char)packet[i + j]);
			}
			else {
				printf("   ");
			}
		}

		printf(" ");

		// 打印可打印字符
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

// 处理入站UDP 55847端口（DART协议）报文
void handle_inbound_dart(char* packet, UINT& packetLen, WINDIVERT_ADDRESS* addr) {
	printf("[INBOUND][UDP 55847] Received UDP 55847 packet (%d bytes)\n", packetLen);

	// 1. 解析IP和UDP头部，定位DART负载
	PWINDIVERT_IPHDR ip_header = NULL;
	PWINDIVERT_UDPHDR udp_header = NULL;
	UINT8* payload = NULL;
	UINT payload_len = 0;
	if (!WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL, NULL, NULL, NULL, NULL, &udp_header, (PVOID*)&payload, &payload_len, NULL, NULL)) {
		printf("Failed to parse packet headers\n");
		return;
	}
	if (!ip_header || !udp_header || !payload) {
		printf("Invalid DART packet\n");
		return;
	}

	// 2. 检查DART头部长度
	if (payload_len < sizeof(DartHeader)) {
		printf("DART header too short\n");
		return;
	}
	DartHeader* dart = (DartHeader*)payload;
	UINT8* dart_payload = payload + sizeof(DartHeader);

	// 3. 解析变长地址字段
	if (payload_len < sizeof(DartHeader) + dart->dst_addr_len + dart->src_addr_len) {
		printf("DART address fields too short\n");
		return;
	}
	const char* dst_addr = (const char*)(payload + sizeof(DartHeader));
	const char* src_addr = dst_addr + dart->dst_addr_len;
	// DART负载起始
	UINT8* dart_data = (UINT8*)(src_addr + dart->src_addr_len);
	UINT dart_data_len = static_cast<UINT>(payload_len - (dart_data - payload));

	// 提取源地址和目标地址为std::string
	std::string dst_addr_str(dst_addr, dart->dst_addr_len);
	std::string src_addr_str(src_addr, dart->src_addr_len);

	// 查询伪地址
	// 源IP为UDP包的源IP
	uint32_t src_ip = ntohl(ip_header->SrcAddr);
	uint32_t pseudo_ip = allocate_pseudoip(src_addr_str, src_ip);
	if (pseudo_ip == 0) {
		printf("Pseudo IP pool exhausted or allocation failed\n");
		return;
	}

	// 打印时
	printf("DART src_addr: %.*s, dst_addr: %.*s\n",
		dart->src_addr_len, src_addr,
		dart->dst_addr_len, dst_addr);

	// 5. 构造新的IP包（覆盖原始包内存）
	// 移动dart_data到UDP头后，覆盖原UDP负载
	size_t ip_header_len = sizeof(WINDIVERT_IPHDR);
	size_t new_payload_len = dart_data_len;
	size_t new_packet_len = ip_header_len + new_payload_len;

	// 修改IP头
	ip_header = (PWINDIVERT_IPHDR)packet;
	ip_header->SrcAddr = htonl(pseudo_ip);
	ip_header->Protocol = dart->protocol;
	ip_header->Length = htons((USHORT)(ip_header_len + new_payload_len));
	// 校验和置0，WinDivert会自动重算
	ip_header->Checksum = 0;

	// 只保留IP头，后面直接跟DART负载
	memmove(packet + ip_header_len, dart_data, dart_data_len);

	// 更新包长度，供主循环统一发送
	packetLen = (UINT)new_packet_len;

	hex_dump(packet, packetLen);
}

// 处理出站DHCP报文
void handle_outbound_dhcp(char* packet, UINT& packetLen, WINDIVERT_ADDRESS* addr) {
	printf("[OUTBOUND][DHCP] Sent DHCP packet (%d bytes)\n", packetLen);

	// 1. 解析IP和UDP头部，定位DHCP数据
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

	// 2. 检查DHCP报文最小长度（BOOTP固定部分）
	if (payload_len < 240) return; // 236字节BOOTP + 4字节Magic Cookie

	UINT8* dhcp = payload;
	UINT8* options = dhcp + 240;
	UINT options_len = payload_len - 240;

	// 3. 查找DHCP Message Type
	UINT8 dhcp_type = 0;
	UINT8* opt = options;
	UINT8* end = options + options_len;
	while (opt < end && *opt != 0xFF) { // 0xFF为option结束
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

	// 4. 仅处理DHCP Discover(1)和Request(3)
	if (dhcp_type != 1 && dhcp_type != 3) return;

	// 5. 检查是否已存在Option 224
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
	if (has_224) return; // 已有Option 224，无需添加

	// 6. 添加Option 224（"Dart:v1"），插入到0xFF结束符前
	const char dart_val[] = "Dart:v1";
	const UINT8 dart_opt_code = 224;
	const UINT8 dart_opt_len = sizeof(dart_val) - 1; // 不含\0
	UINT8 extra[2 + sizeof(dart_val) - 1 + 1]; // code+len+value+end
	extra[0] = dart_opt_code;
	extra[1] = dart_opt_len;
	memcpy(extra + 2, dart_val, dart_opt_len);
	extra[2 + dart_opt_len] = 0xFF; // 结束符

	// 找到0xFF结束符
	UINT8* ff = options;
	while (ff < end && *ff != 0xFF) {
		if (*ff == 0) { ff++; continue; }
		if (ff + 1 >= end) break;
		ff += 2 + ff[1];
	}
	if (ff >= end) return; // 没有找到结束符

	// 计算新包长度
	size_t before_ff = ff - payload;
	size_t after_ff = payload_len - before_ff - 1; // payload_len 是 DHCP 负载长度
	size_t new_len = before_ff + 2 + dart_opt_len + 1 + after_ff;

	// 移动后续数据，为Option 224腾出空间
	memmove(payload + before_ff + 2 + dart_opt_len + 1, payload + before_ff + 1, after_ff);
	// 插入Option 224和结束符
	memcpy(payload + before_ff, extra, 2 + dart_opt_len + 1);

	// 更新包长度
	packetLen += (2 + dart_opt_len); // 新增的Option长度

	// 更新IP和UDP长度字段
	if (ip_header) ip_header->Length = htons((USHORT)(packetLen));
	if (udp_header) udp_header->Length = htons((USHORT)(packetLen - sizeof(WINDIVERT_IPHDR)));

	printf("DHCP Option 224 (Dart:v1) added.\n");
}

// 处理出站目标为198.18.0.0/15的IP报文
void handle_outbound_to_pseudo_addr(char* packet, UINT& packetLen, WINDIVERT_ADDRESS* addr) {
	printf("[OUTBOUND][198.18.0.0/15] Sent IP packet to 198.18.0.0/15 (%d bytes)\n", packetLen);

	// 1. 解析IP头
	PWINDIVERT_IPHDR ip_header = NULL;
	WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	if (!ip_header) {
		printf("Invalid IP header\n");
		return;
	}

	uint32_t pseudo_ip = ntohl(ip_header->DstAddr);

	// 1.1 查找伪地址对应的域名和真实IP
	std::string domain;
	uint32_t real_ip = 0;
	if (!query_pseudoip(pseudo_ip, domain, real_ip)) {
		printf("Pseudo IP not found in mapping table\n");
		return;
	}

	// 2. 获取本机FQDN作为源地址
	std::string local_fqdn = get_resolvable_domain();

	// 3. 构造DART头
	DartHeader dart_hdr;
	dart_hdr.version = 1;
	dart_hdr.protocol = ip_header->Protocol;
	dart_hdr.dst_addr_len = (uint8_t)domain.size();
	dart_hdr.src_addr_len = (uint8_t)local_fqdn.size();

	// 4. 计算新包长度
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

	// 5. 移动原始负载，为UDP头+DART头腾出空间
	memmove(packet + ip_header_len + udp_header_len + dart_header_len,
		packet + ip_header_len,
		orig_payload_len);

	// 6. 构造UDP头
	PWINDIVERT_UDPHDR udp_header = (PWINDIVERT_UDPHDR)(packet + ip_header_len);
	udp_header->SrcPort = htons(DART_PORT);
	udp_header->DstPort = htons(DART_PORT);
	udp_header->Length = htons((USHORT)(udp_header_len + dart_header_len + orig_payload_len));
	udp_header->Checksum = 0; // 让WinDivert自动计算

	// 7. 构造DART头和地址
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

	// 8. 修改IP头
	ip_header = (PWINDIVERT_IPHDR)packet;
	ip_header->DstAddr = htonl(real_ip);
	ip_header->Protocol = 17; // UDP
	ip_header->Length = htons((USHORT)new_packet_len);
	ip_header->Checksum = 0; // 让WinDivert自动计算

	// 9. 更新包长度
	packetLen = (UINT)new_packet_len;
	printf("DART encapsulation packet ready to send...\n");
}

int main() {
	// 初始化 Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("WSAStartup failed\n");
		return -1;
	}

	get_resolvable_domain();

	HANDLE handle = WinDivertOpen(
		// 过滤入站DNS、入站UDP 55847、出站UDP 67/68（DHCP）、出站198.18.0.0/15、其他全部
		"(inbound and udp.DstPort == 53) or "
		"(inbound and udp.DstPort == 55847) or "
		"(inbound and udp.SrcPort == 55847) or "
		"(outbound and udp.SrcPort == 68 and udp.DstPort == 67) or "
		"(outbound and ip.DstAddr >= 198.18.0.0 and ip.DstAddr <= 198.19.255.255) or "
		"true",
		WINDIVERT_LAYER_NETWORK, 0, 0);
	if (handle == INVALID_HANDLE_VALUE) {
		printf("WinDivertOpen failed: %d\n", GetLastError());
		WSACleanup();
		return -1;
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
		WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL, NULL, NULL, NULL, NULL, &udp_header, NULL, NULL, NULL, NULL);

		if (addr.Outbound) {
			if (udp_header && ntohs(udp_header->SrcPort) == 68 && ntohs(udp_header->DstPort) == 67) {
				handle_outbound_dhcp(packet, packetLen, &addr);
			}
			else if (ip_header && is_pseudoip(ntohl(ip_header->DstAddr))) {
				handle_outbound_to_pseudo_addr(packet, packetLen, &addr);
			}
			else {
				// 其他出站报文直接放行
			}
		}
		else {
			if (udp_header && ntohs(udp_header->SrcPort) == 53) {
				handle_inbound_dns(packet, packetLen, &addr);
			}
			else if (udp_header && ntohs(udp_header->DstPort) == 55847) {
				handle_inbound_dart(packet, packetLen, &addr);
			}
			else {
				// 其他入站报文直接放行
			}
		}


		// 放行所有报文
		if (!WinDivertSend(handle, packet, packetLen, NULL, &addr)) {
			printf("WinDivertSend failed: %d\n", GetLastError());
		}
	}

	WinDivertClose(handle);
	WSACleanup(); // 程序结束时清理
	return 0;
}





