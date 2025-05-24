#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdio>
#include "windivert.h"
#include "pseudoip.h"
#include "DartHeader.h"

#pragma comment(lib, "ws2_32.lib")


// ������վDNS����
void handle_inbound_dns(char *packet, UINT packetLen, WINDIVERT_ADDRESS *addr) {
    printf("[INBOUND][DNS] Received DNS packet (%d bytes)\n", packetLen);

    // 1. ����IP��UDPͷ������λDNS����
    PWINDIVERT_IPHDR ip_header = NULL;
    PWINDIVERT_UDPHDR udp_header = NULL;
    UINT8 *payload = NULL;
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
    UINT8 *dns = payload;
    UINT16 qdcount = (dns[4] << 8) | dns[5];
    UINT16 ancount = (dns[6] << 8) | dns[7];
    UINT8 *p = dns + 12;
    UINT8 *end = dns + payload_len;

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

    // 4. ����Answer��������A��¼���滻
    for (int i = 0; i < ancount; ++i) {
        UINT8 *rr_start = p;
        if (p >= end) break;

        // ����NAME
        if ((*p & 0xC0) == 0xC0) {
            p += 2;
        } else {
            while (p < end && *p != 0) {
                p += (*p) + 1;
            }
            if (p < end && *p == 0) ++p;
        }
        if (p + 10 > end) break; // TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2)
        UINT16 type = (p[0] << 8) | p[1];
        UINT16 class_ = (p[2] << 8) | p[3];
        UINT16 rdlength = (p[8] << 8) | p[9];
        p += 10;

        if (type == 1 && class_ == 1 && rdlength == 4 && p + 4 <= end) { // A��¼
            // ��ȡA��¼����
            char name[256] = {0};
            UINT8 *name_ptr = rr_start;
            int name_len = 0;
            UINT8 *dns_base = dns;
            // ����NAME��֧��ָ��ͱ�ǩ��
            int jumped = 0, offset = 0;
            while (name_ptr < end && name_len < 255) {
                if ((*name_ptr & 0xC0) == 0xC0) {
                    if (!jumped) offset = (int)(name_ptr - dns_base + 2);
                    int ptr = ((name_ptr[0] & 0x3F) << 8) | name_ptr[1];
                    name_ptr = dns_base + ptr;
                    jumped = 1;
                } else if (*name_ptr == 0) {
                    if (!jumped) offset = (int)(name_ptr - dns_base + 1);
                    break;
                } else {
                    int len = *name_ptr++;
                    if (name_len && name_len < 255) name[name_len++] = '.';
                    for (int j = 0; j < len && name_len < 255 && name_ptr < end; ++j) {
                        name[name_len++] = *name_ptr++;
                    }
                }
            }
            name[name_len] = 0;

            // ֻ������"dart-gateway."��"dart-host."��ͷ��A��¼
            if (strncmp(name, "dart-gateway.", 13) != 0 && strncmp(name, "dart-host.", 10) != 0) {
                p += 4;
                continue;
            }

            // ��ȡԭʼIP
            uint32_t real_ip = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
            // ����α��ַ
            uint32_t pseudo_ip = allocate_pseudoip(name, real_ip);
            if (pseudo_ip != 0) {
                // �滻A��¼IP
                p[0] = (pseudo_ip >> 24) & 0xFF;
                p[1] = (pseudo_ip >> 16) & 0xFF;
                p[2] = (pseudo_ip >> 8) & 0xFF;
                p[3] = (pseudo_ip) & 0xFF;
                printf("A record: %s, real IP: %u.%u.%u.%u -> pseudo IP: %u.%u.%u.%u\n",
                    name,
                    (real_ip >> 24) & 0xFF, (real_ip >> 16) & 0xFF, (real_ip >> 8) & 0xFF, real_ip & 0xFF,
                    (pseudo_ip >> 24) & 0xFF, (pseudo_ip >> 16) & 0xFF, (pseudo_ip >> 8) & 0xFF, pseudo_ip & 0xFF
                );
            }
            p += 4;
        } else {
            p += rdlength;
        }
    }
}

// ������վUDP 55847�˿ڣ�DARTЭ�飩����
void handle_inbound_dart(char *packet, UINT &packetLen, WINDIVERT_ADDRESS *addr) {
    printf("[INBOUND][UDP 55847] Received UDP 55847 packet (%d bytes)\n", packetLen);

    // 1. ����IP��UDPͷ������λDART����
    PWINDIVERT_IPHDR ip_header = NULL;
    PWINDIVERT_UDPHDR udp_header = NULL;
    UINT8 *payload = NULL;
    UINT payload_len = 0;
    if (!WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL, NULL,NULL,NULL,NULL, &udp_header, (PVOID*)&payload, &payload_len, NULL,NULL)) {
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
    DartHeader *dart = (DartHeader*)payload;
    UINT8 *dart_payload = payload + sizeof(DartHeader);

    // 3. �����䳤��ַ�ֶ�
    if (payload_len < sizeof(DartHeader) + dart->dst_addr_len + dart->src_addr_len) {
        printf("DART address fields too short\n");
        return;
    }
    const char *dst_addr = (const char *)(payload + sizeof(DartHeader));
    const char *src_addr = dst_addr + dart->dst_addr_len;
    // DART������ʼ
    UINT8 *dart_data = (UINT8 *)(src_addr + dart->src_addr_len);
    UINT dart_data_len = static_cast<UINT>(payload_len - (dart_data - payload));

    // ��ȡԴ��ַ��Ŀ���ַΪstd::string
    std::string dst_addr_str(dst_addr, dart->dst_addr_len);
    std::string src_addr_str(src_addr, dart->src_addr_len);

    // ��ѯα��ַ
    // ԴIPΪUDP����ԴIP
    uint32_t src_ip = ntohl(ip_header->SrcAddr);
    uint32_t pseudo_ip = allocate_pseudoip(src_addr_str, src_ip);
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

    // ֻ����IPͷ������ֱ�Ӹ�DART����
    memmove(packet + ip_header_len, dart_data, dart_data_len);

    // �޸�IPͷ
    ip_header = (PWINDIVERT_IPHDR)packet;
    ip_header->SrcAddr = htonl(pseudo_ip);
    ip_header->Protocol = dart->protocol;
    ip_header->Length = htons((USHORT)(ip_header_len + new_payload_len));
    // У�����0��WinDivert���Զ�����
    ip_header->Checksum = 0;

    // ���°����ȣ�����ѭ��ͳһ����
    packetLen = (UINT)new_packet_len;
}

// �����վDHCP����
void handle_outbound_dhcp(char* packet, UINT& packetLen, WINDIVERT_ADDRESS* addr) {
    printf("[OUTBOUND][DHCP] Sent DHCP packet (%d bytes)\n", packetLen);

    // 1. ����IP��UDPͷ������λDHCP����
    PWINDIVERT_IPHDR ip_header = NULL;
    PWINDIVERT_UDPHDR udp_header = NULL;
    UINT8* payload = NULL;
    UINT payload_len = 0;
    if (!WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL, NULL,NULL, NULL,NULL, &udp_header, (PVOID*)&payload, &payload_len,NULL,NULL)) {
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

// ��ȡ����FQDN��ȫ�޶���������δʵ��
std::string get_local_fqdn() {
    // TODO: ʵ�ֻ�ȡ����FQDN���߼�
    return std::string();
}

// �����վĿ��Ϊ198.18.0.0/15��IP����
void handle_outbound_to_pseudo_addr(char* packet, UINT& packetLen, WINDIVERT_ADDRESS* addr) {
    printf("[OUTBOUND][198.18.0.0/15] Sent IP packet to 198.18.0.0/15 (%d bytes)\n", packetLen);

    // 1. ����IPͷ
    PWINDIVERT_IPHDR ip_header = NULL;
    WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    if (!ip_header) {
        printf("Invalid IP header\n");
        return;
    }

    uint32_t pseudo_ip = ntohl(ip_header->DstAddr);

    // 1.1 ����α��ַ��Ӧ����������ʵIP
    std::string domain;
    uint32_t real_ip = 0;
    if (!query_pseudoip(pseudo_ip, domain, real_ip)) {
        printf("Pseudo IP not found in mapping table\n");
        return;
    }

    // 2. ��ȡ����FQDN��ΪԴ��ַ
    std::string local_fqdn = get_local_fqdn();

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

    // 5. �ƶ�ԭʼ���أ�ΪUDPͷ+DARTͷ�ڳ��ռ�
    memmove(packet + ip_header_len + udp_header_len + dart_header_len,
        packet + ip_header_len,
        orig_payload_len);

    // 6. ����UDPͷ
    PWINDIVERT_UDPHDR udp_header = (PWINDIVERT_UDPHDR)(packet + ip_header_len);
    udp_header->SrcPort = htons(DART_PORT);
    udp_header->DstPort = htons(DART_PORT);
    udp_header->Length = htons((USHORT)(udp_header_len + dart_header_len + orig_payload_len));
    udp_header->Checksum = 0; // ��WinDivert�Զ�����

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
    ip_header->Checksum = 0; // ��WinDivert�Զ�����

    // 9. ���°�����
    packetLen = (UINT)new_packet_len;
}

int main() {
    HANDLE handle = WinDivertOpen(
        // ������վDNS����վUDP 55847����վUDP 67/68��DHCP������վ198.18.0.0/15������ȫ��
        "(inbound and udp.DstPort == 53) or "
        "(inbound and udp.DstPort == 55847) or "
        "(outbound and udp.SrcPort == 68 and udp.DstPort == 67) or "
        "(outbound and ip.DstAddr >= 198.18.0.0 and ip.DstAddr <= 198.19.255.255) or "
        "true",
        WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        printf("WinDivertOpen failed: %d\n", GetLastError());
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
            } else if (ip_header && is_pseudoip(ntohl(ip_header->DstAddr))) {
                handle_outbound_to_pseudo_addr(packet, packetLen, &addr);
            } else {
                // ������վ����ֱ�ӷ���
            }
        } else {
            if (udp_header && ntohs(udp_header->DstPort) == 53) {
                handle_inbound_dns(packet, packetLen, &addr);
            } else if (udp_header && ntohs(udp_header->DstPort) == 55847) {
                handle_inbound_dart(packet, packetLen, &addr);
            } else {
                // ������վ����ֱ�ӷ���
            }
        } 


        // �������б���
        if (!WinDivertSend(handle, packet, packetLen, NULL, &addr)) {
            printf("WinDivertSend failed: %d\n", GetLastError());
        }
    }

    WinDivertClose(handle);
    return 0;
}