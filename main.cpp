#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdio>
#include "windivert.h"
#include "pseudoip.h"
#include "DartHeader.h"

#pragma comment(lib, "ws2_32.lib")


// 处理入站DNS报文
void handle_inbound_dns(char *packet, UINT packetLen, WINDIVERT_ADDRESS *addr) {
    printf("[INBOUND][DNS] Received DNS packet (%d bytes)\n", packetLen);

    // 1. 跳过IP和UDP头部，定位DNS数据
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

    // 2. 解析DNS头部
    if (payload_len < 12) return; // DNS头部12字节
    UINT8 *dns = payload;
    UINT16 qdcount = (dns[4] << 8) | dns[5];
    UINT16 ancount = (dns[6] << 8) | dns[7];
    UINT8 *p = dns + 12;
    UINT8 *end = dns + payload_len;

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

    // 4. 遍历Answer区，查找A记录并替换
    for (int i = 0; i < ancount; ++i) {
        UINT8 *rr_start = p;
        if (p >= end) break;

        // 跳过NAME
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

        if (type == 1 && class_ == 1 && rdlength == 4 && p + 4 <= end) { // A记录
            // 提取A记录名称
            char name[256] = {0};
            UINT8 *name_ptr = rr_start;
            int name_len = 0;
            UINT8 *dns_base = dns;
            // 解析NAME（支持指针和标签）
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

            // 只处理以"dart-gateway."或"dart-host."开头的A记录
            if (strncmp(name, "dart-gateway.", 13) != 0 && strncmp(name, "dart-host.", 10) != 0) {
                p += 4;
                continue;
            }

            // 提取原始IP
            uint32_t real_ip = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
            // 申请伪地址
            uint32_t pseudo_ip = allocate_pseudoip(name, real_ip);
            if (pseudo_ip != 0) {
                // 替换A记录IP
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

// 处理入站UDP 55847端口（DART协议）报文
void handle_inbound_dart(char *packet, UINT &packetLen, WINDIVERT_ADDRESS *addr) {
    printf("[INBOUND][UDP 55847] Received UDP 55847 packet (%d bytes)\n", packetLen);

    // 1. 解析IP和UDP头部，定位DART负载
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

    // 2. 检查DART头部长度
    if (payload_len < sizeof(DartHeader)) {
        printf("DART header too short\n");
        return;
    }
    DartHeader *dart = (DartHeader*)payload;
    UINT8 *dart_payload = payload + sizeof(DartHeader);

    // 3. 解析变长地址字段
    if (payload_len < sizeof(DartHeader) + dart->dst_addr_len + dart->src_addr_len) {
        printf("DART address fields too short\n");
        return;
    }
    const char *dst_addr = (const char *)(payload + sizeof(DartHeader));
    const char *src_addr = dst_addr + dart->dst_addr_len;
    // DART负载起始
    UINT8 *dart_data = (UINT8 *)(src_addr + dart->src_addr_len);
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

    // 只保留IP头，后面直接跟DART负载
    memmove(packet + ip_header_len, dart_data, dart_data_len);

    // 修改IP头
    ip_header = (PWINDIVERT_IPHDR)packet;
    ip_header->SrcAddr = htonl(pseudo_ip);
    ip_header->Protocol = dart->protocol;
    ip_header->Length = htons((USHORT)(ip_header_len + new_payload_len));
    // 校验和置0，WinDivert会自动重算
    ip_header->Checksum = 0;

    // 更新包长度，供主循环统一发送
    packetLen = (UINT)new_packet_len;
}

// 处理出站DHCP报文
void handle_outbound_dhcp(char* packet, UINT& packetLen, WINDIVERT_ADDRESS* addr) {
    printf("[OUTBOUND][DHCP] Sent DHCP packet (%d bytes)\n", packetLen);

    // 1. 解析IP和UDP头部，定位DHCP数据
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

// 获取本机FQDN（全限定域名），未实现
std::string get_local_fqdn() {
    // TODO: 实现获取本机FQDN的逻辑
    return std::string();
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
    std::string local_fqdn = get_local_fqdn();

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
}

int main() {
    HANDLE handle = WinDivertOpen(
        // 过滤入站DNS、入站UDP 55847、出站UDP 67/68（DHCP）、出站198.18.0.0/15、其他全部
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
                // 其他出站报文直接放行
            }
        } else {
            if (udp_header && ntohs(udp_header->DstPort) == 53) {
                handle_inbound_dns(packet, packetLen, &addr);
            } else if (udp_header && ntohs(udp_header->DstPort) == 55847) {
                handle_inbound_dart(packet, packetLen, &addr);
            } else {
                // 其他入站报文直接放行
            }
        } 


        // 放行所有报文
        if (!WinDivertSend(handle, packet, packetLen, NULL, &addr)) {
            printf("WinDivertSend failed: %d\n", GetLastError());
        }
    }

    WinDivertClose(handle);
    return 0;
}