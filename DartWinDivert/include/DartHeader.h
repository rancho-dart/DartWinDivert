#pragma once

#include <cstdint>

#define MAX_PACKET_SIZE 0x10000

// 定义跨平台的 packed 宏
#if defined(_MSC_VER)
    #define PACKED_STRUCT __pragma(pack(push, 1))
    #define END_PACKED_STRUCT __pragma(pack(pop))
#elif defined(__GNUC__) || defined(__clang__)
    #define PACKED_STRUCT
    #define END_PACKED_STRUCT __attribute__((__packed__))
#else
    #error "Unsupported compiler for packed struct"
#endif

// DART协议报头定义
PACKED_STRUCT
struct DartHeader {
    uint8_t version;         // 版本号
    uint8_t protocol;        // 协议号
    uint8_t dst_addr_len;    // 目标地址长度
    uint8_t src_addr_len;    // 源地址长度
    // 紧接着是目标地址字符串和源地址字符串（不包含\0，长度由上面字段指定）
    // char dst_addr[dst_addr_len];
    // char src_addr[src_addr_len];
} END_PACKED_STRUCT;

uint16_t DartHeaderLength(const DartHeader* header);