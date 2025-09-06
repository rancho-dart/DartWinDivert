#pragma once

#include <cstdint>

#define MAX_PACKET_SIZE 0x10000

// Define cross-platform packed macros
#if defined(_MSC_VER)
    #define PACKED_STRUCT __pragma(pack(push, 1))
    #define END_PACKED_STRUCT __pragma(pack(pop))
#elif defined(__GNUC__) || defined(__clang__)
    #define PACKED_STRUCT
    #define END_PACKED_STRUCT __attribute__((__packed__))
#else
    #error "Unsupported compiler for packed struct"
#endif

// DART protocol header definition
PACKED_STRUCT
struct DartHeader {
    uint8_t version;         // Version number
    uint8_t protocol;        // Protocol number
    uint8_t dst_addr_len;    // Destination address length
    uint8_t src_addr_len;    // Source address length
    // Immediately followed by destination address string and source address string (without \0, length specified by the above fields)
    // char dst_addr[dst_addr_len];
    // char src_addr[src_addr_len];
} END_PACKED_STRUCT;

uint16_t DartHeaderLength(const DartHeader* header);