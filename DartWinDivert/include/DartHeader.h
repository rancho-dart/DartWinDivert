#pragma once

#include <cstdint>

#define MAX_PACKET_SIZE 0x10000

// �����ƽ̨�� packed ��
#if defined(_MSC_VER)
    #define PACKED_STRUCT __pragma(pack(push, 1))
    #define END_PACKED_STRUCT __pragma(pack(pop))
#elif defined(__GNUC__) || defined(__clang__)
    #define PACKED_STRUCT
    #define END_PACKED_STRUCT __attribute__((__packed__))
#else
    #error "Unsupported compiler for packed struct"
#endif

// DARTЭ�鱨ͷ����
PACKED_STRUCT
struct DartHeader {
    uint8_t version;         // �汾��
    uint8_t protocol;        // Э���
    uint8_t dst_addr_len;    // Ŀ���ַ����
    uint8_t src_addr_len;    // Դ��ַ����
    // ��������Ŀ���ַ�ַ�����Դ��ַ�ַ�����������\0�������������ֶ�ָ����
    // char dst_addr[dst_addr_len];
    // char src_addr[src_addr_len];
} END_PACKED_STRUCT;

uint16_t DartHeaderLength(const DartHeader* header);