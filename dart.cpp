#include "DartHeader.h"

// ����DartHeader�ܳ��ȣ����䳤��ַ�ֶΣ�
size_t DartHeaderLength(const DartHeader* header) {
    if (!header) return 0;
    return sizeof(DartHeader) + header->dst_addr_len + header->src_addr_len;
}

