#include "DartHeader.h"

// 计算DartHeader总长度（含变长地址字段）
size_t DartHeaderLength(const DartHeader* header) {
    if (!header) return 0;
    return sizeof(DartHeader) + header->dst_addr_len + header->src_addr_len;
}

