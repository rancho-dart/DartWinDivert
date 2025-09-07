// Copyright (c) 2025 rancho.dart@qq.com
// Licensed under the MIT License. See LICENSE file for details.

#include "include/DartHeader.h"

// Calculate the total length of DartHeader (including variable-length address fields)
uint16_t DartHeaderLength(const DartHeader* header) {
    if (!header) return 0;
    return sizeof(DartHeader) + header->dst_addr_len + header->src_addr_len;
}

