#pragma once

#include <string>
#include <cstdint>
#include <unordered_map>
#include <chrono>
#include <algorithm>
#include <mutex>

// 伪地址池范围常量
constexpr uint32_t PSEUDOIP_START = 0xC6130000; // 198.19.0.0
constexpr uint32_t PSEUDOIP_END   = 0xC613FFFF; // 198.19.255.255
constexpr uint32_t PSEUDOIP_MASK  = 0XFFFF0000; // 255.255.0.0
constexpr uint32_t PSEUDOIP_POOL_SIZE = PSEUDOIP_END - PSEUDOIP_START + 1;

// 分配生存期（秒）
constexpr int PSEUDOIP_TTL = 300;
constexpr int DART_PORT = 0XDA27; // DART协议端口号

// 分配伪地址：输入域名和真实IP，返回伪地址（0表示分配失败）
uint32_t allocate_pseudoip(const std::string& domain, uint32_t real_ip);

// 查询伪地址对应的域名和真实IP，返回true表示查到且未过期
bool query_pseudoip(uint32_t pseudoip, std::string& domain, uint32_t& real_ip);


// 查询域名和真实IP对应的伪地址（未过期），查不到返回0
uint32_t query_pseudoip_by_domain(const std::string& domain, uint32_t real_ip);

// 清理所有过期的分配记录
void cleanup_expired_pseudoip();

// 判断一个IP是否属于伪地址池（198.18.0.0/15）
bool is_pseudoip(uint32_t ip);