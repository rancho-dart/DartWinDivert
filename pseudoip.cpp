#include <unordered_map>
#include <string>
#include <chrono>
#include <cstdint>
#include <vector>
#include <algorithm>
#include "pseudoip.h"


struct PseudoIpRecord {
    std::string domain;
    uint32_t real_ip;
    std::chrono::steady_clock::time_point expire_time;
};

static std::unordered_map<uint32_t, PseudoIpRecord> pseudoip_map; // 伪地址 -> 记录
static std::unordered_map<std::string, uint32_t> domain_ip_map;   // 域名+真实IP -> 伪地址
static uint32_t next_alloc = PSEUDOIP_START;

// 辅助函数：将域名和真实IP拼接为唯一key
static std::string make_key(const std::string& domain, uint32_t real_ip) {
    return domain + "#" + std::to_string(real_ip);
}

// 判断一个IP是否属于伪地址池（198.18.0.0/15）
bool is_pseudoip(uint32_t ip) {
    return (ip & PSEUDOIP_MASK) == PSEUDOIP_START;
}

// 内部辅助函数：尝试分配一个伪地址，成功返回伪地址，否则返回0
static uint32_t try_allocate_pseudoip(const std::string& domain, uint32_t real_ip, std::chrono::steady_clock::time_point now) {
    std::string key = make_key(domain, real_ip);
    for (uint32_t i = 0; i < PSEUDOIP_POOL_SIZE; ++i) {
        uint32_t candidate = PSEUDOIP_START + ((next_alloc - PSEUDOIP_START + i) % PSEUDOIP_POOL_SIZE);
        auto rec = pseudoip_map.find(candidate);
        if (rec == pseudoip_map.end() || rec->second.expire_time <= now) {
            // 分配
            pseudoip_map[candidate] = PseudoIpRecord{
                domain,
                real_ip,
                now + std::chrono::seconds(PSEUDOIP_TTL)
            };
            domain_ip_map[key] = candidate;
            next_alloc = candidate + 1;
            return candidate;
        }
    }
    return 0;
}

// 修改 allocate_pseudoip 函数中 domain 的处理方式，避免直接修改 const std::string& 参数  
uint32_t allocate_pseudoip(const std::string& domain, uint32_t real_ip) {  
    auto now = std::chrono::steady_clock::now();  
    std::string mutable_domain = domain; // 创建一个可修改的副本  
    // 如果域名不以.结尾，则添加一个点  
    if (mutable_domain.back() != '.') {  
        mutable_domain += '.';  
    }  

    std::string key = make_key(mutable_domain, real_ip);  

    // 已分配过，刷新分配时间并返回  
    auto it = domain_ip_map.find(key);  
    if (it != domain_ip_map.end()) {  
        uint32_t pseudoip = it->second;  
        // 检查是否过期  
        auto rec_it = pseudoip_map.find(pseudoip);  
        if (rec_it != pseudoip_map.end() && rec_it->second.expire_time > now) {  
            // 刷新分配时间  
            rec_it->second.expire_time = now + std::chrono::seconds(PSEUDOIP_TTL);  
            return pseudoip;  
        }  
        // 过期则清理  
        pseudoip_map.erase(pseudoip);  
        domain_ip_map.erase(it);  
    }  

    // 第一次尝试分配  
    uint32_t result = try_allocate_pseudoip(mutable_domain, real_ip, now);  
    if (result != 0) return result;  

    // 池已满，清理过期数据后再尝试一次  
    cleanup_expired_pseudoip();  
    now = std::chrono::steady_clock::now();  
    return try_allocate_pseudoip(mutable_domain, real_ip, now);  
}

// 查询伪地址对应的域名和真实IP
bool query_pseudoip(uint32_t pseudoip, std::string& domain, uint32_t& real_ip) {
    auto now = std::chrono::steady_clock::now();
    auto it = pseudoip_map.find(pseudoip);
    if (it != pseudoip_map.end() && it->second.expire_time > now) {
        domain = it->second.domain;
        real_ip = it->second.real_ip;
        return true;
    }
    return false;
}

// 查询域名对应的伪地址（未过期），查不到返回0
uint32_t query_pseudoip_by_domain(const std::string& domain) {
    auto now = std::chrono::steady_clock::now();
    // 遍历 domain_ip_map，查找所有以 domain# 开头的 key
    for (const auto& kv : domain_ip_map) {
        const std::string& key = kv.first;
        size_t pos = key.find('#');
        if (pos != std::string::npos && key.substr(0, pos) == domain) {
            uint32_t pseudoip = kv.second;
            auto it = pseudoip_map.find(pseudoip);
            if (it != pseudoip_map.end() && it->second.expire_time > now) {
                return pseudoip;
            }
        }
    }
    return 0;
}

// 查询域名和真实IP对应的伪地址（未过期），查不到返回0
uint32_t query_pseudoip_by_domain(const std::string& domain, uint32_t real_ip) {
    auto now = std::chrono::steady_clock::now();
    std::string key = make_key(domain, real_ip);
    auto it = domain_ip_map.find(key);
    if (it != domain_ip_map.end()) {
        uint32_t pseudoip = it->second;
        auto rec_it = pseudoip_map.find(pseudoip);
        if (rec_it != pseudoip_map.end() && rec_it->second.expire_time > now) {
            return pseudoip;
        }
    }
    return 0;
}

// 清理所有过期的分配记录
void cleanup_expired_pseudoip() {
    auto now = std::chrono::steady_clock::now();
    std::vector<uint32_t> expired;
    for (const auto& kv : pseudoip_map) {
        if (kv.second.expire_time <= now) {
            expired.push_back(kv.first);
        }
    }
    for (uint32_t ip : expired) {
        std::string key = make_key(pseudoip_map[ip].domain, pseudoip_map[ip].real_ip);
        pseudoip_map.erase(ip);
        domain_ip_map.erase(key);
    }
}
