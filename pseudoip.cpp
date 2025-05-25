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

static std::unordered_map<uint32_t, PseudoIpRecord> pseudoip_map; // α��ַ -> ��¼
static std::unordered_map<std::string, uint32_t> domain_ip_map;   // ����+��ʵIP -> α��ַ
static uint32_t next_alloc = PSEUDOIP_START;

// ��������������������ʵIPƴ��ΪΨһkey
static std::string make_key(const std::string& domain, uint32_t real_ip) {
    return domain + "#" + std::to_string(real_ip);
}

// �ж�һ��IP�Ƿ�����α��ַ�أ�198.18.0.0/15��
bool is_pseudoip(uint32_t ip) {
    return (ip & PSEUDOIP_MASK) == PSEUDOIP_START;
}

// �ڲ��������������Է���һ��α��ַ���ɹ�����α��ַ�����򷵻�0
static uint32_t try_allocate_pseudoip(const std::string& domain, uint32_t real_ip, std::chrono::steady_clock::time_point now) {
    std::string key = make_key(domain, real_ip);
    for (uint32_t i = 0; i < PSEUDOIP_POOL_SIZE; ++i) {
        uint32_t candidate = PSEUDOIP_START + ((next_alloc - PSEUDOIP_START + i) % PSEUDOIP_POOL_SIZE);
        auto rec = pseudoip_map.find(candidate);
        if (rec == pseudoip_map.end() || rec->second.expire_time <= now) {
            // ����
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

// �޸� allocate_pseudoip ������ domain �Ĵ���ʽ������ֱ���޸� const std::string& ����  
uint32_t allocate_pseudoip(const std::string& domain, uint32_t real_ip) {  
    auto now = std::chrono::steady_clock::now();  
    std::string mutable_domain = domain; // ����һ�����޸ĵĸ���  
    // �����������.��β�������һ����  
    if (mutable_domain.back() != '.') {  
        mutable_domain += '.';  
    }  

    std::string key = make_key(mutable_domain, real_ip);  

    // �ѷ������ˢ�·���ʱ�䲢����  
    auto it = domain_ip_map.find(key);  
    if (it != domain_ip_map.end()) {  
        uint32_t pseudoip = it->second;  
        // ����Ƿ����  
        auto rec_it = pseudoip_map.find(pseudoip);  
        if (rec_it != pseudoip_map.end() && rec_it->second.expire_time > now) {  
            // ˢ�·���ʱ��  
            rec_it->second.expire_time = now + std::chrono::seconds(PSEUDOIP_TTL);  
            return pseudoip;  
        }  
        // ����������  
        pseudoip_map.erase(pseudoip);  
        domain_ip_map.erase(it);  
    }  

    // ��һ�γ��Է���  
    uint32_t result = try_allocate_pseudoip(mutable_domain, real_ip, now);  
    if (result != 0) return result;  

    // ������������������ݺ��ٳ���һ��  
    cleanup_expired_pseudoip();  
    now = std::chrono::steady_clock::now();  
    return try_allocate_pseudoip(mutable_domain, real_ip, now);  
}

// ��ѯα��ַ��Ӧ����������ʵIP
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

// ��ѯ������Ӧ��α��ַ��δ���ڣ����鲻������0
uint32_t query_pseudoip_by_domain(const std::string& domain) {
    auto now = std::chrono::steady_clock::now();
    // ���� domain_ip_map������������ domain# ��ͷ�� key
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

// ��ѯ��������ʵIP��Ӧ��α��ַ��δ���ڣ����鲻������0
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

// �������й��ڵķ����¼
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
