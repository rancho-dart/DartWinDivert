#include <unordered_map>
#include <string>
#include <chrono>
#include <cstdint>
#include <vector>
#include <algorithm>
#include "include/pseudoip.h"

struct PseudoIpRecord {
    std::string domain;
    uint32_t real_ip;
    uint16_t port;
    std::chrono::steady_clock::time_point expire_time;
};

static std::mutex pseudoip_mutex;
static std::unordered_map<uint32_t, PseudoIpRecord> pseudoip_map; // 伪地址 -> 记录
static std::unordered_map<std::string, uint32_t> domain_ip_port_map; // 域名+真实IP+端口 -> 伪地址
static uint32_t next_alloc = PSEUDOIP_START;

// 辅助函数：将域名、真实IP和端口拼接为唯一key
static std::string make_key(const std::string& domain, uint32_t real_ip, uint16_t port) {
    return domain + "#" + std::to_string(real_ip) + "#" + std::to_string(port);
}

// 判断一个IP是否属于伪地址池（198.18.0.0/15）
bool is_pseudoip(uint32_t ip) {
    return (ip & PSEUDOIP_MASK) == PSEUDOIP_START;
}

// 内部辅助函数：尝试分配一个伪地址，成功返回伪地址，否则返回0
static uint32_t try_allocate_pseudoip(const std::string& domain, uint32_t real_ip, uint16_t port, std::chrono::steady_clock::time_point now) {
    std::string key = make_key(domain, real_ip, port);
    for (uint32_t i = 0; i < PSEUDOIP_POOL_SIZE; ++i) {
        uint32_t candidate = PSEUDOIP_START + ((next_alloc - PSEUDOIP_START + i) % PSEUDOIP_POOL_SIZE);
        auto rec = pseudoip_map.find(candidate);
        if (rec == pseudoip_map.end() || rec->second.expire_time <= now) {
            // 分配
            pseudoip_map[candidate] = PseudoIpRecord{
                domain,
                real_ip,
                port,
                now + std::chrono::seconds(PSEUDOIP_TTL)
            };
            domain_ip_port_map[key] = candidate;
            next_alloc = candidate + 1;
            return candidate;
        }
    }
    return 0;
}

// 修改 allocate_pseudoip 函数中 domain 的处理方式，避免直接修改 const std::string& 参数  
uint32_t allocate_pseudoip(const std::string& domain, uint32_t real_ip, uint16_t port) {  
	// 保留域名、真实IP与伪地址的映射关系，这样我们收到发往伪地址的报文的时候可以还原真实的IP和DART报头的目标地址。
	// 为什么要把端口也包含在内？因为一个DART报文从一个NAT网关出来的时候，UDP的源端口会被修改，所以我们需要记录这个端口。
	// 这样，在构造返回报文的时候将其作为目标端口，DART报文才能够穿越NAT网关正确返回。
    std::lock_guard<std::mutex> lock(pseudoip_mutex);

    auto now = std::chrono::steady_clock::now();  
    std::string mutable_domain = domain; // 创建一个可修改的副本  
    // 如果域名不以.结尾，则添加一个点  
    if (mutable_domain.back() != '.') {  
        mutable_domain += '.';  
    }  

    std::string key = make_key(mutable_domain, real_ip, port);  

    // 已分配过，刷新分配时间并返回  
    auto it = domain_ip_port_map.find(key);  
    if (it != domain_ip_port_map.end()) {  
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
        domain_ip_port_map.erase(it);  
    }  

    // 第一次尝试分配  
    uint32_t result = try_allocate_pseudoip(mutable_domain, real_ip, port, now);  
    if (result != 0) return result;  

    // 池已满，清理过期数据后再尝试一次  
    cleanup_expired_pseudoip();  
    now = std::chrono::steady_clock::now();  
    return try_allocate_pseudoip(mutable_domain, real_ip, port, now);  
}

// 查询伪地址对应的域名、真实IP和端口
bool query_by_pseudoip(uint32_t pseudoip, std::string& domain, uint32_t& real_ip, uint16_t& port) {
    std::lock_guard<std::mutex> lock(pseudoip_mutex);

    auto now = std::chrono::steady_clock::now();
    auto it = pseudoip_map.find(pseudoip);
    if (it != pseudoip_map.end() && it->second.expire_time > now) {
        domain = it->second.domain;
        real_ip = it->second.real_ip;
        port = it->second.port;
        return true;
    }
    return false;
}

// 查询域名、真实IP和端口对应的伪地址（未过期），查不到返回0
uint32_t query_pseudoip_by_domain(const std::string& domain, uint32_t real_ip, uint16_t port) {
    std::lock_guard<std::mutex> lock(pseudoip_mutex);
    
    auto now = std::chrono::steady_clock::now();
    std::string key = make_key(domain, real_ip, port);
    auto it = domain_ip_port_map.find(key);
    if (it != domain_ip_port_map.end()) {
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
    std::lock_guard<std::mutex> lock(pseudoip_mutex);
    
    auto now = std::chrono::steady_clock::now();
    std::vector<uint32_t> expired;
    for (const auto& kv : pseudoip_map) {
        if (kv.second.expire_time <= now) {
            expired.push_back(kv.first);
        }
    }
    for (uint32_t ip : expired) {
        std::string key = make_key(pseudoip_map[ip].domain, pseudoip_map[ip].real_ip, pseudoip_map[ip].port);
        pseudoip_map.erase(ip);
        domain_ip_port_map.erase(key);
    }
}


static std::atomic<bool> cleanup_thread_running{ false };
static std::thread cleanup_thread;

// 定时任务线程函数
static void cleanup_expired_pseudoip_periodic() {
    using namespace std::chrono_literals;
    while (cleanup_thread_running) {
        cleanup_expired_pseudoip();
        std::this_thread::sleep_for(std::chrono::hours(4));
    }
}

// 启动定时清理线程
void start_pseudoip_cleanup_thread() {
    if (!cleanup_thread_running) {
        cleanup_thread_running = true;
        cleanup_thread = std::thread(cleanup_expired_pseudoip_periodic);
    }
}

// 停止定时清理线程（可选，程序退出时调用）
void stop_pseudoip_cleanup_thread() {
    cleanup_thread_running = false;
    if (cleanup_thread.joinable()) {
        cleanup_thread.join();
    }
}
