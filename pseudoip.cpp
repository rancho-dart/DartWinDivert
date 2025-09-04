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
static std::unordered_map<uint32_t, PseudoIpRecord> pseudoip_map; // α��ַ -> ��¼
static std::unordered_map<std::string, uint32_t> domain_ip_port_map; // ����+��ʵIP+�˿� -> α��ַ
static uint32_t next_alloc = PSEUDOIP_START;

// ��������������������ʵIP�Ͷ˿�ƴ��ΪΨһkey
static std::string make_key(const std::string& domain, uint32_t real_ip, uint16_t port) {
    return domain + "#" + std::to_string(real_ip) + "#" + std::to_string(port);
}

// �ж�һ��IP�Ƿ�����α��ַ�أ�198.18.0.0/15��
bool is_pseudoip(uint32_t ip) {
    return (ip & PSEUDOIP_MASK) == PSEUDOIP_START;
}

// �ڲ��������������Է���һ��α��ַ���ɹ�����α��ַ�����򷵻�0
static uint32_t try_allocate_pseudoip(const std::string& domain, uint32_t real_ip, uint16_t port, std::chrono::steady_clock::time_point now) {
    std::string key = make_key(domain, real_ip, port);
    for (uint32_t i = 0; i < PSEUDOIP_POOL_SIZE; ++i) {
        uint32_t candidate = PSEUDOIP_START + ((next_alloc - PSEUDOIP_START + i) % PSEUDOIP_POOL_SIZE);
        auto rec = pseudoip_map.find(candidate);
        if (rec == pseudoip_map.end() || rec->second.expire_time <= now) {
            // ����
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

// �޸� allocate_pseudoip ������ domain �Ĵ���ʽ������ֱ���޸� const std::string& ����  
uint32_t allocate_pseudoip(const std::string& domain, uint32_t real_ip, uint16_t port) {  
	// ������������ʵIP��α��ַ��ӳ���ϵ�����������յ�����α��ַ�ı��ĵ�ʱ����Ի�ԭ��ʵ��IP��DART��ͷ��Ŀ���ַ��
	// ΪʲôҪ�Ѷ˿�Ҳ�������ڣ���Ϊһ��DART���Ĵ�һ��NAT���س�����ʱ��UDP��Դ�˿ڻᱻ�޸ģ�����������Ҫ��¼����˿ڡ�
	// �������ڹ��췵�ر��ĵ�ʱ������ΪĿ��˿ڣ�DART���Ĳ��ܹ���ԽNAT������ȷ���ء�
    std::lock_guard<std::mutex> lock(pseudoip_mutex);

    auto now = std::chrono::steady_clock::now();  
    std::string mutable_domain = domain; // ����һ�����޸ĵĸ���  
    // �����������.��β�������һ����  
    if (mutable_domain.back() != '.') {  
        mutable_domain += '.';  
    }  

    std::string key = make_key(mutable_domain, real_ip, port);  

    // �ѷ������ˢ�·���ʱ�䲢����  
    auto it = domain_ip_port_map.find(key);  
    if (it != domain_ip_port_map.end()) {  
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
        domain_ip_port_map.erase(it);  
    }  

    // ��һ�γ��Է���  
    uint32_t result = try_allocate_pseudoip(mutable_domain, real_ip, port, now);  
    if (result != 0) return result;  

    // ������������������ݺ��ٳ���һ��  
    cleanup_expired_pseudoip();  
    now = std::chrono::steady_clock::now();  
    return try_allocate_pseudoip(mutable_domain, real_ip, port, now);  
}

// ��ѯα��ַ��Ӧ����������ʵIP�Ͷ˿�
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

// ��ѯ��������ʵIP�Ͷ˿ڶ�Ӧ��α��ַ��δ���ڣ����鲻������0
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

// �������й��ڵķ����¼
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

// ��ʱ�����̺߳���
static void cleanup_expired_pseudoip_periodic() {
    using namespace std::chrono_literals;
    while (cleanup_thread_running) {
        cleanup_expired_pseudoip();
        std::this_thread::sleep_for(std::chrono::hours(4));
    }
}

// ������ʱ�����߳�
void start_pseudoip_cleanup_thread() {
    if (!cleanup_thread_running) {
        cleanup_thread_running = true;
        cleanup_thread = std::thread(cleanup_expired_pseudoip_periodic);
    }
}

// ֹͣ��ʱ�����̣߳���ѡ�������˳�ʱ���ã�
void stop_pseudoip_cleanup_thread() {
    cleanup_thread_running = false;
    if (cleanup_thread.joinable()) {
        cleanup_thread.join();
    }
}
