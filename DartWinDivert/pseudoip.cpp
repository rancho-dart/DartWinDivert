// Copyright (c) 2025 rancho.dart@qq.com
// Licensed under the MIT License. See LICENSE file for details.

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
static std::unordered_map<uint32_t, PseudoIpRecord> pseudoip_map; // pseudo address -> record
static std::unordered_map<std::string, uint32_t> domain_ip_port_map; // domain + real IP + port -> pseudo address
static uint32_t next_alloc = PSEUDOIP_START;

// Helper function: concatenate domain, real IP, and port as a unique key
static std::string make_key(const std::string& domain, uint32_t real_ip, uint16_t port) {
    return domain + "#" + std::to_string(real_ip) + "#" + std::to_string(port);
}

// Determine whether an IP belongs to the pseudo address pool (198.18.0.0/15)
bool is_pseudoip(uint32_t ip) {
    return (ip & PSEUDOIP_MASK) == PSEUDOIP_START;
}

// Internal helper function: try to allocate a pseudo address, return pseudo address if successful, otherwise return 0
static uint32_t try_allocate_pseudoip(const std::string& domain, uint32_t real_ip, uint16_t port, std::chrono::steady_clock::time_point now) {
    std::string key = make_key(domain, real_ip, port);
    for (uint32_t i = 0; i < PSEUDOIP_POOL_SIZE; ++i) {
        uint32_t candidate = PSEUDOIP_START + ((next_alloc - PSEUDOIP_START + i) % PSEUDOIP_POOL_SIZE);
        auto rec = pseudoip_map.find(candidate);
        if (rec == pseudoip_map.end() || rec->second.expire_time <= now) {
            // Allocate
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

// Modify the handling of domain in allocate_pseudoip to avoid directly modifying the const std::string& parameter
uint32_t allocate_pseudoip(const std::string& domain, uint32_t real_ip, uint16_t port) {
    // Preserve the mapping between domain, real IP, and pseudo address, so that when we receive packets sent to the pseudo address, we can restore the real IP and the destination address in the DART header.
    // Why include the port? Because when a DART packet comes out of a NAT gateway, the UDP source port will be changed, so we need to record this port.
    // In this way, when constructing the return packet, use it as the destination port, so the DART packet can traverse the NAT gateway and return correctly.
    std::lock_guard<std::mutex> lock(pseudoip_mutex);

    auto now = std::chrono::steady_clock::now();
    std::string mutable_domain = domain; // Create a modifiable copy
    // If the domain does not end with '.', add a dot
    if (mutable_domain.back() != '.') {
        mutable_domain += '.';
    }

    std::string key = make_key(mutable_domain, real_ip, port);

    // Already allocated, refresh allocation time and return
    auto it = domain_ip_port_map.find(key);
    if (it != domain_ip_port_map.end()) {
        uint32_t pseudoip = it->second;
        // Check if expired
        auto rec_it = pseudoip_map.find(pseudoip);
        if (rec_it != pseudoip_map.end() && rec_it->second.expire_time > now) {
            // Refresh allocation time
            rec_it->second.expire_time = now + std::chrono::seconds(PSEUDOIP_TTL);
            return pseudoip;
        }
        // If expired, clean up
        pseudoip_map.erase(pseudoip);
        domain_ip_port_map.erase(it);
    }

    // First attempt to allocate
    uint32_t result = try_allocate_pseudoip(mutable_domain, real_ip, port, now);
    if (result != 0) return result;

    // Pool is full, clean up expired data and try again
    cleanup_expired_pseudoip();
    now = std::chrono::steady_clock::now();
    return try_allocate_pseudoip(mutable_domain, real_ip, port, now);
}

// Query the domain, real IP, and port corresponding to the pseudo address
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

// Query the pseudo address corresponding to domain, real IP, and port (not expired), return 0 if not found
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

// Clean up all expired allocation records
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

// Periodic task thread function
static void cleanup_expired_pseudoip_periodic() {
    using namespace std::chrono_literals;
    while (cleanup_thread_running) {
        cleanup_expired_pseudoip();
        std::this_thread::sleep_for(std::chrono::hours(4));
    }
}

// Start periodic cleanup thread
void start_pseudoip_cleanup_thread() {
    if (!cleanup_thread_running) {
        cleanup_thread_running = true;
        cleanup_thread = std::thread(cleanup_expired_pseudoip_periodic);
    }
}

// Stop periodic cleanup thread (optional, call when program exits)
void stop_pseudoip_cleanup_thread() {
    cleanup_thread_running = false;
    if (cleanup_thread.joinable()) {
        cleanup_thread.join();
    }
}
