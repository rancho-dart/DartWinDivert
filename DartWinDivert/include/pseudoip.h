// Copyright (c) 2025 rancho.dart@qq.com
// Licensed under the MIT License. See LICENSE file for details.

#pragma once

#include <string>
#include <cstdint>
#include <unordered_map>
#include <chrono>
#include <algorithm>
#include <mutex>

// Pseudo address pool range constants
constexpr uint32_t PSEUDOIP_START = 0xC6130000; // 198.19.0.0
constexpr uint32_t PSEUDOIP_END   = 0xC613FFFF; // 198.19.255.255
constexpr uint32_t PSEUDOIP_MASK  = 0XFFFF0000; // 255.255.0.0
constexpr uint32_t PSEUDOIP_POOL_SIZE = PSEUDOIP_END - PSEUDOIP_START + 1;

// Allocation lifetime (seconds)
constexpr int PSEUDOIP_TTL = 300;
constexpr int DART_PORT = 0XDA27; // DART protocol port number

// Allocate pseudo address: input domain and real IP, return pseudo address (0 means allocation failed)
uint32_t allocate_pseudoip(const std::string& domain, uint32_t real_ip, uint16_t port);

// Query the domain, real IP, and port number corresponding to the pseudo address, return true if found and not expired
bool query_by_pseudoip(uint32_t pseudoip, std::string& domain, uint32_t& real_ip, uint16_t& port);

// Query the pseudo address corresponding to the domain and real IP (not expired), return 0 if not found
uint32_t query_pseudoip_by_domain(const std::string& domain, uint32_t real_ip, uint16_t port);

// Clean up all expired allocation records
void cleanup_expired_pseudoip();

// Determine whether an IP belongs to the pseudo address pool (198.18.0.0/15)
bool is_pseudoip(uint32_t ip);

void start_pseudoip_cleanup_thread();
void stop_pseudoip_cleanup_thread();
