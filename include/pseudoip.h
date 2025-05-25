#pragma once

#include <string>
#include <cstdint>
#include <unordered_map>
#include <chrono>
#include <algorithm>
#include <mutex>

// α��ַ�ط�Χ����
constexpr uint32_t PSEUDOIP_START = 0xC6130000; // 198.19.0.0
constexpr uint32_t PSEUDOIP_END   = 0xC613FFFF; // 198.19.255.255
constexpr uint32_t PSEUDOIP_MASK  = 0XFFFF0000; // 255.255.0.0
constexpr uint32_t PSEUDOIP_POOL_SIZE = PSEUDOIP_END - PSEUDOIP_START + 1;

// ���������ڣ��룩
constexpr int PSEUDOIP_TTL = 300;
constexpr int DART_PORT = 0XDA27; // DARTЭ��˿ں�

// ����α��ַ��������������ʵIP������α��ַ��0��ʾ����ʧ�ܣ�
uint32_t allocate_pseudoip(const std::string& domain, uint32_t real_ip);

// ��ѯα��ַ��Ӧ����������ʵIP������true��ʾ�鵽��δ����
bool query_pseudoip(uint32_t pseudoip, std::string& domain, uint32_t& real_ip);


// ��ѯ��������ʵIP��Ӧ��α��ַ��δ���ڣ����鲻������0
uint32_t query_pseudoip_by_domain(const std::string& domain, uint32_t real_ip);

// �������й��ڵķ����¼
void cleanup_expired_pseudoip();

// �ж�һ��IP�Ƿ�����α��ַ�أ�198.18.0.0/15��
bool is_pseudoip(uint32_t ip);