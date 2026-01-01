#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

// Protocol numbers
constexpr uint8_t PROTO_ICMP = 1;
constexpr uint8_t PROTO_TCP = 6;
constexpr uint8_t PROTO_UDP = 17;
constexpr uint8_t PROTO_ICMPV6 = 58;

// EtherTypes
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_ARP = 0x0806;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;

// TCP Flags
constexpr uint8_t TCP_FIN = 0x01;
constexpr uint8_t TCP_SYN = 0x02;
constexpr uint8_t TCP_RST = 0x04;
constexpr uint8_t TCP_PSH = 0x08;
constexpr uint8_t TCP_ACK = 0x10;
constexpr uint8_t TCP_URG = 0x20;

struct PacketInfo {
    std::chrono::system_clock::time_point timestamp;
    uint32_t length;
    uint32_t original_length;

    // Ethernet layer
    std::array<uint8_t, 6> src_mac;
    std::array<uint8_t, 6> dst_mac;
    uint16_t ether_type;

    // IP layer
    uint8_t ip_version;
    std::string src_ip;
    std::string dst_ip;
    uint8_t protocol;
    uint8_t ttl;

    // Transport layer
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t tcp_flags;

    // Raw data for inspection
    std::vector<uint8_t> raw_data;

    // Helper methods
    std::string protocol_name() const;
    std::string tcp_flags_str() const;
    std::string summary() const;
    std::string format_mac(const std::array<uint8_t, 6>& mac) const;
    std::string timestamp_str() const;
};

// Packet header structures (packed for direct memory mapping)
#pragma pack(push, 1)

struct EthernetHeader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

struct IPv4Header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};

struct IPv6Header {
    uint32_t version_class_flow;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

struct ARPHeader {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_size;
    uint8_t proto_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

#pragma pack(pop)

// Parse a raw packet into PacketInfo
PacketInfo parse_packet(const uint8_t* data, uint32_t caplen, uint32_t len);
