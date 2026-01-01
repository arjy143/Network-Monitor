#include "packet.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <iomanip>
#include <sstream>

std::string PacketInfo::protocol_name() const {
    if (ether_type == ETHERTYPE_ARP) {
        return "ARP";
    }

    switch (protocol) {
        case PROTO_ICMP: return "ICMP";
        case PROTO_TCP: return "TCP";
        case PROTO_UDP: return "UDP";
        case PROTO_ICMPV6: return "ICMPv6";
        default:
            if (ip_version == 4 || ip_version == 6) {
                return "IP/" + std::to_string(protocol);
            }
            return "ETH";
    }
}

std::string PacketInfo::tcp_flags_str() const {
    if (protocol != PROTO_TCP) return "";

    std::string flags;
    if (tcp_flags & TCP_SYN) flags += "S";
    if (tcp_flags & TCP_ACK) flags += "A";
    if (tcp_flags & TCP_FIN) flags += "F";
    if (tcp_flags & TCP_RST) flags += "R";
    if (tcp_flags & TCP_PSH) flags += "P";
    if (tcp_flags & TCP_URG) flags += "U";

    return flags.empty() ? "" : "[" + flags + "]";
}

std::string PacketInfo::format_mac(const std::array<uint8_t, 6>& mac) const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < 6; ++i) {
        if (i > 0) oss << ":";
        oss << std::setw(2) << static_cast<int>(mac[i]);
    }
    return oss.str();
}

std::string PacketInfo::timestamp_str() const {
    auto time = std::chrono::system_clock::to_time_t(timestamp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()) % 1000;

    std::tm tm_buf;
    localtime_r(&time, &tm_buf);

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

std::string PacketInfo::summary() const {
    std::ostringstream oss;

    if (ether_type == ETHERTYPE_ARP) {
        oss << "ARP";
        return oss.str();
    }

    if (ip_version == 0) {
        oss << format_mac(src_mac) << " -> " << format_mac(dst_mac);
        return oss.str();
    }

    if (protocol == PROTO_TCP || protocol == PROTO_UDP) {
        oss << src_port << " -> " << dst_port;
        if (protocol == PROTO_TCP) {
            oss << " " << tcp_flags_str();
        }
    } else if (protocol == PROTO_ICMP || protocol == PROTO_ICMPV6) {
        oss << "Echo request/reply";
    }

    return oss.str();
}

PacketInfo parse_packet(const uint8_t* data, uint32_t caplen, uint32_t len) {
    PacketInfo info{};
    info.timestamp = std::chrono::system_clock::now();
    info.length = caplen;
    info.original_length = len;
    info.ip_version = 0;
    info.protocol = 0;
    info.src_port = 0;
    info.dst_port = 0;
    info.tcp_flags = 0;
    info.ttl = 0;

    // Store raw data
    info.raw_data.assign(data, data + caplen);

    // Need at least Ethernet header
    if (caplen < sizeof(EthernetHeader)) {
        return info;
    }

    // Parse Ethernet
    const auto* eth = reinterpret_cast<const EthernetHeader*>(data);
    std::copy(eth->src_mac, eth->src_mac + 6, info.src_mac.begin());
    std::copy(eth->dst_mac, eth->dst_mac + 6, info.dst_mac.begin());
    info.ether_type = ntohs(eth->ether_type);

    const uint8_t* payload = data + sizeof(EthernetHeader);
    size_t remaining = caplen - sizeof(EthernetHeader);

    // Handle VLAN tags (802.1Q)
    while (info.ether_type == 0x8100 && remaining >= 4) {
        info.ether_type = ntohs(*reinterpret_cast<const uint16_t*>(payload + 2));
        payload += 4;
        remaining -= 4;
    }

    // Parse ARP
    if (info.ether_type == ETHERTYPE_ARP) {
        if (remaining >= sizeof(ARPHeader)) {
            const auto* arp = reinterpret_cast<const ARPHeader*>(payload);
            char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp->sender_ip, src_str, sizeof(src_str));
            inet_ntop(AF_INET, arp->target_ip, dst_str, sizeof(dst_str));
            info.src_ip = src_str;
            info.dst_ip = dst_str;
        }
        return info;
    }

    // Parse IPv4
    if (info.ether_type == ETHERTYPE_IPV4) {
        if (remaining < sizeof(IPv4Header)) {
            return info;
        }

        const auto* ip = reinterpret_cast<const IPv4Header*>(payload);
        info.ip_version = 4;
        info.protocol = ip->protocol;
        info.ttl = ip->ttl;

        char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->src_addr, src_str, sizeof(src_str));
        inet_ntop(AF_INET, &ip->dst_addr, dst_str, sizeof(dst_str));
        info.src_ip = src_str;
        info.dst_ip = dst_str;

        size_t ip_hdr_len = (ip->version_ihl & 0x0F) * 4;
        if (ip_hdr_len > remaining) {
            return info;
        }

        payload += ip_hdr_len;
        remaining -= ip_hdr_len;
    }
    // Parse IPv6
    else if (info.ether_type == ETHERTYPE_IPV6) {
        if (remaining < sizeof(IPv6Header)) {
            return info;
        }

        const auto* ip6 = reinterpret_cast<const IPv6Header*>(payload);
        info.ip_version = 6;
        info.protocol = ip6->next_header;
        info.ttl = ip6->hop_limit;

        char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ip6->src_addr, src_str, sizeof(src_str));
        inet_ntop(AF_INET6, ip6->dst_addr, dst_str, sizeof(dst_str));
        info.src_ip = src_str;
        info.dst_ip = dst_str;

        payload += sizeof(IPv6Header);
        remaining -= sizeof(IPv6Header);
    }
    else {
        return info;
    }

    // Parse TCP
    if (info.protocol == PROTO_TCP) {
        if (remaining >= sizeof(TCPHeader)) {
            const auto* tcp = reinterpret_cast<const TCPHeader*>(payload);
            info.src_port = ntohs(tcp->src_port);
            info.dst_port = ntohs(tcp->dst_port);
            info.tcp_flags = tcp->flags;
        }
    }
    // Parse UDP
    else if (info.protocol == PROTO_UDP) {
        if (remaining >= sizeof(UDPHeader)) {
            const auto* udp = reinterpret_cast<const UDPHeader*>(payload);
            info.src_port = ntohs(udp->src_port);
            info.dst_port = ntohs(udp->dst_port);
        }
    }

    return info;
}
