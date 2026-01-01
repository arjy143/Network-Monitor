/*
 * packet.cpp - Network packet parsing implementation
 *
 * Implements packet parsing for multiple protocol layers:
 * - Layer 2: Ethernet, VLAN (802.1Q)
 * - Layer 3: IPv4, IPv6, ARP
 * - Layer 4: TCP, UDP, ICMP
 * - Layer 7: DNS queries, HTTP requests, TLS Client Hello (SNI extraction)
 *
 * The hostname extraction features allow the application to show what
 * domains/URLs are being accessed, even for encrypted HTTPS traffic
 * (via TLS SNI).
 */

#include "packet.hpp"
#include <arpa/inet.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>

std::string PacketInfo::protocol_name() const {
    // Return application protocol if we detected one
    if (!app_protocol.empty()) {
        return app_protocol;
    }

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

    // Show hostname if we have one
    if (!hostname.empty()) {
        oss << hostname;
        if (!app_info.empty()) {
            oss << " " << app_info;
        }
        return oss.str();
    }

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

// Parse a DNS name from the packet data
// DNS names are encoded as length-prefixed labels (e.g., 3www6google3com0)
std::string parse_dns_name(const uint8_t* data, size_t len, size_t& offset) {
    std::string name;
    size_t pos = offset;
    bool jumped = false;
    size_t jump_count = 0;
    const size_t max_jumps = 50;  // Prevent infinite loops from malformed packets

    while (pos < len && jump_count < max_jumps) {
        uint8_t label_len = data[pos];

        if (label_len == 0) {
            if (!jumped) offset = pos + 1;
            break;
        }

        // Check for compression pointer (starts with 0xC0)
        if ((label_len & 0xC0) == 0xC0) {
            if (pos + 1 >= len) break;
            uint16_t pointer = ((label_len & 0x3F) << 8) | data[pos + 1];
            if (!jumped) offset = pos + 2;
            pos = pointer;
            jumped = true;
            jump_count++;
            continue;
        }

        if (pos + 1 + label_len > len) break;

        if (!name.empty()) name += ".";
        name.append(reinterpret_cast<const char*>(data + pos + 1), label_len);
        pos += label_len + 1;
    }

    if (!jumped) offset = pos;
    return name;
}

// Parse DNS query to extract the queried hostname
void parse_dns_query(PacketInfo& info, const uint8_t* data, size_t len) {
    if (len < sizeof(DNSHeader)) return;

    const auto* dns = reinterpret_cast<const DNSHeader*>(data);
    uint16_t flags = ntohs(dns->flags);
    uint16_t qdcount = ntohs(dns->qdcount);

    // Check if this is a query (QR bit = 0)
    bool is_query = (flags & 0x8000) == 0;

    if (qdcount == 0) return;

    // Parse the first question
    size_t offset = sizeof(DNSHeader);
    std::string qname = parse_dns_name(data, len, offset);

    if (qname.empty()) return;

    info.hostname = qname;
    info.app_protocol = "DNS";

    // Get query type if we have room
    if (offset + 4 <= len) {
        uint16_t qtype = ntohs(*reinterpret_cast<const uint16_t*>(data + offset));
        std::string type_str;
        switch (qtype) {
            case 1:  type_str = "A"; break;
            case 28: type_str = "AAAA"; break;
            case 5:  type_str = "CNAME"; break;
            case 15: type_str = "MX"; break;
            case 16: type_str = "TXT"; break;
            case 2:  type_str = "NS"; break;
            case 6:  type_str = "SOA"; break;
            default: type_str = std::to_string(qtype); break;
        }
        info.app_info = is_query ? "Query " + type_str : "Response " + type_str;
    }
}

// Parse HTTP request to extract Host header
void parse_http_request(PacketInfo& info, const uint8_t* data, size_t len) {
    // Need at least some data for HTTP
    if (len < 16) return;

    // Check for HTTP method
    const char* methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
                             "OPTIONS ", "PATCH ", "CONNECT "};
    bool is_http = false;
    std::string method;

    for (const char* m : methods) {
        size_t mlen = strlen(m);
        if (len >= mlen && memcmp(data, m, mlen) == 0) {
            is_http = true;
            method = std::string(m, mlen - 1);  // Remove trailing space
            break;
        }
    }

    // Also check for HTTP response
    if (!is_http && len >= 9 && memcmp(data, "HTTP/1.", 7) == 0) {
        is_http = true;
        method = "Response";
    }

    if (!is_http) return;

    info.app_protocol = "HTTP";
    info.app_info = method;

    // Search for Host header
    std::string content(reinterpret_cast<const char*>(data),
                        std::min(len, static_cast<size_t>(2048)));

    // Look for Host: header (case-insensitive)
    size_t pos = 0;
    while (pos < content.length()) {
        size_t line_end = content.find("\r\n", pos);
        if (line_end == std::string::npos) break;

        std::string line = content.substr(pos, line_end - pos);

        // Check for Host header
        if (line.length() > 6) {
            std::string header_name = line.substr(0, 5);
            std::transform(header_name.begin(), header_name.end(),
                           header_name.begin(), ::tolower);

            if (header_name == "host:") {
                size_t value_start = 5;
                while (value_start < line.length() && line[value_start] == ' ') {
                    value_start++;
                }
                info.hostname = line.substr(value_start);
                // Remove port if present for cleaner display
                size_t colon = info.hostname.find(':');
                if (colon != std::string::npos) {
                    info.hostname = info.hostname.substr(0, colon);
                }
                break;
            }
        }

        pos = line_end + 2;

        // Stop at end of headers
        if (line.empty()) break;
    }

    // Also try to extract the path from the request line
    if (method != "Response") {
        size_t first_line_end = content.find("\r\n");
        if (first_line_end != std::string::npos) {
            std::string request_line = content.substr(0, first_line_end);
            size_t path_start = request_line.find(' ');
            size_t path_end = request_line.rfind(' ');
            if (path_start != std::string::npos && path_end != std::string::npos
                && path_start < path_end) {
                std::string path = request_line.substr(path_start + 1,
                                                       path_end - path_start - 1);
                if (path.length() > 1 && path.length() < 50) {
                    info.app_info = method + " " + path;
                }
            }
        }
    }
}

// Parse TLS Client Hello to extract Server Name Indication (SNI)
void parse_tls_client_hello(PacketInfo& info, const uint8_t* data, size_t len) {
    // TLS record header: type(1) + version(2) + length(2)
    if (len < 5) return;

    // Check for TLS handshake record (type 0x16)
    if (data[0] != 0x16) return;

    // Skip record header
    size_t pos = 5;

    // Handshake header: type(1) + length(3)
    if (pos + 4 > len) return;

    // Check for Client Hello (type 0x01)
    if (data[pos] != 0x01) return;
    pos += 4;  // Skip handshake header

    // Client Hello: version(2) + random(32) + session_id_len(1)
    if (pos + 35 > len) return;
    pos += 34;

    // Skip session ID
    uint8_t session_id_len = data[pos++];
    pos += session_id_len;

    // Skip cipher suites
    if (pos + 2 > len) return;
    uint16_t cipher_suites_len = (data[pos] << 8) | data[pos + 1];
    pos += 2 + cipher_suites_len;

    // Skip compression methods
    if (pos + 1 > len) return;
    uint8_t compression_len = data[pos++];
    pos += compression_len;

    // Extensions length
    if (pos + 2 > len) return;
    uint16_t extensions_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;

    size_t extensions_end = pos + extensions_len;
    if (extensions_end > len) extensions_end = len;

    // Parse extensions looking for SNI (type 0x0000)
    while (pos + 4 <= extensions_end) {
        uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
        uint16_t ext_len = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;

        if (pos + ext_len > extensions_end) break;

        // SNI extension
        if (ext_type == 0x0000 && ext_len >= 5) {
            // SNI list length (2) + name type (1) + name length (2)
            size_t sni_pos = pos + 2;  // Skip list length
            if (sni_pos + 3 > pos + ext_len) break;

            uint8_t name_type = data[sni_pos];
            uint16_t name_len = (data[sni_pos + 1] << 8) | data[sni_pos + 2];
            sni_pos += 3;

            // Host name type is 0
            if (name_type == 0 && sni_pos + name_len <= pos + ext_len) {
                info.hostname = std::string(
                    reinterpret_cast<const char*>(data + sni_pos), name_len);
                info.app_protocol = "TLS";
                info.app_info = "Client Hello";
                return;
            }
        }

        pos += ext_len;
    }
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

    // Track application layer payload for later parsing
    const uint8_t* app_payload = nullptr;
    size_t app_remaining = 0;

    // Parse TCP
    if (info.protocol == PROTO_TCP) {
        if (remaining >= sizeof(TCPHeader)) {
            const auto* tcp = reinterpret_cast<const TCPHeader*>(payload);
            info.src_port = ntohs(tcp->src_port);
            info.dst_port = ntohs(tcp->dst_port);
            info.tcp_flags = tcp->flags;

            // Calculate TCP header length and get payload
            size_t tcp_hdr_len = ((tcp->data_offset >> 4) & 0x0F) * 4;
            if (tcp_hdr_len <= remaining) {
                app_payload = payload + tcp_hdr_len;
                app_remaining = remaining - tcp_hdr_len;
            }
        }
    }
    // Parse UDP
    else if (info.protocol == PROTO_UDP) {
        if (remaining >= sizeof(UDPHeader)) {
            const auto* udp = reinterpret_cast<const UDPHeader*>(payload);
            info.src_port = ntohs(udp->src_port);
            info.dst_port = ntohs(udp->dst_port);

            app_payload = payload + sizeof(UDPHeader);
            app_remaining = remaining - sizeof(UDPHeader);
        }
    }

    // Parse application layer protocols
    if (app_payload && app_remaining > 0) {
        // DNS (port 53)
        if (info.src_port == PORT_DNS || info.dst_port == PORT_DNS) {
            parse_dns_query(info, app_payload, app_remaining);
        }
        // HTTP (port 80)
        else if (info.src_port == PORT_HTTP || info.dst_port == PORT_HTTP) {
            parse_http_request(info, app_payload, app_remaining);
        }
        // HTTPS/TLS (port 443) - extract SNI from Client Hello
        else if (info.dst_port == PORT_HTTPS) {
            parse_tls_client_hello(info, app_payload, app_remaining);
        }
    }

    return info;
}
