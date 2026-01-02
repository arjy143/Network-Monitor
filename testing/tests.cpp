/*
 * tests.cpp - Unit tests for network-scanner
 *
 * Uses the attest.h single-header testing framework to test
 * pure/utility functions from the project.
 */

#define ATTEST_IMPLEMENTATION
#include "attest.h"

#include <string>
#include <vector>
#include <cstring>
#include <arpa/inet.h>

// Include project headers
#include "../src/packet.hpp"
#include "../src/config.hpp"
#include "../src/descriptions.hpp"
#include "../src/watchlist.hpp"

// =============================================================================
// Config::parse_fields Tests
// =============================================================================

REGISTER_TEST(config_parse_fields_basic)
{
    std::vector<std::string> fields = Config::parse_fields("a:b:c", ':');
    ATTEST_EQUAL(fields.size(), 3u);
    ATTEST_EQUAL(fields[0], "a");
    ATTEST_EQUAL(fields[1], "b");
    ATTEST_EQUAL(fields[2], "c");
}

REGISTER_TEST(config_parse_fields_empty)
{
    std::vector<std::string> fields = Config::parse_fields("", ':');
    ATTEST_EQUAL(fields.size(), 1u);
    ATTEST_EQUAL(fields[0], "");
}

REGISTER_TEST(config_parse_fields_single)
{
    std::vector<std::string> fields = Config::parse_fields("hello", ':');
    ATTEST_EQUAL(fields.size(), 1u);
    ATTEST_EQUAL(fields[0], "hello");
}

REGISTER_TEST(config_parse_fields_escaped_delimiter)
{
    // Test escaped colon: "a\:b:c" should give ["a:b", "c"]
    std::vector<std::string> fields = Config::parse_fields("a\\:b:c", ':');
    ATTEST_EQUAL(fields.size(), 2u);
    ATTEST_EQUAL(fields[0], "a:b");
    ATTEST_EQUAL(fields[1], "c");
}

REGISTER_TEST(config_parse_fields_multiple_escapes)
{
    // "a\\:b\\:c:d" should give ["a:b:c", "d"]
    std::vector<std::string> fields = Config::parse_fields("a\\:b\\:c:d", ':');
    ATTEST_EQUAL(fields.size(), 2u);
    ATTEST_EQUAL(fields[0], "a:b:c");
    ATTEST_EQUAL(fields[1], "d");
}

REGISTER_TEST(config_parse_fields_trailing_delimiter)
{
    std::vector<std::string> fields = Config::parse_fields("a:b:", ':');
    ATTEST_EQUAL(fields.size(), 3u);
    ATTEST_EQUAL(fields[0], "a");
    ATTEST_EQUAL(fields[1], "b");
    ATTEST_EQUAL(fields[2], "");
}

REGISTER_TEST(config_parse_fields_custom_delimiter)
{
    std::vector<std::string> fields = Config::parse_fields("a,b,c", ',');
    ATTEST_EQUAL(fields.size(), 3u);
    ATTEST_EQUAL(fields[0], "a");
    ATTEST_EQUAL(fields[1], "b");
    ATTEST_EQUAL(fields[2], "c");
}

// =============================================================================
// DescriptionDatabase::detect_match_type Tests
// =============================================================================

REGISTER_TEST(detect_match_type_exact)
{
    auto type = DescriptionDatabase::detect_match_type("example.com");
    ATTEST_TRUE(type == DescriptionEntry::MatchType::EXACT);
}

REGISTER_TEST(detect_match_type_wildcard_star)
{
    auto type = DescriptionDatabase::detect_match_type("*.example.com");
    ATTEST_TRUE(type == DescriptionEntry::MatchType::WILDCARD);
}

REGISTER_TEST(detect_match_type_wildcard_question)
{
    auto type = DescriptionDatabase::detect_match_type("example?.com");
    ATTEST_TRUE(type == DescriptionEntry::MatchType::WILDCARD);
}

REGISTER_TEST(detect_match_type_regex)
{
    auto type = DescriptionDatabase::detect_match_type("~.*\\.example\\.com");
    ATTEST_TRUE(type == DescriptionEntry::MatchType::REGEX);
}

REGISTER_TEST(detect_match_type_empty)
{
    auto type = DescriptionDatabase::detect_match_type("");
    ATTEST_TRUE(type == DescriptionEntry::MatchType::EXACT);
}

// =============================================================================
// DescriptionDatabase::wildcard_to_regex Tests
// =============================================================================

REGISTER_TEST(wildcard_to_regex_star)
{
    std::string result = DescriptionDatabase::wildcard_to_regex("*.example.com");
    // Should escape the dot and convert * to .*
    ATTEST_EQUAL(result, "^.*\\.example\\.com$");
}

REGISTER_TEST(wildcard_to_regex_question)
{
    std::string result = DescriptionDatabase::wildcard_to_regex("test?.com");
    ATTEST_EQUAL(result, "^test.\\.com$");
}

REGISTER_TEST(wildcard_to_regex_no_wildcards)
{
    std::string result = DescriptionDatabase::wildcard_to_regex("example.com");
    ATTEST_EQUAL(result, "^example\\.com$");
}

REGISTER_TEST(wildcard_to_regex_special_chars)
{
    // Test that special regex chars are escaped
    std::string result = DescriptionDatabase::wildcard_to_regex("test+file[1].com");
    ATTEST_EQUAL(result, "^test\\+file\\[1\\]\\.com$");
}

// =============================================================================
// Watchlist::wildcard_to_regex Tests (same logic, but verify consistency)
// =============================================================================

REGISTER_TEST(watchlist_wildcard_to_regex)
{
    std::string result = Watchlist::wildcard_to_regex("*.badsite.com");
    ATTEST_EQUAL(result, "^.*\\.badsite\\.com$");
}

// =============================================================================
// DescriptionEntry::matches Tests
// =============================================================================

REGISTER_TEST(description_entry_matches_exact)
{
    std::vector<std::string> fields = {"google.com", "Google", "Google Services"};
    auto entry = DescriptionEntry::from_fields(fields);
    ATTEST_TRUE(entry.has_value());
    ATTEST_TRUE(entry->matches("google.com"));
    ATTEST_TRUE(entry->matches("GOOGLE.COM"));  // case insensitive
    ATTEST_FALSE(entry->matches("www.google.com"));
    ATTEST_FALSE(entry->matches("google.com.evil.com"));
}

REGISTER_TEST(description_entry_matches_wildcard)
{
    std::vector<std::string> fields = {"*.google.com", "Google", "Google Services"};
    auto entry = DescriptionEntry::from_fields(fields);
    ATTEST_TRUE(entry.has_value());
    ATTEST_TRUE(entry->matches("www.google.com"));
    ATTEST_TRUE(entry->matches("mail.google.com"));
    ATTEST_TRUE(entry->matches("a.b.c.google.com"));
    ATTEST_FALSE(entry->matches("google.com"));  // * requires at least one char
    ATTEST_FALSE(entry->matches("google.com.evil.com"));
}

REGISTER_TEST(description_entry_matches_empty_hostname)
{
    std::vector<std::string> fields = {"example.com", "Test", "Test site"};
    auto entry = DescriptionEntry::from_fields(fields);
    ATTEST_TRUE(entry.has_value());
    ATTEST_FALSE(entry->matches(""));
}

REGISTER_TEST(description_entry_from_fields_invalid)
{
    // Too few fields
    std::vector<std::string> fields = {"example.com", "Test"};
    auto entry = DescriptionEntry::from_fields(fields);
    ATTEST_FALSE(entry.has_value());
}

REGISTER_TEST(description_entry_from_fields_empty_pattern)
{
    std::vector<std::string> fields = {"", "Test", "Test site"};
    auto entry = DescriptionEntry::from_fields(fields);
    ATTEST_FALSE(entry.has_value());
}

// =============================================================================
// WatchlistEntry Tests
// =============================================================================

REGISTER_TEST(watchlist_entry_exact_match)
{
    std::vector<std::string> fields = {"exact", "malware.com", "Known malware domain"};
    auto entry = WatchlistEntry::from_fields(fields);
    ATTEST_TRUE(entry.has_value());
    ATTEST_TRUE(entry->matches_hostname("malware.com"));
    ATTEST_TRUE(entry->matches_hostname("MALWARE.COM"));
    ATTEST_FALSE(entry->matches_hostname("www.malware.com"));
}

REGISTER_TEST(watchlist_entry_wildcard_match)
{
    std::vector<std::string> fields = {"wildcard", "*.tracking.com", "Tracking domain"};
    auto entry = WatchlistEntry::from_fields(fields);
    ATTEST_TRUE(entry.has_value());
    ATTEST_TRUE(entry->matches_hostname("pixel.tracking.com"));
    ATTEST_TRUE(entry->matches_hostname("a.b.tracking.com"));
    ATTEST_FALSE(entry->matches_hostname("tracking.com"));
}

REGISTER_TEST(watchlist_entry_regex_match)
{
    std::vector<std::string> fields = {"regex", ".*\\.evil\\.(com|net)", "Evil domains"};
    auto entry = WatchlistEntry::from_fields(fields);
    ATTEST_TRUE(entry.has_value());
    ATTEST_TRUE(entry->matches_hostname("www.evil.com"));
    ATTEST_TRUE(entry->matches_hostname("sub.evil.net"));
    ATTEST_FALSE(entry->matches_hostname("www.evil.org"));
}

REGISTER_TEST(watchlist_entry_ip_match)
{
    std::vector<std::string> fields = {"ip", "192.168.1.100", "Suspicious IP"};
    auto entry = WatchlistEntry::from_fields(fields);
    ATTEST_TRUE(entry.has_value());
    ATTEST_TRUE(entry->matches_ip("192.168.1.100"));
    ATTEST_FALSE(entry->matches_ip("192.168.1.101"));
    ATTEST_FALSE(entry->matches_ip("10.0.0.1"));
}

REGISTER_TEST(watchlist_entry_cidr_match)
{
    std::vector<std::string> fields = {"cidr", "10.0.0.0/8", "Private network"};
    auto entry = WatchlistEntry::from_fields(fields);
    ATTEST_TRUE(entry.has_value());
    ATTEST_TRUE(entry->matches_ip("10.0.0.1"));
    ATTEST_TRUE(entry->matches_ip("10.255.255.255"));
    ATTEST_TRUE(entry->matches_ip("10.100.50.25"));
    ATTEST_FALSE(entry->matches_ip("192.168.1.1"));
    ATTEST_FALSE(entry->matches_ip("11.0.0.1"));
}

REGISTER_TEST(watchlist_entry_cidr_match_24)
{
    std::vector<std::string> fields = {"cidr", "192.168.1.0/24", "Local subnet"};
    auto entry = WatchlistEntry::from_fields(fields);
    ATTEST_TRUE(entry.has_value());
    ATTEST_TRUE(entry->matches_ip("192.168.1.0"));
    ATTEST_TRUE(entry->matches_ip("192.168.1.255"));
    ATTEST_TRUE(entry->matches_ip("192.168.1.100"));
    ATTEST_FALSE(entry->matches_ip("192.168.2.1"));
    ATTEST_FALSE(entry->matches_ip("192.168.0.255"));
}

REGISTER_TEST(watchlist_entry_cidr_match_16)
{
    std::vector<std::string> fields = {"cidr", "172.16.0.0/16", "Private range"};
    auto entry = WatchlistEntry::from_fields(fields);
    ATTEST_TRUE(entry.has_value());
    ATTEST_TRUE(entry->matches_ip("172.16.0.1"));
    ATTEST_TRUE(entry->matches_ip("172.16.255.255"));
    ATTEST_FALSE(entry->matches_ip("172.17.0.1"));
}

REGISTER_TEST(watchlist_entry_invalid_type)
{
    std::vector<std::string> fields = {"invalid_type", "pattern", "Label"};
    auto entry = WatchlistEntry::from_fields(fields);
    ATTEST_FALSE(entry.has_value());
}

REGISTER_TEST(watchlist_entry_invalid_cidr)
{
    // Invalid prefix
    std::vector<std::string> fields = {"cidr", "10.0.0.0/33", "Invalid"};
    auto entry = WatchlistEntry::from_fields(fields);
    ATTEST_FALSE(entry.has_value());
}

REGISTER_TEST(watchlist_entry_invalid_ip)
{
    std::vector<std::string> fields = {"ip", "not.an.ip.address", "Invalid"};
    auto entry = WatchlistEntry::from_fields(fields);
    ATTEST_FALSE(entry.has_value());
}

// =============================================================================
// PacketInfo Helper Method Tests
// =============================================================================

REGISTER_TEST(packet_info_protocol_name_tcp)
{
    PacketInfo pkt{};
    pkt.protocol = PROTO_TCP;
    pkt.ip_version = 4;
    ATTEST_EQUAL(pkt.protocol_name(), "TCP");
}

REGISTER_TEST(packet_info_protocol_name_udp)
{
    PacketInfo pkt{};
    pkt.protocol = PROTO_UDP;
    pkt.ip_version = 4;
    ATTEST_EQUAL(pkt.protocol_name(), "UDP");
}

REGISTER_TEST(packet_info_protocol_name_icmp)
{
    PacketInfo pkt{};
    pkt.protocol = PROTO_ICMP;
    pkt.ip_version = 4;
    ATTEST_EQUAL(pkt.protocol_name(), "ICMP");
}

REGISTER_TEST(packet_info_protocol_name_app_override)
{
    PacketInfo pkt{};
    pkt.protocol = PROTO_TCP;
    pkt.ip_version = 4;
    pkt.app_protocol = "DNS";
    ATTEST_EQUAL(pkt.protocol_name(), "DNS");
}

REGISTER_TEST(packet_info_protocol_name_arp)
{
    PacketInfo pkt{};
    pkt.ether_type = ETHERTYPE_ARP;
    ATTEST_EQUAL(pkt.protocol_name(), "ARP");
}

REGISTER_TEST(packet_info_tcp_flags_syn)
{
    PacketInfo pkt{};
    pkt.protocol = PROTO_TCP;
    pkt.tcp_flags = TCP_SYN;
    ATTEST_EQUAL(pkt.tcp_flags_str(), "[S]");
}

REGISTER_TEST(packet_info_tcp_flags_syn_ack)
{
    PacketInfo pkt{};
    pkt.protocol = PROTO_TCP;
    pkt.tcp_flags = TCP_SYN | TCP_ACK;
    ATTEST_EQUAL(pkt.tcp_flags_str(), "[SA]");
}

REGISTER_TEST(packet_info_tcp_flags_all)
{
    PacketInfo pkt{};
    pkt.protocol = PROTO_TCP;
    pkt.tcp_flags = TCP_SYN | TCP_ACK | TCP_FIN | TCP_RST | TCP_PSH | TCP_URG;
    ATTEST_EQUAL(pkt.tcp_flags_str(), "[SAFRPU]");
}

REGISTER_TEST(packet_info_tcp_flags_non_tcp)
{
    PacketInfo pkt{};
    pkt.protocol = PROTO_UDP;
    pkt.tcp_flags = TCP_SYN;  // Should be ignored for non-TCP
    ATTEST_EQUAL(pkt.tcp_flags_str(), "");
}

REGISTER_TEST(packet_info_format_mac)
{
    PacketInfo pkt{};
    std::array<uint8_t, 6> mac = {0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc};
    std::string formatted = pkt.format_mac(mac);
    ATTEST_EQUAL(formatted, "00:11:22:aa:bb:cc");
}

REGISTER_TEST(packet_info_format_mac_zeros)
{
    PacketInfo pkt{};
    std::array<uint8_t, 6> mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::string formatted = pkt.format_mac(mac);
    ATTEST_EQUAL(formatted, "00:00:00:00:00:00");
}

REGISTER_TEST(packet_info_format_mac_broadcast)
{
    PacketInfo pkt{};
    std::array<uint8_t, 6> mac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    std::string formatted = pkt.format_mac(mac);
    ATTEST_EQUAL(formatted, "ff:ff:ff:ff:ff:ff");
}

// =============================================================================
// DNS Name Parsing Tests
// =============================================================================

REGISTER_TEST(parse_dns_name_simple)
{
    // DNS encoding for "www.google.com": 3www6google3com0
    uint8_t data[] = {3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0};
    size_t offset = 0;
    std::string name = parse_dns_name(data, sizeof(data), offset);
    ATTEST_EQUAL(name, "www.google.com");
    // Offset should point past the parsed name (after the null terminator)
    ATTEST_TRUE(offset > 0);
}

REGISTER_TEST(parse_dns_name_single_label)
{
    // DNS encoding for "localhost": 9localhost0
    uint8_t data[] = {9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0};
    size_t offset = 0;
    std::string name = parse_dns_name(data, sizeof(data), offset);
    ATTEST_EQUAL(name, "localhost");
}

REGISTER_TEST(parse_dns_name_empty)
{
    uint8_t data[] = {0};
    size_t offset = 0;
    std::string name = parse_dns_name(data, sizeof(data), offset);
    ATTEST_EQUAL(name, "");
}

REGISTER_TEST(parse_dns_name_with_compression)
{
    // Compression pointer test
    // First name at offset 0: "google.com" (6google3com0)
    // Second reference at offset 12 points back to offset 0 (0xC000)
    uint8_t data[] = {
        6, 'g', 'o', 'o', 'g', 'l', 'e',  // offset 0-6
        3, 'c', 'o', 'm',                  // offset 7-10
        0,                                  // offset 11 (end)
        0xC0, 0x00                         // offset 12-13 (pointer to offset 0)
    };

    // Parse the compressed name at offset 12
    size_t offset = 12;
    std::string name = parse_dns_name(data, sizeof(data), offset);
    ATTEST_EQUAL(name, "google.com");
}

// =============================================================================
// Packet Parsing Tests (with synthetic packets)
// =============================================================================

REGISTER_TEST(parse_packet_too_short)
{
    uint8_t data[] = {0x00, 0x01, 0x02};
    PacketInfo pkt = parse_packet(data, sizeof(data), sizeof(data));
    // Should return basic info without crashing
    ATTEST_EQUAL(pkt.length, 3u);
    ATTEST_EQUAL(pkt.ip_version, 0);
}

REGISTER_TEST(parse_packet_ethernet_only)
{
    // Minimal Ethernet frame (just header, unknown ethertype)
    uint8_t data[] = {
        // Dst MAC
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        // Src MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        // EtherType (unknown)
        0x00, 0x00
    };

    PacketInfo pkt = parse_packet(data, sizeof(data), sizeof(data));
    ATTEST_EQUAL(pkt.length, sizeof(data));
    ATTEST_EQUAL(pkt.ether_type, 0x0000);

    // Check MAC addresses
    std::array<uint8_t, 6> expected_dst = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    std::array<uint8_t, 6> expected_src = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    ATTEST_TRUE(pkt.dst_mac == expected_dst);
    ATTEST_TRUE(pkt.src_mac == expected_src);
}

// =============================================================================
// Alert Formatting Tests
// =============================================================================

REGISTER_TEST(alert_format_short)
{
    Alert alert{};
    alert.matched_value = "evil.com";
    alert.label = "Known malware";

    std::string formatted = alert.format_short();
    ATTEST_EQUAL(formatted, "evil.com: Known malware");
}

// =============================================================================
// Integration-style Tests
// =============================================================================

REGISTER_TEST(watchlist_entry_matches_packet_by_hostname)
{
    std::vector<std::string> fields = {"wildcard", "*.tracking.com", "Tracker"};
    auto entry = WatchlistEntry::from_fields(fields);
    ATTEST_TRUE(entry.has_value());

    PacketInfo pkt{};
    pkt.hostname = "pixel.tracking.com";
    pkt.src_ip = "1.2.3.4";
    pkt.dst_ip = "5.6.7.8";

    ATTEST_TRUE(entry->matches(pkt));
}

REGISTER_TEST(watchlist_entry_matches_packet_by_ip)
{
    std::vector<std::string> fields = {"cidr", "10.0.0.0/8", "Private network"};
    auto entry = WatchlistEntry::from_fields(fields);
    ATTEST_TRUE(entry.has_value());

    PacketInfo pkt{};
    pkt.hostname = "";
    pkt.src_ip = "10.1.2.3";
    pkt.dst_ip = "8.8.8.8";

    ATTEST_TRUE(entry->matches(pkt));
}

REGISTER_TEST(watchlist_entry_no_match)
{
    std::vector<std::string> fields = {"exact", "evil.com", "Bad site"};
    auto entry = WatchlistEntry::from_fields(fields);
    ATTEST_TRUE(entry.has_value());

    PacketInfo pkt{};
    pkt.hostname = "good.com";
    pkt.src_ip = "1.2.3.4";
    pkt.dst_ip = "5.6.7.8";

    ATTEST_FALSE(entry->matches(pkt));
}
