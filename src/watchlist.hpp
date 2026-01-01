/*
 * watchlist.hpp - Watchlist and alert system
 *
 * Monitors network traffic for matches against user-defined patterns.
 * Supports exact hostname/IP matching, wildcard patterns, regex, and CIDR ranges.
 * Generates alerts when matches are detected and logs them to file.
 */

#pragma once

#include "packet.hpp"
#include <string>
#include <vector>
#include <deque>
#include <optional>
#include <mutex>
#include <regex>
#include <chrono>
#include <atomic>

struct WatchlistEntry {
    enum class MatchType { EXACT, WILDCARD, REGEX, IP, CIDR };

    MatchType type;
    std::string pattern;        // Original pattern string
    std::string label;          // User-defined label/reason

    // For IP/CIDR matching
    uint32_t ip_addr = 0;
    uint32_t netmask = 0xFFFFFFFF;

    // Compiled regex for efficient matching
    std::optional<std::regex> compiled_regex;

    // Check if this entry matches the packet
    bool matches(const PacketInfo& pkt) const;

    // Check hostname match
    bool matches_hostname(const std::string& hostname) const;

    // Check IP match
    bool matches_ip(const std::string& ip) const;

    // Create entry from parsed fields
    static std::optional<WatchlistEntry> from_fields(const std::vector<std::string>& fields);

private:
    // Parse IP address string to uint32_t
    static uint32_t parse_ip_addr(const std::string& ip);
};

struct Alert {
    std::chrono::system_clock::time_point timestamp;
    std::string matched_value;  // The hostname/IP that matched
    std::string pattern;        // The watchlist pattern that matched
    std::string label;          // The label from watchlist entry
    size_t packet_index;        // Index in PacketStore for reference

    // Format for display
    std::string format_short() const;
    std::string format_full() const;
};

class Watchlist {
public:
    static constexpr size_t MAX_ALERTS = 100;

    Watchlist() = default;

    // Load watchlist from a file
    int load(const std::string& filepath);

    // Load from default config location
    int load_default();

    // Check packet against watchlist
    // Returns the matching entry if found
    std::optional<WatchlistEntry> check(const PacketInfo& pkt) const;

    // Check and update packet with match info
    // Returns true if matched
    bool check_and_mark(PacketInfo& pkt) const;

    // Alert management
    void add_alert(const Alert& alert);
    std::vector<Alert> get_recent_alerts(size_t count = 10) const;
    void clear_alerts();
    size_t alert_count() const;

    // Get the most recent alert (for status bar display)
    std::optional<Alert> get_latest_alert() const;

    // Check if there are new alerts since last check
    bool has_new_alerts();

    // Reload watchlist (thread-safe)
    bool reload();

    // Get number of entries
    size_t size() const;

    // Check if watchlist is loaded
    bool is_loaded() const { return loaded_; }

    // Alert logging
    void set_log_file(const std::string& filepath);
    void log_alert(const Alert& alert);

    // Convert wildcard pattern to regex (public for use by WatchlistEntry)
    static std::string wildcard_to_regex(const std::string& pattern);

private:
    mutable std::mutex mutex_;
    std::vector<WatchlistEntry> entries_;
    std::deque<Alert> alerts_;
    std::string filepath_;
    std::string log_filepath_;
    bool loaded_ = false;
    std::atomic<bool> has_new_alerts_{false};
};
