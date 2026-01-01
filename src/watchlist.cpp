/*
 * watchlist.cpp - Watchlist and alert system implementation
 *
 * Handles loading watchlist files, matching packets against entries,
 * and managing alerts with logging to file.
 */

#include "watchlist.hpp"
#include "config.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <arpa/inet.h>

// WatchlistEntry implementation

bool WatchlistEntry::matches(const PacketInfo& pkt) const {
    // Check hostname first (if available)
    if (!pkt.hostname.empty() && matches_hostname(pkt.hostname)) {
        return true;
    }

    // Check source IP
    if (!pkt.src_ip.empty() && matches_ip(pkt.src_ip)) {
        return true;
    }

    // Check destination IP
    if (!pkt.dst_ip.empty() && matches_ip(pkt.dst_ip)) {
        return true;
    }

    return false;
}

bool WatchlistEntry::matches_hostname(const std::string& hostname) const {
    if (hostname.empty()) {
        return false;
    }

    // Convert to lowercase for comparison
    std::string lower_host = hostname;
    std::transform(lower_host.begin(), lower_host.end(), lower_host.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    switch (type) {
        case MatchType::EXACT: {
            std::string lower_pattern = pattern;
            std::transform(lower_pattern.begin(), lower_pattern.end(),
                           lower_pattern.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            return lower_host == lower_pattern;
        }

        case MatchType::WILDCARD:
        case MatchType::REGEX: {
            if (!compiled_regex) {
                return false;
            }
            try {
                return std::regex_match(lower_host, *compiled_regex);
            } catch (...) {
                return false;
            }
        }

        case MatchType::IP:
        case MatchType::CIDR:
            // These don't match hostnames
            return false;
    }

    return false;
}

bool WatchlistEntry::matches_ip(const std::string& ip) const {
    if (ip.empty()) {
        return false;
    }

    switch (type) {
        case MatchType::EXACT: {
            // Exact string match for IP
            return ip == pattern;
        }

        case MatchType::IP: {
            uint32_t check_ip = parse_ip_addr(ip);
            return check_ip != 0 && check_ip == ip_addr;
        }

        case MatchType::CIDR: {
            uint32_t check_ip = parse_ip_addr(ip);
            if (check_ip == 0) return false;
            return (check_ip & netmask) == (ip_addr & netmask);
        }

        case MatchType::WILDCARD:
        case MatchType::REGEX:
            // These typically match hostnames, not IPs
            // But we can try regex matching on IP string
            if (compiled_regex) {
                try {
                    return std::regex_match(ip, *compiled_regex);
                } catch (...) {
                    return false;
                }
            }
            return false;
    }

    return false;
}

uint32_t WatchlistEntry::parse_ip_addr(const std::string& ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
        return ntohl(addr.s_addr);
    }
    return 0;
}

std::optional<WatchlistEntry> WatchlistEntry::from_fields(
    const std::vector<std::string>& fields) {
    // Format: TYPE:PATTERN:LABEL
    if (fields.size() < 3) {
        return std::nullopt;
    }

    WatchlistEntry entry;
    std::string type_str = fields[0];
    entry.pattern = fields[1];
    entry.label = fields[2];

    // Trim whitespace
    auto trim = [](std::string& s) {
        size_t start = s.find_first_not_of(" \t");
        size_t end = s.find_last_not_of(" \t");
        if (start == std::string::npos) {
            s.clear();
        } else {
            s = s.substr(start, end - start + 1);
        }
    };

    trim(type_str);
    trim(entry.pattern);
    trim(entry.label);

    if (entry.pattern.empty()) {
        return std::nullopt;
    }

    // Convert type string to lowercase
    std::transform(type_str.begin(), type_str.end(), type_str.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (type_str == "exact") {
        entry.type = MatchType::EXACT;
    } else if (type_str == "wildcard") {
        entry.type = MatchType::WILDCARD;
        std::string regex_pattern = Watchlist::wildcard_to_regex(entry.pattern);
        try {
            entry.compiled_regex = std::regex(regex_pattern,
                std::regex::icase | std::regex::optimize);
        } catch (...) {
            return std::nullopt;
        }
    } else if (type_str == "regex") {
        entry.type = MatchType::REGEX;
        try {
            entry.compiled_regex = std::regex(entry.pattern,
                std::regex::icase | std::regex::optimize);
        } catch (...) {
            return std::nullopt;
        }
    } else if (type_str == "ip") {
        entry.type = MatchType::IP;
        entry.ip_addr = parse_ip_addr(entry.pattern);
        if (entry.ip_addr == 0) {
            return std::nullopt;
        }
    } else if (type_str == "cidr") {
        entry.type = MatchType::CIDR;
        // Parse CIDR notation (e.g., 10.0.0.0/8)
        size_t slash_pos = entry.pattern.find('/');
        if (slash_pos == std::string::npos) {
            return std::nullopt;
        }
        std::string ip_part = entry.pattern.substr(0, slash_pos);
        std::string prefix_part = entry.pattern.substr(slash_pos + 1);

        entry.ip_addr = parse_ip_addr(ip_part);
        if (entry.ip_addr == 0) {
            return std::nullopt;
        }

        int prefix = 0;
        try {
            prefix = std::stoi(prefix_part);
        } catch (...) {
            return std::nullopt;
        }

        if (prefix < 0 || prefix > 32) {
            return std::nullopt;
        }

        // Create netmask from prefix
        if (prefix == 0) {
            entry.netmask = 0;
        } else {
            entry.netmask = 0xFFFFFFFF << (32 - prefix);
        }
    } else {
        return std::nullopt;  // Unknown type
    }

    return entry;
}

// Alert implementation

std::string Alert::format_short() const {
    std::ostringstream oss;
    oss << matched_value << ": " << label;
    return oss.str();
}

std::string Alert::format_full() const {
    std::ostringstream oss;
    auto time_t = std::chrono::system_clock::to_time_t(timestamp);
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    oss << " | " << matched_value;
    oss << " | Pattern: " << pattern;
    oss << " | " << label;
    return oss.str();
}

// Watchlist implementation

std::string Watchlist::wildcard_to_regex(const std::string& pattern) {
    std::string regex;
    regex.reserve(pattern.length() * 2);
    regex += '^';

    for (char c : pattern) {
        switch (c) {
            case '*':
                regex += ".*";
                break;
            case '?':
                regex += '.';
                break;
            case '.':
            case '+':
            case '^':
            case '$':
            case '(':
            case ')':
            case '[':
            case ']':
            case '{':
            case '}':
            case '|':
            case '\\':
                regex += '\\';
                regex += c;
                break;
            default:
                regex += c;
                break;
        }
    }

    regex += '$';
    return regex;
}

int Watchlist::load(const std::string& filepath) {
    auto lines = Config::read_config_lines(filepath);

    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    filepath_ = filepath;

    int count = 0;
    for (const auto& line : lines) {
        auto fields = Config::parse_fields(line, ':');
        auto entry = WatchlistEntry::from_fields(fields);
        if (entry) {
            entries_.push_back(std::move(*entry));
            count++;
        }
    }

    loaded_ = true;
    return count;
}

int Watchlist::load_default() {
    std::string filepath = Config::get_config_path("watchlist.txt");
    return load(filepath);
}

std::optional<WatchlistEntry> Watchlist::check(const PacketInfo& pkt) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& entry : entries_) {
        if (entry.matches(pkt)) {
            return entry;
        }
    }

    return std::nullopt;
}

bool Watchlist::check_and_mark(PacketInfo& pkt) const {
    auto match = check(pkt);
    if (match) {
        pkt.watchlist_match = true;
        pkt.watchlist_label = match->label;
        return true;
    }
    return false;
}

void Watchlist::add_alert(const Alert& alert) {
    std::lock_guard<std::mutex> lock(mutex_);

    alerts_.push_front(alert);
    if (alerts_.size() > MAX_ALERTS) {
        alerts_.pop_back();
    }

    has_new_alerts_.store(true);

    // Log to file if configured
    if (!log_filepath_.empty()) {
        log_alert(alert);
    }
}

std::vector<Alert> Watchlist::get_recent_alerts(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<Alert> result;
    size_t n = std::min(count, alerts_.size());
    result.reserve(n);

    for (size_t i = 0; i < n; ++i) {
        result.push_back(alerts_[i]);
    }

    return result;
}

void Watchlist::clear_alerts() {
    std::lock_guard<std::mutex> lock(mutex_);
    alerts_.clear();
}

size_t Watchlist::alert_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return alerts_.size();
}

std::optional<Alert> Watchlist::get_latest_alert() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (alerts_.empty()) {
        return std::nullopt;
    }
    return alerts_.front();
}

bool Watchlist::has_new_alerts() {
    return has_new_alerts_.exchange(false);
}

bool Watchlist::reload() {
    if (filepath_.empty()) {
        return false;
    }
    return load(filepath_) >= 0;
}

size_t Watchlist::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

void Watchlist::set_log_file(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    log_filepath_ = filepath;
}

void Watchlist::log_alert(const Alert& alert) {
    if (log_filepath_.empty()) {
        return;
    }

    std::ofstream file(log_filepath_, std::ios::app);
    if (file.is_open()) {
        file << alert.format_full() << "\n";
    }
}
