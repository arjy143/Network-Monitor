/*
 * descriptions.cpp - Traffic description database implementation
 *
 * Loads and queries the description database for hostname categorisation.
 * Supports wildcard patterns like *.google.com and full regex patterns.
 */

#include "descriptions.hpp"
#include "config.hpp"
#include <algorithm>
#include <cctype>

bool DescriptionEntry::matches(const std::string& hostname) const {
    if (hostname.empty()) {
        return false;
    }

    // Convert hostname to lowercase for case-insensitive matching
    std::string lower_host = hostname;
    std::transform(lower_host.begin(), lower_host.end(), lower_host.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    switch (type) {
        case MatchType::EXACT: {
            std::string lower_pattern = pattern;
            std::transform(lower_pattern.begin(), lower_pattern.end(), lower_pattern.begin(),
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
    }

    return false;
}

std::optional<DescriptionEntry> DescriptionEntry::from_fields(const std::vector<std::string>& fields) {
    // Format: PATTERN:CATEGORY:DESCRIPTION
    if (fields.size() < 3) {
        return std::nullopt;
    }

    DescriptionEntry entry;
    entry.pattern = fields[0];
    entry.category = fields[1];
    entry.description = fields[2];

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

    trim(entry.pattern);
    trim(entry.category);
    trim(entry.description);

    if (entry.pattern.empty() || entry.category.empty()) {
        return std::nullopt;
    }

    // Detect match type and compile regex if needed
    entry.type = DescriptionDatabase::detect_match_type(entry.pattern);

    if (entry.type == MatchType::WILDCARD) {
        std::string regex_pattern = DescriptionDatabase::wildcard_to_regex(entry.pattern);
        try {
            entry.compiled_regex = std::regex(regex_pattern,
                std::regex::icase | std::regex::optimize);
        } catch (...) {
            return std::nullopt;  // Invalid pattern
        }
    } else if (entry.type == MatchType::REGEX) {
        // Pattern starts with ~ to indicate regex
        std::string regex_pattern = entry.pattern.substr(1);
        try {
            entry.compiled_regex = std::regex(regex_pattern,
                std::regex::icase | std::regex::optimize);
        } catch (...) {
            return std::nullopt;  // Invalid regex
        }
    }

    return entry;
}

DescriptionEntry::MatchType DescriptionDatabase::detect_match_type(const std::string& pattern) {
    if (pattern.empty()) {
        return DescriptionEntry::MatchType::EXACT;
    }

    // Pattern starting with ~ is explicit regex
    if (pattern[0] == '~') {
        return DescriptionEntry::MatchType::REGEX;
    }

    // Check for wildcard characters
    if (pattern.find('*') != std::string::npos ||
        pattern.find('?') != std::string::npos) {
        return DescriptionEntry::MatchType::WILDCARD;
    }

    return DescriptionEntry::MatchType::EXACT;
}

std::string DescriptionDatabase::wildcard_to_regex(const std::string& pattern) {
    std::string regex;
    regex.reserve(pattern.length() * 2);

    // Anchor at start
    regex += '^';

    for (char c : pattern) {
        switch (c) {
            case '*':
                regex += ".*";
                break;
            case '?':
                regex += '.';
                break;
            // Escape regex metacharacters
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

    // Anchor at end
    regex += '$';

    return regex;
}

int DescriptionDatabase::load(const std::string& filepath) {
    auto lines = Config::read_config_lines(filepath);

    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    filepath_ = filepath;

    int count = 0;
    for (const auto& line : lines) {
        auto fields = Config::parse_fields(line, ':');
        auto entry = DescriptionEntry::from_fields(fields);
        if (entry) {
            entries_.push_back(std::move(*entry));
            count++;
        }
    }

    loaded_ = true;
    return count;
}

int DescriptionDatabase::load_default() {
    // Try to install default config if it doesn't exist
    Config::install_default_config("descriptions.txt");

    std::string filepath = Config::get_config_path("descriptions.txt");
    return load(filepath);
}

std::optional<DescriptionDatabase::LookupResult> DescriptionDatabase::lookup(
    const std::string& hostname) const {

    if (hostname.empty()) {
        return std::nullopt;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // First match wins
    for (const auto& entry : entries_) {
        if (entry.matches(hostname)) {
            return LookupResult{entry.category, entry.description};
        }
    }

    return std::nullopt;
}

bool DescriptionDatabase::reload() {
    if (filepath_.empty()) {
        return false;
    }
    return load(filepath_) >= 0;
}

size_t DescriptionDatabase::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}
