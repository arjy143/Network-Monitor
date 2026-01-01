/*
 * descriptions.hpp - Traffic description database
 *
 * Maps hostnames and domains to human-readable descriptions and categories.
 * Supports exact matching, wildcard patterns (*.example.com), and regex.
 * Thread-safe for concurrent lookups from UI and capture threads.
 */

#pragma once

#include <string>
#include <vector>
#include <optional>
#include <mutex>
#include <regex>

struct DescriptionEntry {
    enum class MatchType { EXACT, WILDCARD, REGEX };

    MatchType type;
    std::string pattern;        // Original pattern string
    std::string category;       // e.g., "Google", "Microsoft", "Telemetry"
    std::string description;    // e.g., "Google Services", "Certificate validation"

    // Compiled regex for efficient matching
    std::optional<std::regex> compiled_regex;

    // Check if this entry matches the given hostname
    bool matches(const std::string& hostname) const;

    // Create entry from parsed fields
    static std::optional<DescriptionEntry> from_fields(const std::vector<std::string>& fields);
};

class DescriptionDatabase {
public:
    DescriptionDatabase() = default;

    // Load descriptions from a file
    // Returns number of entries loaded, or -1 on error
    int load(const std::string& filepath);

    // Load from default config location
    // Installs bundled defaults if config file doesn't exist
    int load_default();

    // Look up description for a hostname
    struct LookupResult {
        std::string category;
        std::string description;
    };
    std::optional<LookupResult> lookup(const std::string& hostname) const;

    // Reload from file (thread-safe)
    bool reload();

    // Get number of entries
    size_t size() const;

    // Check if database is loaded
    bool is_loaded() const { return loaded_; }

    // Convert wildcard pattern to regex (public for use by DescriptionEntry)
    static std::string wildcard_to_regex(const std::string& pattern);

    // Determine match type from pattern string (public for use by DescriptionEntry)
    static DescriptionEntry::MatchType detect_match_type(const std::string& pattern);

private:
    mutable std::mutex mutex_;
    std::vector<DescriptionEntry> entries_;
    std::string filepath_;
    bool loaded_ = false;
};
