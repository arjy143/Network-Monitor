/*
 * config.hpp - Configuration file utilities
 *
 * Provides functions for locating and reading configuration files.
 * Follows XDG Base Directory specification for config file locations.
 * Uses a simple line-based format with colon-separated fields.
 */

#pragma once

#include <string>
#include <vector>
#include <optional>

class Config {
public:
    // Get the configuration directory path
    // Checks $XDG_CONFIG_HOME first, falls back to ~/.config/network-monitor
    static std::string get_config_dir();

    // Ensure the configuration directory exists (creates if needed)
    static bool ensure_config_dir();

    // Get the full path to a config file
    static std::string get_config_path(const std::string& filename);

    // Read lines from a config file, stripping comments and empty lines
    // Returns empty vector if file doesn't exist
    static std::vector<std::string> read_config_lines(const std::string& filepath);

    // Parse a colon-separated line into fields
    // Handles escaped colons (\:) within fields
    static std::vector<std::string> parse_fields(const std::string& line, char delimiter = ':');

    // Get the data directory (for bundled files)
    static std::string get_data_dir();

    // Copy bundled file to config dir if it doesn't exist
    static bool install_default_config(const std::string& filename);

private:
    static std::optional<std::string> cached_config_dir_;
    static std::optional<std::string> cached_data_dir_;
};
