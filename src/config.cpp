/*
 * config.cpp - Configuration file utilities implementation
 *
 * Handles XDG-compliant config directory resolution and file operations.
 * Supports reading line-based config files with comments and field parsing.
 */

#include "config.hpp"
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>

std::optional<std::string> Config::cached_config_dir_;
std::optional<std::string> Config::cached_data_dir_;

std::string Config::get_config_dir() {
    if (cached_config_dir_) {
        return *cached_config_dir_;
    }

    std::string config_dir;

    // Check XDG_CONFIG_HOME first
    const char* xdg_config = std::getenv("XDG_CONFIG_HOME");
    if (xdg_config && xdg_config[0] != '\0') {
        config_dir = std::string(xdg_config) + "/network-monitor";
    } else {
        // Fall back to ~/.config/network-monitor
        const char* home = std::getenv("HOME");
        if (!home || home[0] == '\0') {
            // Last resort: use passwd entry
            struct passwd* pw = getpwuid(getuid());
            if (pw) {
                home = pw->pw_dir;
            }
        }
        if (home) {
            config_dir = std::string(home) + "/.config/network-monitor";
        } else {
            // Fallback to current directory
            config_dir = ".";
        }
    }

    cached_config_dir_ = config_dir;
    return config_dir;
}

bool Config::ensure_config_dir() {
    std::string dir = get_config_dir();

    // Check if directory exists
    struct stat st;
    if (stat(dir.c_str(), &st) == 0) {
        return S_ISDIR(st.st_mode);
    }

    // Need to create parent directories too
    // First ensure ~/.config exists
    std::string parent = dir.substr(0, dir.rfind('/'));
    if (!parent.empty() && stat(parent.c_str(), &st) != 0) {
        if (mkdir(parent.c_str(), 0755) != 0) {
            return false;
        }
    }

    // Create config directory
    return mkdir(dir.c_str(), 0755) == 0;
}

std::string Config::get_config_path(const std::string& filename) {
    return get_config_dir() + "/" + filename;
}

std::vector<std::string> Config::read_config_lines(const std::string& filepath) {
    std::vector<std::string> lines;
    std::ifstream file(filepath);

    if (!file.is_open()) {
        return lines;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines
        if (line.empty()) {
            continue;
        }

        // Skip lines starting with # (comments)
        size_t first_non_space = line.find_first_not_of(" \t");
        if (first_non_space == std::string::npos) {
            continue;
        }
        if (line[first_non_space] == '#') {
            continue;
        }

        // Trim leading/trailing whitespace
        size_t last_non_space = line.find_last_not_of(" \t\r\n");
        if (last_non_space != std::string::npos) {
            line = line.substr(first_non_space, last_non_space - first_non_space + 1);
        }

        if (!line.empty()) {
            lines.push_back(line);
        }
    }

    return lines;
}

std::vector<std::string> Config::parse_fields(const std::string& line, char delimiter) {
    std::vector<std::string> fields;
    std::string current;
    bool escaped = false;

    for (size_t i = 0; i < line.length(); ++i) {
        char c = line[i];

        if (escaped) {
            // Previous character was backslash
            current += c;
            escaped = false;
        } else if (c == '\\') {
            // Start escape sequence
            escaped = true;
        } else if (c == delimiter) {
            // Field separator
            fields.push_back(current);
            current.clear();
        } else {
            current += c;
        }
    }

    // Don't forget the last field
    fields.push_back(current);

    return fields;
}

std::string Config::get_data_dir() {
    if (cached_data_dir_) {
        return *cached_data_dir_;
    }

    // Check common locations for bundled data
    std::vector<std::string> search_paths = {
        "/usr/share/network-monitor",
        "/usr/local/share/network-monitor",
        "./data",
        "../data"
    };

    // Also check relative to executable (for development)
    char exe_path[4096];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
        std::string exe_dir(exe_path);
        size_t last_slash = exe_dir.rfind('/');
        if (last_slash != std::string::npos) {
            exe_dir = exe_dir.substr(0, last_slash);
            search_paths.insert(search_paths.begin(), exe_dir + "/data");
            search_paths.insert(search_paths.begin(), exe_dir + "/../data");
        }
    }

    for (const auto& path : search_paths) {
        struct stat st;
        if (stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
            cached_data_dir_ = path;
            return path;
        }
    }

    // Fallback
    cached_data_dir_ = "./data";
    return "./data";
}

bool Config::install_default_config(const std::string& filename) {
    std::string dest_path = get_config_path(filename);

    // Check if destination already exists
    struct stat st;
    if (stat(dest_path.c_str(), &st) == 0) {
        return true;  // Already exists
    }

    // Ensure config directory exists
    if (!ensure_config_dir()) {
        return false;
    }

    // Find source file in data directory
    std::string src_path = get_data_dir() + "/" + filename;
    if (stat(src_path.c_str(), &st) != 0) {
        return false;  // Source doesn't exist
    }

    // Copy file
    std::ifstream src(src_path, std::ios::binary);
    std::ofstream dst(dest_path, std::ios::binary);

    if (!src.is_open() || !dst.is_open()) {
        return false;
    }

    dst << src.rdbuf();
    return dst.good();
}
