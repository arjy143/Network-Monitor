/*
 * process_mapper.cpp - Process attribution implementation (Linux)
 *
 * Parses /proc/net/tcp and /proc/net/udp to get socket inodes, then
 * scans /proc/[pid]/fd/ to map inodes to process PIDs. Results are cached
 * to reduce filesystem overhead.
 */

#include "process_mapper.hpp"
#include "packet.hpp"
#include <arpa/inet.h>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

std::optional<ProcessInfo> ProcessMapper::lookup(
    const std::string& local_ip,
    uint16_t local_port,
    const std::string& remote_ip,
    uint16_t remote_port,
    uint8_t protocol
) {
#ifndef __linux__
    // Not supported on non-Linux platforms
    return std::nullopt;
#else
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if we need to refresh socket tables
    auto now = std::chrono::steady_clock::now();
    if (!is_cache_valid(last_socket_refresh_)) {
        refresh_socket_table(PROTO_TCP);
        refresh_socket_table(PROTO_UDP);
        refresh_inode_mapping();
        last_socket_refresh_ = now;
    }

    // Build socket key
    SocketKey key;
    struct in_addr addr;

    if (inet_pton(AF_INET, local_ip.c_str(), &addr) == 1) {
        key.local_addr = ntohl(addr.s_addr);
    } else {
        return std::nullopt;  // IPv6 not supported yet
    }

    if (inet_pton(AF_INET, remote_ip.c_str(), &addr) == 1) {
        key.remote_addr = ntohl(addr.s_addr);
    } else {
        return std::nullopt;
    }

    key.local_port = local_port;
    key.remote_port = remote_port;
    key.protocol = protocol;

    // Look up socket in table
    auto socket_it = socket_table_.find(key);
    if (socket_it == socket_table_.end()) {
        // Try swapped (we might be looking at the remote's perspective)
        std::swap(key.local_addr, key.remote_addr);
        std::swap(key.local_port, key.remote_port);
        socket_it = socket_table_.find(key);
        if (socket_it == socket_table_.end()) {
            return std::nullopt;
        }
    }

    uint64_t inode = socket_it->second.inode;

    // Look up inode -> process
    auto proc_it = inode_to_process_.find(inode);
    if (proc_it == inode_to_process_.end()) {
        return std::nullopt;
    }

    return proc_it->second;
#endif
}

std::optional<ProcessInfo> ProcessMapper::lookup_packet(
    const std::string& src_ip,
    uint16_t src_port,
    const std::string& dst_ip,
    uint16_t dst_port,
    uint8_t protocol
) {
    // Try both directions since we might be seeing incoming or outgoing packet
    auto result = lookup(src_ip, src_port, dst_ip, dst_port, protocol);
    if (result) {
        return result;
    }
    return lookup(dst_ip, dst_port, src_ip, src_port, protocol);
}

void ProcessMapper::refresh() {
    std::lock_guard<std::mutex> lock(mutex_);
    refresh_socket_table(PROTO_TCP);
    refresh_socket_table(PROTO_UDP);
    refresh_inode_mapping();
    last_socket_refresh_ = std::chrono::steady_clock::now();
}

void ProcessMapper::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    socket_table_.clear();
    inode_to_process_.clear();
    process_name_cache_.clear();
    last_socket_refresh_ = {};
}

size_t ProcessMapper::cache_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return inode_to_process_.size();
}

size_t ProcessMapper::socket_table_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return socket_table_.size();
}

#ifdef __linux__

void ProcessMapper::refresh_socket_table(uint8_t protocol) {
    std::string path = (protocol == PROTO_TCP) ? "/proc/net/tcp" : "/proc/net/udp";
    std::ifstream file(path);
    if (!file.is_open()) {
        return;
    }

    std::string line;
    std::getline(file, line);  // Skip header

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string sl, local_addr, remote_addr, state;
        uint64_t inode = 0;

        // Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
        iss >> sl >> local_addr >> remote_addr >> state;

        // Skip remaining fields to get to inode
        std::string field;
        for (int i = 0; i < 6; ++i) {
            iss >> field;
        }
        iss >> inode;

        if (inode == 0) {
            continue;
        }

        // Parse local address (format: HHHHHHHH:PPPP)
        size_t colon_pos = local_addr.find(':');
        if (colon_pos == std::string::npos) {
            continue;
        }

        SocketKey key;
        key.local_addr = parse_proc_ip(local_addr.substr(0, colon_pos));
        key.local_port = static_cast<uint16_t>(parse_hex(local_addr.substr(colon_pos + 1)));

        // Parse remote address
        colon_pos = remote_addr.find(':');
        if (colon_pos == std::string::npos) {
            continue;
        }

        key.remote_addr = parse_proc_ip(remote_addr.substr(0, colon_pos));
        key.remote_port = static_cast<uint16_t>(parse_hex(remote_addr.substr(colon_pos + 1)));
        key.protocol = protocol;

        // Store in table
        SocketEntry entry;
        entry.inode = inode;
        entry.cached_at = std::chrono::steady_clock::now();
        socket_table_[key] = entry;
    }
}

void ProcessMapper::refresh_inode_mapping() {
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        return;
    }

    struct dirent* proc_entry;
    while ((proc_entry = readdir(proc_dir)) != nullptr) {
        // Skip non-numeric entries (not process directories)
        if (proc_entry->d_type != DT_DIR) {
            continue;
        }

        char* end;
        long pid = strtol(proc_entry->d_name, &end, 10);
        if (*end != '\0' || pid <= 0) {
            continue;
        }

        // Open /proc/PID/fd
        std::string fd_path = "/proc/" + std::string(proc_entry->d_name) + "/fd";
        DIR* fd_dir = opendir(fd_path.c_str());
        if (!fd_dir) {
            continue;
        }

        struct dirent* fd_entry;
        while ((fd_entry = readdir(fd_dir)) != nullptr) {
            if (fd_entry->d_type != DT_LNK) {
                continue;
            }

            std::string link_path = fd_path + "/" + fd_entry->d_name;
            char target[256];
            ssize_t len = readlink(link_path.c_str(), target, sizeof(target) - 1);
            if (len <= 0) {
                continue;
            }
            target[len] = '\0';

            // Check if this is a socket (format: socket:[inode])
            std::string target_str(target);
            if (target_str.substr(0, 8) != "socket:[") {
                continue;
            }

            // Extract inode number
            size_t bracket_pos = target_str.find(']');
            if (bracket_pos == std::string::npos) {
                continue;
            }

            std::string inode_str = target_str.substr(8, bracket_pos - 8);
            uint64_t inode = 0;
            try {
                inode = std::stoull(inode_str);
            } catch (...) {
                continue;
            }

            // Check if we care about this inode (is it in our socket table?)
            bool relevant = false;
            for (const auto& [key, entry] : socket_table_) {
                if (entry.inode == inode) {
                    relevant = true;
                    break;
                }
            }

            if (!relevant) {
                continue;
            }

            // Get process name
            ProcessInfo info;
            info.pid = static_cast<int32_t>(pid);
            info.name = get_process_name(info.pid);
            info.cached_at = std::chrono::steady_clock::now();

            inode_to_process_[inode] = info;
        }

        closedir(fd_dir);
    }

    closedir(proc_dir);
}

std::string ProcessMapper::get_process_name(int32_t pid) {
    // Check cache first
    auto it = process_name_cache_.find(pid);
    if (it != process_name_cache_.end()) {
        return it->second;
    }

    // Read from /proc/PID/comm
    std::string path = "/proc/" + std::to_string(pid) + "/comm";
    std::ifstream file(path);
    if (!file.is_open()) {
        return "";
    }

    std::string name;
    std::getline(file, name);

    // Remove trailing newline if present
    if (!name.empty() && name.back() == '\n') {
        name.pop_back();
    }

    process_name_cache_[pid] = name;
    return name;
}

uint32_t ProcessMapper::parse_proc_ip(const std::string& hex_ip) {
    // /proc stores IP in little-endian hex format
    // e.g., "0100007F" for 127.0.0.1
    uint32_t ip = static_cast<uint32_t>(parse_hex(hex_ip));
    // Convert from little-endian to host byte order
    return ntohl(ip);
}

uint64_t ProcessMapper::parse_hex(const std::string& hex) {
    try {
        return std::stoull(hex, nullptr, 16);
    } catch (...) {
        return 0;
    }
}

#else
// Non-Linux stubs
void ProcessMapper::refresh_socket_table(uint8_t) {}
void ProcessMapper::refresh_inode_mapping() {}
std::string ProcessMapper::get_process_name(int32_t) { return ""; }
uint32_t ProcessMapper::parse_proc_ip(const std::string&) { return 0; }
uint64_t ProcessMapper::parse_hex(const std::string&) { return 0; }
#endif

bool ProcessMapper::is_cache_valid(const std::chrono::steady_clock::time_point& cached_at) const {
    if (cached_at.time_since_epoch().count() == 0) {
        return false;
    }
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - cached_at);
    return elapsed < cache_ttl_;
}
