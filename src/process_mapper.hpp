/*
 * process_mapper.hpp - Process attribution for network packets (Linux)
 *
 * Maps network connections to their originating processes by parsing
 * /proc/net/tcp and /proc/net/udp for socket inodes, then scanning
 * /proc/[pid]/fd/ to find which process owns each socket. Results are
 * cached with a short TTL to minimise /proc scanning overhead.
 *
 * This is a Linux-only feature. On other platforms, lookups return empty.
 */

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

// Key for socket lookup (local addr:port + remote addr:port)
struct SocketKey {
    uint32_t local_addr;
    uint16_t local_port;
    uint32_t remote_addr;
    uint16_t remote_port;
    uint8_t protocol;  // PROTO_TCP or PROTO_UDP

    bool operator==(const SocketKey& other) const {
        return local_addr == other.local_addr &&
               local_port == other.local_port &&
               remote_addr == other.remote_addr &&
               remote_port == other.remote_port &&
               protocol == other.protocol;
    }
};

// Hash function for SocketKey
struct SocketKeyHash {
    std::size_t operator()(const SocketKey& key) const {
        std::size_t h = 0;
        h ^= std::hash<uint32_t>{}(key.local_addr) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(key.local_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint32_t>{}(key.remote_addr) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(key.remote_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t>{}(key.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

// Process information
struct ProcessInfo {
    int32_t pid = 0;
    std::string name;
    std::chrono::steady_clock::time_point cached_at;

    bool is_valid() const { return pid > 0 && !name.empty(); }
};

class ProcessMapper {
public:
    ProcessMapper() = default;

    // Look up process for a given connection
    // Returns empty optional if not found or not on Linux
    std::optional<ProcessInfo> lookup(
        const std::string& local_ip,
        uint16_t local_port,
        const std::string& remote_ip,
        uint16_t remote_port,
        uint8_t protocol
    );

    // Convenience lookup from PacketInfo-style data
    std::optional<ProcessInfo> lookup_packet(
        const std::string& src_ip,
        uint16_t src_port,
        const std::string& dst_ip,
        uint16_t dst_port,
        uint8_t protocol
    );

    // Force refresh of socket->inode and inode->process mappings
    void refresh();

    // Clear all caches
    void clear();

    // Cache statistics
    size_t cache_size() const;
    size_t socket_table_size() const;

    // Set cache TTL (default 500ms)
    void set_cache_ttl(std::chrono::milliseconds ttl) { cache_ttl_ = ttl; }

private:
    // Socket inode from /proc/net/{tcp,udp}
    struct SocketEntry {
        uint64_t inode;
        std::chrono::steady_clock::time_point cached_at;
    };

    // Mapping from socket key to inode
    std::unordered_map<SocketKey, SocketEntry, SocketKeyHash> socket_table_;

    // Mapping from inode to process info (cached)
    std::unordered_map<uint64_t, ProcessInfo> inode_to_process_;

    // Process info cache (by pid -> name)
    std::unordered_map<int32_t, std::string> process_name_cache_;

    mutable std::mutex mutex_;
    std::chrono::milliseconds cache_ttl_{500};
    std::chrono::steady_clock::time_point last_socket_refresh_;

    // Parse /proc/net/tcp or /proc/net/udp
    void refresh_socket_table(uint8_t protocol);

    // Scan /proc/[pid]/fd/ to map inodes to PIDs
    void refresh_inode_mapping();

    // Get process name from /proc/PID/comm
    std::string get_process_name(int32_t pid);

    // Parse IP address to uint32_t (network byte order as in /proc)
    static uint32_t parse_proc_ip(const std::string& hex_ip);

    // Parse hex string to number
    static uint64_t parse_hex(const std::string& hex);

    // Check if cache entry is still valid
    bool is_cache_valid(const std::chrono::steady_clock::time_point& cached_at) const;
};
