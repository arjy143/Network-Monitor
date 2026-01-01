#pragma once

#include "packet.hpp"
#include <chrono>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <vector>

struct InterfaceStats {
    std::string name;
    uint64_t packets_received = 0;
    uint64_t bytes_received = 0;
    double packets_per_second = 0.0;
    double bytes_per_second = 0.0;

    // Protocol breakdown
    std::map<std::string, uint64_t> protocol_counts;
    std::map<std::string, uint64_t> protocol_bytes;

    // For rate calculation
    std::chrono::steady_clock::time_point last_rate_update;
    uint64_t last_packets = 0;
    uint64_t last_bytes = 0;

    // Traffic history for graphing (packets per second over time)
    std::deque<double> pps_history;
    std::deque<double> bps_history;
    static constexpr size_t MAX_HISTORY = 60;  // 60 seconds of history
};

class PacketStore {
public:
    static constexpr size_t MAX_PACKETS = 10000;

    PacketStore();

    // Thread-safe packet operations
    void push(PacketInfo packet);
    std::vector<PacketInfo> get_recent(size_t count) const;
    std::vector<PacketInfo> get_all() const;
    PacketInfo get(size_t index) const;
    size_t size() const;
    void clear();

    // Statistics
    InterfaceStats get_stats() const;
    void update_rates();  // Call periodically (every second)
    void set_interface_name(const std::string& name);

    // Selected packet for detail view
    void set_selected_index(size_t index);
    size_t get_selected_index() const;
    PacketInfo get_selected_packet() const;

private:
    mutable std::mutex mutex_;
    std::deque<PacketInfo> packets_;
    InterfaceStats stats_;
    size_t selected_index_ = 0;

    void update_stats_unlocked(const PacketInfo& pkt);
};
