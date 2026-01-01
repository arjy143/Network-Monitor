/*
 * packet_store.cpp - Thread-safe packet storage implementation
 *
 * Implements the circular buffer and statistics tracking for captured packets.
 * All public methods are mutex-protected to allow concurrent access from the
 * capture thread (writing) and UI thread (reading).
 */

#include "packet_store.hpp"
#include <algorithm>

PacketStore::PacketStore() {
    stats_.last_rate_update = std::chrono::steady_clock::now();
}

void PacketStore::push(PacketInfo packet) {
    std::lock_guard<std::mutex> lock(mutex_);

    packets_.push_back(std::move(packet));
    update_stats_unlocked(packets_.back());

    if (packets_.size() > MAX_PACKETS) {
        packets_.pop_front();
        // Adjust selected index if needed
        if (selected_index_ > 0) {
            selected_index_--;
        }
    }
}

void PacketStore::update_stats_unlocked(const PacketInfo& pkt) {
    stats_.packets_received++;
    stats_.bytes_received += pkt.original_length;

    std::string proto = pkt.protocol_name();
    stats_.protocol_counts[proto]++;
    stats_.protocol_bytes[proto] += pkt.original_length;
}

std::vector<PacketInfo> PacketStore::get_recent(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t n = std::min(count, packets_.size());
    if (n == 0) return {};

    return std::vector<PacketInfo>(packets_.end() - n, packets_.end());
}

std::vector<PacketInfo> PacketStore::get_all() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<PacketInfo>(packets_.begin(), packets_.end());
}

PacketInfo PacketStore::get(size_t index) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (index >= packets_.size()) {
        return PacketInfo{};
    }
    return packets_[index];
}

size_t PacketStore::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return packets_.size();
}

void PacketStore::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    packets_.clear();
    stats_ = InterfaceStats{};
    stats_.last_rate_update = std::chrono::steady_clock::now();
    selected_index_ = 0;
}

InterfaceStats PacketStore::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void PacketStore::update_rates() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration<double>(now - stats_.last_rate_update).count();

    if (elapsed >= 1.0) {
        uint64_t delta_packets = stats_.packets_received - stats_.last_packets;
        uint64_t delta_bytes = stats_.bytes_received - stats_.last_bytes;

        stats_.packets_per_second = static_cast<double>(delta_packets) / elapsed;
        stats_.bytes_per_second = static_cast<double>(delta_bytes) / elapsed;

        // Update history
        stats_.pps_history.push_back(stats_.packets_per_second);
        stats_.bps_history.push_back(stats_.bytes_per_second);

        if (stats_.pps_history.size() > InterfaceStats::MAX_HISTORY) {
            stats_.pps_history.pop_front();
        }
        if (stats_.bps_history.size() > InterfaceStats::MAX_HISTORY) {
            stats_.bps_history.pop_front();
        }

        stats_.last_packets = stats_.packets_received;
        stats_.last_bytes = stats_.bytes_received;
        stats_.last_rate_update = now;
    }
}

void PacketStore::set_interface_name(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.name = name;
}

void PacketStore::set_selected_index(size_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index < packets_.size()) {
        selected_index_ = index;
    }
}

size_t PacketStore::get_selected_index() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return selected_index_;
}

PacketInfo PacketStore::get_selected_packet() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (selected_index_ < packets_.size()) {
        return packets_[selected_index_];
    }
    return PacketInfo{};
}
