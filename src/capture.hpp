/*
 * capture.hpp - Network packet capture using libpcap
 *
 * Wraps libpcap functionality for capturing packets from network interfaces.
 * Runs packet capture in a background thread, parsing each packet and pushing
 * it to the PacketStore for display. Supports interface enumeration, starting/
 * stopping capture, and graceful thread shutdown.
 *
 * Optionally integrates with Watchlist for real-time alert checking and
 * ProcessMapper for process attribution.
 *
 * Usage: Create a PacketCapture with a PacketStore reference, call open() with
 * an interface name, then start() to begin capturing. Call stop() to end.
 */

#pragma once

#include "packet_store.hpp"
#include <atomic>
#include <functional>
#include <memory>
#include <pcap.h>
#include <string>
#include <thread>
#include <vector>

// Forward declarations
class Watchlist;
class ProcessMapper;

struct NetworkInterface {
    std::string name;
    std::string description;
    std::vector<std::string> addresses;
    bool is_loopback = false;
    bool is_up = false;
};

class PacketCapture {
public:
    PacketCapture(PacketStore& store);
    ~PacketCapture();

    // Non-copyable
    PacketCapture(const PacketCapture&) = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    // Interface enumeration
    static std::vector<NetworkInterface> get_all_interfaces();

    // Capture control
    bool open(const std::string& interface_name);
    void start();
    void stop();
    void close();

    // State queries
    bool is_open() const { return handle_ != nullptr; }
    bool is_running() const { return running_.load(); }
    std::string get_error() const { return error_; }
    std::string get_interface_name() const { return interface_name_; }

    // Optional integrations
    void set_watchlist(Watchlist* wl) { watchlist_ = wl; }
    void set_process_mapper(ProcessMapper* pm) { process_mapper_ = pm; }
    void set_process_enabled(bool enabled) { process_enabled_.store(enabled); }
    bool is_process_enabled() const { return process_enabled_.load(); }

private:
    void capture_loop();
    static void packet_callback(u_char* user, const struct pcap_pkthdr* header,
                                const u_char* data);

    PacketStore& store_;
    pcap_t* handle_ = nullptr;
    std::string interface_name_;
    std::string error_;

    std::atomic<bool> running_{false};
    std::thread capture_thread_;

    // Optional integrations
    Watchlist* watchlist_ = nullptr;
    ProcessMapper* process_mapper_ = nullptr;
    std::atomic<bool> process_enabled_{false};
};
