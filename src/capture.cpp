/*
 * capture.cpp - libpcap-based packet capture implementation
 *
 * Handles opening network interfaces, running the capture loop in a background
 * thread, and parsing captured packets. Uses pcap_dispatch() with a callback
 * that pushes parsed packets to the PacketStore.
 */

#include "capture.hpp"
#include <arpa/inet.h>
#include <cstring>

PacketCapture::PacketCapture(PacketStore& store) : store_(store) {}

PacketCapture::~PacketCapture() {
    stop();
    close();
}

std::vector<NetworkInterface> PacketCapture::get_all_interfaces() {
    std::vector<NetworkInterface> interfaces;
    pcap_if_t* all_devs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&all_devs, errbuf) == -1) {
        return interfaces;
    }

    for (pcap_if_t* dev = all_devs; dev != nullptr; dev = dev->next) {
        NetworkInterface iface;
        iface.name = dev->name;

        if (dev->description) {
            iface.description = dev->description;
        }

        iface.is_loopback = (dev->flags & PCAP_IF_LOOPBACK) != 0;
        iface.is_up = (dev->flags & PCAP_IF_UP) != 0;

        // Get addresses
        for (pcap_addr_t* addr = dev->addresses; addr != nullptr; addr = addr->next) {
            if (addr->addr == nullptr) continue;

            char buf[INET6_ADDRSTRLEN];
            if (addr->addr->sa_family == AF_INET) {
                auto* sin = reinterpret_cast<struct sockaddr_in*>(addr->addr);
                inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
                iface.addresses.push_back(buf);
            } else if (addr->addr->sa_family == AF_INET6) {
                auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(addr->addr);
                inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
                iface.addresses.push_back(buf);
            }
        }

        interfaces.push_back(std::move(iface));
    }

    pcap_freealldevs(all_devs);
    return interfaces;
}

bool PacketCapture::open(const std::string& interface_name) {
    if (handle_) {
        close();
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    // Open interface for capture
    // snaplen: 65535 (full packets)
    // promisc: 1 (capture all packets, not just those for this host)
    // timeout: 100ms (for pcap_dispatch)
    handle_ = pcap_open_live(
        interface_name.c_str(),
        65535,
        1,
        100,
        errbuf
    );

    if (handle_ == nullptr) {
        error_ = errbuf;
        return false;
    }

    // Set non-blocking mode for cleaner shutdown
    if (pcap_setnonblock(handle_, 1, errbuf) == -1) {
        // Non-fatal, continue anyway
    }

    interface_name_ = interface_name;
    store_.set_interface_name(interface_name);
    store_.clear();
    error_.clear();

    return true;
}

void PacketCapture::start() {
    if (!handle_ || running_.load()) {
        return;
    }

    running_.store(true);
    capture_thread_ = std::thread([this]() {
        capture_loop();
    });
}

void PacketCapture::stop() {
    if (!running_.load()) {
        return;
    }

    running_.store(false);

    if (handle_) {
        pcap_breakloop(handle_);
    }

    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
}

void PacketCapture::close() {
    stop();

    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }

    interface_name_.clear();
}

void PacketCapture::capture_loop() {
    while (running_.load()) {
        // Process up to 10 packets per iteration
        int result = pcap_dispatch(handle_, 10, packet_callback,
                                   reinterpret_cast<u_char*>(this));

        if (result == PCAP_ERROR) {
            error_ = pcap_geterr(handle_);
            break;
        }

        // result == 0 means timeout (no packets), that's fine
        // result == -2 means pcap_breakloop was called

        if (result == -2) {
            break;
        }

        // Small sleep if no packets to avoid busy-waiting
        if (result == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

void PacketCapture::packet_callback(u_char* user,
                                    const struct pcap_pkthdr* header,
                                    const u_char* data) {
    auto* self = reinterpret_cast<PacketCapture*>(user);

    // Parse the packet
    PacketInfo info = parse_packet(data, header->caplen, header->len);

    // Push to store (thread-safe)
    self->store_.push(std::move(info));
}
