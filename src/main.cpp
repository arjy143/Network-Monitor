/*
 * main.cpp - Network Monitor entry point
 *
 * Minimal entry point that creates the App instance and runs it.
 * All application logic is encapsulated in the App class.
 *
 * Note: Packet capture requires root privileges or CAP_NET_RAW capability.
 * Run with: sudo ./network-monitor
 * Or set capabilities: sudo setcap cap_net_raw,cap_net_admin=eip ./network-monitor
 */

#include "app.hpp"
#include <iostream>

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    App app;

    if (!app.init()) {
        std::cerr << "Failed to initialize application" << std::endl;
        return 1;
    }

    app.run();
    app.shutdown();

    return 0;
}
