/*
 * app.hpp - Main application controller
 *
 * Orchestrates all components of the network monitor: UI initialisation,
 * window layout, packet capture, and the main event loop. Owns the PacketStore,
 * PacketCapture, Sidebar, and all Panel instances.
 *
 * Also manages the DescriptionDatabase for traffic categorisation and
 * Watchlist for alert monitoring.
 *
 * The event loop polls for keyboard input (non-blocking), updates statistics,
 * and renders all UI components. Handles global keys (F1-F4 panel switching,
 * Tab for focus, q to quit) and delegates other keys to the focused component.
 */

#pragma once

#include "capture.hpp"
#include "descriptions.hpp"
#include "packet_store.hpp"
#include "panel.hpp"
#include "process_mapper.hpp"
#include "sidebar.hpp"
#include "ui.hpp"
#include "watchlist.hpp"
#include <array>
#include <chrono>
#include <memory>

class App {
public:
    App();
    ~App();

    // Non-copyable
    App(const App&) = delete;
    App& operator=(const App&) = delete;

    // Main lifecycle
    bool init();
    void run();
    void shutdown();

private:
    // Focus state
    enum class Focus { SIDEBAR, PANEL };

    // Core components
    UI ui_;
    PacketStore store_;
    std::unique_ptr<PacketCapture> capture_;
    Sidebar sidebar_;

    // Configuration databases
    DescriptionDatabase descriptions_;
    Watchlist watchlist_;
    ProcessMapper process_mapper_;

    // Panels
    std::array<std::unique_ptr<Panel>, 4> panels_;
    size_t active_panel_ = 0;

    // Windows
    WINDOW* top_bar_ = nullptr;
    WINDOW* sidebar_win_ = nullptr;
    WINDOW* main_win_ = nullptr;
    WINDOW* status_bar_ = nullptr;

    // State
    bool running_ = false;
    Focus focus_ = Focus::SIDEBAR;
    std::string error_message_;
    std::chrono::steady_clock::time_point last_rate_update_;
    std::chrono::steady_clock::time_point last_alert_time_;
    bool process_enabled_ = false;

    // Event handling
    void handle_key(int key);
    void handle_resize();

    // Rendering
    void create_windows();
    void destroy_windows();
    void render();
    void render_top_bar();
    void render_status_bar();

    // Capture control
    void start_capture(const std::string& interface_name);
    void stop_capture();

    // Panel switching
    void switch_panel(size_t index);
};
