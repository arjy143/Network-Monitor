/*
 * sidebar.hpp - Network interface selector widget
 *
 * Displays a navigable list of available network interfaces in the left
 * sidebar. Users can scroll through interfaces with arrow keys and select
 * one with Enter to start capturing. Shows interface status (up/down) and
 * supports refreshing the interface list.
 *
 * The sidebar callback is invoked when an interface is selected, triggering
 * the App to start packet capture on that interface.
 */

#pragma once

#include "capture.hpp"
#include "ui.hpp"
#include <functional>
#include <ncurses.h>
#include <string>
#include <vector>

class Sidebar {
public:
    using SelectCallback = std::function<void(const std::string&)>;

    Sidebar(UI& ui);

    // Refresh interface list
    void refresh_interfaces();

    // Render the sidebar
    void render(WINDOW* win);

    // Handle keyboard input (return true if handled)
    bool handle_key(int key);

    // State
    void set_active(bool active) { active_ = active; }
    bool is_active() const { return active_; }

    // Selection
    std::string get_selected_interface() const;
    void set_on_select(SelectCallback callback) { on_select_ = std::move(callback); }

    // Get number of interfaces
    size_t interface_count() const { return interfaces_.size(); }

private:
    UI& ui_;
    std::vector<NetworkInterface> interfaces_;
    size_t selected_index_ = 0;
    size_t scroll_offset_ = 0;
    bool active_ = false;
    SelectCallback on_select_;
};
