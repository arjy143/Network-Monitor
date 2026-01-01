#pragma once

#include "packet_store.hpp"
#include "ui.hpp"
#include <ncurses.h>
#include <string>

class Panel {
public:
    Panel(const std::string& title, PacketStore& store, UI& ui);
    virtual ~Panel() = default;

    // Render the panel content
    virtual void render(WINDOW* win) = 0;

    // Handle keyboard input (return true if handled)
    virtual bool handle_key(int key) = 0;

    // Panel state
    void set_active(bool active) { active_ = active; }
    bool is_active() const { return active_; }

    const std::string& get_title() const { return title_; }

protected:
    std::string title_;
    PacketStore& store_;
    UI& ui_;
    bool active_ = false;

    // Scroll state
    size_t scroll_offset_ = 0;

    // Helper to get content area dimensions (inside box)
    static int content_height(WINDOW* win) { return getmaxy(win) - 2; }
    static int content_width(WINDOW* win) { return getmaxx(win) - 2; }
};
