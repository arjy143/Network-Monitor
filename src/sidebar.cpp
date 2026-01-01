/*
 * sidebar.cpp - Network interface selector implementation
 *
 * Renders the interface list with keyboard navigation (up/down arrows,
 * Enter to select). Enumerates interfaces via PacketCapture::get_all_interfaces()
 * and displays their status.
 */

#include "sidebar.hpp"
#include <algorithm>

Sidebar::Sidebar(UI& ui) : ui_(ui) {
    refresh_interfaces();
}

void Sidebar::refresh_interfaces() {
    interfaces_ = PacketCapture::get_all_interfaces();
    selected_index_ = 0;
    scroll_offset_ = 0;
}

void Sidebar::render(WINDOW* win) {
    UI::clear_window(win);

    int max_y = getmaxy(win);
    int max_x = getmaxx(win);
    int content_height = max_y - 2;

    // Draw title
    wattron(win, A_BOLD);
    mvwprintw(win, 1, 2, "Interfaces");
    wattroff(win, A_BOLD);

    // Draw separator
    mvwhline(win, 2, 1, ACS_HLINE, max_x - 2);

    // Adjust scroll offset if needed
    if (selected_index_ < scroll_offset_) {
        scroll_offset_ = selected_index_;
    }
    if (selected_index_ >= scroll_offset_ + static_cast<size_t>(content_height - 3)) {
        scroll_offset_ = selected_index_ - content_height + 4;
    }

    // Draw interfaces
    int y = 3;
    for (size_t i = scroll_offset_; i < interfaces_.size() && y < max_y - 1; ++i, ++y) {
        const auto& iface = interfaces_[i];

        bool is_selected = (i == selected_index_);

        if (is_selected) {
            wattron(win, A_REVERSE);
        }

        // Clear line
        mvwhline(win, y, 1, ' ', max_x - 2);

        // Draw marker and name
        if (is_selected && active_) {
            mvwprintw(win, y, 1, "> ");
        } else {
            mvwprintw(win, y, 1, "  ");
        }

        std::string name = UI::truncate(iface.name, max_x - 5);
        mvwprintw(win, y, 3, "%s", name.c_str());

        // Show indicator for up/down status
        if (iface.is_up) {
            ui_.set_color(win, COLOR_UDP);
            mvwprintw(win, y, max_x - 3, "*");
            ui_.unset_color(win, COLOR_UDP);
        }

        if (is_selected) {
            wattroff(win, A_REVERSE);
        }
    }

    // Draw scroll indicators
    if (scroll_offset_ > 0) {
        mvwprintw(win, 3, max_x - 2, "^");
    }
    if (scroll_offset_ + content_height - 3 < interfaces_.size()) {
        mvwprintw(win, max_y - 2, max_x - 2, "v");
    }

    // Draw box (active state indicated by colour)
    UI::draw_box(win, active_);

    wrefresh(win);
}

bool Sidebar::handle_key(int key) {
    if (!active_ || interfaces_.empty()) {
        return false;
    }

    switch (key) {
        case KEY_UP:
        case 'k':
            if (selected_index_ > 0) {
                selected_index_--;
            }
            return true;

        case KEY_DOWN:
        case 'j':
            if (selected_index_ < interfaces_.size() - 1) {
                selected_index_++;
            }
            return true;

        case KEY_HOME:
        case 'g':
            selected_index_ = 0;
            return true;

        case KEY_END:
        case 'G':
            selected_index_ = interfaces_.size() - 1;
            return true;

        case '\n':
        case KEY_ENTER:
            if (on_select_ && !interfaces_.empty()) {
                on_select_(interfaces_[selected_index_].name);
            }
            return true;

        case 'r':
        case 'R':
            refresh_interfaces();
            return true;

        default:
            return false;
    }
}

std::string Sidebar::get_selected_interface() const {
    if (interfaces_.empty()) {
        return "";
    }
    return interfaces_[selected_index_].name;
}
