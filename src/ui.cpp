/*
 * ui.cpp - ncurses UI wrapper implementation
 *
 * Provides terminal UI functionality including colour initialisation,
 * non-blocking input handling, and utility functions for drawing
 * boxes, centring text, and formatting numbers.
 */

#include "ui.hpp"
#include <cstring>
#include <iomanip>
#include <sstream>

void UI::init() {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);

    // Enable non-blocking input with 100ms timeout
    timeout(100);

    // Initialise colours if available
    init_colors();
}

void UI::init_colors() {
    if (::has_colors()) {
        start_color();
        use_default_colors();
        has_colors_ = true;

        // Define colour pairs
        init_pair(COLOR_HEADER, COLOR_BLACK, COLOR_CYAN);
        init_pair(COLOR_SELECTED, COLOR_BLACK, COLOR_WHITE);
        init_pair(COLOR_TCP, COLOR_CYAN, -1);
        init_pair(COLOR_UDP, COLOR_GREEN, -1);
        init_pair(COLOR_ICMP, COLOR_YELLOW, -1);
        init_pair(COLOR_ARP, COLOR_MAGENTA, -1);
        init_pair(COLOR_OTHER, COLOR_WHITE, -1);
        init_pair(COLOR_STATUS, COLOR_WHITE, COLOR_BLUE);
        init_pair(COLOR_ACTIVE_BORDER, COLOR_GREEN, -1);
        init_pair(COLOR_ERROR, COLOR_RED, -1);
    }
}

void UI::shutdown() {
    endwin();
}

int UI::poll_input() {
    return getch();
}

void UI::set_input_timeout(int ms) {
    timeout(ms);
}

int UI::get_max_y() const {
    int y, x;
    getmaxyx(stdscr, y, x);
    return y;
}

int UI::get_max_x() const {
    int y, x;
    getmaxyx(stdscr, y, x);
    (void)y;  // Suppress unused warning
    return x;
}

void UI::set_color(WINDOW* win, ColorPair pair) {
    if (has_colors_) {
        wattron(win, COLOR_PAIR(pair));
    }
}

void UI::unset_color(WINDOW* win, ColorPair pair) {
    if (has_colors_) {
        wattroff(win, COLOR_PAIR(pair));
    }
}

void UI::draw_box(WINDOW* win, bool active) {
    if (active) {
        wattron(win, COLOR_PAIR(COLOR_ACTIVE_BORDER) | A_BOLD);
        box(win, 0, 0);
        wattroff(win, COLOR_PAIR(COLOR_ACTIVE_BORDER) | A_BOLD);
    } else {
        box(win, 0, 0);
    }
}

void UI::clear_window(WINDOW* win) {
    werase(win);
}

void UI::print_centered(WINDOW* win, int y, const std::string& text) {
    int max_x = getmaxx(win);
    int x = (max_x - static_cast<int>(text.length())) / 2;
    if (x < 0) x = 0;
    mvwprintw(win, y, x, "%s", text.c_str());
}

void UI::print_right_aligned(WINDOW* win, int y, const std::string& text) {
    int max_x = getmaxx(win);
    int x = max_x - static_cast<int>(text.length()) - 1;
    if (x < 0) x = 0;
    mvwprintw(win, y, x, "%s", text.c_str());
}

std::string UI::format_bytes(uint64_t bytes) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1);

    if (bytes >= 1000000000ULL) {
        oss << static_cast<double>(bytes) / 1000000000.0 << " GB";
    } else if (bytes >= 1000000ULL) {
        oss << static_cast<double>(bytes) / 1000000.0 << " MB";
    } else if (bytes >= 1000ULL) {
        oss << static_cast<double>(bytes) / 1000.0 << " KB";
    } else {
        oss << bytes << " B";
    }

    return oss.str();
}

std::string UI::format_rate(double bytes_per_sec) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1);

    if (bytes_per_sec >= 1000000000.0) {
        oss << bytes_per_sec / 1000000000.0 << " GB/s";
    } else if (bytes_per_sec >= 1000000.0) {
        oss << bytes_per_sec / 1000000.0 << " MB/s";
    } else if (bytes_per_sec >= 1000.0) {
        oss << bytes_per_sec / 1000.0 << " KB/s";
    } else {
        oss << bytes_per_sec << " B/s";
    }

    return oss.str();
}

std::string UI::truncate(const std::string& str, size_t max_len) {
    if (str.length() <= max_len) {
        return str;
    }
    if (max_len <= 3) {
        return str.substr(0, max_len);
    }
    return str.substr(0, max_len - 3) + "...";
}

// Legacy methods
void UI::print_center(const char* text) {
    clear();
    int rows, columns;
    getmaxyx(stdscr, rows, columns);
    int y = rows / 2 - 1;
    int x = (columns - static_cast<int>(strlen(text))) / 2;
    mvprintw(y, x, "%s", text);
}

void UI::refresh() {
    ::refresh();
}

void UI::wait_for_key() {
    timeout(-1);  // Blocking
    getch();
    timeout(100);  // Restore non-blocking
}
