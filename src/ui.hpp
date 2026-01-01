#pragma once

#include <ncurses.h>
#include <string>

// Color pair IDs
enum ColorPair {
    COLOR_DEFAULT = 0,
    COLOR_HEADER = 1,
    COLOR_SELECTED = 2,
    COLOR_TCP = 3,
    COLOR_UDP = 4,
    COLOR_ICMP = 5,
    COLOR_ARP = 6,
    COLOR_OTHER = 7,
    COLOR_STATUS = 8,
    COLOR_ACTIVE_BORDER = 9,
    COLOR_ERROR = 10
};

class UI {
public:
    void init();
    void shutdown();

    // Input handling
    int poll_input();  // Non-blocking, returns ERR if no input
    void set_input_timeout(int ms);

    // Screen info
    int get_max_y() const;
    int get_max_x() const;

    // Color support
    bool has_colors() const { return has_colors_; }
    void set_color(WINDOW* win, ColorPair pair);
    void unset_color(WINDOW* win, ColorPair pair);

    // Window utilities
    static void draw_box(WINDOW* win, bool active = false);
    static void clear_window(WINDOW* win);
    static void print_centered(WINDOW* win, int y, const std::string& text);
    static void print_right_aligned(WINDOW* win, int y, const std::string& text);

    // Formatting helpers
    static std::string format_bytes(uint64_t bytes);
    static std::string format_rate(double bytes_per_sec);
    static std::string truncate(const std::string& str, size_t max_len);

    // Legacy methods for compatibility
    void print_center(const char* text);
    void refresh();
    void wait_for_key();

private:
    void init_colors();
    bool has_colors_ = false;
};
