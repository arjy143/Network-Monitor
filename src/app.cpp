#include "app.hpp"
#include "panels/detail.hpp"
#include "panels/graph.hpp"
#include "panels/packet_list.hpp"
#include "panels/stats.hpp"
#include <cstring>
#include <sstream>

App::App()
    : sidebar_(ui_),
      last_rate_update_(std::chrono::steady_clock::now()) {

    // Set up sidebar callback
    sidebar_.set_on_select([this](const std::string& iface) {
        start_capture(iface);
    });
}

App::~App() {
    shutdown();
}

bool App::init() {
    ui_.init();

    // Create panels
    panels_[0] = std::make_unique<PacketListPanel>(store_, ui_);
    panels_[1] = std::make_unique<StatsPanel>(store_, ui_);
    panels_[2] = std::make_unique<GraphPanel>(store_, ui_);
    panels_[3] = std::make_unique<DetailPanel>(store_, ui_);

    // Create capture handler
    capture_ = std::make_unique<PacketCapture>(store_);

    // Create windows
    create_windows();

    // Set initial focus
    sidebar_.set_active(true);
    panels_[active_panel_]->set_active(false);

    return true;
}

void App::create_windows() {
    int max_y = ui_.get_max_y();
    int max_x = ui_.get_max_x();

    constexpr int TOP_BAR_HEIGHT = 3;
    constexpr int STATUS_BAR_HEIGHT = 3;
    constexpr int SIDEBAR_WIDTH = 20;

    int main_height = max_y - TOP_BAR_HEIGHT - STATUS_BAR_HEIGHT;
    int main_width = max_x - SIDEBAR_WIDTH;

    top_bar_ = newwin(TOP_BAR_HEIGHT, max_x, 0, 0);
    sidebar_win_ = newwin(main_height, SIDEBAR_WIDTH, TOP_BAR_HEIGHT, 0);
    main_win_ = newwin(main_height, main_width, TOP_BAR_HEIGHT, SIDEBAR_WIDTH);
    status_bar_ = newwin(STATUS_BAR_HEIGHT, max_x, max_y - STATUS_BAR_HEIGHT, 0);

    // Enable keypad for function keys
    keypad(top_bar_, TRUE);
    keypad(sidebar_win_, TRUE);
    keypad(main_win_, TRUE);
    keypad(status_bar_, TRUE);
}

void App::destroy_windows() {
    if (top_bar_) { delwin(top_bar_); top_bar_ = nullptr; }
    if (sidebar_win_) { delwin(sidebar_win_); sidebar_win_ = nullptr; }
    if (main_win_) { delwin(main_win_); main_win_ = nullptr; }
    if (status_bar_) { delwin(status_bar_); status_bar_ = nullptr; }
}

void App::run() {
    running_ = true;

    while (running_) {
        // Handle input
        int key = ui_.poll_input();
        if (key != ERR) {
            handle_key(key);
        }

        // Update rates periodically
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - last_rate_update_).count();
        if (elapsed >= 1) {
            store_.update_rates();
            last_rate_update_ = now;
        }

        // Render
        render();
    }
}

void App::shutdown() {
    stop_capture();
    destroy_windows();
    ui_.shutdown();
}

void App::handle_key(int key) {
    // Handle resize
    if (key == KEY_RESIZE) {
        handle_resize();
        return;
    }

    // Global keys
    switch (key) {
        case 'q':
        case 'Q':
            running_ = false;
            return;

        case KEY_F(1):
            switch_panel(0);
            return;

        case KEY_F(2):
            switch_panel(1);
            return;

        case KEY_F(3):
            switch_panel(2);
            return;

        case KEY_F(4):
            switch_panel(3);
            return;

        case '\t':
            // Toggle focus between sidebar and panel
            if (focus_ == Focus::SIDEBAR) {
                focus_ = Focus::PANEL;
                sidebar_.set_active(false);
                panels_[active_panel_]->set_active(true);
            } else {
                focus_ = Focus::SIDEBAR;
                sidebar_.set_active(true);
                panels_[active_panel_]->set_active(false);
            }
            return;

        case KEY_LEFT:
            if (focus_ == Focus::PANEL) {
                focus_ = Focus::SIDEBAR;
                sidebar_.set_active(true);
                panels_[active_panel_]->set_active(false);
            }
            return;

        case KEY_RIGHT:
            if (focus_ == Focus::SIDEBAR) {
                focus_ = Focus::PANEL;
                sidebar_.set_active(false);
                panels_[active_panel_]->set_active(true);
            }
            return;

        case 's':
        case 'S':
            // Stop capture
            stop_capture();
            return;
    }

    // Pass to focused component
    if (focus_ == Focus::SIDEBAR) {
        sidebar_.handle_key(key);
    } else {
        panels_[active_panel_]->handle_key(key);
    }
}

void App::handle_resize() {
    destroy_windows();
    clear();
    refresh();
    create_windows();
}

void App::render() {
    render_top_bar();
    sidebar_.render(sidebar_win_);
    panels_[active_panel_]->render(main_win_);
    render_status_bar();

    // Refresh stdscr to update screen
    refresh();
}

void App::render_top_bar() {
    UI::clear_window(top_bar_);

    int max_x = getmaxx(top_bar_);

    // Title
    wattron(top_bar_, A_BOLD);
    mvwprintw(top_bar_, 1, 2, "Network Monitor");
    wattroff(top_bar_, A_BOLD);

    // Panel tabs
    const char* tabs[] = {"F1:Packets", "F2:Stats", "F3:Graph", "F4:Detail"};
    int x = max_x - 50;

    for (size_t i = 0; i < 4; ++i) {
        if (i == active_panel_) {
            wattron(top_bar_, A_REVERSE | A_BOLD);
        }
        mvwprintw(top_bar_, 1, x, " %s ", tabs[i]);
        if (i == active_panel_) {
            wattroff(top_bar_, A_REVERSE | A_BOLD);
        }
        x += static_cast<int>(strlen(tabs[i])) + 3;
    }

    UI::draw_box(top_bar_, false);
    wrefresh(top_bar_);
}

void App::render_status_bar() {
    UI::clear_window(status_bar_);

    int max_x = getmaxx(status_bar_);

    // Left side: capture status
    if (capture_ && capture_->is_running()) {
        ui_.set_color(status_bar_, COLOR_UDP);
        mvwprintw(status_bar_, 1, 2, "[CAPTURING: %s]",
                  capture_->get_interface_name().c_str());
        ui_.unset_color(status_bar_, COLOR_UDP);
    } else {
        mvwprintw(status_bar_, 1, 2, "[STOPPED] Select interface and press Enter");
    }

    // Center: packet count
    InterfaceStats stats = store_.get_stats();
    std::ostringstream oss;
    oss << stats.packets_received << " packets | "
        << UI::format_bytes(stats.bytes_received);
    std::string stats_str = oss.str();
    mvwprintw(status_bar_, 1, (max_x - static_cast<int>(stats_str.length())) / 2,
              "%s", stats_str.c_str());

    // Right side: help
    mvwprintw(status_bar_, 1, max_x - 25, "Tab:Focus  s:Stop  q:Quit");

    // Error message if any
    if (!error_message_.empty()) {
        ui_.set_color(status_bar_, COLOR_ERROR);
        mvwprintw(status_bar_, 1, max_x / 2 - static_cast<int>(error_message_.length()) / 2,
                  "%s", error_message_.c_str());
        ui_.unset_color(status_bar_, COLOR_ERROR);
    }

    UI::draw_box(status_bar_, false);
    wrefresh(status_bar_);
}

void App::switch_panel(size_t index) {
    if (index >= panels_.size()) return;

    panels_[active_panel_]->set_active(false);
    active_panel_ = index;

    if (focus_ == Focus::PANEL) {
        panels_[active_panel_]->set_active(true);
    }
}

void App::start_capture(const std::string& interface_name) {
    stop_capture();
    error_message_.clear();

    if (!capture_->open(interface_name)) {
        error_message_ = "Failed to open: " + capture_->get_error();
        return;
    }

    capture_->start();

    // Switch focus to packet list
    switch_panel(0);
    focus_ = Focus::PANEL;
    sidebar_.set_active(false);
    panels_[active_panel_]->set_active(true);
}

void App::stop_capture() {
    if (capture_) {
        capture_->stop();
        capture_->close();
    }
}
