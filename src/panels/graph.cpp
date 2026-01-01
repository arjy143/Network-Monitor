/*
 * graph.cpp - Traffic graph implementation
 *
 * Renders an ASCII bar chart showing traffic rates over time.
 * Uses block characters for the bars with color coding based on
 * traffic intensity. Y-axis auto-scales to the maximum value.
 */

#include "graph.hpp"
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <sstream>

GraphPanel::GraphPanel(PacketStore& store, UI& ui)
    : Panel("Traffic Graph", store, ui) {}

void GraphPanel::render(WINDOW* win) {
    UI::clear_window(win);

    int max_y = getmaxy(win);
    int max_x = getmaxx(win);

    InterfaceStats stats = store_.get_stats();

    // Title
    wattron(win, A_BOLD);
    mvwprintw(win, 1, 2, "Traffic Graph - %s",
              show_bytes_ ? "Throughput (bytes/sec)" : "Packets/sec");
    wattroff(win, A_BOLD);

    // Help text
    mvwprintw(win, 1, max_x - 20, "[b] Toggle view");

    // Current rate
    std::string current_rate;
    if (show_bytes_) {
        current_rate = "Current: " + UI::format_rate(stats.bytes_per_second);
    } else {
        std::ostringstream oss;
        oss << "Current: " << std::fixed << std::setprecision(1)
            << stats.packets_per_second << " pkt/s";
        current_rate = oss.str();
    }
    mvwprintw(win, 2, 2, "%s", current_rate.c_str());

    // Separator
    mvwhline(win, 3, 1, ACS_HLINE, max_x - 2);

    // Graph area
    int graph_start_y = 4;
    int graph_height = max_y - 6;  // Leave room for x-axis labels
    int graph_width = max_x - 12;  // Leave room for y-axis labels

    if (graph_height < 5 || graph_width < 20) {
        mvwprintw(win, graph_start_y, 2, "(Window too small for graph)");
        UI::draw_box(win, active_);
        wrefresh(win);
        return;
    }

    const auto& data = show_bytes_ ? stats.bps_history : stats.pps_history;

    if (data.empty()) {
        mvwprintw(win, graph_start_y + graph_height / 2, max_x / 2 - 10,
                  "(Collecting data...)");
        UI::draw_box(win, active_);
        wrefresh(win);
        return;
    }

    render_graph(win, graph_start_y, graph_height, graph_width, data,
                 show_bytes_ ? "B/s" : "pkt/s");

    // Draw box
    UI::draw_box(win, active_);

    wrefresh(win);
}

void GraphPanel::render_graph(WINDOW* win, int start_y, int height, int width,
                              const std::deque<double>& data, const std::string& /*label*/) {
    double max_val = get_max_value(data);
    if (max_val < 1.0) max_val = 1.0;

    // Round up to nice number
    double scale = std::pow(10, std::floor(std::log10(max_val)));
    max_val = std::ceil(max_val / scale) * scale;

    int label_x = 2;
    int graph_x = 10;

    // Y-axis labels
    for (int i = 0; i <= 4; ++i) {
        int y = start_y + (height - 1) * i / 4;
        double val = max_val * (4 - i) / 4;

        std::string val_str;
        if (val >= 1000000000) {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(1) << val / 1000000000 << "G";
            val_str = oss.str();
        } else if (val >= 1000000) {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(1) << val / 1000000 << "M";
            val_str = oss.str();
        } else if (val >= 1000) {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(1) << val / 1000 << "K";
            val_str = oss.str();
        } else {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(0) << val;
            val_str = oss.str();
        }

        mvwprintw(win, y, label_x, "%6s", val_str.c_str());
        mvwaddch(win, y, graph_x - 1, ACS_VLINE);
    }

    // Draw vertical axis
    for (int y = start_y; y < start_y + height; ++y) {
        mvwaddch(win, y, graph_x - 1, ACS_VLINE);
    }

    // Draw horizontal axis
    mvwhline(win, start_y + height, graph_x, ACS_HLINE, width);
    mvwaddch(win, start_y + height, graph_x - 1, ACS_LLCORNER);

    // X-axis label
    mvwprintw(win, start_y + height + 1, graph_x + width / 2 - 5, "Time (sec)");

    // Time labels
    mvwprintw(win, start_y + height + 1, graph_x, "-%zus", data.size());
    mvwprintw(win, start_y + height + 1, graph_x + width - 3, "now");

    // Draw bars
    size_t num_bars = std::min(data.size(), static_cast<size_t>(width));
    size_t start_idx = data.size() > static_cast<size_t>(width)
                           ? data.size() - width
                           : 0;

    for (size_t i = 0; i < num_bars; ++i) {
        double val = data[start_idx + i];
        int bar_height = static_cast<int>((val / max_val) * (height - 1));
        if (bar_height < 0) bar_height = 0;
        if (bar_height >= height) bar_height = height - 1;

        int x = graph_x + static_cast<int>(i);

        // Choose color based on value intensity
        ColorPair color = COLOR_UDP;
        if (val > max_val * 0.75) {
            color = COLOR_ERROR;
        } else if (val > max_val * 0.5) {
            color = COLOR_ICMP;
        }

        ui_.set_color(win, color);
        for (int h = 0; h < bar_height; ++h) {
            int y = start_y + height - 1 - h;
            mvwaddch(win, y, x, ACS_BLOCK);
        }
        ui_.unset_color(win, color);
    }
}

double GraphPanel::get_max_value(const std::deque<double>& data) const {
    if (data.empty()) return 1.0;

    double max_val = 0.0;
    for (double val : data) {
        if (val > max_val) max_val = val;
    }
    return max_val > 0 ? max_val : 1.0;
}

bool GraphPanel::handle_key(int key) {
    if (!active_) return false;

    switch (key) {
        case 'b':
        case 'B':
            show_bytes_ = !show_bytes_;
            return true;

        default:
            return false;
    }
}
