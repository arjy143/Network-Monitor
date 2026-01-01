/*
 * stats.cpp - Statistics panel implementation
 *
 * Displays capture statistics including packet counts, byte totals,
 * current rates, and a sorted protocol breakdown with visual bars.
 */

#include "stats.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <vector>

StatsPanel::StatsPanel(PacketStore& store, UI& ui)
    : Panel("Statistics", store, ui) {}

void StatsPanel::render(WINDOW* win) {
    UI::clear_window(win);

    int max_x = getmaxx(win);
    int content_w = max_x - 4;

    InterfaceStats stats = store_.get_stats();

    int y = 1;

    // Title
    wattron(win, A_BOLD);
    if (stats.name.empty()) {
        mvwprintw(win, y, 2, "Interface Statistics");
    } else {
        mvwprintw(win, y, 2, "Interface: %s", stats.name.c_str());
    }
    wattroff(win, A_BOLD);
    y += 2;

    // Summary statistics
    render_summary(win, y, stats);
    y += 1;

    // Protocol breakdown
    mvwhline(win, y, 1, ACS_HLINE, max_x - 2);
    y += 1;

    wattron(win, A_BOLD);
    mvwprintw(win, y, 2, "Protocol Breakdown:");
    wattroff(win, A_BOLD);
    y += 2;

    render_protocol_breakdown(win, y, content_w, stats);

    // Draw box
    UI::draw_box(win, active_);

    wrefresh(win);
}

void StatsPanel::render_summary(WINDOW* win, int& y, const InterfaceStats& stats) {
    // Total packets
    mvwprintw(win, y, 2, "Total Packets: ");
    wattron(win, A_BOLD);
    mvwprintw(win, y, 17, "%lu", stats.packets_received);
    wattroff(win, A_BOLD);
    y++;

    // Total bytes
    mvwprintw(win, y, 2, "Total Bytes:   ");
    wattron(win, A_BOLD);
    mvwprintw(win, y, 17, "%s", UI::format_bytes(stats.bytes_received).c_str());
    wattroff(win, A_BOLD);
    y++;

    // Packets per second
    mvwprintw(win, y, 2, "Packets/sec:   ");
    ui_.set_color(win, COLOR_UDP);
    wattron(win, A_BOLD);
    mvwprintw(win, y, 17, "%.1f", stats.packets_per_second);
    wattroff(win, A_BOLD);
    ui_.unset_color(win, COLOR_UDP);
    y++;

    // Bytes per second
    mvwprintw(win, y, 2, "Throughput:    ");
    ui_.set_color(win, COLOR_TCP);
    wattron(win, A_BOLD);
    mvwprintw(win, y, 17, "%s", UI::format_rate(stats.bytes_per_second).c_str());
    wattroff(win, A_BOLD);
    ui_.unset_color(win, COLOR_TCP);
    y++;
}

void StatsPanel::render_protocol_breakdown(WINDOW* win, int& y, int width,
                                           const InterfaceStats& stats) {
    if (stats.protocol_counts.empty()) {
        mvwprintw(win, y, 2, "(No packets captured yet)");
        return;
    }

    // Sort protocols by count
    std::vector<std::pair<std::string, uint64_t>> sorted_protos(
        stats.protocol_counts.begin(), stats.protocol_counts.end());

    std::sort(sorted_protos.begin(), sorted_protos.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    uint64_t total = stats.packets_received;
    int bar_width = width - 30;
    if (bar_width < 10) bar_width = 10;

    for (const auto& [proto, count] : sorted_protos) {
        double percentage = total > 0 ? (static_cast<double>(count) / total) * 100.0 : 0.0;

        // Get colour for protocol
        ColorPair color = COLOR_OTHER;
        if (proto == "TCP") color = COLOR_TCP;
        else if (proto == "UDP") color = COLOR_UDP;
        else if (proto == "ICMP" || proto == "ICMPv6") color = COLOR_ICMP;
        else if (proto == "ARP") color = COLOR_ARP;

        // Protocol name
        ui_.set_color(win, color);
        mvwprintw(win, y, 2, "%-8s", proto.c_str());
        ui_.unset_color(win, color);

        // Count
        mvwprintw(win, y, 11, "%8lu", count);

        // Percentage
        mvwprintw(win, y, 21, "%5.1f%%", percentage);

        // Bar
        render_bar(win, y, 28, bar_width, percentage, color);

        y++;

        // Limit to visible area
        if (y >= getmaxy(win) - 2) break;
    }
}

void StatsPanel::render_bar(WINDOW* win, int y, int x, int width,
                            double percentage, ColorPair color) {
    int filled = static_cast<int>((percentage / 100.0) * width);
    if (filled > width) filled = width;

    ui_.set_color(win, color);

    mvwprintw(win, y, x, "[");
    for (int i = 0; i < width; ++i) {
        if (i < filled) {
            waddch(win, '#');
        } else {
            waddch(win, ' ');
        }
    }
    waddch(win, ']');

    ui_.unset_color(win, color);
}

bool StatsPanel::handle_key(int key) {
    // Stats panel doesn't need much keyboard handling
    (void)key;
    return false;
}
