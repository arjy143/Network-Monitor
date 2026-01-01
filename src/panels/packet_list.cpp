/*
 * packet_list.cpp - Live packet list implementation
 *
 * Renders the packet table with colour-coded protocols. Handles scrolling,
 * packet selection, and auto-scroll mode. Shows Category column with
 * descriptions from the database, and highlights watchlist matches.
 */

#include "packet_list.hpp"
#include "../descriptions.hpp"
#include <iomanip>
#include <sstream>

PacketListPanel::PacketListPanel(PacketStore& store, UI& ui, DescriptionDatabase* descriptions)
    : Panel("Packets", store, ui), descriptions_(descriptions) {}

void PacketListPanel::render(WINDOW* win) {
    UI::clear_window(win);

    int max_y = getmaxy(win);
    int max_x = getmaxx(win);
    int content_h = max_y - 2;
    int content_w = max_x - 2;

    // Render header
    render_header(win, 1, content_w);

    // Get packets
    auto packets = store_.get_all();
    size_t packet_count = packets.size();

    // Calculate visible rows (minus header and separator)
    int visible_rows = content_h - 2;

    // Auto-scroll: show newest packets at bottom
    if (auto_scroll_ && packet_count > 0) {
        if (packet_count > static_cast<size_t>(visible_rows)) {
            scroll_offset_ = packet_count - visible_rows;
        } else {
            scroll_offset_ = 0;
        }
        selected_row_ = packet_count > 0 ? packet_count - 1 : 0;
    }

    // Clamp scroll offset
    if (scroll_offset_ > packet_count) {
        scroll_offset_ = packet_count > 0 ? packet_count - 1 : 0;
    }

    // Render packets
    int y = 3;  // Start after header and separator
    for (size_t i = scroll_offset_; i < packet_count && y < max_y - 1; ++i, ++y) {
        bool is_selected = (i == selected_row_) && active_;
        render_packet_row(win, y, content_w, packets[i], is_selected);
    }

    // Show packet count in corner
    std::ostringstream oss;
    oss << "[" << packet_count << " pkts]";
    mvwprintw(win, max_y - 1, max_x - static_cast<int>(oss.str().length()) - 1,
              "%s", oss.str().c_str());

    // Draw box
    UI::draw_box(win, active_);

    wrefresh(win);
}

void PacketListPanel::render_header(WINDOW* win, int y, int width) {
    wattron(win, A_BOLD | A_UNDERLINE);

    // Column layout with Category:
    // Time(10) Src(14) Dst(14) Proto(5) Len(5) Category(10) Info(rest)
    mvwprintw(win, y, 1, "%-10s", "Time");
    mvwprintw(win, y, 12, "%-14s", "Source");
    mvwprintw(win, y, 27, "%-14s", "Destination");
    mvwprintw(win, y, 42, "%-5s", "Proto");
    mvwprintw(win, y, 48, "%-5s", "Len");
    mvwprintw(win, y, 54, "%-10s", "Category");
    mvwprintw(win, y, 65, "Info");

    wattroff(win, A_BOLD | A_UNDERLINE);

    // Separator line
    mvwhline(win, y + 1, 1, ACS_HLINE, width);
}

void PacketListPanel::render_packet_row(WINDOW* win, int y, int width,
                                        const PacketInfo& pkt, bool selected) {
    // Check for watchlist match - use alert colour
    bool is_alert = pkt.watchlist_match;

    if (selected) {
        wattron(win, A_REVERSE);
    } else if (is_alert) {
        // Highlight watchlist matches (if COLOR_ALERT is defined, otherwise use ERROR)
        ui_.set_color(win, COLOR_ERROR);
    }

    // Clear line
    mvwhline(win, y, 1, ' ', width);

    // Time (10 chars)
    std::string time_str = pkt.timestamp_str();
    if (time_str.length() > 10) {
        time_str = time_str.substr(0, 10);
    }
    mvwprintw(win, y, 1, "%-10s", time_str.c_str());

    // Source (14 chars)
    std::string src = pkt.src_ip.empty() ? pkt.format_mac(pkt.src_mac) : pkt.src_ip;
    mvwprintw(win, y, 12, "%-14s", UI::truncate(src, 13).c_str());

    // Destination (14 chars)
    std::string dst = pkt.dst_ip.empty() ? pkt.format_mac(pkt.dst_mac) : pkt.dst_ip;
    mvwprintw(win, y, 27, "%-14s", UI::truncate(dst, 13).c_str());

    // Protocol with colour (5 chars)
    if (!selected && !is_alert) {
        ColorPair color = get_protocol_color(pkt);
        ui_.set_color(win, color);
        mvwprintw(win, y, 42, "%-5s", UI::truncate(pkt.protocol_name(), 4).c_str());
        ui_.unset_color(win, color);
    } else {
        mvwprintw(win, y, 42, "%-5s", UI::truncate(pkt.protocol_name(), 4).c_str());
    }

    // Length (5 chars)
    mvwprintw(win, y, 48, "%-5u", pkt.length);

    // Category (10 chars)
    std::string category = get_category(pkt);
    mvwprintw(win, y, 54, "%-10s", UI::truncate(category, 9).c_str());

    // Info (rest)
    std::string info = pkt.summary();
    int info_width = width - 65;
    if (info_width > 0) {
        mvwprintw(win, y, 65, "%s", UI::truncate(info, info_width).c_str());
    }

    if (selected) {
        wattroff(win, A_REVERSE);
    } else if (is_alert) {
        ui_.unset_color(win, COLOR_ERROR);
    }
}

ColorPair PacketListPanel::get_protocol_color(const PacketInfo& pkt) const {
    if (pkt.ether_type == ETHERTYPE_ARP) {
        return COLOR_ARP;
    }

    switch (pkt.protocol) {
        case PROTO_TCP: return COLOR_TCP;
        case PROTO_UDP: return COLOR_UDP;
        case PROTO_ICMP:
        case PROTO_ICMPV6: return COLOR_ICMP;
        default: return COLOR_OTHER;
    }
}

std::string PacketListPanel::get_category(const PacketInfo& pkt) const {
    // First check if packet already has a category set
    if (!pkt.category.empty()) {
        return pkt.category;
    }

    // Look up in descriptions database if available
    if (descriptions_ && !pkt.hostname.empty()) {
        auto result = descriptions_->lookup(pkt.hostname);
        if (result) {
            return result->category;
        }
    }

    // Fall back to app_protocol if available
    if (!pkt.app_protocol.empty()) {
        return pkt.app_protocol;
    }

    return "";
}

bool PacketListPanel::handle_key(int key) {
    if (!active_) return false;

    size_t packet_count = store_.size();
    if (packet_count == 0) return false;

    size_t visible_rows = 20;  // Approximate, will be recalculated on render

    switch (key) {
        case KEY_UP:
        case 'k':
            auto_scroll_ = false;
            if (selected_row_ > 0) {
                selected_row_--;
                if (selected_row_ < scroll_offset_) {
                    scroll_offset_ = selected_row_;
                }
            }
            return true;

        case KEY_DOWN:
        case 'j':
            if (selected_row_ < packet_count - 1) {
                selected_row_++;
                if (selected_row_ >= scroll_offset_ + visible_rows) {
                    scroll_offset_ = selected_row_ - visible_rows + 1;
                }
            }
            // Re-enable auto-scroll if at bottom
            if (selected_row_ == packet_count - 1) {
                auto_scroll_ = true;
            }
            return true;

        case KEY_PPAGE:  // Page Up
            auto_scroll_ = false;
            if (selected_row_ > visible_rows) {
                selected_row_ -= visible_rows;
            } else {
                selected_row_ = 0;
            }
            if (scroll_offset_ > visible_rows) {
                scroll_offset_ -= visible_rows;
            } else {
                scroll_offset_ = 0;
            }
            return true;

        case KEY_NPAGE:  // Page Down
            selected_row_ += visible_rows;
            if (selected_row_ >= packet_count) {
                selected_row_ = packet_count - 1;
                auto_scroll_ = true;
            }
            scroll_offset_ += visible_rows;
            if (scroll_offset_ + visible_rows > packet_count) {
                scroll_offset_ = packet_count > static_cast<size_t>(visible_rows)
                                     ? packet_count - visible_rows
                                     : 0;
            }
            return true;

        case KEY_HOME:
        case 'g':
            auto_scroll_ = false;
            selected_row_ = 0;
            scroll_offset_ = 0;
            return true;

        case KEY_END:
        case 'G':
            selected_row_ = packet_count - 1;
            scroll_offset_ = packet_count > static_cast<size_t>(visible_rows)
                                 ? packet_count - visible_rows
                                 : 0;
            auto_scroll_ = true;
            return true;

        case 'a':
        case 'A':
            auto_scroll_ = !auto_scroll_;
            return true;

        case '\n':
        case KEY_ENTER:
            // Select packet for detail view
            store_.set_selected_index(selected_row_);
            return true;

        default:
            return false;
    }
}
