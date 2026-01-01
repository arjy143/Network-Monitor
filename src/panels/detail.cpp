#include "detail.hpp"
#include <iomanip>
#include <sstream>

DetailPanel::DetailPanel(PacketStore& store, UI& ui)
    : Panel("Packet Detail", store, ui) {}

void DetailPanel::render(WINDOW* win) {
    UI::clear_window(win);

    int max_y = getmaxy(win);
    int max_x = getmaxx(win);

    PacketInfo pkt = store_.get_selected_packet();

    // Title and mode indicator
    wattron(win, A_BOLD);
    mvwprintw(win, 1, 2, "Packet Detail");
    wattroff(win, A_BOLD);

    // View mode tabs
    int tab_x = max_x - 30;
    if (view_mode_ == ViewMode::PARSED) wattron(win, A_REVERSE);
    mvwprintw(win, 1, tab_x, "[p]arsed");
    if (view_mode_ == ViewMode::PARSED) wattroff(win, A_REVERSE);

    tab_x += 10;
    if (view_mode_ == ViewMode::HEX) wattron(win, A_REVERSE);
    mvwprintw(win, 1, tab_x, "[h]ex");
    if (view_mode_ == ViewMode::HEX) wattroff(win, A_REVERSE);

    tab_x += 7;
    if (view_mode_ == ViewMode::ASCII) wattron(win, A_REVERSE);
    mvwprintw(win, 1, tab_x, "[a]scii");
    if (view_mode_ == ViewMode::ASCII) wattroff(win, A_REVERSE);

    // Separator
    mvwhline(win, 2, 1, ACS_HLINE, max_x - 2);

    if (pkt.raw_data.empty()) {
        mvwprintw(win, max_y / 2, max_x / 2 - 15, "(Select a packet with Enter)");
        UI::draw_box(win, active_);
        wrefresh(win);
        return;
    }

    switch (view_mode_) {
        case ViewMode::PARSED:
            render_parsed(win, pkt);
            break;
        case ViewMode::HEX:
            render_hex_dump(win, pkt);
            break;
        case ViewMode::ASCII:
            render_ascii(win, pkt);
            break;
    }

    // Draw box
    UI::draw_box(win, active_);

    wrefresh(win);
}

void DetailPanel::render_parsed(WINDOW* win, const PacketInfo& pkt) {
    int y = 3;
    int max_y = getmaxy(win);

    // General info section
    wattron(win, A_BOLD | A_UNDERLINE);
    mvwprintw(win, y++, 2, "General");
    wattroff(win, A_BOLD | A_UNDERLINE);
    y++;

    mvwprintw(win, y++, 4, "Time:     %s", pkt.timestamp_str().c_str());
    mvwprintw(win, y++, 4, "Length:   %u bytes (captured), %u bytes (on wire)",
              pkt.length, pkt.original_length);
    y++;

    // Ethernet section
    if (y < max_y - 2) {
        wattron(win, A_BOLD | A_UNDERLINE);
        mvwprintw(win, y++, 2, "Ethernet");
        wattroff(win, A_BOLD | A_UNDERLINE);
        y++;

        mvwprintw(win, y++, 4, "Src MAC:  %s", pkt.format_mac(pkt.src_mac).c_str());
        mvwprintw(win, y++, 4, "Dst MAC:  %s", pkt.format_mac(pkt.dst_mac).c_str());
        mvwprintw(win, y++, 4, "Type:     0x%04X (%s)", pkt.ether_type,
                  pkt.ether_type == ETHERTYPE_IPV4 ? "IPv4" :
                  pkt.ether_type == ETHERTYPE_IPV6 ? "IPv6" :
                  pkt.ether_type == ETHERTYPE_ARP ? "ARP" : "Other");
        y++;
    }

    // IP section
    if (pkt.ip_version != 0 && y < max_y - 2) {
        wattron(win, A_BOLD | A_UNDERLINE);
        mvwprintw(win, y++, 2, "IPv%d", pkt.ip_version);
        wattroff(win, A_BOLD | A_UNDERLINE);
        y++;

        mvwprintw(win, y++, 4, "Src IP:   %s", pkt.src_ip.c_str());
        mvwprintw(win, y++, 4, "Dst IP:   %s", pkt.dst_ip.c_str());
        mvwprintw(win, y++, 4, "Protocol: %d (%s)", pkt.protocol, pkt.protocol_name().c_str());
        mvwprintw(win, y++, 4, "TTL:      %d", pkt.ttl);
        y++;
    }

    // Transport section
    if ((pkt.protocol == PROTO_TCP || pkt.protocol == PROTO_UDP) && y < max_y - 2) {
        wattron(win, A_BOLD | A_UNDERLINE);
        mvwprintw(win, y++, 2, "%s", pkt.protocol == PROTO_TCP ? "TCP" : "UDP");
        wattroff(win, A_BOLD | A_UNDERLINE);
        y++;

        mvwprintw(win, y++, 4, "Src Port: %u", pkt.src_port);
        mvwprintw(win, y++, 4, "Dst Port: %u", pkt.dst_port);

        if (pkt.protocol == PROTO_TCP) {
            std::string flags;
            if (pkt.tcp_flags & TCP_SYN) flags += "SYN ";
            if (pkt.tcp_flags & TCP_ACK) flags += "ACK ";
            if (pkt.tcp_flags & TCP_FIN) flags += "FIN ";
            if (pkt.tcp_flags & TCP_RST) flags += "RST ";
            if (pkt.tcp_flags & TCP_PSH) flags += "PSH ";
            if (pkt.tcp_flags & TCP_URG) flags += "URG ";
            mvwprintw(win, y++, 4, "Flags:    %s", flags.c_str());
        }
    }
}

void DetailPanel::render_hex_dump(WINDOW* win, const PacketInfo& pkt) {
    int y = 3;
    int max_y = getmaxy(win);
    int max_x = getmaxx(win);

    const auto& data = pkt.raw_data;
    size_t bytes_per_line = 16;

    // Adjust scroll
    size_t max_lines = (max_y - 4);
    size_t total_lines = (data.size() + bytes_per_line - 1) / bytes_per_line;

    if (scroll_offset_ > total_lines) {
        scroll_offset_ = 0;
    }

    size_t start_offset = scroll_offset_ * bytes_per_line;

    for (size_t offset = start_offset;
         offset < data.size() && y < max_y - 1;
         offset += bytes_per_line, ++y) {

        size_t line_len = std::min(bytes_per_line, data.size() - offset);
        std::string hex_line = format_hex_line(data.data() + offset, offset, line_len);

        // Truncate if needed
        if (hex_line.length() > static_cast<size_t>(max_x - 4)) {
            hex_line = hex_line.substr(0, max_x - 4);
        }

        mvwprintw(win, y, 2, "%s", hex_line.c_str());
    }

    // Scroll indicator
    if (total_lines > max_lines) {
        mvwprintw(win, max_y - 1, max_x - 15, "[%zu/%zu lines]",
                  scroll_offset_ + 1, total_lines);
    }
}

std::string DetailPanel::format_hex_line(const uint8_t* data, size_t offset, size_t len) {
    std::ostringstream oss;

    // Offset
    oss << std::hex << std::setfill('0') << std::setw(4) << offset << "  ";

    // Hex bytes
    for (size_t i = 0; i < 16; ++i) {
        if (i < len) {
            oss << std::hex << std::setfill('0') << std::setw(2)
                << static_cast<int>(data[i]) << " ";
        } else {
            oss << "   ";
        }
        if (i == 7) oss << " ";
    }

    oss << " ";

    // ASCII representation
    for (size_t i = 0; i < len; ++i) {
        char c = static_cast<char>(data[i]);
        if (c >= 32 && c < 127) {
            oss << c;
        } else {
            oss << '.';
        }
    }

    return oss.str();
}

void DetailPanel::render_ascii(WINDOW* win, const PacketInfo& pkt) {
    int y = 3;
    int max_y = getmaxy(win);
    int max_x = getmaxx(win);
    int content_width = max_x - 4;

    const auto& data = pkt.raw_data;

    std::string line;
    size_t line_start = scroll_offset_ * content_width;

    for (size_t i = line_start; i < data.size() && y < max_y - 1; ++i) {
        char c = static_cast<char>(data[i]);

        if (c >= 32 && c < 127) {
            line += c;
        } else if (c == '\n' || c == '\r') {
            mvwprintw(win, y++, 2, "%s", line.c_str());
            line.clear();
        } else {
            line += '.';
        }

        if (line.length() >= static_cast<size_t>(content_width)) {
            mvwprintw(win, y++, 2, "%s", line.c_str());
            line.clear();
        }
    }

    if (!line.empty() && y < max_y - 1) {
        mvwprintw(win, y, 2, "%s", line.c_str());
    }
}

bool DetailPanel::handle_key(int key) {
    if (!active_) return false;

    PacketInfo pkt = store_.get_selected_packet();
    int max_y = 20;  // Approximate
    size_t bytes_per_line = 16;
    size_t total_lines = pkt.raw_data.empty()
                             ? 0
                             : (pkt.raw_data.size() + bytes_per_line - 1) / bytes_per_line;

    switch (key) {
        case 'p':
        case 'P':
            view_mode_ = ViewMode::PARSED;
            scroll_offset_ = 0;
            return true;

        case 'h':
        case 'H':
            view_mode_ = ViewMode::HEX;
            scroll_offset_ = 0;
            return true;

        case 'a':
        case 'A':
            view_mode_ = ViewMode::ASCII;
            scroll_offset_ = 0;
            return true;

        case KEY_UP:
        case 'k':
            if (scroll_offset_ > 0) {
                scroll_offset_--;
            }
            return true;

        case KEY_DOWN:
        case 'j':
            if (scroll_offset_ < total_lines - 1) {
                scroll_offset_++;
            }
            return true;

        case KEY_PPAGE:
            if (scroll_offset_ > static_cast<size_t>(max_y)) {
                scroll_offset_ -= max_y;
            } else {
                scroll_offset_ = 0;
            }
            return true;

        case KEY_NPAGE:
            scroll_offset_ += max_y;
            if (scroll_offset_ >= total_lines) {
                scroll_offset_ = total_lines > 0 ? total_lines - 1 : 0;
            }
            return true;

        default:
            return false;
    }
}
