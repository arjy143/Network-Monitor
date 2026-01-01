#pragma once

#include "../panel.hpp"

class PacketListPanel : public Panel {
public:
    PacketListPanel(PacketStore& store, UI& ui);

    void render(WINDOW* win) override;
    bool handle_key(int key) override;

    // Auto-scroll mode
    void set_auto_scroll(bool enabled) { auto_scroll_ = enabled; }
    bool is_auto_scroll() const { return auto_scroll_; }

private:
    bool auto_scroll_ = true;
    size_t selected_row_ = 0;

    void render_header(WINDOW* win, int y, int width);
    void render_packet_row(WINDOW* win, int y, int width, const PacketInfo& pkt, bool selected);
    ColorPair get_protocol_color(const PacketInfo& pkt) const;
};
