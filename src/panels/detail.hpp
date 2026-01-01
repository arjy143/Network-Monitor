#pragma once

#include "../panel.hpp"

class DetailPanel : public Panel {
public:
    DetailPanel(PacketStore& store, UI& ui);

    void render(WINDOW* win) override;
    bool handle_key(int key) override;

private:
    enum class ViewMode { PARSED, HEX, ASCII };
    ViewMode view_mode_ = ViewMode::PARSED;

    void render_parsed(WINDOW* win, const PacketInfo& pkt);
    void render_hex_dump(WINDOW* win, const PacketInfo& pkt);
    void render_ascii(WINDOW* win, const PacketInfo& pkt);
    std::string format_hex_line(const uint8_t* data, size_t offset, size_t len);
};
