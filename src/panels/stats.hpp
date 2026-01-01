#pragma once

#include "../panel.hpp"

class StatsPanel : public Panel {
public:
    StatsPanel(PacketStore& store, UI& ui);

    void render(WINDOW* win) override;
    bool handle_key(int key) override;

private:
    void render_summary(WINDOW* win, int& y, const InterfaceStats& stats);
    void render_protocol_breakdown(WINDOW* win, int& y, int width, const InterfaceStats& stats);
    void render_bar(WINDOW* win, int y, int x, int width, double percentage, ColorPair color);
};
