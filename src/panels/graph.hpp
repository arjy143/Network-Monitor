/*
 * graph.hpp - Traffic graph panel (F3)
 *
 * Displays an ASCII bar chart of network traffic over time. Shows either
 * packets per second or bytes per second (toggle with 'b' key). The graph
 * scrolls horizontally to show the last 60 seconds of data.
 */

#pragma once

#include "../panel.hpp"

class GraphPanel : public Panel {
public:
    GraphPanel(PacketStore& store, UI& ui);

    void render(WINDOW* win) override;
    bool handle_key(int key) override;

private:
    bool show_bytes_ = false;  // false = packets/sec, true = bytes/sec

    void render_graph(WINDOW* win, int start_y, int height, int width,
                      const std::deque<double>& data, const std::string& label);
    double get_max_value(const std::deque<double>& data) const;
};
