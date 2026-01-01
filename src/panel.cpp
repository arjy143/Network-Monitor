#include "panel.hpp"

Panel::Panel(const std::string& title, PacketStore& store, UI& ui)
    : title_(title), store_(store), ui_(ui) {}
