/*
 * panel.cpp - Base panel class implementation
 *
 * Provides the constructor for the abstract Panel base class.
 * Derived panels (PacketList, Stats, Graph, Detail) implement
 * the virtual render() and handle_key() methods.
 */

#include "panel.hpp"

Panel::Panel(const std::string& title, PacketStore& store, UI& ui)
    : title_(title), store_(store), ui_(ui) {}
