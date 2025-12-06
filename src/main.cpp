#include <iostream>
#include <pcap.h>
#include <ncurses.h>
#include "ui.hpp"
#include <string>

int main(int argc, char** argv)
{
    UI ui;
    ui.init();

    pcap_if_t* all_devs;
    char error_buffer[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&all_devs, error_buffer) == -1)
    {
        ui.print_center("Error finding devices.");
        ui.refresh();
        ui.wait_for_key();
        return 1;
    }

    std::string device_list = "Interfaces:\n";

    for (pcap_if_t* device = all_devs; device != nullptr; device = device->next)
    {
        device_list += " - ";
        device_list += device->name;
        device_list += "\n";
    }

    pcap_freealldevs(all_devs);

    int height = 10;
    int width = 20;
    int start_y = 10;
    int start_x = 10;

    WINDOW* win = newwin(height, width, start_y, start_x);
    //refresh to let application know new window exists
    refresh();

    //put content before boxing
    wprintw(win, "%s", device_list.c_str());

    box(win, 0,0);
    wrefresh(win);

    //ui.print_center(device_list.c_str());
    ui.refresh();
    ui.wait_for_key();

    ui.shutdown();
    return 0;
}