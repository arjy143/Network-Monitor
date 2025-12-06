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

    std::string device_list;

    for (pcap_if_t* device = all_devs; device != nullptr; device = device->next)
    {
        device_list += device->name;
        device_list += " | ";
    }

    pcap_freealldevs(all_devs);

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    WINDOW* interface_bar  = newwin(3, max_x, 0, 0);
    WINDOW* status_bar = newwin(3, max_x, max_y - 3, 0);
    WINDOW* main_win = newwin(max_y - 6, max_x, 3, 0);
    //refresh to let application know new window exists
    refresh();
    mvwprintw(interface_bar, 1, 1, "%s", device_list.c_str());
    mvwprintw(status_bar, 1, 1, "Press F1-F4 to switch panels");
    mvwprintw(main_win, 1, 2, "Hello from the main panel!");

    //put content before boxing
    //wprintw(win, "%s", device_list.c_str());

    //box(win, 0,0);
    //wrefresh(win);

    box(interface_bar,0,0);
    box(status_bar,0,0);
    box(main_win,0,0);

    wrefresh(interface_bar);
    wrefresh(status_bar);
    wrefresh(main_win);
    //ui.print_center(device_list.c_str());
    ui.refresh();
    ui.wait_for_key();

    ui.shutdown();
    return 0;
}