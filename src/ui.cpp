#include "ui.hpp"
#include <ncurses.h>

void UI::init()
{
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
}

void UI::print_center(const char* text)
{
    clear();
    int rows;
    int columns;
    
    getmaxyx(stdscr, rows, columns);

    int y = rows/2 - 1;
    int x = (columns - sizeof(text)) / 2;

    mvprintw(y, x, "%s", text);
}

void UI::refresh()
{
    ::refresh();
}

void UI::wait_for_key()
{
    getch();
}

void UI::shutdown()
{
    endwin();
}