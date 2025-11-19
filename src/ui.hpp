#pragma once

class UI
{
    public:
        void init();
        void print_center(const char* text);
        void refresh();
        void wait_for_key();
        void shutdown();
};