#include "app.hpp"
#include <iostream>

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    App app;

    if (!app.init()) {
        std::cerr << "Failed to initialize application" << std::endl;
        return 1;
    }

    app.run();
    app.shutdown();

    return 0;
}
