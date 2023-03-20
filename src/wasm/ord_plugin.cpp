#include <iostream>
#include <chrono>
#include <strings.h>

#include <emscripten.h>
#include <emscripten/bind.h>

std::string EMSCRIPTEN_KEEPALIVE getTimestamp(const std::string &prefix) {
    return prefix + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
    ).count());
}

EMSCRIPTEN_BINDINGS(my_module) {
        emscripten::function("getTimestamp", &getTimestamp);
}

int EMSCRIPTEN_KEEPALIVE main() {
    std::cout << "Hello from Emscripten, Жывотнайе! " << getTimestamp("Timestamp is: ") << std::endl;
    return 0;
}
