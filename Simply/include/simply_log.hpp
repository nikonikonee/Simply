#pragma once

#include <format>
#include <iostream>
#include <string_view>

namespace simply::log {

inline bool verbose = false;

template <class... Args>
void info(std::format_string<Args...> fmt, Args&&... args) {
    std::cout << "[*] " << std::format(fmt, std::forward<Args>(args)...) << '\n';
}

template <class... Args>
void warn(std::format_string<Args...> fmt, Args&&... args) {
    std::cout << "[!] " << std::format(fmt, std::forward<Args>(args)...) << '\n';
}

template <class... Args>
void error(std::format_string<Args...> fmt, Args&&... args) {
    std::cerr << "[-] " << std::format(fmt, std::forward<Args>(args)...) << '\n';
}

template <class... Args>
void debug(std::format_string<Args...> fmt, Args&&... args) {
    if (!verbose) return;
    std::cout << "[.] " << std::format(fmt, std::forward<Args>(args)...) << '\n';
}

}  // namespace simply::log
