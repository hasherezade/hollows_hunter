#pragma once

#include <iostream>

#include <iomanip>
#define OUT_PADDED_HEX(stream, val) std::cout.fill('0'); stream << std::hex << std::setw(sizeof(val)*2) << val;

void set_color(int color);

void unset_color();

void print_in_color(int color, std::string text);
