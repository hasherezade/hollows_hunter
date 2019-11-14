#pragma once

#include <Windows.h>
#include <iostream>
#include <string>
#include <set>

size_t strip_to_list(IN std::string s, IN std::string delim, OUT std::set<std::string> &elements_list);

std::string& trim(std::string& str, const std::string& chars = "\t\n\v\f\r ");

std::string& str_to_lower(std::string& str);
