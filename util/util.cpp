#include "util.h"

#include <algorithm>
#include <cctype>

size_t strip_to_list(IN std::string s, IN std::string delim, OUT std::set<std::string> &elements_list)
{
    size_t start = 0;
    size_t end = s.find(delim);
    while (end != std::string::npos)
    {
        std::string next_str = s.substr(start, end - start);
        trim(next_str);

        elements_list.insert(next_str);
        start = end + delim.length();
        end = s.find(delim, start);
    }
    std::string next_str = s.substr(start, end);
    trim(next_str);
    elements_list.insert(next_str);
    return elements_list.size();
}

/*
string trimming util from: http://www.martinbroadhurst.com/how-to-trim-a-stdstring.html
*/

std::string& ltrim(std::string& str, const std::string& chars = "\t\n\v\f\r ")
{
    str.erase(0, str.find_first_not_of(chars));
    return str;
}

std::string& rtrim(std::string& str, const std::string& chars = "\t\n\v\f\r ")
{
    str.erase(str.find_last_not_of(chars) + 1);
    return str;
}

std::string& trim(std::string& str, const std::string& chars)
{
    return ltrim(rtrim(str, chars), chars);
}

//

std::string& str_to_lower(std::string& str)
{
    std::transform(str.begin(), str.end(), str.begin(), tolower);
    return str;
}

