#include "etw_settings.h"

#include <string>
#include <vector>
#include <sstream>
#include <fstream>

#define WATCH_PROCESS_START "WATCH_PROCESS_START"
#define WATCH_IMG_LOAD      "WATCH_IMG_LOAD"
#define WATCH_ALLOCATION    "WATCH_ALLOCATION"
#define WATCH_TCP_IP        "WATCH_TCP_IP"
#define WATCH_OBJ_MGR       "WATCH_OBJ_MGR"

namespace util {

    static inline void ltrim(std::string& s)
    {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
            return !std::isspace(ch);
            }));
    }

    static inline void rtrim(std::string& s)
    {
        s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
            return !std::isspace(ch);
            }).base(), s.end());
    }

    void trim(std::string& s)
    {
        ltrim(s);
        rtrim(s);
    }

    bool iequals(const std::string& a, const std::string& b)
    {
        size_t aLen = a.size();
        if (b.size() != aLen) return false;

        for (size_t i = 0; i < aLen; ++i) {
            if (tolower(a[i]) != tolower(b[i])) return false;
        }
        return true;
    }

    size_t splitList(const std::string& sline, const char delimiter, std::vector<std::string>& args)
    {
        std::istringstream f(sline);
        std::string s;
        while (getline(f, s, delimiter)) {
            args.push_back(s);
        }
        return args.size();
    }


    int loadInt(const std::string& str, bool as_hex=false)
    {
        int intVal = 0;

        std::stringstream ss;
        ss << (as_hex ? std::hex : std::dec) << str;
        ss >> intVal;

        return intVal;
    }

    bool loadBoolean(const std::string& str, bool defaultVal)
    {
        if (util::iequals(str, "True") || util::iequals(str, "on") || util::iequals(str, "yes")) {
            return true;
        }
        if (util::iequals(str, "False") || util::iequals(str, "off") || util::iequals(str, "no")) {
            return false;
        }
        const int val = loadInt(str);
        if (val == 0) return false;
        return true;
    }

    std::string booleanToStr(bool val)
    {
        return (val) ? "True": "False";
    }


}; // util

//---
const char ETWProfile::DELIM = '=';

void ETWProfile::stripComments(std::string& str)
{
    size_t found = str.find_first_of(";#");
    if (found != std::string::npos) {
        str.resize(found);
    }
}

bool ETWProfile::fillSettings(std::string line)
{
    using namespace util;

    std::vector<std::string> args;
    util::splitList(line, DELIM, args);

    if (args.size() < 2) {
        return false;
    }
    bool isFilled = false;
    std::string valName = args[0];
    std::string valStr = args[1];
    util::trim(valName);
    util::trim(valStr);

    if (util::iequals(valName, WATCH_PROCESS_START)) {
        this->process_start = loadBoolean(valStr, this->process_start);
        isFilled = true;
    }
    if (util::iequals(valName, WATCH_IMG_LOAD)) {
        this->img_load = loadBoolean(valStr, this->img_load);
        isFilled = true;
    }
    if (util::iequals(valName, WATCH_ALLOCATION)) {
        this->allocation = loadBoolean(valStr, this->allocation);
        isFilled = true;
    }
    if (util::iequals(valName, WATCH_TCP_IP)) {
        this->tcpip = loadBoolean(valStr, this->tcpip);
        isFilled = true;
    }
    if (util::iequals(valName, WATCH_OBJ_MGR)) {
        this->obj_mgr = loadBoolean(valStr, this->obj_mgr);
        isFilled = true;
    }
    return isFilled;
}

bool ETWProfile::loadIni(const std::string& filename)
{
    std::ifstream myfile(filename.c_str());
    if (!myfile.is_open()) {
        return false;
    }
    const size_t MAX_LINE = 300;
    char line[MAX_LINE] = { 0 };
    bool filledAny = false;

    while (!myfile.eof()) {
        myfile.getline(line, MAX_LINE);
        std::string lineStr = line;
        stripComments(lineStr);

        if (fillSettings(lineStr)) {
            filledAny = true;
        }
    }
    myfile.close();
    return filledAny;
}

bool ETWProfile::saveIni(const std::string& filename)
{
    using namespace util;
    std::ofstream myfile(filename.c_str());
    if (!myfile.is_open()) {
        return false;
    }
    myfile << WATCH_PROCESS_START << DELIM << booleanToStr(this->process_start) << "\n";
    myfile << WATCH_IMG_LOAD << DELIM << booleanToStr(this->img_load) << "\n";
    myfile << WATCH_ALLOCATION << DELIM << booleanToStr(this->allocation) << "\n";
    myfile << WATCH_TCP_IP << DELIM << booleanToStr(this->tcpip) << "\n";
    myfile << WATCH_OBJ_MGR << DELIM << booleanToStr(this->obj_mgr) << "\n";
    myfile.close();
    return true;
}
