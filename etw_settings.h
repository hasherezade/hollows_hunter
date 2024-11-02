#pragma once

#include <iostream>

struct ETWProfile {
public:
    bool process_start;
    bool img_load;
    bool allocation;
    bool tcpip;
    bool obj_mgr;

    ETWProfile(bool _process_start = false, bool _img_load = false, bool _allocation = false, bool _tcpip = false, bool _obj_mgr = false)
        : process_start(_process_start), img_load(_img_load), allocation(_allocation), tcpip(_tcpip), obj_mgr(_obj_mgr)
    {
    }

    bool initProfile(const std::string& fileName)
    {
        bool isOk = loadIni(fileName);
        if (!isOk) {
            setAll();
            isOk = saveIni(fileName);
        }
        return isOk;
    }

    bool loadIni(const std::string& fileName);
    bool saveIni(const std::string& fileName);

    void setAll()
    {
        this->process_start = true;
        this->img_load = true;
        this->allocation = true;
        this->tcpip = true;
        this->obj_mgr = true;
    }

    bool isEnabled()
    {
        if (this->process_start 
            || this->img_load
            || this->allocation 
            || this->tcpip
            || this->obj_mgr
        )
        {
            return true;
        }
        return false;
    }

protected:
    static const char DELIM;

    bool fillSettings(std::string line);
    void stripComments(std::string& str);
};
