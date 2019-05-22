#include "hh_report.h"

#include <string>
#include <sstream>

bool is_suspicious_process(t_report report)
{
    if (report.errors) return false;
    if (report.replaced) {
        return true;
    }
    if (report.suspicious) {
        return true;
    }
    return false;
}

bool HHScanReport::appendReport(t_report &scan_report, std::string img_name)
{
    pidToReport[scan_report.pid] = scan_report;
    pidToName[scan_report.pid] = img_name;
    if (is_suspicious_process(scan_report)) {
        this->suspicious.push_back(scan_report.pid);
    }
    return true;
}

size_t HHScanReport::printSuspicious(std::stringstream &stream)
{
    std::vector<DWORD>::const_iterator itr;

    size_t printed = 0;
    size_t counter = 0;
    for (itr = this->suspicious.begin(); itr != suspicious.end(); itr++) {
        DWORD pid = *itr;
        stream << "[" << counter++ << "]:\n> PID: " << std::dec << pid << std::endl;
        stream << "> Path: " << this->pidToName[pid] << std::endl;
        printed++;
    }
    return printed;
}

std::string HHScanReport::toString()
{
    std::stringstream stream;
    //summary:
    stream << "--------" << std::endl;
    stream << "Finished scan in: " << std::dec << getScanTime() << " milliseconds" << std::endl;

    stream << "SUMMARY:" << std::endl;
    stream << "[+] Total Suspicious: " << std::dec << countSuspicious() << std::endl;
    if (countSuspicious() > 0) {
        stream << "[+] List of suspicious: " << std::endl;
    }
    printSuspicious(stream);
    return stream.str();
}
