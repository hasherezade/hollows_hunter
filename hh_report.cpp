#include "hh_report.h"

#include <string>
#include <sstream>

#include <iostream>
#include <iomanip>
#include <ctime>
#include <cmath>

#define OUT_PADDED(stream, field_size, str) \
std::cout.fill(' '); \
if (field_size) stream << std::setw(field_size) << ' '; \
stream << str;

bool is_suspicious_process(t_report report)
{
    if (report.errors) return false;
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

size_t HHScanReport::reportsToString(std::stringstream &stream)
{
    std::vector<DWORD>::const_iterator itr;

    size_t printed = 0;
    size_t counter = 0;
    const size_t max_len = size_t(std::floor(std::log10(double(suspicious.size() - 1))) + 1);
    for (itr = this->suspicious.begin(); itr != suspicious.end(); itr++) {
        DWORD pid = *itr;
        stream << "[" << std::setw(max_len) << counter++ << "]: PID: " << std::dec << pid << ", ";
        stream << "Name: " << this->pidToName[pid] << "\n";
        printed++;
    }
    return printed;
}

size_t HHScanReport::reportsToJSON(std::stringstream &stream, size_t level, const t_hh_params &params)
{
    std::vector<DWORD>::const_iterator itr;
    OUT_PADDED(stream, level, "\"suspicious\" : [\n");
    level++;
    size_t printed = 0;
    for (itr = this->suspicious.begin(); itr != suspicious.end(); itr++) {
        DWORD pid = *itr;
        OUT_PADDED(stream, level, "{\n");
        level++;

        OUT_PADDED(stream, level, "\"pid\" : ");
        stream << std::dec << pid << ",\n";
        OUT_PADDED(stream, level, "\"name\" : ");
        stream << "\"" << this->pidToName[pid] << "\",\n";
        OUT_PADDED(stream, level, "\"replaced\" : ");
        stream << std::dec << pidToReport[pid].replaced << ",\n";
        if (!params.pesieve_args.no_hooks) {
            OUT_PADDED(stream, level, "\"patched\" : ");
            stream << std::dec << pidToReport[pid].hooked << ",\n";
        }
        OUT_PADDED(stream, level, "\"implanted\" : ");
        stream << std::dec << pidToReport[pid].implanted << ",\n";
        OUT_PADDED(stream, level, "\"detached\" : ");
        stream << std::dec << pidToReport[pid].detached << "\n";

        level--;
        OUT_PADDED(stream, level, "}");
        printed++;
        if (printed < suspicious.size()) {
            stream << ",";
        }
        stream << "\n";
    }
    level--;
    OUT_PADDED(stream, level, "]\n");
    return printed;
}

std::string HHScanReport::toJSON(const t_hh_params &params)
{
    std::stringstream stream;
    size_t level = 0;
    OUT_PADDED(stream, level, "{\n");
    level++;
    //summary:
    OUT_PADDED(stream, level, "\"scan_timestamp\" : ");
    stream << std::dec << startTime << ",\n";
    OUT_PADDED(stream, level, "\"scan_time_ms\" : ");
    stream << std::dec << getScanTime() << ",\n";
    OUT_PADDED(stream, level, "\"susipcious_count\" : ");
    stream << std::dec << countSuspicious();
    if (countSuspicious() > 0) {
        stream << ",\n";
        reportsToJSON(stream, level, params);
    }
    else {
        stream << "\n";
    }
    level--;
    OUT_PADDED(stream, level, "}\n");
    return stream.str();
}

std::string strtime(const time_t t)
{
    struct tm time_info;
    if (localtime_s(&time_info, &t) == 0) {
        std::stringstream str;
        str << std::put_time(&time_info, "%c");
        return str.str();
    }
    return "";
}

std::string HHScanReport::toString()
{
    std::stringstream stream;
    //summary:
    stream << "--------" << std::endl;
    stream << "SUMMARY:\n";
    stream << "Scan at: " << strtime(this->startTime) << " (" << std::dec << startTime << ")\n";
    stream << "Finished scan in: " << std::dec << getScanTime() << " milliseconds\n";
    stream << "[+] Total Suspicious: " << std::dec << countSuspicious() << "\n";
    if (countSuspicious() > 0) {
        stream << "[+] List of suspicious: \n";
        reportsToString(stream);
    }
    return stream.str();
}
