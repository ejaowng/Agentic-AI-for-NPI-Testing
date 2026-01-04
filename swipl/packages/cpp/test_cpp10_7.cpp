#define PROLOG_MODULE "user"
#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <SWI-Stream.h>
#include <SWI-Prolog.h>
#include "SWI-cpp2.h"
#include <errno.h>
#include <math.h>
#include <cassert>
#include <cstdio> // for MyFileBlob
#include <limits>
#include <string>
#include <map>
#include <vector>
#include <cctype>
#include <deque>
#include <optional>
#include <regex>
#include <unordered_map>
#include <cstdlib>


using namespace std;

#include <algorithm>

static bool run_cmd(const std::string &ctx, const std::string &cmd)
{
    std::cout << "[attachUE] Running (" << ctx << "): " << cmd << std::endl;
    int rc = std::system(cmd.c_str());
    if (rc != 0) {
        std::cerr << "[attachUE] Command failed (" << ctx
                  << ") with code " << rc << std::endl;
        return false;
    }
    return true;
}

// Helper: convert Windows path to scp/ssh-friendly version (slashes)
static std::string escape_win_path(std::string path)
{
    for (char &c : path) {
        if (c == '\\') c = '/';
    }
    return path;
}


class RemoteDesktopClient {
public:
    RemoteDesktopClient(std::string host,
                        std::string user,
                        std::string remoteDesktopDir,
                        std::string localWorkDir)
        : host_(std::move(host)),
          user_(std::move(user)),
          remoteDesktopDir_(std::move(remoteDesktopDir)),
          localWorkDir_(std::move(localWorkDir)) {}

    bool uploadScript(const std::string &localScriptPath,
                      const std::string &remoteScriptName)
    {
        std::string userAtHost = user_ + "@" + host_;
        std::string remotePath = remoteDesktopDir_ + "\\" + remoteScriptName;

        // NOTE: Path syntax for Windows + OpenSSH sometimes needs tweaking.
        // If this fails, try changing remotePath to something like /c/Users/... instead.
        std::string cmd = "scp \"" + localScriptPath + "\" \"" +
                          userAtHost + ":/" + escapeForRemotePath(remotePath) + "\"";

        return runCommand(cmd, "uploadScript");
    }

    bool runScript(const std::string &remoteScriptName)
    {
        std::string userAtHost = user_ + "@" + host_;
        std::string remotePath = remoteDesktopDir_ + "\\" + remoteScriptName;

        std::string cmd = "ssh " + userAtHost +
                          " \"powershell -ExecutionPolicy Bypass -File '" +
                          remotePath + "'\"";

        return runCommand(cmd, "runScript");
    }

    bool downloadLog(const std::string &remoteLogName,
                     const std::string &localLogPath)
    {
        std::string userAtHost = user_ + "@" + host_;
        std::string remotePath = remoteDesktopDir_ + "\\" + remoteLogName;

        std::string cmd = "scp \"" + userAtHost + ":/" +
                          escapeForRemotePath(remotePath) + "\" \"" +
                          localLogPath + "\"";

        return runCommand(cmd, "downloadLog");
    }

    bool showLogInWindow(const std::string &localLogPath)
    {
        // You can change xterm to gnome-terminal, konsole, etc., if needed.
        std::string cmd = "xterm -hold -e \"less '" + localLogPath + "'\" &";
        return runCommand(cmd, "showLogInWindow");
    }

private:
    std::string host_;
    std::string user_;
    std::string remoteDesktopDir_;
    std::string localWorkDir_;

    static std::string escapeForRemotePath(const std::string &winPath)
    {
        std::string result = winPath;
        for (char &c : result) {
            if (c == '\\') {
                c = '/';
            }
        }
        return result;
    }

    bool runCommand(const std::string &cmd, const std::string &context)
    {
        std::cout << "[RemoteDesktopClient] Running (" << context << "): "
                  << cmd << std::endl;

        int rc = std::system(cmd.c_str());
        if (rc != 0) {
            std::cerr << "[RemoteDesktopClient] Command failed (" << context
                      << ") with code " << rc << std::endl;
            return false;
        }
        return true;
    }
};


void dataPreprocessingFunc(const std::string& inputFile, const std::string& outputFile) {
    std::ifstream inFile(inputFile);
    std::ofstream outFile(outputFile);
    if (!inFile || !outFile) {
        std::cerr << "Error opening input or output file.\n";
        return;
    }

    std::string line;
    std::string data;
    bool afterBye = false;
    bool inBlock = false;
    bool blockFound = false;

    while (std::getline(inFile, line)) {
        // Stop reading after "Bye..."
        if (line.find("Bye...") != std::string::npos) {
            afterBye = true;
            break;
        }

        // Detect start of MO block
        if (line.find("====") != std::string::npos && !inBlock) {
            inBlock = true;
            data += line + "\n";
            continue;
        }

        // Capture lines inside the block
        if (inBlock) {
            data += line + "\n";
            // Detect end of block
            if (line.find("Total:") != std::string::npos) {
                blockFound = true;
                inBlock = false;
            }
        }
    }

    inFile.close();

    // Write extracted block to output
    if (blockFound) {
        outFile << data;
        std::cout << "Extracted MO block written to " << outputFile << "\n";
    } else {
        std::cout << "No MO block found in " << inputFile << "\n";
    }

    outFile.close();
}

inline std::string toLower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower((unsigned char)c));
    return s;
}

std::string get_attribute_value0(const std::string& cell_id, const std::string& network_data) {
    std::smatch match;

    std::regex pattern("GNBDUFunction=([^,]+),NRCellDU=" + cell_id);
//    std::regex pattern(R"(GNBDUFunction=([^,]+),NRCellDU=)" + cell_id);
    if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
            return match[1].str();
    }

    return cell_id;
}

std::string get_attribute_value0_1(const std::string& du_func_id, const std::string& attribute_name, const std::string& network_data) {
    std::smatch match;

    std::regex pattern("GNBDUFunction=" + du_func_id + "\\s+" + attribute_name + "\\s+(\\S+)");
    if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
            return match[1].str();
    }

    return du_func_id;
}

std::string get_attribute_value0_2(const std::string& cell_id, const std::string& network_data) {
    std::smatch match;

    std::regex pattern("GNBDUFunction=" + cell_id + R"(\s+gNBId\s+(\S+))");
    if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
            return match[1].str();
    }

    return cell_id;
}

std::string get_attribute_value1(const std::string& cell_id, const std::string& attribute_name, const std::string& network_data) {
    std::smatch match;

    if (attribute_name == "nRSectorCarrierRef") {
        std::regex pattern("NRCellDU=" + cell_id + ".*?" + attribute_name + "[^\n]*\n.*?>.*?NRSectorCarrier=(\\d+)");
        if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
            return match[1].str();
        }
    }
    else {
        std::regex pattern("(?:^|\n)\\s*NRCellDU=" + cell_id + "\\s+" + attribute_name + "\\s+(\\S+)");
//        std::regex pattern("NRCellDU=" + cell_id + "\\s+" + attribute_name + "\\s+(\\d+)");
        if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
            return match[1].str();
        }
    }

    return cell_id;
}

std::string get_attribute_value2(const std::string& sec_id, const std::string& attribute_name, const std::string& network_data) {
    std::smatch match;

    std::regex pattern("(?:^|\n)\\s*NRSectorCarrier=" + sec_id + "\\s+" + attribute_name + "\\s+(\\S+)");
    if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
        std::string full = match[1].str();
        std::string key = "SectorEquipmentFunction=";
        size_t pos = full.find(key);
        if (pos != std::string::npos) {
            pos += key.size();  // move past "SectorEquipmentFunction="
            size_t end = full.find_first_of(" \n\r\t", pos); // stop at whitespace or newline
            return full.substr(pos, end - pos);
        }
        return full;
    }

    return sec_id;
}

std::string get_attribute_value2_1(const std::string& sec_id, const std::string& attribute_name, const std::string& network_data) {
    std::smatch match;

    std::regex pattern("(?:^|\n)\\s*TermPointToAmf=" + sec_id + "\\s+" + attribute_name + "\\s+(\\S+)");
    if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
        std::string full = match[1].str();
        std::string key = "SectorEquipmentFunction=";
        size_t pos = full.find(key);
        if (pos != std::string::npos) {
            pos += key.size();  // move past "SectorEquipmentFunction="
            size_t end = full.find_first_of(" \n\r\t", pos); // stop at whitespace or newline
            return full.substr(pos, end - pos);
        }
        return full;
    }

    return sec_id;
}

std::string get_attribute_value3(const std::string& se_id, const std::string& attribute_name, const std::string& network_data) {
    std::smatch match;

    std::regex pattern("SectorEquipmentFunction=" + se_id + ".*?" + attribute_name + ".*?\n.*?FieldReplaceableUnit=([^,\\s]+)");
    if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
        std::string full = match[1].str();
        std::string key = "FieldReplaceableUnit=";
        size_t pos = full.find(key);
        if (pos != std::string::npos) {
            pos += key.size();  // move past "FieldReplaceableUnit="
            size_t end = full.find_first_of(',', pos); // stop at ','
            return full.substr(pos, end - pos);
        }
        return full;
    }

    return se_id;
}

std::string get_attribute_value3_1(const std::string& se_id, const std::string& attribute_name, const std::string& network_data) {
    std::smatch match;

    // Use [\s\S]*? instead of .*? to include newlines
    std::regex pattern("SectorEquipmentFunction=" + se_id +
                       "[\\s\\S]*?" + attribute_name +
                       "[\\s\\S]*?Equipment=1,([^\\n]*)");

    if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
        std::string captured = match[1].str();
        // Trim leading/trailing whitespace
        captured.erase(0, captured.find_first_not_of(" \t\r\n"));
        captured.erase(captured.find_last_not_of(" \t\r\n") + 1);
        return captured;
    }

    return se_id;
}

std::string get_attribute_value3_2(const std::string& attribute_name, const std::string& network_data) {
    std::smatch match;

    // This pattern works for lines like:
    // rfPortRef                            FieldReplaceableUnit=RRU-21,RfPort=A
    std::regex pattern(attribute_name + R"([\s=]*FieldReplaceableUnit\s*=\s*([^, \t\r\n]+))",
                       std::regex_constants::icase);

    if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
        return match[1].str();  // e.g. "RRU-21"
    }

    return "";  // Not found
}

std::string get_attribute_value4(const std::string& rru_id, const std::string& attribute_name, const std::string& network_data) {
    std::smatch match;

    std::regex pattern("(?:^|\n)\\s*FieldReplaceableUnit=" + rru_id + "\\s+" + attribute_name + "\\s+(\\S+)");
    if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
        std::string full = match[1].str();
        return full;
    }

    return rru_id;
}

std::map<std::string, std::string> get_attribute_value4_2(const std::string& attribute_name, const std::string& network_data)
{
    std::map<std::string, std::string> results;

    // Match lines like: FieldReplaceableUnit=RRU-21   operationalState  1 (ENABLED)
    std::regex pattern(
        R"(FieldReplaceableUnit=(\S+)\s+)" + attribute_name + R"(\s+(\S+))"
    );

    for (std::sregex_iterator it(network_data.begin(), network_data.end(), pattern), end; it != end; ++it) {
        std::smatch match = *it;
        if (match.size() > 2) {
            std::string fru_id = match[1].str();        // e.g., "RRU-21"
            std::string state_value = match[2].str();   // e.g., "1"
            results[fru_id] = state_value;
        }
    }

    return results;
}

std::string get_attribute_value5(const std::string& rilink_id, const std::string& attribute_name, const std::string& network_data) {
    std::smatch match;

    std::regex pattern("(?:^|\n)\\s*RiLink=" + rilink_id + "\\s+" + attribute_name + "\\s+(\\S+)");
    if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
        std::string full = match[1].str();
        std::string key = "FieldReplaceableUnit=";
        size_t pos = full.find(key);
        if (pos != std::string::npos) {
            pos += key.size();  // move past "FieldReplaceableUnit="
            size_t end = full.find_first_of(',', pos); // stop at ','

            if (end == std::string::npos) end = full.size();

            std::string value = full.substr(pos, end - pos);  // e.g. "RRU-110"

            // Remove "RRU-" prefix if present
            if (value.rfind("RRU-", 0) == 0) {
//                value = value.substr(4);  // keep only digits
//                return value;
            }
            return value; // e.g. "110"
        }
        return full;
    }

    return rilink_id;
}

std::string get_attribute_value5_1(const std::string& rilink_id, const std::string& attribute_name, const std::string& network_data) {
    std::smatch match;

    std::regex pattern("(?:^|\n)\\s*RiLink=" + rilink_id + "\\s+" + attribute_name + "\\s+(\\S+)");
    if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
        std::string full = match[1].str();
        std::string key = "RiPort=";
        size_t pos = full.find(key);
        if (pos != std::string::npos) {
            pos += key.size();  // move past "RiPort="
            size_t end = full.find_first_of(" \n\r\t", pos); // stop at whitespace or newline
            return full.substr(pos, end - pos);
        }
        return full;
    }

    return rilink_id;
}

std::map<std::string, std::string> get_attribute_value5_2(const std::string& attribute_name, const std::string& network_data) {

    std::map<std::string, std::string> results;
    std::regex pattern(
        "(?:^|\\n)\\s*RiLink=(\\d+)\\s+" + attribute_name + "\\s+(\\S+)"
    );

    for (std::sregex_iterator it(network_data.begin(), network_data.end(), pattern), end; it != end; ++it) {
        std::smatch match = *it;
        if (match.size() > 2) {
            std::string rilink_id = match[1].str();
            std::string full      = match[2].str(); // e.g. "FieldReplaceableUnit=RRU-110,RiPort=DATA_1"

            std::string key = "FieldReplaceableUnit=";
            size_t pos = full.find(key);
            if (pos != std::string::npos) {
                pos += key.size();
                size_t endpos = full.find(',', pos);
                if (endpos == std::string::npos) endpos = full.size();
                std::string value = full.substr(pos, endpos - pos);
                results[rilink_id] = value;
            }
        }
    }
    return results;
}

std::string get_attribute_value5_3(const std::string& rilink_id, const std::string& attribute_name, const std::string& network_data) {
    std::smatch match;

    std::regex pattern("(?:^|\n)\\s*RiLink=" + rilink_id + "\\s+" + attribute_name + "\\s+(\\S+)");

    if (std::regex_search(network_data, match, pattern) && match.size() > 1) {

        std::string full = match[1].str();

        // Look for "RiPort=" inside the matched string:
        const std::string key = "RiPort=";
        size_t pos = full.find(key);

        if (pos != std::string::npos) {
            pos += key.size();  // move past "RiPort="
            size_t end = full.find_first_of(", \n", pos);
            if (end == std::string::npos) end = full.size();

            // Extract only the RiPort ID (DATA_1)
            return full.substr(pos, end - pos);
        }
        return full;
    }
    return "";
}

std::string get_attribute_value6(const std::string& fru_id, const std::string& riport_id, const std::string& attribute_name, const std::string& network_data) {
    std::smatch match;

        std::regex pattern("FieldReplaceableUnit=" + fru_id + ",RiPort=" + riport_id + "\\s+" + attribute_name + "\\s+(\\S+)");
        if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
                std::string full = match[1].str();
                return full;
        }

    return riport_id;
}

std::string get_attribute_value6_1(const std::string& fru_id, const std::string& riport_id, const std::string& attribute_name, const std::string& network_data) {
    std::smatch match;
    std::regex pattern;

    if (fru_id.find("VDU") != std::string::npos) {
        // Case when FRU is a VDU
        pattern = std::regex("FieldReplaceableUnit=" + fru_id + ",RiPort=" + riport_id + "\\s+" + attribute_name + "\\s+(\\S+)");
    } else {
        // Case when FRU is an RRU
        pattern = std::regex("FieldReplaceableUnit=" + fru_id + ",RiPort=" + riport_id + "\\s+" + attribute_name + "\\s+(\\S+)");
    }

    if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
        std::string full = match[1].str();
        return full;
    }

    return riport_id;
}

std::string get_attribute_value6_2(const std::string& fru_id, const std::string& attribute_name, const std::string& network_data) {
    std::smatch match;

    std::regex pattern("FieldReplaceableUnit=" + fru_id + ",RiPort=\\S+\\s+" + attribute_name + "\\s+(\\S+)");
    if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
        std::string full = match[1].str();
        return full;
    }

    return fru_id;
}

std::string get_attribute_value7(const std::string& fru_id, const std::string& tnp_id, const std::string& attribute_name, const std::string& data) {
    std::smatch match;

    std::regex pattern("FieldReplaceableUnit=" + fru_id + ",TnPort=" + tnp_id +"\\s+" + attribute_name + "\\s+\\[\\d+\\]\\s*=\\s*\\n\\s*>>>\\s*" + attribute_name + "\\s*=\\s*(.+)");

    if (std::regex_search(data, match, pattern) && match.size() > 1) {
        std::string full = match[1].str();
        std::string key = "EthernetPort=";
        size_t pos = full.find(key);
        if (pos != std::string::npos) {
            pos += key.size();  // move past "SectorEquipmentFunction="
            size_t end = full.find_first_of(" \n\r\t", pos); // stop at whitespace or newline
            return full.substr(pos, end - pos);
        }
    }

    return fru_id;
}

std::map<std::string, std::string> get_attribute_value7_2(const std::string& fru_id, const std::string& attribute_name, const std::string& data) {
    std::smatch match;

    std::map<std::string, std::string> results;

    std::regex pattern(
        "FieldReplaceableUnit=" + fru_id + ",TnPort=(\\S+)\\s+" + attribute_name +
        "\\s+\\[\\d+\\]\\s*=\\s*\\n\\s*>>>\\s*" + attribute_name + "\\s*=\\s*(.+)"
    );

    for (std::sregex_iterator it(data.begin(), data.end(), pattern), end; it != end; ++it) {
        std::smatch match = *it;
        if (match.size() > 2) {
            std::string rilink_id = match[1].str();
            std::string full      = match[2].str();

            std::string key = "EthernetPort=";
            size_t pos = full.find(key);
            if (pos != std::string::npos) {
                pos += key.size();
                size_t endpos = full.find_first_of(',', pos);
                if (endpos == std::string::npos) endpos = full.size();
                std::string value = full.substr(pos, endpos - pos);
                results[rilink_id] = value;
            }
        }
    }
    return results;
}

std::map<std::string, std::string> get_attribute_value7_3(const std::string& attribute_name, const std::string& data) {
    std::smatch match;

    std::map<std::string, std::string> results;

    std::regex pattern(
        "FieldReplaceableUnit=(\\S+),TnPort=(\\S+)[\\s\\S]*?>>\\s*" +
        attribute_name + "\\s*=\\s*(.+)"
    );

    for (std::sregex_iterator it(data.begin(), data.end(), pattern), end; it != end; ++it) {
        std::smatch match = *it;
        if (match.size() >= 4) {
            std::string fru_id  = match[1].str();
            std::string tn_port = match[2].str();
            std::string value   = match[3].str();

            std::regex eth_pattern(R"(EthernetPort=(\S+))");
            std::smatch eth_match;
            if (std::regex_search(value, eth_match, eth_pattern))
                results[tn_port] = eth_match[1].str();
            else
                results[tn_port] = value;
        }
    }

    return results;
}

std::string get_attribute_value7_4(const std::string& TNPortID, const std::string& data) {
    std::regex pattern(R"(FieldReplaceableUnit=(\S+),TnPort=(\S+))");

    for (std::sregex_iterator it(data.begin(), data.end(), pattern), end; it != end; ++it) {
        std::smatch m = *it;
        std::string fru_id  = m[1].str();
        std::string tn_port = m[2].str();

        // Return the first FRU ID that matches the TNPortID
        if (TNPortID.empty() || tn_port == TNPortID)
            return fru_id;
    }

    // If nothing found, return empty string
    return "";
}

std::map<std::string, std::string> get_attribute_value7_5(const std::string& data) {
    std::map<std::string, std::string> results;

    // Match "FieldReplaceableUnit=VDU-1,TnPort=TN_A"
    std::regex pattern(R"(FieldReplaceableUnit=(\S+),TnPort=(\S+))");

    for (std::sregex_iterator it(data.begin(), data.end(), pattern), end; it != end; ++it) {
        std::string fru_id  = (*it)[1].str();
        std::string tn_port = (*it)[2].str();

        results[fru_id] = tn_port;
    }

    return results;
}

std::string get_attribute_value8(const std::string& eth_id, const std::string& attribute_name, const std::string& data) {
    std::smatch match;

 //   std::regex pattern("EthernetPort=" + eth_id + "\\s+" + attribute_name + "\\s+(\\S+)");
    std::regex pattern("EthernetPort=" + eth_id + "\\s+" + attribute_name + "\\s+(\\S.+)");

    if (std::regex_search(data, match, pattern) && match.size() > 1) {
        std::string full = match[1].str();
        std::string key = "TnPort=";
        size_t pos = full.find(key);
        if (pos != std::string::npos) {
            pos += key.size();
            size_t end = full.find_first_of(" \n\r\t", pos); // stop at whitespace or newline
            return full.substr(pos, end - pos);
        }
    }

    return eth_id;
}

std::map<std::string, std::string> get_attribute_value8_2(const std::string& attribute_name, const std::string& data) {
    std::smatch match;

    std::map<std::string, std::string> results;
 //   std::regex pattern("EthernetPort=(\\S+)\\s+" + attribute_name + "\\s+(\\S+)");
    std::regex pattern("EthernetPort=(\\S+)\\s+" + attribute_name + "\\s+(\\S.+)");
    for (std::sregex_iterator it(data.begin(), data.end(), pattern), end; it != end; ++it) {
        std::smatch match = *it;
        if (match.size() > 2) {
            std::string rilink_id = match[1].str();
            std::string full      = match[2].str();

            std::string key = "TnPort=";
            size_t pos = full.find(key);
            if (pos != std::string::npos) {
                pos += key.size();
                size_t endpos = full.find_first_of(" \n\r\t", pos);
                if (endpos == std::string::npos) endpos = full.size();
                std::string value = full.substr(pos, endpos - pos);
                results[rilink_id] = value;
            }
        }
    }
    return results;
}

std::string get_attribute_value9(const std::string& eth_id, const std::string& attribute_name, const std::string& data) {
    std::smatch match;

    std::regex pattern("VlanPort=" + eth_id + "\\s+" + attribute_name + "\\s+(.*)");
    if (std::regex_search(data, match, pattern) && match.size() > 1) {
        std::string full = match[1].str();
        std::string key = "EthernetPort=";
        size_t pos = full.find(key);
        if (pos != std::string::npos) {
            pos += key.size();
            size_t end = full.find_first_of(" \n\r\t", pos); // stop at whitespace or newline
            return full.substr(pos, end - pos);
        }
        return full;
    }

    return eth_id;
}

std::map<std::string, std::string> get_attribute_value9_2(const std::string& attribute_name, const std::string& data) {
    std::smatch match;

    std::map<std::string, std::string> results;

    std::regex pattern("VlanPort=(\\S+)\\s+" + attribute_name + "\\s+(\\S.+)");
    for (std::sregex_iterator it(data.begin(), data.end(), pattern), end; it != end; ++it) {
        std::smatch match = *it;
        if (match.size() > 2) {
            std::string rilink_id = match[1].str();
            std::string full      = match[2].str();

            std::string key = "EthernetPort=";
            size_t pos = full.find(key);
            if (pos != std::string::npos) {
                pos += key.size();
                size_t endpos = full.find_first_of(" \n\r\t", pos);
                if (endpos == std::string::npos) endpos = full.size();
                std::string value = full.substr(pos, endpos - pos);
                results[rilink_id] = value;
            } else {
                results[rilink_id] = full;
            }
        }
    }
    return results;
}

std::string get_attribute_value10(const std::string& eth_id, const std::string& attribute_name, const std::string& data) {
    std::smatch match;

//    std::regex pattern("ExternalGNBCUCPFunction=" + eth_id + "\\s+" + attribute_name + "\\s+(.*)");
    std::regex pattern(".*ExternalGNBCUCPFunction=" + eth_id + "\\s+" + attribute_name + R"(\s+(\S+))");
    if (std::regex_search(data, match, pattern) && match.size() > 1) {
        std::string full = match[1].str();
        return full;
    }

    return eth_id;
}

std::string get_attribute_value10_1(const std::string& eth_id, const std::string& data) {
    std::smatch match;

    std::regex pattern(
        "ExternalGNBCUCPFunction=" + eth_id +
        R"(,TermPointToGNodeB=([0-9]+))"
    );

    if (std::regex_search(data, match, pattern)) {
        // match[1] contains only the numerical ID
        return match[1].str();
    }

    // not found
    return "";
}

std::map<std::string, std::string> get_attribute_value10_2(const std::string& attribute_name, const std::string& data) {
    std::smatch match;

    std::map<std::string, std::string> results;

//    std::regex pattern("ExternalGNBCUCPFunction=(\\S+)\\s+" + attribute_name + "\\s+(\\S.+)");
    std::regex pattern(".*ExternalGNBCUCPFunction=(\\S+)\\s+" + attribute_name + R"(\s+(\S+))");
    for (std::sregex_iterator it(data.begin(), data.end(), pattern), end; it != end; ++it) {
        std::smatch match = *it;
        if (match.size() > 2) {
            std::string rilink_id = match[1].str();
            std::string full      = match[2].str();
            results[rilink_id] = full;
        }
    }
    return results;
}

std::string get_attribute_value11(const std::string& eth_id, const std::string& attribute_name, const std::string& data) {
    std::smatch match;

    std::regex pattern(".*ExternalGNBCUCPFunction=" + eth_id + R"(.*\s+)" + attribute_name + R"(\s+(\S+))");
    if (std::regex_search(data, match, pattern) && match.size() > 1) {
        std::string full = match[1].str();
        return full;
    }

    return eth_id;
}

std::map<std::string, std::string> get_attribute_value11_2(const std::string& attribute_name, const std::string& data) {
    std::smatch match;

    std::map<std::string, std::string> results;
    std::regex pattern(".*ExternalGNBCUCPFunction=(\\S+)\\s+" + attribute_name + R"(\s+(\S+))");
    for (std::sregex_iterator it(data.begin(), data.end(), pattern), end; it != end; ++it) {
        std::smatch match = *it;
        if (match.size() > 2) {
            std::string rilink_id = match[1].str();
            std::string full      = match[2].str();

            size_t pos = 0;
            size_t endpos = rilink_id.find_first_of(',', pos);
            std::string value1 = rilink_id.substr(pos, endpos);
            results[value1] = full;
        }
    }
    return results;
}

std::string get_attribute_value12(const std::string& eth_id,
                                  const std::string& attribute_name,
                                  const std::string& data) {
    std::smatch match;

    std::regex pattern(
        "NRCellCU=" + eth_id + "\\s+" + attribute_name + "\\s+([^\\s]+)",
        std::regex_constants::icase);

    if (std::regex_search(data, match, pattern) && match.size() > 1) {
        return match[1].str(); // captured value
    }

    return "";  // return empty string if not found
}

std::map<std::string, std::string> get_attribute_value12_2(const std::string& attribute_name, const std::string& data) {
    std::smatch match;

    std::map<std::string, std::string> results;
    std::regex pattern("NRCellCU=(\\S+)\\s+" + attribute_name + R"(\s+(\S+))");
    for (std::sregex_iterator it(data.begin(), data.end(), pattern), end; it != end; ++it) {
        std::smatch match = *it;
        if (match.size() > 2) {
            std::string rilink_id = match[1].str();
            std::string full      = match[2].str();

            std::string key = "NRFrequency=";
            size_t pos = full.find(key);
            if (pos != std::string::npos) {
                pos += key.size();
                size_t endpos = full.find_first_of(" \n\r\t", pos);
                if (endpos == std::string::npos) endpos = full.size();
                std::string value = full.substr(pos, endpos - pos);
                results[rilink_id] = value;
            } else {
                results[rilink_id] = full;
            }
        }
    }
    return results;
}

std::string get_attribute_value12_3(const std::string& eth_id, const std::string& attribute_name, const std::string& data) {
    std::smatch match;

    std::map<std::string, std::string> results;
    std::regex pattern("NRCellCU=(\\S+)\\s+" + attribute_name + R"(\s+(\S+))");
    for (std::sregex_iterator it(data.begin(), data.end(), pattern), end; it != end; ++it) {
        std::smatch match = *it;
        if (match.size() > 2) {
            std::string rilink_id = match[1].str();
            std::string full      = match[2].str();

            if (full == eth_id) return rilink_id;
        }
    }

    return eth_id;
}

std::string get_attribute_value13(const std::string& cid, const std::string& fid, const std::string& attribute_name, const std::string& data) {

    std::smatch match;
    std::regex pattern("NRCellCU=" + cid + ",NRFreqRelation=" + fid +"\\s+" + attribute_name + R"(\s+(\S+))");
   if (std::regex_search(data, match, pattern) && match.size() > 1) {
        std::string full = match[1].str();
        std::string key = "NRFrequency=";
        size_t pos = full.find(key);
        if (pos != std::string::npos) {
            pos += key.size();
            size_t end = full.find_first_of('-', pos); // stop at whitespace or newline
            return full.substr(pos, end - pos);
        }
        return full;
    }

    return cid;
}

std::map<std::string, std::string> get_attribute_value13_2(const std::string& cid, const std::string& attribute_name, const std::string& data) {
    std::smatch match;

    std::map<std::string, std::string> results;
    std::regex pattern("NRCellCU=(\\S+)\\s+" + attribute_name + R"(\s+(\S+))");
    for (std::sregex_iterator it(data.begin(), data.end(), pattern), end; it != end; ++it) {
        std::smatch match = *it;
        if (match.size() > 2) {
            std::string rilink_id = match[1].str();
            std::string full      = match[2].str();

            std::string key = "NRFrequency=";
            size_t pos = full.find(key);
            if (pos != std::string::npos) {
                pos += key.size();
                size_t endpos = full.find_first_of('-', pos);
                if (endpos == std::string::npos) endpos = full.size();
                std::string value = full.substr(pos, endpos - pos);
                results[rilink_id] = value;
            } else {
                results[rilink_id] = full;
            }
        }
    }
    return results;
}

std::string get_attribute_value14(const std::string& cid, const std::string& fid, const std::string& attribute_name, const std::string& data) {

    std::smatch match;
    std::regex pattern(".*ExternalGNBCUCPFunction=" + cid + ",ExternalNRCellCU=" + fid +"\\s+" + attribute_name + R"(\s+(\S+))");
    if (std::regex_search(data, match, pattern) && match.size() > 1) {
        std::string full = match[1].str();
        std::string key = "NRFrequency=";
        size_t pos = full.find(key);
        if (pos != std::string::npos) {
            pos += key.size();
            size_t end = full.find_first_of(" \n\r\t", pos); // stop at whitespace or newline
            return full.substr(pos, end - pos);
        }
        return full;
    }

    return cid;
}

std::map<std::string, std::string> get_attribute_value14_1(const std::string& ecuf, const std::string& attribute_name, const std::string& data) {

    std::map<std::string, std::string> results;

    std::regex pattern("ExternalGNBCUCPFunction=(\\S+),ExternalNRCellCU=(\\S+).*?" + attribute_name + R"(\s+(\S+))");
    for (std::sregex_iterator it(data.begin(), data.end(), pattern), end; it != end; ++it) {
        std::smatch match = *it;
        if (match.size() > 3) {
            std::string func_id  = match[1].str();
            std::string cell_id  = match[2].str();
            std::string attr_val = match[3].str();

            if (func_id == ecuf) {
                results[cell_id] = attr_val;
            }
        }
    }
    return results;
}

std::map<std::string, std::string> get_attribute_value14_2(const std::string& ecuf, const std::string& attribute_name, const std::string& data) {
    std::smatch match;

    std::map<std::string, std::string> results;
    std::regex pattern(".*ExternalGNBCUCPFunction=(\\S+)\\s+" + attribute_name + R"(\s+(\S+))");
    for (std::sregex_iterator it(data.begin(), data.end(), pattern), end; it != end; ++it) {
        std::smatch match = *it;
        if (match.size() > 2) {
            std::string rilink_id = match[1].str();
            std::string full      = match[2].str();

            if (rilink_id.find(ecuf) != std::string::npos) {

                std::string key = "NRFrequency=";
                size_t pos = full.find(key);
                if (pos != std::string::npos) {
                        pos += key.size();
                        size_t endpos = full.find_first_of(" \n\r\t", pos);
                        if (endpos == std::string::npos) endpos = full.size();
                        std::string value = full.substr(pos, endpos - pos);
                        results[rilink_id] = value;
                } else {
                        results[rilink_id] = full;
                }
            }
        }
    }
    return results;
}

std::string get_attribute_value14_3(const std::string& ecuf, const std::string& eth_id, const std::string& attribute_name, const std::string& data) {
    std::smatch match;

    std::map<std::string, std::string> results;
    std::regex pattern(".*ExternalGNBCUCPFunction=(\\S+)\\s+" + attribute_name + R"(\s+(\S+))");
    for (std::sregex_iterator it(data.begin(), data.end(), pattern), end; it != end; ++it) {
        std::smatch match = *it;
        if (match.size() > 2) {
            std::string rilink_id = match[1].str();
            std::string full      = match[2].str();

            if (rilink_id.find(ecuf) != std::string::npos) {
                if (full == eth_id) return rilink_id;
            }
        }
    }

    return eth_id;
}

std::string get_attribute_value15(const std::string& cid, const std::string& fid, const std::string& attribute_name, const std::string& data) {

    std::smatch match;
    std::regex pattern("NRCellCU=" + cid +
                       ",NRCellRelation=" + fid +
                       "\\s+" + attribute_name +
                       R"(\s+(.+))");

    if (std::regex_search(data, match, pattern) && match.size() > 1) {
        std::string full = match[1].str();
        std::string key = "NRFreqRelation=";
        size_t pos = full.find(key);
        if (pos != std::string::npos) {
            pos += key.size();
            size_t end = full.find_first_of(" \n\r\t", pos); // stop at whitespace or newline
            return full.substr(pos, end - pos);
        }
        std::string key1 = "ExternalNRCellCU=";
        size_t pos1 = full.find(key1);
        if (pos1 != std::string::npos) {
            pos1 += key1.size();
            size_t end1 = full.find_first_of(" \n\r\t", pos1); // stop at whitespace or newline
            return full.substr(pos1, end1 - pos1);
        }
        return full;
    }

    return cid;
}

std::map<std::string, std::string> get_attribute_value15_2(
    const std::string& cid,
    const std::string& attribute_name,
    const std::string& data)
{
    std::map<std::string, std::string> results;

    // Flexible regex pattern for lines like:
    // NRCellCU=...,NRCellRelation=... nRFreqRelationRef NRCellCU=...,NRFreqRelation=...
    std::regex pattern(
        "NRCellCU=([^,\\s]+),NRCellRelation=([^\\s]+)\\s+" + attribute_name +
        "\\s+NRCellCU=[^,\\s]+,NRFreqRelation=([^\\s]+)",
        std::regex_constants::icase);

    for (std::sregex_iterator it(data.begin(), data.end(), pattern), end; it != end; ++it)
    {
        std::smatch match = *it;
        if (match.size() > 3)
        {
            std::string cell_cu     = match[1].str(); // serving NRCellCU
            std::string relation_id = match[2].str(); // NRCellRelation
            std::string freq_id     = match[3].str(); // NRFreqRelation

            if (cell_cu == cid)
            {
                results[relation_id] = freq_id;
            }
        }
    }
    return results;
}

std::string get_attribute_value16(const std::string& ext_partner_id, const std::string& attribute_name, const std::string& network_data) {
    std::smatch match;

    std::regex pattern("ExtGNBDUPartnerFunction=" + ext_partner_id + "\\s+" + attribute_name + "\\s+(\\S+)");
    if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
            return match[1].str();
    }

    return ext_partner_id;
}

std::map<std::string, std::string> get_attribute_value16_2(const std::string& attribute_name, const std::string& network_data) {
    std::smatch match;

    std::map<std::string, std::string> results;
    std::regex pattern("ExtGNBDUPartnerFunction=(\\S+)\\s+" + attribute_name + "\\s+(\\S+)");
    for (std::sregex_iterator it(network_data.begin(), network_data.end(), pattern), end; it != end; ++it) {
        std::smatch match = *it;
        if (match.size() > 2) {
            std::string id    = match[1].str();
            std::string value = match[2].str();
            results[id] = value;
        }
    }
    return results;
}

std::string get_attribute_value17(const std::string& network_data) {
    std::smatch match;

    // Regex to capture the value of pmMacPduVolDlUeSCell
    std::regex pattern(R"(pmMacPduVolDlUeSCell\s+(\d+))");

    if (std::regex_search(network_data, match, pattern) && match.size() > 1) {
        return match[1].str();   // return the value directly
    }

    return "";   // return empty string if not found
}

std::string get_attribute_value18(const std::string& network_data) {
    std::smatch match;
    std::regex pattern(R"(([\d\.]+)\s*(Gbits/sec|Mbits/sec).*\breceiver\b)", std::regex::icase);

    std::istringstream iss(network_data);
    std::string line;

    while (std::getline(iss, line)) {
        if (std::regex_search(line, match, pattern) && match.size() > 1) {
            return match[1].str();  // return the throughput number
        }
    }

    return ""; // not found
}

class Chamber;

// Global vector to store all instances
std::vector<Chamber*> globalObjectListChamber;

class Chamber {
public:
    Chamber(string v) : name(v) {
    }

    string getname() const {
        return name;
    }

    std::vector<string> getcells() {
        return cells;
    }

    void pushcell(string cell) {
        cells.push_back(cell);
    }

private:
    string name;
    std::vector<string> cells;
};

void createChamber(string temp) {
    Chamber* a = new Chamber(temp);
    globalObjectListChamber.push_back(a);
}

void searchChamberObjects() {
    std::cout << "All registered Chamber objects:\n";
    for (Chamber* obj : globalObjectListChamber) {
        std::cout << "name: " << obj->getname() << "\n";
    }
}

class MBvDU;

// Global vector to store all instances
std::vector<MBvDU*> globalObjectListMBvDU;

class MBvDU {
public:
    MBvDU(string v) : name(v) {
    }

    string getname() const {
        return name;
    }
    string getID() const {
        return ID;
    }
    void setID(string in) {
        ID = in;
    }
    string getIP() const {
        return ip;
    }
    void setIP(string in) {
        ip = in;
    }
    int getGNBID() const {
        return gnbID;
    }
    void setGNBID(int in) {
        gnbID = in;
    }
    int getcavlanPort() const {
        return cavlanPort;
    }
    void setcavlanPort(int in) {
        cavlanPort = in;
    }
    int getoamvlanPort() const {
        return oamvlanPort;
    }
    void setoamvlanPort(int in) {
        oamvlanPort = in;
    }
    string getBHIP() const {
        return bhip;
    }
    void setBHIP(string in) {
        bhip = in;
    }

private:
    string name;
    string ID;
    string ip;
    int gnbID;
    int cavlanPort;
    int oamvlanPort;
    string bhip;
};

void createMBvDU(string temp) {
    MBvDU* a = new MBvDU(temp);
    globalObjectListMBvDU.push_back(a);
}

void searchMBvDUObjects() {
    std::cout << "All registered MBvDU objects:\n";
    for (MBvDU* obj : globalObjectListMBvDU) {
        std::cout << "name: " << obj->getname() << " ip: " << obj->getIP() << "\n";
    }
}

class MSRBS;

// Global vector to store all instances
std::vector<MSRBS*> globalObjectListMSRBS;

class MSRBS {
public:
    MSRBS(string v) : name(v) {
    }
    string getname() const {
        return name;
    }
    string getID() const {
        return ID;
    }
    void setID(string in) {
        ID = in;
    }
    string getIP() const {
        return ip;
    }
    void setIP(string in) {
        ip = in;
    }
    int getGNBID() const {
        return gnbID;
    }
    void setGNBID(int in) {
        gnbID = in;
    }
    int getcavlanPort() const {
        return cavlanPort;
    }
    void setcavlanPort(int in) {
        cavlanPort = in;
    }
    int getoamvlanPort() const {
        return oamvlanPort;
    }
    void setoamvlanPort(int in) {
        oamvlanPort = in;
    }
    string getBHIP() const {
        return bhip;
    }
    void setBHIP(string in) {
        bhip = in;
    }

private:
    string name;
    string ID;
    string ip;
    int gnbID;
    int cavlanPort;
    int oamvlanPort;
    string bhip;
};

void createMSRBS(string temp) {
    MSRBS* a = new MSRBS(temp);
    globalObjectListMSRBS.push_back(a);
}

void searchMSRBSObjects() {
    std::cout << "All registered MSRBS objects:\n";
    for (MSRBS* obj : globalObjectListMSRBS) {
        std::cout << "name: " << obj->getname() << " ip: " << obj->getIP() << "\n";
    }
}

class MBCell;

// Global vector to store all instances
std::vector<MBCell*> globalObjectListMBCell;

class MBCell {
public:
    MBCell(string v) : name(v) {
    }
    string getname() const {
        return name;
    }
    string getID() const {
        return ID;
    }
    void setID(string in) {
        ID = in;
    }
    MBvDU* getNode() const {
        return node;
    }
    void setNode(MBvDU* in) {
        node = in;
    }
    int getLocalID() const {
        return LocalID;
    }
    void setLocalID(int in) {
        LocalID = in;
    }

private:
    string name;
    string ID;
    MBvDU* node;
    int LocalID;
};

void createMBCell(string temp) {
    MBCell* a = new MBCell(temp);
    globalObjectListMBCell.push_back(a);
}

void searchMBCellObjects() {
    std::cout << "All registered MBCell objects:\n";
    for (MBCell* obj : globalObjectListMBCell) {
        std::cout << "name: " << obj->getname() << "\n";
    }
}

class LBCell;

// Global vector to store all instances
std::vector<LBCell*> globalObjectListLBCell;

class LBCell {
public:
    LBCell(string v) : name(v) {
    }

    string getname() const {
        return name;
    }
    string getID() const {
        return ID;
    }
    void setID(string in) {
        ID = in;
    }
    MSRBS* getNode() const {
        return node;
    }
    void setNode(MSRBS* in) {
        node = in;
    }
    int getLocalID() const {
        return LocalID;
    }
    void setLocalID(int in) {
        LocalID = in;
    }

private:
    string name;
    string ID;
    MSRBS* node;
    int LocalID;
};

void createLBCell(string temp) {
    LBCell* a = new LBCell(temp);
    std::cout << "name: " << a->getname() << "\n";

    globalObjectListLBCell.push_back(a);
}

void searchLBCellObjects() {
    std::cout << "All registered LBCell objects:\n";
    for (LBCell* obj : globalObjectListLBCell) {
        std::cout << "name: " << obj->getname() << "\n";
    }
}

class LTECell;

// Global vector to store all instances
std::vector<LTECell*> globalObjectListLTECell;

class LTECell {
public:
    LTECell(string v) : name(v) {
    }

    string getname() const {
        return name;
    }

private:
    string name;
};

void createLTECell(string temp) {
    LTECell* a = new LTECell(temp);
    globalObjectListLTECell.push_back(a);
}

void searchLTECellObjects() {
    std::cout << "All registered LTECell objects:\n";
    for (LTECell* obj : globalObjectListLTECell) {
        std::cout << "name: " << obj->getname() << "\n";
    }
}

class RemoteDestop;

std::vector<RemoteDestop*> globalObjectListRemoteDestop;

class RemoteDestop {
public:
    RemoteDestop(string v) : name(v) {
    }

    string getname() const {
        return name;
    }

    string getAddr() const {
        return ipaddr;
    }
    void setAddr(string in) {
        ipaddr = in;
    }

private:
    string name;
    string ipaddr;
};

void createRemoteDestop(string temp) {
    RemoteDestop* a = new RemoteDestop(temp);
    globalObjectListRemoteDestop.push_back(a);
}

void searchRemoteDestopObjects() {
    std::cout << "All registered RemoteDestop objects:\n";
    for (RemoteDestop* obj : globalObjectListRemoteDestop) {
        std::cout << "name: " << obj->getname() << "\n";
    }
}

PREDICATE(createObjects, 2)
{

//  std::cout << A1.as_string() << "     " << A2.as_string() << endl;
  if (toLower(A2.as_string()).find("chamber") != std::string::npos) {
     createChamber(A1.as_string());
     searchChamberObjects();
  }

  if (toLower(A2.as_string()).find("mb") != std::string::npos && toLower(A2.as_string()).find("vdu") != std::string::npos) {
     createMBvDU(A1.as_string());
     searchMBvDUObjects();
  }
  if (toLower(A2.as_string()).find("msrbs") != std::string::npos) {
     createMSRBS(A1.as_string());
     searchMSRBSObjects();
  }
  if (toLower(A2.as_string()).find("mb") != std::string::npos && toLower(A2.as_string()).find("cell") != std::string::npos) {
     createMBCell(A1.as_string());
     searchMBCellObjects();
  }
  if (toLower(A2.as_string()).find("lb") != std::string::npos && toLower(A2.as_string()).find("cell") != std::string::npos) {
     createLBCell(A1.as_string());
     searchLBCellObjects();
  }
  if (toLower(A2.as_string()).find("lte") != std::string::npos && toLower(A2.as_string()).find("cell") != std::string::npos) {
     createLTECell(A1.as_string());
     searchLTECellObjects();
  }
  if (toLower(A2.as_string()).find("rdt") != std::string::npos && toLower(A2.as_string()).find("rdt") != std::string::npos) {
     createRemoteDestop(A1.as_string());
     searchRemoteDestopObjects();
  }

  return true;
}

PREDICATE(configChamberCells, 0)
{
    ifstream file("Nodes.txt");
    if (!file.is_open()) {
        cerr << "Error opening file\n";
    }
    std::string s1, s2, s3, s4, s5, s6, s7;
    while (file >> s1 >> s2 >> s3 >> s4 >> s5 >> s6 >> s7) {
            for (MBvDU* obj : globalObjectListMBvDU) {
                if((s1.find(obj->getname()) != std::string::npos || obj->getname().find(s1) != std::string::npos)) {
                    obj->setIP(s2);
                    obj->setGNBID(stoi(s3));
                    obj->setID(s4);
                    obj->setcavlanPort(stoi(s5));
                    obj->setBHIP(s6);
                    obj->setoamvlanPort(stoi(s7));
                    cout << obj->getIP() << " " << obj->getGNBID() << "  " << obj->getID() << endl;
                }
            }
            for (MSRBS* obj : globalObjectListMSRBS) {
                if((s1.find(obj->getname()) != std::string::npos || obj->getname().find(s1) != std::string::npos)) {
                    obj->setIP(s2);
                    obj->setGNBID(stoi(s3));
                    obj->setID(s4);
                    obj->setcavlanPort(stoi(s5));
                    obj->setBHIP(s6);
                    obj->setoamvlanPort(stoi(s7));
                    cout << obj->getIP() << " " << obj->getGNBID() << "  " << obj->getID() << endl;
                }
            }
    }
    file.close();

    ifstream file1("Cells.txt");
    if (!file1.is_open()) {
        cerr << "Error opening file\n";
    }
    while (file1 >> s1 >> s2 >> s3 >> s4) {
            for (MBCell* obj : globalObjectListMBCell) {
                if((s1.find(obj->getname()) != std::string::npos || obj->getname().find(s1) != std::string::npos)) {
                    obj->setID(s2);
                    obj->setLocalID(stoi(s3));
                }
            }
            for (LBCell* obj : globalObjectListLBCell) {
                if((s1.find(obj->getname()) != std::string::npos || obj->getname().find(s1) != std::string::npos)) {
                    obj->setID(s2);
                    obj->setLocalID(stoi(s3));
                }
            }
    }
    file1.close();

    ifstream file2("RDTs.txt");
    if (!file2.is_open()) {
        cerr << "Error opening file\n";
    }
    while (file2 >> s1 >> s2) {
            for (RemoteDestop* obj : globalObjectListRemoteDestop) {
                if((s1.find(obj->getname()) != std::string::npos || obj->getname().find(s1) != std::string::npos)) {
                    obj->setAddr(s2);
                }
            }
    }
    file2.close();

    for (MBCell* obj1 : globalObjectListMBCell) {
        for (MBvDU* obj2 : globalObjectListMBvDU) {
            if((obj1->getname().find(obj2->getname()) != std::string::npos)) {
                obj1->setNode(obj2);
            }
        }
    }

    for (LBCell* obj1 : globalObjectListLBCell) {
        for (MSRBS* obj2 : globalObjectListMSRBS) {
            if((obj1->getname().find(obj2->getname()) != std::string::npos)) {
                obj1->setNode(obj2);
            }
        }
    }

    return true;
}

PREDICATE(labelCells, 3)
{

  std::cout << A1.as_string() << "     " << A2.as_string() << "       " << A3.as_string() << endl;

  return true;
}

PREDICATE(setupChamberCells, 2)
{

  // Print output
  std::cout << "Setting up chamber: " << A1.as_string()  << endl;

  PlTerm_tail tail(A2);
  PlTerm_var e;

  for (Chamber* obj : globalObjectListChamber) {
      if(A1.as_string().find(obj->getname()) != std::string::npos) {
          std::cout << "Find chamber: " << A1.as_string()  << endl;
          while( tail.next(e) ) {
              obj->pushcell(e.as_string());
          }
      }
  }

  for (Chamber* obj : globalObjectListChamber) {
      if(A1.as_string().find(obj->getname()) != std::string::npos) {
          std::vector<string> cells = obj->getcells();
          for (string str : cells) {
              std::cout << str << endl;
          }
      }
  }

    for (MBCell* obj : globalObjectListMBCell) {
        std::cout << obj->getname() << " " << obj->getID() << " " << obj->getNode()->getname() << endl;
    }

    for (LBCell* obj : globalObjectListLBCell) {
        std::cout << obj->getname() << " " << obj->getID() << " " << obj->getNode()->getname() << endl;
   }

  return true;
}







// --- Basic MO queries ---
PREDICATE(prMO, 2)
{

    std::string moType = A1.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "pr " << moType << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

  return true;
}

PREDICATE(getMO, 3)
{
    std::string moType = A1.as_string();
    std::string moName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get " << moType << "=" << moName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

  return true;
}





// --- license ---
PREDICATE(showIPCALicense, 1)
{
    std::string s1;
    ifstream file1("IPCAEnLicenses.txt");
    if (!file1.is_open()) {
        cerr << "Error opening file\n";
    }

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    while (file1 >> s1) {
        outFile << "invl " << s1 << endl;
    }
    outFile << "l-" << endl;
    outFile.close();
    file1.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(enableIPCALicense, 1)
{
    std::string s1;
    ifstream file1("IPCAEnLicenses.txt");
    if (!file1.is_open()) {
        cerr << "Error opening file\n";
    }

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    while (file1 >> s1) {
        outFile << "set SystemFunctions=1,Lm=1,FeatureState=" << s1 << " featureState 1" << endl;
    }
    outFile << "l-" << endl;
    outFile.close();
    file1.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

  return true;
}

PREDICATE(disableIPCALicense, 1)
{
    std::string s1;
    ifstream file1("IPCADisLicenses.txt");
    if (!file1.is_open()) {
        cerr << "Error opening file\n";
    }

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    while (file1 >> s1) {
        outFile << "set SystemFunctions=1,Lm=1,FeatureState=" << s1 << " featureState 0" << endl;
    }
    outFile << "l-" << endl;
    outFile.close();
    file1.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

  return true;
}





// Alarm
PREDICATE(showAlarm, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "alt" << endl;
        outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showColi, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "erancmd listlinks" << endl;
    outFile << "ue print --admitted" << endl;
    outFile << "ue list --scells" << endl;
        outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}





// Counter
PREDICATE(showIPCADUCounter, 2)
{
    std::string s1;
    ifstream file1("IPCADUCounter.txt");
    if (!file1.is_open()) {
        cerr << "Error opening file\n";
    }

    std::string ducellID = A1.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    while (file1 >> s1) {
        outFile << "pdiff NRCellCU=" << ducellID << " " << s1 << endl;
    }
    outFile << "l-" << endl;
    outFile.close();
    file1.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

  return true;
}

PREDICATE(showIPCACUCounter, 2)
{
    std::string s1;
    ifstream file1("IPCACUCounter.txt");
    if (!file1.is_open()) {
        cerr << "Error opening file\n";
    }

    std::string ducellID = A1.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    while (file1 >> s1) {
        outFile << "pdiff NRCellCU=" << ducellID << " " << s1 << endl;
    }
    outFile << "l-" << endl;
    outFile.close();
    file1.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

  return true;
}






// Traces
PREDICATE(enableIPCATrace, 1)
{
    std::string s1;
    ifstream file1("IPCATraces.txt");
    if (!file1.is_open()) {
        cerr << "Error opening file\n";
    }

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    while (file1 >> s1) {
        outFile << s1 << endl;
    }
    outFile << "l-" << endl;
    outFile.close();
    file1.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

  return true;
}

PREDICATE(disableIPCATrace, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "mon-" << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

  return true;
}

PREDICATE(collectDCGM, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "dcgm" << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

  return true;
}









// --- GNBDUFunction ---
PREDICATE(showMOGNBDUFunctionByID, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get GNBDUFunction=" << A1.as_string() << endl;
        outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMOGNBDUFunctionByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get GNBDUFunction=" << A1.as_string() << " " << A2.as_string() << endl;
        outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(configAttributeMOGNBDUFunctionByID, 4)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    if(A2.as_string().find("caVlanPortRef") != std::string::npos) {
        outFile << "set GNBDUFunction=" << A1.as_string() << " " << A2.as_string() << " VlanPort=" << A3.as_string() << endl;
    } else {
        outFile << "set GNBDUFunction=" << A1.as_string() << " " << A2.as_string() << " " << A3.as_string() << endl;
    }
    outFile << "l-" << endl;
        outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getGNBDUFMOCellDUbyID, 3)
{

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "st NRCellDU" << endl;
    outFile << "l-" << endl;
    outFile.close();


// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_cel_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value0(target_cel_id, data_in);

    infile.close();

    std::cout << " DU Func. ID is: " << variable_A << std::endl;
    return A3.unify_atom(variable_A);
}

PREDICATE(getAttributeMOGNBDUFunctionByID, 4)
{

    std::string moID = A1.as_string();
    std::string attrName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get GNBDUFunction=" << moID << " " << attrName << endl;
    outFile << "l-" << endl;
    outFile.close();


// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_sec_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value0_1(target_sec_id, A2.as_string(), data_in);

    infile.close();

    return A3.unify_atom(variable_A);
}

PREDICATE(getNodeIPMOGNBDUFunctionByID, 2)
{
    std::string variable_A = "";
    std::string s1, s2, s3, s4, s5, s6, s7;

    const std::string duName = A1.as_string();
    ifstream file1("Nodes.txt");
    if (!file1.is_open()) {
        cerr << "Error opening file\n";
    }
    while (file1 >> s1 >> s2 >> s3 >> s4 >> s5 >> s6 >> s7) {
        if((toLower(s4).find(toLower(duName)) != std::string::npos || toLower(duName).find(toLower(s4)) != std::string::npos)) {
            variable_A = s2;
        }
    }
    file1.close();

    std::cout << " Found IP is " << variable_A << endl;

    return A2.unify_atom(variable_A);
}

PREDICATE(getCAVlanPortIDMOGNBDUFunctionByID, 2)
{
    std::string variable_A = "";
    std::string s1, s2, s3, s4, s5, s6, s7;

    const std::string duName = A1.as_string();
    ifstream file1("Nodes.txt");
    if (!file1.is_open()) {
        cerr << "Error opening file\n";
    }
    while (file1 >> s1 >> s2 >> s3 >> s4 >> s5 >> s6 >> s7) {
        if((toLower(s4).find(toLower(duName)) != std::string::npos || toLower(duName).find(toLower(s4)) != std::string::npos)) {
            variable_A = s5;
        }
    }
    file1.close();

    std::cout << " Found vlan is " << variable_A << endl;

    return A2.unify_atom(variable_A);
}

PREDICATE(getOAMVlanPortIDMOGNBDUFunctionByID, 2)
{
    std::string variable_A = "";
    std::string s1, s2, s3, s4, s5, s6, s7;

    const std::string duName = A1.as_string();
    ifstream file1("Nodes.txt");
    if (!file1.is_open()) {
        cerr << "Error opening file\n";
    }
    while (file1 >> s1 >> s2 >> s3 >> s4 >> s5 >> s6 >> s7) {
        if((toLower(s4).find(toLower(duName)) != std::string::npos || toLower(duName).find(toLower(s4)) != std::string::npos)) {
            variable_A = s7;
        }
    }
    file1.close();

    std::cout << " Found vlan is " << variable_A << endl;

    return A2.unify_atom(variable_A);
}

PREDICATE(getBackHaulIPMOGNBDUFunctionByID, 2)
{
    std::string variable_A = "";
    std::string s1, s2, s3, s4, s5, s6, s7;

    std::cout << " Found backhaul ip is " << variable_A << endl;

    const std::string duName = A1.as_string();

    std::cout << " Found backhaul ip ... du is " << duName << endl;

    ifstream file1("Nodes.txt");
    if (!file1.is_open()) {
        cerr << "Error opening file\n";
    }
    while (file1 >> s1 >> s2 >> s3 >> s4 >> s5 >> s6 >> s7) {
        if((toLower(s4).find(toLower(duName)) != std::string::npos || toLower(duName).find(toLower(s4)) != std::string::npos)) {
            variable_A = s6;
        }
    }
    file1.close();

    std::cout << " Found backhaul ip is " << variable_A << endl;

    return A2.unify_atom(variable_A);
}











// --- NRCellDU ---
PREDICATE(getIPForNRCellDUByName, 2)
{
    std::string variable_A = "";
    std::string s1, s2, s3, s4;

    const std::string cellName = A1.as_string();
    ifstream file1("Cells.txt");
    if (!file1.is_open()) {
        cerr << "Error opening file\n";
    }
    while (file1 >> s1 >> s2 >> s3 >> s4) {
        if((toLower(s1).find(toLower(cellName)) != std::string::npos || toLower(cellName).find(toLower(s1)) != std::string::npos)) {
            variable_A = s4;
        }
    }
    file1.close();

    std::cout << " Found IP is " << variable_A << endl;

    return A2.unify_atom(variable_A);
}

PREDICATE(showAllNRCellDU, 1)
{

// A1 has the IP to send the moshell commands

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "st NRCellDU" << endl;
    outFile << "l-" << endl;outFile.close();

    std::cout << " show all NR Cells. " << std::endl;

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMONRCellDUByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellDU=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(blockMONRCellDUByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "bl NRCellDU=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(blockAllNRCellDU, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "bl NRCellDU" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deblockMONRCellDUByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "deb NRCellDU=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deblockAllNRCellDU, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "deb NRCellDU" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMONRCellDUByID, 3)
{

    std::cout << A1.as_string() << "     " << A2.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellDU=" << A1.as_string() << " " << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAttributeMONRCellDUByID, 4)
{

    std::string moID = A1.as_string();
    std::string attrName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellDU=" << moID << " " << attrName << endl;
    outFile << "l-" << endl;
    outFile.close();


// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_cell_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value1(target_cell_id, A2.as_string(), data_in);

    infile.close();

    return A3.unify_atom(variable_A);
}

PREDICATE(getMONRCellDUByName, 2)
{
    std::string variable_A = "";
    std::string s1, s2, s3, s4;

    const std::string cellName = A1.as_string();
    ifstream file1("Cells.txt");
    if (!file1.is_open()) {
        cerr << "Error opening file\n";
    }
    while (file1 >> s1 >> s2 >> s3 >> s4) {
        if((toLower(s1).find(toLower(cellName)) != std::string::npos || toLower(cellName).find(toLower(s1)) != std::string::npos)) {
            variable_A = s2;
        }
    }
    file1.close();

    std::cout << " Found Cell ID is " << variable_A << endl;
    return A2.unify_atom(variable_A);
}

PREDICATE(getGNBIDMOCellDUbyID, 3)
{
    std::string moID = A1.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "st NRCellDU=" << moID << endl;
    outFile << "l-" << endl;
    outFile.close();


// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_cel_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value0(target_cel_id, data_in);


    ofstream outFile1("example.mos");  // open for writing
    if (!outFile1) {
        cerr << "Failed to open file for writing\n";
    }
    outFile1 << "l+ example0.txt" << endl;
    outFile1 << "lt all" << endl;
    outFile1 << "get GNBDUFunction=" << variable_A << " gNBID" << endl;
    outFile1 << "l-" << endl;
    outFile1.close();

// wait till send request in example.mos.

        rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.


    const std::string filename1 = "example0.txt";
    std::ifstream infile1(filename1);
    if (!infile1) {
        std::cerr << "Error: cannot open file " << filename1 << std::endl;
        return 1;
    }
    std::ostringstream buffer1;
    buffer1 << infile1.rdbuf();
    std::string fileContent1 = buffer1.str();

    std::string data_in1 = "R\"(\n" + fileContent1 + ")\"";

    std::string variable_B = "";
    variable_B = get_attribute_value0_2(variable_A, data_in1);

    infile.close();
    infile1.close();

    return A2.unify_atom(variable_B);
}

PREDICATE(showAttributeAllNRCellDU, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellDU=" << " " << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(configAttributeMONRCellDUByID, 4)
{

    std::cout << A1.as_string() << "     " << A2.as_string() << "     " << A3.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "set NRCellDU=" << A1.as_string() << " " << A2.as_string() << " " << A3.as_long() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}





// --- NRSectorCarrier ---
PREDICATE(showAllNRSectorCarrier, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "st NRSectorCarrier" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMONRSectorCarrierByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRSectorCarrier=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(blockMONRSectorCarrierByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "bl NRSectorCarrier=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(blockAllNRSectorCarrier, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "bl NRSectorCarrier" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deblockMONRSectorCarrierByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "deb NRSectorCarrier=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deblockAllNRSectorCarrier, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "deb NRSectorCarrier" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMONRSectorCarrierByID, 3)
{

    std::cout << A1.as_string() << "     " << A2.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRSectorCarrier=" << A1.as_string() << " " << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAttributeMONRSectorCarrierByID, 4)
{

    std::string moID = A1.as_string();
    std::string attName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRSectorCarrier=" << moID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();


// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_sec_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value2(target_sec_id, A2.as_string(), data_in);

    infile.close();

    return A3.unify_atom(variable_A);
}

PREDICATE(showAttributeAllNRSectorCarrier, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRSectorCarrier=" << " " << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(configAttributeMONRSectorCarrierByID, 4)
{

    std::cout << A1.as_string() << "     " << A2.as_string() << "     " << A3.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "set NRSectorCarrier=" << A1.as_string() << " " << A2.as_string() << " " << A3.as_long() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}








// --- SectorEquipmentFunction ---
PREDICATE(showAllSectorEquipmentFunction, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "st SectorEquipmentFunction" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMOSectorEquipmentFunctionByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get SectorEquipmentFunction=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(blockMOSectorEquipmentFunctionByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "bl SectorEquipmentFunction=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(blockAllSectorEquipmentFunction, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "bl SectorEquipmentFunction" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deblockMOSectorEquipmentFunctionByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "deb SectorEquipmentFunction=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deblockAllSectorEquipmentFunction, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "deb SectorEquipmentFunction" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMOSectorEquipmentFunctionByID, 3)
{

    std::cout << A1.as_string() << "     " << A2.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get SectorEquipmentFunction=" << A1.as_string() << " " << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAttributeMOSectorEquipmentFunctionByID, 4)
{
    std::string moID = A1.as_string();
    std::string attName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get SectorEquipmentFunction=" << moID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();


// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_sec_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value3_1(target_sec_id, A2.as_string(), data_in);
    std::string variable_B = "";

    std::string key = "FieldReplaceableUnit=";
    size_t pos = variable_A.find(key);
    if (pos != std::string::npos) {
        pos += key.size();
        size_t end = variable_A.find_first_of(", \t\r\n", pos);
        variable_B = variable_A.substr(pos, end - pos);
    } else {
        ofstream outFile1("example.mos");  // open for writing
        if (!outFile1) {
                cerr << "Failed to open file for writing\n";
        }
        outFile1 << "l+ example0.txt" << endl;
        outFile1 << "lt all" << endl;
        outFile1 << "get " << variable_A << endl;
        outFile1 << "l-" << endl;
        outFile1.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

        dataPreprocessingFunc("example0.txt", "example1.txt");
        const std::string filename1 = "example1.txt";
        std::ifstream infile1(filename1);
        if (!infile1) {
                std::cerr << "Error: cannot open file " << filename << std::endl;
                return 1;
        }
        std::ostringstream buffer1;
        buffer1 << infile1.rdbuf();
        std::string fileContent1 = buffer1.str();

        std::string data_in1 = "R\"(\n" + fileContent1 + ")\"";

        variable_B = get_attribute_value3_2("rfPortRef", data_in1);

        std:cout << variable_B << std::endl;

    }

    infile.close();

    return A3.unify_atom(variable_B);
}

PREDICATE(showAttributeAllSectorEquipmentFunction, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get SectorEquipmentFunction=" << " " << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(configAttributeMOSectorEquipmentFunctionByID, 4)
{

    std::cout << A1.as_string() << "     " << A2.as_string() << "     " << A3.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "set SectorEquipmentFunction=" << A1.as_string() << " " << A2.as_string() << " " << A3.as_long() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}








// --- FieldReplaceableUnit ---
PREDICATE(showAllFieldReplaceableUnit, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "st FieldReplaceableUnit" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMOFieldReplaceableUnitByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get FieldReplaceableUnit=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(blockMOFieldReplaceableUnitByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "bl FieldReplaceableUnit=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(blockAllFieldReplaceableUnit, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "bl FieldReplaceableUnit" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(restartMOFieldReplaceableUnitByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "acc FieldReplaceableUnit=" << A1.as_string() << " restartunit" << endl;
    outFile << "1" << endl;
    outFile << "0" << endl;
    outFile << "0" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(restarAllFieldReplaceableUnit, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "acc FieldReplaceableUnit=" << " restartunit" << endl;
    outFile << "1" << endl;
    outFile << "0" << endl;
    outFile << "0" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deblockMOFieldReplaceableUnitByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "deb FieldReplaceableUnit=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deblockAllFieldReplaceableUnit, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "deb FieldReplaceableUnit" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMOFieldReplaceableUnitByID, 3)
{

    std::cout << A1.as_string() << "     " << A2.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get FieldReplaceableUnit=" << A1.as_string() << " " << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAttributeMOFieldReplaceableUnitByID, 4)
{
    std::string moID = A1.as_string();
    std::string attName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get FieldReplaceableUnit=" << moID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();


// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_sec_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value4(target_sec_id, A2.as_string(), data_in);

    infile.close();

    return A3.unify_atom(variable_A);
}

PREDICATE(showAttributeAllFieldReplaceableUnit, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get FieldReplaceableUnit=" << " " << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(configAttributeMOFieldReplaceableUnitByID, 4)
{

    std::cout << A1.as_string() << "     " << A2.as_string() << "     " << A3.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "set FieldReplaceableUnit=" << A1.as_string() << " " << A2.as_string() << " " << A3.as_long() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAllFieldReplaceableUnit, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get FieldReplaceableUnit=" << " operationalState" << endl;
    outFile << "l-" << endl;
    outFile.close();


// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    PlTerm_tail l1(A1);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";
    auto results = get_attribute_value4_2("operationalState", data_in);

    for (const auto& pair : results) {
        const auto& fru = pair.first;
        const auto& state = pair.second;
        if ( !l1.append(PlTerm(PlAtom(fru.c_str()))) ) return false;

    }
    (void) l1.close();

    infile.close();

    return true;
}








// --- RiLink ---
PREDICATE(showAllRiLink, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "st RiLink" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMORiLinkByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get RiLink=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMORiLinkByID, 3)
{

    std::cout << A1.as_string() << "     " << A2.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get RiLink=" << A1.as_string() << " " << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAttributeMORiLinkByID, 4)
{
    std::string moID = A1.as_string();
    std::string attName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get RiLink=" << moID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();


// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_sec_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value5_3(target_sec_id, A2.as_string(), data_in);

    infile.close();

    return A3.unify_atom(variable_A);
}

PREDICATE(getFRUMORiLinkByID, 4)
{

    std::string moID = A1.as_string();
    std::string attName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get RiLink=" << moID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();


// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_sec_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value5(target_sec_id, A2.as_string(), data_in);

    infile.close();

    return A3.unify_atom(variable_A);
}

PREDICATE(getRiportMORiLinkByID, 4)
{

    std::string moID = A1.as_string();
    std::string attName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get RiLink=" << moID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();


// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_sec_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value5_1(target_sec_id, A2.as_string(), data_in);

    infile.close();

    return A3.unify_atom(variable_A);
}

PREDICATE(showAttributeAllRiLink, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get RiLink=" << " " << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAllRiLink, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get RiLink=" << " riPortRef2" << endl;
    outFile << "l-" << endl;
    outFile.close();


// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    PlTerm_tail l1(A1);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";
    auto results = get_attribute_value5_2("riPortRef2", data_in);

    for (const auto& pair : results) {
        const auto& rilink = pair.first;
        const auto& fru = pair.second;
        if ( !l1.append(PlTerm(PlAtom(rilink.c_str()))) ) return false;

    }
    (void) l1.close();

    infile.close();

    return true;
}

PREDICATE(getAttributeAllRiLink, 3)
{

    std::string attName = A1.as_string();
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get RiLink=" << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();


// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    PlTerm_tail l2(A2);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";
    auto results = get_attribute_value5_2(A1.as_string(), data_in);

 //   for (const auto& [rilink, fru] : results) {
    for (const auto& pair : results) {
        const auto& rilink = pair.first;
        const auto& fru = pair.second;
        std::cout << "RiLink=" << rilink << " -> FieldReplaceableUnit=" << fru << "\n";
        if ( !l2.append(PlTerm(PlAtom(fru.c_str()))) ) return false;

    }
    (void) l2.close();

    infile.close();

    return true;
}

PREDICATE(configAttributeMORiLinkByID, 4)
{

    std::cout << A1.as_string() << "     " << A2.as_string() << "     " << A3.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "set RiLink=" << A1.as_string() << " " << A2.as_string() << " " << A3.as_long() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}






// --- RiPort ---
PREDICATE(showAllRiPort, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "st RiPort" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMORiPortByID, 3)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get FieldReplaceableUnit=" << A1.as_string() << ",RiPort=" << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(blockMORiPortByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "bl FieldReplaceableUnit=" << A1.as_string() << ",RiPort=" << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(blockAllRiPort, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "bl RiPort" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deblockMORiPortByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "deb FieldReplaceableUnit=" << A1.as_string() << ",RiPort=" << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deblockAllRiPort, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "deb RiPort" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMORiPortByID, 4)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get FieldReplaceableUnit=" << A1.as_string() << ",RiPort=" << A2.as_string() << " " << A3.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeAllRiPort, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get FieldReplaceableUnit=" << A1.as_string() << ",RiPort=" << " " << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAttributeMORiPortByID, 5)
{

    std::string FRU_ID = A1.as_string();
    std::string MO_ID = A2.as_string();
    std::string attName = A3.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get FieldReplaceableUnit=" << FRU_ID << ",RiPort=" << MO_ID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();


// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A5.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_fru_id = A1.as_string();
    std::string target_rip_id = A2.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value6_1(target_fru_id, target_rip_id, A3.as_string(), data_in);

    infile.close();

    return A4.unify_atom(variable_A);
}

PREDICATE(getAttributeAllRiPort, 4)
{
    std::string FRU_ID = A1.as_string();
    std::string attName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get FieldReplaceableUnit=" << FRU_ID << ",RiPort= " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();


// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_fru_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value6_2(target_fru_id, A2.as_string(), data_in);

    infile.close();

    return A3.unify_atom(variable_A);
}










// --- TermPointToAmf ---
PREDICATE(showAllTermPointToAmf, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "st TermPointToAmf" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMOTermPointToAmfByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get TermPointToAmf=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(blockMOTermPointToAmfByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "bl TermPointToAmf=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(blockAllTermPointToAmf, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "bl TermPointToAmf" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deblockMOTermPointToAmfByID, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "deb TermPointToAmf=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deblockAllTermPointToAmf, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "deb TermPointToAmf" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMOTermPointToAmfByID, 3)
{

    std::cout << A1.as_string() << "     " << A2.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get TermPointToAmf=" << A1.as_string() << " " << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeAllTermPointToAmf, 2)
{
    std::cout << A1.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get TermPointToAmf=" << " " << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(configAttributeMOTermPointToAmfByID, 4)
{

    std::cout << A1.as_string() << "     " << A2.as_string() << "     " << A3.as_string() << endl;

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "set TermPointToAmf=" << A1.as_string() << " " << A2.as_string() << " " << A3.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAttributeMOTermPointToAmfByID, 4)
{
    std::string MO_ID = A1.as_string();
    std::string attName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get TermPointToAmf=" << MO_ID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_sec_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value2_1(target_sec_id, A2.as_string(), data_in);

    infile.close();

    return A3.unify_atom(variable_A);
}







// --------------------------------------------------------------//


// --- TnPort instructions ---
PREDICATE(showAllTnPort, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get TnPort= " << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMOTnPortByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get FieldReplaceableUnit=" << A1.as_string() << ",TnPort=" << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(createMOTnPortByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "cr FieldReplaceableUnit=" << A1.as_string() << ",TnPort=" << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deleteMOTnPortByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "del FieldReplaceableUnit=" << A1.as_string() << ",TnPort=" << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMOTnPortByID, 4)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get FieldReplaceableUnit=" << A1.as_string() << ",RiPort=" << A2.as_string() << " " << A3.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeAllTnPort, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get FieldReplaceableUnit=" << A1.as_string() << ",RiPort=" << " " << A3.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(configAttributeMOTnPortByID, 5)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "set FieldReplaceableUnit=" << A1.as_string() << ",RiPort=" << A2.as_string() << " " << A3.as_string() << A4.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A5.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAttributeMOTnPortByID, 5)
{
    std::string FRU_ID = A1.as_string();
    std::string MO_ID = A2.as_string();
    std::string attName = A3.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get FieldReplaceableUnit=" << FRU_ID << ",TnPort=" << MO_ID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A5.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_fru_id = A1.as_string();
    std::string target_tnp_id = A2.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value7(target_fru_id, target_tnp_id, A3.as_string(), data_in);

    infile.close();

    return A4.unify_atom(variable_A);
}

PREDICATE(getAttributeAllTnPort, 4)
{

    std::string FRU_ID = A1.as_string();
    std::string attName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get FieldReplaceableUnit=" << FRU_ID << ",TnPort=" << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A3);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    auto results = get_attribute_value7_2(A1.as_string(), A2.as_string(), data_in);
    for (const auto& pair : results) {
        const auto& tnp = pair.first;
        const auto& enp = pair.second;
        if ( !l1.append(PlTerm(PlAtom(enp.c_str()))) ) return false;

    }
    (void) l1.close();

    infile.close();

    return true;
}

PREDICATE(getAllTnPort, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get TnPort=" << " reservedBy" << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A1);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    auto results = get_attribute_value7_3("reservedBy", data_in);
    for (const auto& pair : results) {
        const auto& tnp = pair.first;
        const auto& enp = pair.second;
       if ( !l1.append(PlTerm(PlAtom(tnp.c_str()))) ) return false;

    }
    (void) l1.close();

    infile.close();

    return true;
}

PREDICATE(getFRUMOTnPort, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "pr TNport" << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_id = A1.as_string();

    std::string variable_A = "";
    variable_A = get_attribute_value7_4(target_id, data_in);

    infile.close();

    return A2.unify_atom(variable_A);

}

PREDICATE(getAllFRUMOTnPort, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "pr TNport" << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A1);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    auto results = get_attribute_value7_5(data_in);
    for (const auto& pair : results) {
        const auto& fru = pair.first;
        const auto& tnp = pair.second;
       if ( !l1.append(PlTerm(PlAtom(fru.c_str()))) ) return false;

    }
    (void) l1.close();

    infile.close();

    return true;
}







// --- EthernetPort instructions ---
PREDICATE(showAllEthernetPort, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get EthernetPort= " << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMOEthernetPortByID, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get EthernetPort=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(createMOEthernetPortByID, 4)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "cr Transport=1,EthernetPort=" << A3.as_string() << endl;
    outFile << "FieldReplaceableUnit=" << A2.as_string() << ",TnPort=" << A3.as_string() << endl;
    outFile << "1" << endl;
    outFile << "true" << endl;
    outFile << "l-" << endl;outFile.close();

    std::string variable_A = A3.as_string();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return A1.unify_atom(variable_A);
}

PREDICATE(deleteMOEthernetPortByID, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "del EthernetPort=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(blckMOEthernetPortByID, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "bl EthernetPort=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deblockMOEthernetPortByID, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "deb EthernetPort=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}


PREDICATE(showAttributeMOEthernetPortByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get EthernetPort=" << A1.as_string() << " " << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeAllEthernetPort, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get EthernetPort= " << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(configAttributeMOEthernetPortByID, 4)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "set EthernetPort=" << A1.as_string() << " " << A2.as_string() << " " << A3.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAttributeMOEthernetPortByID, 4)
{
    std::string MO_ID = A1.as_string();
    std::string attName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get EthernetPort=" << MO_ID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_fru_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value8(target_fru_id, A2.as_string(), data_in);

    infile.close();

    return A3.unify_atom(variable_A);
}

PREDICATE(getAttributeAllEthernetPort, 3)
{
    std::string attName = A1.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get EthernetPort=" << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A2);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    auto results = get_attribute_value8_2(A1.as_string(), data_in);
    for (const auto& pair : results) {
        const auto& eth = pair.first;
        const auto& tnp = pair.second;
        if ( !l1.append(PlTerm(PlAtom(tnp.c_str()))) ) return false;

    }
    (void) l1.close();

    infile.close();

    return true;
}

PREDICATE(getAllEthernetPort, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get EthernetPort=" << " encapsulation" << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A1);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    auto results = get_attribute_value8_2("encapsulation", data_in);
//    for (const auto& [eth, tnp] : results) {
    for (const auto& pair : results) {
        const auto& eth = pair.first;
        const auto& tnp = pair.second;
        if ( !l1.append(PlTerm(PlAtom(eth.c_str()))) ) return false;

    }
    (void) l1.close();

    infile.close();

    return true;
}







// --- VlanPort instructions ---
PREDICATE(showAllVlanPort, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get VlanPort= " << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMOVlanPortByID, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get VlanPort=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(createMOVlanPortByID, 4)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "cr Transport=1,VlanPort=" << A2.as_string() << endl;
    outFile << "Transport=1,EthernetPort=" << A2.as_string() << endl;
    outFile <<  A3.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return A1.unify_atom(A2.as_string());
}

PREDICATE(deleteMOVlanPortByID, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "del Transport=1,VlanPort=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMOVlanPortByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get VlanPort=" << A1.as_string() << " " << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeAllVlanPort, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get VlanPort= " << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(configAttributeMOVlanPortByID, 4)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "set VlanPort=" << A1.as_string() << " " << A2.as_string() << " " << A3.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAllVlanPort, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get VlanPort=" << " vlanId" << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A1);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    auto results = get_attribute_value9_2("vlanId", data_in);
    for (const auto& pair : results) {
        const auto& vlp = pair.first;
        const auto& vid = pair.second;
        if ( !l1.append(PlTerm(PlAtom(vlp.c_str()))) ) return false;

    }
    (void) l1.close();

    infile.close();

    return true;
}

PREDICATE(getAttributeAllVlanPort, 3)
{
    std::string attName = A1.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get VlanPort=" << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A2);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    auto results = get_attribute_value9_2(A1.as_string(), data_in);
    for (const auto& pair : results) {
        const auto& vlp = pair.first;
        const auto& vid = pair.second;
        if ( !l1.append(PlTerm(PlAtom(vid.c_str()))) ) return false;

    }
    (void) l1.close();

    infile.close();

    return true;
}


PREDICATE(getAttributeMOVlanPortByID, 4)
{
    std::string MO_ID = A1.as_string();
    std::string attName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get VlanPort=" << MO_ID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_fru_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value9(target_fru_id, A2.as_string(), data_in);

    infile.close();

    return A3.unify_atom(variable_A);
}









// --------------------------------------------------------------//


// --- ExternalGNBCUCPFunction instructions ---
PREDICATE(showAllExternalGNBCUCPFunction, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExternalGNBCUCPFunction= " << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMOExternalGNBCUCPFunctionByID, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExternalGNBCUCPFunction=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(createMOExternalGNBCUCPFunctionByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "cr GNBCUCPFunction=1,NRNetwork=1,ExternalGNBCUCPFunction=" << A1.as_string() << endl;
    outFile << "" << A2.as_string() << endl;
    outFile << "mcc=311,mnc=480" << endl;
    outFile << "22" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deleteMOExternalGNBCUCPFunctionByID, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "del GNBCUCPFunction=1,NRNetwork=1,ExternalGNBCUCPFunction=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMOExternalGNBCUCPFunctionByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExternalGNBCUCPFunction=" << A1.as_string() << " " << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeAllExternalGNBCUCPFunction, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExternalGNBCUCPFunction= " << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(configAttributeMOExternalGNBCUCPFunctionByID, 4)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "set ExternalGNBCUCPFunction=" << A1.as_string() << " " << A2.as_string() << " " << A3.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAllExternalGNBCUCPFunction, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExternalGNBCUCPFunction=" << " gNBId" << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A1);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    auto results = get_attribute_value10_2("gNBId", data_in);
    for (const auto& pair : results) {
        const auto& ecuf = pair.first;
        const auto& gid = pair.second;
        if ( !l1.append(PlTerm(PlAtom(ecuf.c_str()))) ) return false;

    }
    (void) l1.close();

    infile.close();

    return true;
}

PREDICATE(getAttributeAllExternalGNBCUCPFunction, 3)
{
    std::string attName = A1.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExternalGNBCUCPFunction=" << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A2);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    auto results = get_attribute_value10_2(A1.as_string(), data_in);
    for (const auto& pair : results) {
        const auto& ecuf = pair.first;
        const auto& gid = pair.second;
        if ( !l1.append(PlTerm(PlAtom(gid.c_str()))) ) return false;

    }
    (void) l1.close();

    infile.close();

    return true;
}


PREDICATE(getAttributeMOExternalGNBCUCPFunctionByID, 4)
{
    std::string MO_ID = A1.as_string();
    std::string attName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExternalGNBCUCPFunction=" << MO_ID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_fru_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value10(target_fru_id, A2.as_string(), data_in);

    infile.close();

    std::cout << target_fru_id << "     " << A2.as_string() << "     " << variable_A << endl;

    return A3.unify_atom(variable_A);
}

PREDICATE(getTermPointToGNodeBMOExternalGNBCUCPFunctionByID, 3)
{
    std::string MO_ID = A1.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "pr ExternalGNBCUCPFunction=" << MO_ID <<",TermPointToGNodeB="  << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value10_1(target_id, data_in);

    infile.close();

    std::cout << target_id << "     " << variable_A << endl;

    if (variable_A == "") {
        return false;
    } else {
        return A2.unify_atom(variable_A);
    }
}









// --- TermPointToGNodeB instructions ---
PREDICATE(showAllTermPointToGNodeB, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get TermPointToGNodeB= " << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMOTermPointToGNodeBByID, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExternalGNBCUCPFunction=" << A1.as_string() << ",TermPointToGNodeB=" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(createMOTermPointToGNodeBByID, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "cr GNBCUCPFunction=1,NRNetwork=1,ExternalGNBCUCPFunction=" << A1.as_string() << ",TermPointToGNodeB=1" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deleteMOTermPointToGNodeBByID, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "del GNBCUCPFunction=1,NRNetwork=1,ExternalGNBCUCPFunction=" << A1.as_string() << ",TermPointToGNodeB=" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMOTermPointToGNodeBByID, 4)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExternalGNBCUCPFunction=" << A1.as_string() << ",TermPointToGNodeB=" << A2.as_string() << " " << A3.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeAllTermPointToGNodeB, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get TermPointToGNodeB= " << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(configAttributeMOTermPointToGNodeBByID, 5)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "set ExternalGNBCUCPFunction=" << A1.as_string() << ",TermPointToGNodeB=" << A2.as_string() << " " << A3.as_string() << " " << A4.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A5.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAllTermPointToGNodeB, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get TermPointToGNodeB=" << " ipv6Address" << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A1);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    auto results = get_attribute_value11_2("ipv6Address", data_in);
    for (const auto& pair : results) {
        const auto& ecuf = pair.first;
        const auto& ip = pair.second;
        if ( !l1.append(PlTerm(PlAtom(ecuf.c_str()))) ) return false;

    }
    (void) l1.close();

    infile.close();

    return true;
}

PREDICATE(getAttributeAllTermPointToGNodeB, 3)
{
    std::string attName = A1.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get TermPointToGNodeB=" << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A2);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    auto results = get_attribute_value11_2(A1.as_string(), data_in);
    for (const auto& pair : results) {
        const auto& ecuf = pair.first;
        const auto& ip = pair.second;
        if ( !l1.append(PlTerm(PlAtom(ip.c_str()))) ) return false;

    }
    (void) l1.close();

    infile.close();

    return true;
}


PREDICATE(getAttributeMOTermPointToGNodeBByID, 4)
{
    std::string EID = A1.as_string();
    std::string attName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExternalGNBCUCPFunction=" << EID << ",TermPointToGNodeB=" << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_fru_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value11(target_fru_id, A2.as_string(), data_in);

    infile.close();

    return A3.unify_atom(variable_A);
}








// --------------------------------------------------------------//


// --- NRCellCU instructions ---
PREDICATE(showAllNRCellCU, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "pr NRCellCU= " << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMONRCellCUByID, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellCU=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMONRCellCUByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellCU=" << A1.as_string() << " " << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeAllNRCellCU, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellCU= " << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(configAttributeMONRCellCUByID, 4)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "set NRCellCU=" << A1.as_string() << " " << A2.as_string() << " " << A3.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAllNRCellCU, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellCU=" << " cellLocalId" << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A1);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    auto results = get_attribute_value12_2("cellLocalId", data_in);
    for (const auto& pair : results) {
        const auto& cu = pair.first;
        const auto& lid = pair.second;
        if ( !l1.append(PlTerm(PlAtom(cu.c_str()))) ) return false;

    }
    (void) l1.close();

    infile.close();

    return true;
}

PREDICATE(getAttributeAllNRCellCU, 3)
{
    std::string attName = A1.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellCU=" << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A2);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    auto results = get_attribute_value12_2(A1.as_string(), data_in);
    for (const auto& pair : results) {
        const auto& cu = pair.first;
        const auto& lid = pair.second;
        if ( !l1.append(PlTerm(PlAtom(lid.c_str()))) ) return false;

    }
    (void) l1.close();

    infile.close();

    return true;
}

PREDICATE(getAttributeMONRCellCUByID, 4)
{
    std::string CID = A1.as_string();
    std::string attName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellCU=" << CID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_fru_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value12(target_fru_id, A2.as_string(), data_in);

    infile.close();

    return A3.unify_atom(variable_A);
}










// --- NRFreqRelation instructions ---
PREDICATE(showAllNRFreqRelation, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "pr NRCellCU=" << A1.as_string() << ",NRFreqRelation=" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMONRFreqRelationByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "pr NRCellCU=" << A1.as_string() << ",NRFreqRelation=" << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(createMONRFreqRelationByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "cr NRCellCU=" << A1.as_string() << ",NRFreqRelation=" << A2.as_string() << endl;
    outFile << "NRNetwork=1,NRFrequency=" << A2.as_string() << "-15" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(deleteMONRFreqRelationByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "del NRCellCU=" << A1.as_string() << ",NRFreqRelation=" << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMONRFreqRelationByID, 4)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellCU=" << A1.as_string() << ",NRFreqRelation=" << A2.as_string() << " " << A3.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeAllNRFreqRelation, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRFreqRelation= " << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(configAttributeMONRFreqRelationByID, 5)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "set NRCellCU=" << A1.as_string() << ",NRFreqRelation=" << A2.as_string() << " " << A3.as_string() << " " << A4.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A5.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAllNRFreqRelationPerCUCell, 3)
{
    std::string CUID = A1.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellCU=" << CUID << ",NRFreqRelation=" << " nRFrequencyRef" << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A2);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_cid = A1.as_string();
    auto results = get_attribute_value13_2(target_cid, "nRFrequencyRef", data_in);
    for (const auto& pair : results) {
        const auto& cid = pair.first;
        const auto& fid = pair.second;
        if ( !l1.append(PlTerm(PlAtom(fid.c_str()))) ) return false;
    }
    (void) l1.close();

    infile.close();

    return true;
}

PREDICATE(getAttributeMONRFreqRelationByIDPerCUCell, 5)
{
    std::string CUID = A1.as_string();
    std::string FID = A2.as_string();
    std::string attName = A3.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellCU=" << CUID << ",NRFreqRelation=" << FID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A5.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_cid = A1.as_string();
    std::string target_fid = A2.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value13(target_cid, target_fid, A3.as_string(), data_in);

    infile.close();

    return A4.unify_atom(variable_A);
}








// --- ExternalNRCellCU instructions ---
PREDICATE(showAllExternalNRCellCU, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "pr ExternalNRCellCU= " << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMOExternalNRCellCUByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExternalGNBCUCPFunction=" << A1.as_string() << ",ExternalNRCellCU=" << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMOExternalNRCellCUByID, 4)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExternalGNBCUCPFunction=" << A1.as_string() << ",ExternalNRCellCU=" << A2.as_string() << " " << A3.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeAllExternalNRCellCU, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExternalNRCellCU= " << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(configAttributeMOExternalNRCellCUByID, 5)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "set ExternalGNBCUCPFunction=" << A1.as_string() << ",ExternalNRCellCU=" << A2.as_string() << " " << A3.as_string() << " " << A4.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A5.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAllExternalNRCellCUPerExternalGNBCUCPFunction, 3)
{
    std::string ECUID = A1.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExternalGNBCUCPFunction=" << ECUID << ",ExternalNRCellCU=" << " cellLocalId" << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A2);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    auto results = get_attribute_value14_1(A1.as_string(), "cellLocalId", data_in);
    for (const auto& pair : results) {
        const auto& ecu = pair.first;
        const auto& lid = pair.second;
        if ( !l1.append(PlTerm(PlAtom(ecu.c_str()))) ) return false;

    }

    (void) l1.close();
    infile.close();
    return true;
}

PREDICATE(getAttributeAllExternalNRCellCUPerExternalGNBCUCPFunction, 4)
{
    std::string ECUID = A1.as_string();
    std::string attName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExternalGNBCUCPFunction=" << ECUID << ",ExternalNRCellCU=" << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A3);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    auto results = get_attribute_value14_2(A1.as_string(), A2.as_string(), data_in);
    for (const auto& pair : results) {
        const auto& ecu = pair.first;
        const auto& lid = pair.second;
        if ( !l1.append(PlTerm(PlAtom(lid.c_str()))) ) return false;

    }

    (void) l1.close();
    infile.close();
    return true;
}


PREDICATE(getAttributeMOExternalNRCellCUByIDPerExternalGNBCUCPFunction, 5)
{
    std::string ECUID = A1.as_string();
    std::string EID = A2.as_string();
    std::string attName = A3.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExternalGNBCUCPFunction=" << ECUID << ",ExternalNRCellCU=" << EID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A5.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_cuf_id = A1.as_string();
    std::string target_ecu_id = A2.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value14(target_cuf_id, target_ecu_id, A3.as_string(), data_in);

    infile.close();

    return A4.unify_atom(variable_A);
}








// --- NRCellRelation instructions ---
PREDICATE(showAllNRCellRelation, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "pr NRCellCU=" << A1.as_string() << ",NRCellRelation=" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMONRCellRelationByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "pr NRCellCU=" << A1.as_string() << ",NRCellRelation=" << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(createMONRCellRelationByID, 6)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "cr NRCellCU=" << A1.as_string() << ",NRCellRelation=" << A3.as_string() << endl;
    outFile << "GNBCUCPFunction=1,NRNetwork=1,ExternalGNBCUCPFunction=" << A2.as_string() << ",ExternalNRCellCU=" << A3.as_string() << endl;
    outFile << "GNBCUCPFunction=1,NRCellCU=" << A1.as_string() << ",NRFreqRelation=" << A5.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A6.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return A4.unify_atom(A3.as_string());
}

PREDICATE(deleteMONRCellRelationByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "del NRCellCU=" << A1.as_string() << ",NRCellRelation=" << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMONRCellRelationByID, 4)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellCU=" << A1.as_string() << ",NRCellRelation=" << A2.as_string() << " " << A3.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeAllNRCellRelation, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellRelation= " << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(configAttributeMONRCellRelationByID, 5)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "set NRCellCU=" << A1.as_string() << ",NRCellRelation=" << A2.as_string() << " " << A3.as_string() << " " << A4.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A5.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAllNRCellRelationPerCUCell, 3)
{
    std::string CCUID = A1.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellCU=" << CCUID << ",NRCellRelation=" << " nRFreqRelationRef" << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A2);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string source_cid = A1.as_string();
    auto results = get_attribute_value15_2(source_cid, "nRFreqRelationRef", data_in);
    for (const auto& pair : results) {
        const auto& crid = pair.first;
        const auto& frid = pair.second;
        if ( !l1.append(PlTerm(PlAtom(crid.c_str()))) ) return false;
    }

    (void) l1.close();
    infile.close();
    return true;
}

PREDICATE(getAttributeMONRCellRelationByIDPerCUCell, 5)
{
    std::string CCUID = A1.as_string();
    std::string CID = A2.as_string();
    std::string attName = A3.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get NRCellCU=" << CCUID << ",NRCellRelation=" << CID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A5.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_cid = A1.as_string();
    std::string target_fid = A2.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value15(target_cid, target_fid, A3.as_string(), data_in);

    infile.close();

    return A4.unify_atom(variable_A);
}








// --- ExtGNBDUPartnerFunction ---
PREDICATE(showAllExtGNBDUPartnerFunction, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "pr ExtGNBDUPartnerFunction" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMOExtGNBDUPartnerFunctionByID, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExtGNBDUPartnerFunction=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(createMOExtGNBDUPartnerFunctionByID, 5)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "cr GNBDUFunction=" << A2.as_string() << ",ExtGNBDUPartnerFunction=" << A3.as_string() << endl;
    outFile <<  A3.as_string() << endl;
    outFile <<  A4.as_string() << endl;
    outFile <<  "22" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A5.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return A1.unify_atom(A3.as_string());
}

PREDICATE(deleteMOExtGNBDUPartnerFunctionByID, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "del ExtGNBDUPartnerFunction=" << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMOExtGNBDUPartnerFunctionByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExtGNBDUPartnerFunction=" << A1.as_string() << " " << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeAllExtGNBDUPartnerFunction, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExtGNBDUPartnerFunction=" << " " << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(configAttributeMOExtGNBDUPartnerFunctionByID, 4)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "set ExtGNBDUPartnerFunction=" << A1.as_string() << " " << A2.as_string() << " " << A3.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(getAllExtGNBDUPartnerFunction, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExtGNBDUPartnerFunction=" << " gNBId" << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    PlTerm_tail l1(A1);

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();
    std::string data_in = "R\"(\n" + fileContent + ")\"";

    auto results = get_attribute_value16_2("gNBId", data_in);
    for (const auto& pair : results) {
        const auto& pid = pair.first;
        const auto& gid = pair.second;
        if ( !l1.append(PlTerm(PlAtom(pid.c_str()))) ) return false;
    }

    (void) l1.close();
    infile.close();
    return true;
}

PREDICATE(getAttributeMOExtGNBDUPartnerFunctionByID, 4)
{
    std::string MO_ID = A1.as_string();
    std::string attName = A2.as_string();

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExtGNBDUPartnerFunction=" << MO_ID << " " << attName << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string target_sec_id = A1.as_string();
    std::string variable_A = "";
    variable_A = get_attribute_value16(target_sec_id, A2.as_string(), data_in);

    infile.close();

    return A3.unify_atom(variable_A);
}








// --- InterMeLink ---
PREDICATE(showAllInterMeLink, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "pr InterMeLink" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAllInterMeLinkPerEPF, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "pr ExtGNBDUPartnerFunction=" << A1.as_string() << ",InterMeLink=" << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showMOInterMeLinkByID, 3)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExtGNBDUPartnerFunction=" << A1.as_string() << ",InterMeLink=" << A2.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A3.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeMOInterMeLinkByID, 4)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get ExtGNBDUPartnerFunction=" << A1.as_string() << ",InterMeLink=" << A2.as_string() << " " << A3.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A4.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(showAttributeAllInterMeLink, 2)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "get InterMeLink=" << " " << A1.as_string() << endl;
    outFile << "l-" << endl;outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A2.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}











// --- Test Execution ---

PREDICATE(getIPForRDTByName, 2)
{
    std::string variable_A = "";
    std::string s1, s2;

    const std::string rdtName = A1.as_string();
    ifstream file1("RDTs.txt");
    if (!file1.is_open()) {
        cerr << "Error opening file\n";
    }
    while (file1 >> s1 >> s2) {
        if((toLower(s1).find(toLower(rdtName)) != std::string::npos || toLower(rdtName).find(toLower(s1)) != std::string::npos)) {
            variable_A = s2;
        }
    }
    file1.close();

    std::cout << " Found IP is " << variable_A << endl;
    return A2.unify_atom(variable_A);
}

PREDICATE(attachUE, 1)
{
  std::cout << "UE Attach: " << A1.as_string() << endl;
  return true;
}

PREDICATE(runTraffic, 1)
{
    try
    {
        // =========================================================
        // 1) Read IP from Prolog: attachUE('10.111.237.105').
        // =========================================================
        std::string ueIp = A1.as_string();
        std::cout << "Attach UE (IP from Prolog arg): " << ueIp << std::endl;

        // =========================================================
        // 2) Config
        // =========================================================
        // Use the IP passed from Prolog as the RDT host
        const std::string rdtHost = ueIp;

        // Windows username on the RDT server
        const char *envUser = std::getenv("RDT_USER");
        const std::string rdtUser = envUser ? std::string(envUser) : "MIDBANDPC6";

        const std::string rdtPass = "Ericss0n";

        // Local path where example20.ps1 exists on the VM
        const std::string localScriptPath =
            "/home/WKMGAGAMBT/swipl-devel/build/example20.ps1";

        // Remote Windows desktop dir & filenames
        const std::string remoteDesktopDir = R"(C:\Users\MIDBANDPC6\Desktop)";
        const std::string remoteScriptName = "example20.ps1"; // PowerShell script
        const std::string remoteLogName    = "DT-Logs";       // file created by script

        // Local path to store downloaded DT-Logs (file)
        const char *home = std::getenv("HOME");
        const std::string localWorkDir = home ? std::string(home) : "/tmp";
        const std::string localLogPath = localWorkDir + "/DT-Logs";

        // Sanity check: ensure script exists locally
        {
            std::ifstream f(localScriptPath);
            if (!f.good()) {
                std::cerr << "[attachUE] Local script not found at: "
                          << localScriptPath << std::endl;
                return FALSE;
            }
        }

        // Debug info
        std::cout << "RDT host: " << rdtHost
                  << ", user: " << rdtUser << std::endl;
        std::cout << "Local script: " << localScriptPath << std::endl;
        std::cout << "Remote desktop dir: " << remoteDesktopDir << std::endl;
        std::cout << "Local DT-Logs path: " << localLogPath << std::endl;

        // =========================================================
        // Helpers
        // =========================================================

        auto run_cmd = [](const std::string &ctx, const std::string &cmd) -> bool {
            std::cout << "[attachUE] Running (" << ctx << "): " << cmd << std::endl;
            int rc = std::system(cmd.c_str());
            if (rc != 0) {
                std::cerr << "[attachUE] Command failed (" << ctx
                          << ") with code " << rc << std::endl;
                return false;
            }
            return true;
        };

        // Convert Windows path to scp/ssh-friendly forward-slash version
        auto escape_win_path = [](std::string path) -> std::string {
            for (char &c : path) {
                if (c == '\\') c = '/';
            }
            return path;
        };

        const std::string remoteDesktopEsc = escape_win_path(remoteDesktopDir);
        const std::string remoteScriptPath = remoteDesktopEsc + "/" + remoteScriptName;
        const std::string remoteLogPath    = remoteDesktopEsc + "/" + remoteLogName;
        const std::string userAtHost       = rdtUser + "@" + rdtHost;

        // =========================================================
        // (2) & (3) Connect and upload example20.ps1 to the RDT server
        // =========================================================
        // Using sshpass so we don't get an interactive password prompt.
        // Requires sshpass installed on the VM:
        //   sudo apt-get install sshpass
        std::string cmdUpload =
            "sshpass -p '" + rdtPass + "' "
            "scp \"" + localScriptPath + "\" "
            "\"" + userAtHost + ":" + remoteScriptPath + "\"";

        if (!run_cmd("upload script", cmdUpload)) {
            return FALSE;
        }

        // =========================================================
        // (4) Execute example20.ps1 on the RDT server in PowerShell
        // =========================================================
        const std::string remoteScriptPathWin =
    remoteDesktopDir + "\\" + remoteScriptName;

        std::string cmdRun =
        "sshpass -p '" + rdtPass + "' "
        "ssh " + userAtHost + " "
        "\"powershell -ExecutionPolicy Bypass -File \\\"" +
        remoteScriptPathWin + "\\\"\"";

        if (!run_cmd("run script", cmdRun)) {
            return FALSE;
        }

        // (5) Script should create DT-Logs on Desktop automatically.
        // Path: C:\\Users\\MIDBANDPC6\\Desktop\\DT-Logs

        // =========================================================
        // (6) Download DT-Logs back to the VM
        // =========================================================
        std::string cmdDownload =
            "sshpass -p '" + rdtPass + "' "
            "scp \"" + userAtHost + ":" +
            remoteLogPath + "\" \"" + localLogPath + "\"";

        if (!run_cmd("download log", cmdDownload)) {
            return FALSE;
        }

        // =========================================================
        // (7) Display DT-Logs in a window
        // =========================================================
        std::string cmdShow =
        "cat '" + localLogPath + "'";

        if (!run_cmd("show log", cmdShow)) {
        return FALSE;
        }
        return TRUE;
    }
    catch (const PlTypeError &)
    {
        std::cerr << "attachUE/1: Type error" << std::endl;
        return FALSE;
    }
    catch (const PlException &)
    {
        std::cerr << "attachUE/1: Unexpected Prolog exception" << std::endl;
        return FALSE;
    }
    catch (const std::exception &e)
    {
        std::cerr << "attachUE/1: std::exception: " << e.what() << std::endl;
        return FALSE;
    }
    catch (...)
    {
        std::cerr << "attachUE/1: Unknown exception" << std::endl;
        return FALSE;
    }
}

PREDICATE(getIPCADUCounter, 4)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "pget NRCellDU=" << A2.as_string() << " " << A3.as_string() << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }

// wait till get response in example0.txt.

    dataPreprocessingFunc("example0.txt", "example1.txt");
    const std::string filename = "example1.txt";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string variable_A = "";
    variable_A = get_attribute_value17(data_in);

    infile.close();

    float A_num = std::stof(variable_A);
    return A4.unify_float(A_num);
}

PREDICATE(startIPCATrace, 1)
{
    ifstream file1("IPCATrace.txt");
    if (!file1.is_open()) {
        cerr << "Error opening file\n";
    }

    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    std::string line;
    while (std::getline(file1, line)) {
        outFile << line << endl;
    }
    outFile << "l-" << endl;
    outFile.close();
    file1.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(stopIPCATrace, 1)
{
    ofstream outFile("example.mos");  // open for writing
    if (!outFile) {
        cerr << "Failed to open file for writing\n";
    }
    outFile << "l+ example0.txt" << endl;
    outFile << "lt all" << endl;
    outFile << "mon-" << endl;
    outFile << "l-" << endl;
    outFile.close();

// wait till send request in example.mos.

        int rc2 = std::system("bash ~/swipl/scripts/moshell_step2_prepare.sh");
        if (rc2 != 0) {
        std::cerr << "[ERR] Step 2 failed (prepare remote)\n";
        return 1;
        }

        int rc3 = std::system("bash ~/swipl/scripts/moshell_step3_upload.sh example.mos");
        if (rc3 != 0) {
        std::cerr << "[ERR] Step 3 failed (upload example.mos)\n";
        return 1;
        }

        std::string crgnbIp = A1.as_string();

        {
        std::string cmd = "bash ~/swipl/scripts/moshell_step4_run_once.sh '" + crgnbIp + "'";
        int rc4 = std::system(cmd.c_str());
                if (rc4 != 0) {
                std::cerr << "[ERR] Step 4 failed (start watcher)\n";
                return 1;
                }
        }

        {
         int rc6 = std::system("bash ~/swipl/scripts/moshell_step6_download.sh example0.txt");
         if (rc6 != 0) {
         std::cerr << "[ERR] Step 6 failed (download example0.txt)\n";
          return 1;
         }
        }


// wait till get response in example0.txt.

    return true;
}

PREDICATE(verifyIPCATput, 1)
{
    const std::string filename = "/home/WKMGAGAMBT/DT-Logs";
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string fileContent = buffer.str();

    std::string data_in = "R\"(\n" + fileContent + ")\"";

    std::string variable_A = "";
    variable_A = get_attribute_value18(data_in);

    infile.close();

    float A_num = std::stof(variable_A);
    if (A_num < 2) A_num *= 1024;

    return A1.unify_float(A_num);

}
