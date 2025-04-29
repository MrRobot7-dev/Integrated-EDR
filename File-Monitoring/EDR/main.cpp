#include "monitor.h"
#include <iostream>

int main() {
    std::cout << "[*] Starting live file & registry monitoring...\n";
    monitor_loop();
    return 0;
}

/*#include <iostream>
#include <fstream>
#include <filesystem>
#include <windows.h>
#include <winreg.h>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <thread>
#include <chrono>
#include <unordered_map>

using json = nlohmann::json;
namespace fs = std::filesystem;

// Get last write time of a file
std::string get_file_timestamp(const std::string& path) {
    try {
        if (!std::filesystem::exists(path)) {
            std::cerr << "[!] File does not exist: " << path << "\n";
            return "N/A";
        }

        auto ftime = std::filesystem::last_write_time(path);
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - std::filesystem::file_time_type::clock::now()
            + std::chrono::system_clock::now()
        );
        std::time_t cftime = std::chrono::system_clock::to_time_t(sctp);

        std::tm timeinfo;
        if (localtime_s(&timeinfo, &cftime) != 0) {
            std::cerr << "[!] Failed to convert timestamp for: " << path << "\n";
            return "N/A";
        }

        std::stringstream ss;
        ss << std::put_time(&timeinfo, "%F %T");
        return ss.str();
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Error reading timestamp for " << path << ": " << e.what() << "\n";
        return "N/A";
    }
}

std::string get_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);

    std::tm timeinfo;
    if (localtime_s(&timeinfo, &now_time) != 0) {
        std::cerr << "[!] Failed to get current local time.\n";
        return "N/A";
    }

    std::stringstream ss;
    ss << std::put_time(&timeinfo, "%F %T");
    return ss.str();
}


// Read specific registry value
std::string read_registry_value(HKEY root, const std::string& subKey, const std::string& valueName) {
    try {
        HKEY hKey;
        char value[1024];
        DWORD value_length = sizeof(value);
        DWORD type = 0;

        if (RegOpenKeyExA(root, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return "N/A";
        }

        if (RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type, reinterpret_cast<LPBYTE>(value), &value_length) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return "N/A";
        }

        RegCloseKey(hKey);
        return std::string(value, value + value_length);
    }
    catch (...) {
        return "N/A";
    }
}

// Show Windows toast using PowerShell
void show_toast_notification(const std::string& title, const std::string& message) {
    std::stringstream psScript;
    psScript << "powershell -ExecutionPolicy Bypass -Command \""
        << "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null;"
        << "$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
        << "$template.SelectSingleNode('//text[@id=1]').InnerText = '" << title << "';"
        << "$template.SelectSingleNode('//text[@id=2]').InnerText = '" << message << "';"
        << "$toast = [Windows.UI.Notifications.ToastNotification]::new($template);"
        << "$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('MonitorApp');"
        << "$notifier.Show($toast)\"";

    system(psScript.str().c_str());
}

void monitor_loop() {
    std::vector<std::string> files = {
        "C:\\Windows\\regedit.exe",
        "C:\\Windows\\System32\\userinit.exe",
        "C:\\Windows\\explorer.exe",
        "C:\\Windows\\system.ini",
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\config\\SYSTEM",
        "C:\\Windows\\System32\\config\\SOFTWARE",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\winlogon.exe",
        "C:\\Windows\\System32\\lsass.exe"
    };

    struct RegistryEntry {
        HKEY root;
        std::string subkey;
        std::vector<std::string> values;
    };

    std::vector<RegistryEntry> registryKeys = {
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", {"loadappinit_dlls", "appinit_dlls", "iconservicelib"} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", {"common startup", "startup"} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", {"common startup", "startup"} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", {} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", {} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", {} },
        { HKEY_LOCAL_MACHINE, "SECURITY\\POLICY\\SECRETS", {} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID", {} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\NT\\CurrentVersion\\Windows", {"appinit_dlls", "loadappinit_dlls"} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", {"common startup", "startup"} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", {"common startup", "startup"} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", {} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", {} }
    };

    std::unordered_map<std::string, std::string> previous_file_timestamps;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> previous_registry_values;

    while (true) {
        try {
            json result;

            // File monitoring
            for (const auto& file : files) {
                std::string current_timestamp = get_file_timestamp(file);
                if (previous_file_timestamps[file] != current_timestamp) {
                    std::cout << "[*] File changed: " << file << " (New timestamp: " << current_timestamp << ")\n";
                    previous_file_timestamps[file] = current_timestamp;
                }
                result["files"][file] = {
                    {"last_modified", current_timestamp}
                };
            }

            // Registry monitoring
            for (const auto& entry : registryKeys) {
                json regData;
                if (!entry.values.empty()) {
                    for (const auto& val : entry.values) {
                        std::string current_value = read_registry_value(entry.root, entry.subkey, val);
                        if (previous_registry_values[entry.subkey][val] != current_value) {
                            std::cout << "[*] Registry changed: " << entry.subkey << "\\" << val << " (New value: " << current_value << ")\n";
                            previous_registry_values[entry.subkey][val] = current_value;
                        }
                        regData[val] = current_value;
                    }
                }
                else {
                    // Empty JSON object to ensure it's not null
                    regData = json::object();
                }
                result["registry"][entry.subkey] = regData;
            }

            // Write to JSON
            std::ofstream outFile("file_registry_monitor.json");
            outFile << result.dump(4);
            outFile.close();

            std::cout << "[✓] Updated JSON at " << get_current_timestamp() << "\n";

            show_toast_notification("File & Registry Monitor", "Snapshot saved successfully.");

            std::this_thread::sleep_for(std::chrono::minutes(1));
        }
        catch (const std::exception& e) {
            std::cerr << "Monitoring error: " << e.what() << "\n";
        }
    }
}

int main() {
    std::cout << "[*] Starting live file & registry monitoring...\n";
    monitor_loop();
    return 0;
}*/
