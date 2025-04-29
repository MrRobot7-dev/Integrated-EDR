#include "registry_utils.h"
#include <windows.h>
#include <string>

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
