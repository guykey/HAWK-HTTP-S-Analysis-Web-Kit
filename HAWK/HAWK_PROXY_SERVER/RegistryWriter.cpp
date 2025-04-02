#include "RegistryWriter.h"

/*
*********************************************************************************************************
  _____  ______ _____  _____  ______ _____       _______ ______ _____
 |  __ \|  ____|  __ \|  __ \|  ____/ ____|   /\|__   __|  ____|  __ \
 | |  | | |__  | |__) | |__) | |__ | |       /  \  | |  | |__  | |  | |
 | |  | |  __| |  ___/|  _  /|  __|| |      / /\ \ | |  |  __| | |  | |
 | |__| | |____| |    | | \ \| |___| |____ / ____ \| |  | |____| |__| |
 |_____/|______|_|    |_|  \_\______\_____/_/    \_\_|  |______|_____/

*********************************************************************************************************
*/


bool RegistryWriter::setProxy()
{
    LPCSTR path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    LPCSTR proxyEnable = "ProxyEnable";
    DWORD proxyEnableVal = 0x1;

    LPCSTR proxyOverride = "ProxyOverride";
    LPCSTR proxyOverrideVal = "<-loopback>";

    LPCSTR proxyServer = "ProxyServer";
    LPCSTR proxyServerVal = "http=127.0.0.1:8582;https=127.0.0.1:8582";

    
    if (setRegistryValDWORD(path, proxyEnable, (BYTE*)&proxyEnableVal) &&
        setRegistryValSTR(path, proxyOverride, proxyOverrideVal) &&
        setRegistryValSTR(path, proxyServer, proxyServerVal))
    {
        std::cout << "Proxy set successfully\n";
        return true;
    }
    else
    {
        std::cout << "Error occurred\n";
        return false;
    }
}
bool RegistryWriter::setHTTPSProxy()
{
    LPCSTR path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    LPCSTR proxyEnable = "ProxyEnable";
    DWORD proxyEnableVal = 0x1;

    LPCSTR proxyOverride = "ProxyOverride";
    LPCSTR proxyOverrideVal = "<-loopback>";

    LPCSTR proxyServer = "ProxyServer";
    LPCSTR proxyServerVal = "https=127.0.0.1:8582";


    if (setRegistryValDWORD(path, proxyEnable, (BYTE*)&proxyEnableVal) &&
        setRegistryValSTR(path, proxyOverride, proxyOverrideVal) &&
        setRegistryValSTR(path, proxyServer, proxyServerVal))
    {
        std::cout << "Proxy set successfully\n";
        return true;
    }
    else
    {
        std::cout << "Error occurred\n";
        return false;
    }
}
bool RegistryWriter::setHTTPProxy()
{
    LPCSTR path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    LPCSTR proxyEnable = "ProxyEnable";
    DWORD proxyEnableVal = 0x1;

    LPCSTR proxyOverride = "ProxyOverride";
    LPCSTR proxyOverrideVal = "<-loopback>";

    LPCSTR proxyServer = "ProxyServer";
    LPCSTR proxyServerVal = "http=127.0.0.1:8582";


    if (setRegistryValDWORD(path, proxyEnable, (BYTE*)&proxyEnableVal) &&
        setRegistryValSTR(path, proxyOverride, proxyOverrideVal) &&
        setRegistryValSTR(path, proxyServer, proxyServerVal))
    {
        std::cout << "Proxy set successfully\n";
        return true;
    }
    else
    {
        std::cout << "Error occurred\n";
        return false;
    }
}
//very nice
bool RegistryWriter::revertChanges()
{
    LPCSTR path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    LPCSTR proxyEnable = "ProxyEnable";
    DWORD proxyEnableVal = 0x0;

    LPCSTR proxyOverride = "ProxyOverride";

    LPCSTR proxyServer = "ProxyServer";

    if (setRegistryValDWORD(path, proxyEnable, (BYTE*)&proxyEnableVal) &&
        deleteRegistryVal(path, proxyOverride) &&
        deleteRegistryVal(path, proxyServer))
    {
        std::cout << "Reverted proxy successfully\n";
        return true;
    }
    else
    {
        std::cout << "Error occurred\n";
        return false;
    }
}

bool RegistryWriter::setRegistryValDWORD(LPCSTR path, LPCSTR valueName, BYTE* newValue)
{
    HKEY key;

    // Open the registry key
    if (RegOpenKeyExA(HKEY_CURRENT_USER, path, 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS)
    {
        // Set the new value
        if (RegSetValueExA(key, valueName, 0, REG_DWORD, newValue, sizeof(DWORD)) == ERROR_SUCCESS)
        {
            RegCloseKey(key);
            return true;
        }
    }

    return false;
}

bool RegistryWriter::setRegistryValSTR(LPCSTR path, LPCSTR valueName, LPCSTR newValue)
{
    HKEY key;

    // Open the registry key
    if (RegOpenKeyExA(HKEY_CURRENT_USER, path, 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS) {
        // Set the new value
        if (RegSetValueExA(key, valueName, 0, REG_SZ, (const BYTE*)newValue, (DWORD)(strlen(newValue) + 1)) == ERROR_SUCCESS)
        {
            RegCloseKey(key);
            return true;
        }
    }
    
    return false;
}

bool RegistryWriter::deleteRegistryVal(LPCSTR path, LPCSTR valueName)
{
    HKEY hKey;

    // Open the registry key
    if (RegOpenKeyExA(HKEY_CURRENT_USER, path, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        // Attempt to delete the specified value
        if (RegDeleteValueA(hKey, valueName) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }

    return false;
}
