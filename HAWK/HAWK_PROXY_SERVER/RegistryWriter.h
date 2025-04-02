#pragma once

#include <windows.h>
#include <iostream>


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


class RegistryWriter
{
public:
    static bool setProxy();
    static bool setHTTPSProxy();
    static bool setHTTPProxy();

    static bool revertChanges();

private:
    static bool setRegistryValDWORD(LPCSTR path, LPCSTR valueName, BYTE* newValue);
    static bool setRegistryValSTR(LPCSTR path, LPCSTR valueName, LPCSTR newValue);
    static bool deleteRegistryVal(LPCSTR path, LPCSTR valueName);
};
