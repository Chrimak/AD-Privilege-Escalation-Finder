#ifndef UNICODE
#define UNICODE
#endif

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <Winnetwk.h>					// WNetAddConnection2
#include <lmaccess.h>
#include <iostream>						// std::wstring
#include <vector>
#include<errno.h>
#include <iphlpapi.h>
#include <strsafe.h>
#include <tchar.h>
#include <locale.h>
#include <thread>
#include <mutex>
#include <time.h>
#include <string>			// std::
#include <lm.h>				// LPSESSION_INFO_10   NetSessionEnum
#include "winldap.h"		// ldap
#include <sddl.h>			// ldap
#include <Dsgetdc.h>		// ldap
#include <algorithm>		// ldap
#include <tuple>

#pragma comment(lib,"iphlpapi.lib")		// sendarp
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mpr.lib")			// Winnet
#pragma comment(lib, "Netapi32.lib")			// Winnet
#pragma comment(lib, "Kernel32.lib")