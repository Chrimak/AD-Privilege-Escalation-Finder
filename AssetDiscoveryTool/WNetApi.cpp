#include "WNetApi.h"
#include <iostream>

// Constructor
WNetApi::WNetApi()
{
}

// Destructor
WNetApi::~WNetApi()
{
}

// Connect to network share using IPC
bool WNetApi::ConnectToShare(LPWSTR remoteName, LPWSTR userName, LPWSTR password)
{
    if (!remoteName || !userName || !password)
    {
        return false;
    }

    NETRESOURCE netResource = {0};
    netResource.dwType = RESOURCETYPE_ANY;
    netResource.lpLocalName = nullptr;      // No local drive mapping
    netResource.lpRemoteName = remoteName;  // UNC path (e.g., \\192.168.1.1\share)
    netResource.lpProvider = nullptr;

    DWORD flags = CONNECT_UPDATE_PROFILE;
    DWORD result = WNetAddConnection2(&netResource, password, userName, flags);

    switch (result)
    {
    case NO_ERROR:
        return true;

    case ERROR_BAD_NET_NAME:  // 67 - Network name not found
        return false;

    case ERROR_LOGON_FAILURE:  // 1326 - Invalid username or password
        return false;

    case ERROR_SESSION_CREDENTIAL_CONFLICT:  // Already connected with different credentials
        DisconnectFromShare(remoteName);
        return ConnectToShare(remoteName, userName, password);

    default:
        return false;
    }
}

// Disconnect from network share
bool WNetApi::DisconnectFromShare(LPWSTR remoteName)
{
    if (!remoteName)
    {
        return false;
    }

    DWORD result = WNetCancelConnection2(remoteName, 0, TRUE);
    return (result == NO_ERROR);
}

// Get list of domain computers from group
std::vector<std::wstring> WNetApi::GetDomainComputerList(LPWSTR serverName, LPWSTR groupName)
{
    std::vector<std::wstring> computerList;

    if (!serverName || !groupName)
    {
        return computerList;
    }

    wprintf(L"[*] Retrieving domain computer list...\n");
    wprintf(L"========================================\n");

    GROUP_USERS_INFO_1* buffer = nullptr;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD level = 1;
    DWORD maxLength = MAX_PREFERRED_LENGTH;

    NET_API_STATUS status = NetGroupGetUsers(
        serverName,
        groupName,
        level,
        reinterpret_cast<LPBYTE*>(&buffer),
        maxLength,
        &entriesRead,
        &totalEntries,
        nullptr
    );

    if (status != NO_ERROR)
    {
        wprintf(L"[Error] NetGroupGetUsers failed with error: %u\n", status);
        wprintf(L"[Info] See: https://docs.microsoft.com/en-us/windows/win32/netmgmt/network-management-error-codes\n");
        return computerList;
    }

    wprintf(L"[Info] Found %d computer(s)\n\n", entriesRead);

    for (DWORD i = 0; i < entriesRead; ++i)
    {
        if (buffer[i].grui1_name)
        {
            std::wstring computerName(buffer[i].grui1_name);
            
            // Remove trailing $ sign from computer names
            if (!computerName.empty() && computerName.back() == L'$')
            {
                computerName.pop_back();
            }

            computerList.push_back(computerName);
            wprintf(L"  [%u] %s\n", i + 1, computerName.c_str());
        }
    }

    if (buffer)
    {
        NetApiBufferFree(buffer);
    }

    wprintf(L"========================================\n\n");
    return computerList;
}

// Get local group members (e.g., Administrators)
std::vector<std::wstring> WNetApi::GetLocalGroupMembers(LPWSTR serverName)
{
    std::vector<std::wstring> members;

    if (!serverName)
    {
        return members;
    }

    LPCWSTR groupName = L"administrators";
    LOCALGROUP_MEMBERS_INFO_2* buffer = nullptr;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD maxLength = MAX_PREFERRED_LENGTH;

    NET_API_STATUS status = NetLocalGroupGetMembers(
        serverName,
        groupName,
        2,  // Level 2 for detailed information
        reinterpret_cast<LPBYTE*>(&buffer),
        maxLength,
        &entriesRead,
        &totalEntries,
        nullptr
    );

    if (status != NO_ERROR)
    {
        return members;
    }

    for (DWORD i = 0; i < entriesRead; ++i)
    {
        if (buffer[i].lgrmi2_domainandname)
        {
            members.push_back(buffer[i].lgrmi2_domainandname);
        }
    }

    if (buffer)
    {
        NetApiBufferFree(buffer);
    }

    return members;
}

// Detect if host is alive using ARP
bool WNetApi::DetectAlive(int threadId, LPCWSTR ipAddress, LPCWSTR computerName)
{
    if (!ipAddress)
    {
        return false;
    }

    auto ipAnsi = m_commonApi.UnicodeToAnsi(ipAddress);
    if (!ipAnsi)
    {
        return false;
    }

    ULONG macAddress[2] = {0};
    ULONG physicalAddressLength = 6;  // MAC address is 6 bytes

    DWORD result = SendARP(
        inet_addr(ipAnsi.get()),
        0,
        macAddress,
        &physicalAddressLength
    );

    if (result == NO_ERROR)
    {
        wprintf(L"[#%d] %s -> %s is alive\n", threadId, computerName, ipAddress);
        return true;
    }

    // Log error details
    wprintf(L"[#%d] %s -> %s is not responding ", threadId, computerName, ipAddress);
    
    switch (result)
    {
    case ERROR_GEN_FAILURE:
        printf("(ERROR_GEN_FAILURE)\n");
        break;
    case ERROR_INVALID_PARAMETER:
        printf("(ERROR_INVALID_PARAMETER)\n");
        break;
    case ERROR_INVALID_USER_BUFFER:
        printf("(ERROR_INVALID_USER_BUFFER)\n");
        break;
    case ERROR_BAD_NET_NAME:
        printf("(ERROR_BAD_NET_NAME)\n");
        break;
    case ERROR_BUFFER_OVERFLOW:
        printf("(ERROR_BUFFER_OVERFLOW)\n");
        break;
    case ERROR_NOT_FOUND:
        printf("(ERROR_NOT_FOUND)\n");
        break;
    default:
        printf("(Error: %u)\n", result);
        break;
    }

    return false;
}

// Enumerate network sessions on a server
std::vector<LPSESSION_INFO_10> WNetApi::EnumerateNetworkSessions(LPWSTR serverName)
{
    std::vector<LPSESSION_INFO_10> sessions;

    if (!serverName)
    {
        return sessions;
    }

    LPSESSION_INFO_10 buffer = nullptr;
    LPSESSION_INFO_10 currentEntry = nullptr;
    DWORD level = 10;
    DWORD maxLength = MAX_PREFERRED_LENGTH;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD resumeHandle = 0;
    NET_API_STATUS status;

    do
    {
        status = NetSessionEnum(
            serverName,      // Target server
            nullptr,         // All clients
            nullptr,         // All users
            level,           // Information level
            reinterpret_cast<LPBYTE*>(&buffer),
            maxLength,
            &entriesRead,
            &totalEntries,
            &resumeHandle
        );

        if (status == NERR_Success || status == ERROR_MORE_DATA)
        {
            currentEntry = buffer;

            for (DWORD i = 0; i < entriesRead; ++i)
            {
                if (currentEntry)
                {
                    // Store session info (caller is responsible for freeing)
                    sessions.push_back(currentEntry);
                    ++currentEntry;
                }
            }
        }
        else
        {
            fprintf(stderr, "[Error] NetSessionEnum failed with error: %d\n", status);
            break;
        }

        // Note: We don't free the buffer here because the caller needs the data
        // The caller must call NetApiBufferFree for each session info pointer
        buffer = nullptr;

    } while (status == ERROR_MORE_DATA);

    return sessions;
}

// Check if host is reachable (ping alternative using connect test)
bool WNetApi::IsHostReachable(LPCWSTR ipAddress)
{
    if (!ipAddress)
    {
        return false;
    }

    auto ipAnsi = m_commonApi.UnicodeToAnsi(ipAddress);
    if (!ipAnsi)
    {
        return false;
    }

    ULONG macAddress[2] = {0};
    ULONG physicalAddressLength = 6;

    DWORD result = SendARP(
        inet_addr(ipAnsi.get()),
        0,
        macAddress,
        &physicalAddressLength
    );

    return (result == NO_ERROR);
}

// Get error message for network API errors
std::wstring WNetApi::GetNetworkErrorMessage(DWORD errorCode)
{
    switch (errorCode)
    {
    case NO_ERROR:
        return L"Success";
    case ERROR_ACCESS_DENIED:
        return L"Access denied";
    case ERROR_BAD_NET_NAME:
        return L"Network name not found";
    case ERROR_LOGON_FAILURE:
        return L"Invalid username or password";
    case ERROR_SESSION_CREDENTIAL_CONFLICT:
        return L"Credential conflict with existing connection";
    case ERROR_GEN_FAILURE:
        return L"General failure";
    case ERROR_INVALID_PARAMETER:
        return L"Invalid parameter";
    case ERROR_NOT_FOUND:
        return L"Not found";
    //case NERR_Success:
    //    return L"Network operation successful";
    default:
        wchar_t buffer[256];
        swprintf_s(buffer, L"Unknown error (Code: %u)", errorCode);
        return buffer;
    }
}

// Validate UNC path format
bool WNetApi::ValidateUncPath(LPCWSTR uncPath)
{
    if (!uncPath)
    {
        return false;
    }

    std::wstring path(uncPath);
    
    // UNC path should start with \\
    if (path.length() < 3 || path.substr(0, 2) != L"\\\\")
    {
        return false;
    }

    // Should have at least server name
    size_t pos = path.find(L'\\', 2);
    if (pos == std::wstring::npos || pos == 2)
    {
        return false;
    }

    return true;
}