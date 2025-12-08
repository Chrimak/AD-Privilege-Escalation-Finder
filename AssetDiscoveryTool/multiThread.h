#pragma once
#include "tou.h"
#include "CommonApi.h"
#include "WNetApi.h"
#include <vector>
#include <string>
#include <mutex>

/**
 * @class MultiThread
 * @brief Multi-threaded network scanning and weak password attack framework
 * 
 * This class implements a multi-threaded approach to:
 * - Scan network hosts for availability
 * - Enumerate local administrators
 * - Attempt weak password attacks
 * - Log network sessions and successful authentications
 */
class MultiThread
{
public:
    /**
     * @brief Constructor
     * @param domainUserName Domain username in format "domain\username"
     * @param domainPassword Password for the domain user
     * @param passwordList List of passwords to try for local accounts
     * @param aliveFile File handle for logging alive hosts
     * @param localFile File handle for logging local administrators
     * @param successFile File handle for logging successful authentications
     * @param netSessionsFile File handle for logging network sessions
     */
    MultiThread(
        LPWSTR domainUserName,
        LPWSTR domainPassword,
        const std::vector<std::wstring>& passwordList,
        HANDLE aliveFile,
        HANDLE localFile,
        HANDLE successFile,
        HANDLE netSessionsFile);

    /**
     * @brief Destructor - cleanup resources
     */
    ~MultiThread();

    /**
     * @brief Worker thread function - processes hosts from the list
     * @param threadId Thread identifier for logging
     * @param hostList Pointer to shared list of hostnames to process
     */
    void AttackWorker(int threadId, std::vector<std::wstring>* hostList);

    /**
     * @brief Process a single host
     * @param threadId Thread identifier for logging
     * @param computerName Computer name or hostname to process
     */
    void ProcessHost(int threadId, LPCWSTR computerName);

    /**
     * @brief Get network sessions for a host
     * @param threadId Thread identifier for logging
     * @param computerName Computer name
     * @param uncPath UNC path to the host
     */
    void GetNetworkSessions(int threadId, LPCWSTR computerName, LPWSTR uncPath);

    /**
     * @brief Attempt weak password attack
     * @param threadId Thread identifier for logging
     * @param computerName Computer name
     * @param administrators List of administrator accounts
     * @return true if attack successful, false otherwise
     */
    bool AttemptWeakPasswordAttack(
        int threadId,
        LPCWSTR computerName,
        const std::vector<std::wstring>& administrators);

private:
    /**
     * @brief Parse domain and username from "domain\username" format
     */
    void ParseDomainAndUsername();

    /**
     * @brief Save alive host information to file
     * @param computerName Computer name
     * @param ipAddress IP address
     * @return true if save successful, false otherwise
     */
    bool SaveAliveHost(LPCWSTR computerName, LPCWSTR ipAddress);

    /**
     * @brief Save local administrator information to file
     * @param computerName Computer name
     * @param administratorName Administrator account name
     * @return true if save successful, false otherwise
     */
    bool SaveLocalAdministrator(LPCWSTR computerName, const std::wstring& administratorName);

    /**
     * @brief Save network session information to file
     * @param computerName Computer name
     * @param sessionInfo Session information structure
     * @return true if save successful, false otherwise
     */
    bool SaveNetworkSession(LPCWSTR computerName, LPSESSION_INFO_10 sessionInfo);

    /**
     * @brief Process all IP addresses for a host
     * @param threadId Thread identifier
     * @param computerName Computer name
     * @param remoteHost Host entry structure
     */
    void ProcessHostIpAddresses(int threadId, LPCWSTR computerName, struct hostent* remoteHost);

    /**
     * @brief Process a single IP address
     * @param threadId Thread identifier
     * @param computerName Computer name
     * @param ipAddress IP address
     * @return true if host compromised, false otherwise
     */
    bool ProcessSingleIpAddress(int threadId, LPCWSTR computerName, LPCWSTR ipAddress);

    /**
     * @brief Process individual administrator account
     * @param threadId Thread identifier
     * @param computerName Computer name
     * @param uncPath UNC path
     * @param hostName Host portion of domain\username
     * @param adminUserName Username portion
     * @param fullAdminName Full administrator name (domain\username)
     * @return true if authentication successful, false otherwise
     */
    bool ProcessAdministratorAccount(
        int threadId,
        LPCWSTR computerName,
        LPWSTR uncPath,
        const std::wstring& hostName,
        const std::wstring& adminUserName,
        const std::wstring& fullAdminName);

    /**
     * @brief Process domain administrator account
     * @param threadId Thread identifier
     * @param uncPath UNC path
     * @param fullAdminName Full administrator name
     * @param adminUserName Username portion
     * @return true if authentication successful, false otherwise
     */
    bool ProcessDomainAccount(
        int threadId,
        LPWSTR uncPath,
        LPWSTR fullAdminName,
        const std::wstring& adminUserName);

    /**
     * @brief Process local administrator account
     * @param threadId Thread identifier
     * @param uncPath UNC path
     * @param fullAdminName Full administrator name
     * @param adminUserName Username portion
     * @return true if authentication successful, false otherwise
     */
    bool ProcessLocalAccount(
        int threadId,
        LPWSTR uncPath,
        LPWSTR fullAdminName,
        const std::wstring& adminUserName);

    /**
     * @brief Try passwords from the password list
     * @param threadId Thread identifier
     * @param uncPath UNC path
     * @param fullAdminName Full administrator name
     * @return true if authentication successful, false otherwise
     */
    bool TryPasswordList(int threadId, LPWSTR uncPath, LPWSTR fullAdminName);

private:
    CommonApi m_commonApi;                      ///< Common API utilities
    WNetApi m_wnetApi;                          ///< Windows Network API wrapper
    
    LPWSTR m_domainUserName;                    ///< Full domain username (domain\user)
    LPWSTR m_domainPassword;                    ///< Domain user password
    std::wstring m_domainName;                  ///< Domain name portion
    std::wstring m_userName;                    ///< Username portion
    
    std::vector<std::wstring> m_passwordList;   ///< List of passwords to try
    
    HANDLE m_aliveFile;                         ///< File handle for alive hosts
    HANDLE m_localFile;                         ///< File handle for local admins
    HANDLE m_successFile;                       ///< File handle for successful attacks
    HANDLE m_netSessionsFile;                   ///< File handle for network sessions
};