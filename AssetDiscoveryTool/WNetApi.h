#pragma once
#include "tou.h"
#include "CommonApi.h"
#include <vector>
#include <string>

/**
 * @class WNetApi
 * @brief Windows Network API wrapper for network operations
 * 
 * This class provides a simplified interface for:
 * - Network share connections (IPC)
 * - Domain computer enumeration
 * - Local group member enumeration
 * - Network session enumeration
 * - Host availability detection (ARP)
 */
class WNetApi
{
public:
    /**
     * @brief Constructor
     */
    WNetApi();

    /**
     * @brief Destructor
     */
    ~WNetApi();

    /**
     * @brief Connect to a network share using credentials
     * @param remoteName UNC path to the remote share (e.g., \\server\share)
     * @param userName Username for authentication
     * @param password Password for authentication
     * @return true if connection successful, false otherwise
     * 
     * @note Common error codes:
     *       - ERROR_BAD_NET_NAME (67): Network name not found
     *       - ERROR_LOGON_FAILURE (1326): Invalid credentials
     *       - ERROR_SESSION_CREDENTIAL_CONFLICT: Already connected with different credentials
     */
    bool ConnectToShare(LPWSTR remoteName, LPWSTR userName, LPWSTR password);

    /**
     * @brief Disconnect from a network share
     * @param remoteName UNC path to disconnect from
     * @return true if disconnection successful, false otherwise
     */
    bool DisconnectFromShare(LPWSTR remoteName);

    /**
     * @brief Get list of computers from a domain group
     * @param serverName Domain controller name
     * @param groupName Group name (e.g., "Domain Computers")
     * @return Vector of computer names (without trailing $)
     * 
     * @note Computer accounts in AD typically end with $, which is removed
     */
    std::vector<std::wstring> GetDomainComputerList(LPWSTR serverName, LPWSTR groupName);

    /**
     * @brief Get members of a local group
     * @param serverName Server name or IP address
     * @return Vector of member names in domain\username format
     * 
     * @note Default target group is "administrators"
     */
    std::vector<std::wstring> GetLocalGroupMembers(LPWSTR serverName);

    /**
     * @brief Enumerate active network sessions on a server
     * @param serverName Server name or IP address
     * @return Vector of SESSION_INFO_10 structures
     * 
     * @warning Caller is responsible for freeing each SESSION_INFO_10 pointer
     *          using NetApiBufferFree()
     */
    std::vector<LPSESSION_INFO_10> EnumerateNetworkSessions(LPWSTR serverName);

    /**
     * @brief Detect if a host is alive using ARP
     * @param threadId Thread identifier for logging
     * @param ipAddress IP address to check
     * @param computerName Computer name for logging
     * @return true if host responds to ARP, false otherwise
     * 
     * @note Uses SendARP to check if host is reachable at layer 2
     */
    bool DetectAlive(int threadId, LPCWSTR ipAddress, LPCWSTR computerName);

    /**
     * @brief Check if a host is reachable (simplified version)
     * @param ipAddress IP address to check
     * @return true if host is reachable, false otherwise
     */
    bool IsHostReachable(LPCWSTR ipAddress);

    /**
     * @brief Get human-readable error message for network error codes
     * @param errorCode Windows error code
     * @return Error message string
     */
    std::wstring GetNetworkErrorMessage(DWORD errorCode);

    /**
     * @brief Validate UNC path format
     * @param uncPath UNC path to validate
     * @return true if valid UNC path format, false otherwise
     * 
     * @note Valid format: \\server or \\server\share
     */
    bool ValidateUncPath(LPCWSTR uncPath);

private:
    CommonApi m_commonApi;  ///< Common API utilities instance
};