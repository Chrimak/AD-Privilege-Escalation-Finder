#pragma once
#include "tou.h"
#include <string>
#include <vector>

#define BUFFSIZE 1024

/**
 * @class LdapApi
 * @brief LDAP API wrapper for querying Active Directory delegation vulnerabilities
 * 
 * This class provides methods to connect to LDAP servers and query for various
 * types of delegation vulnerabilities including:
 * - Resource-Based Constrained Delegation (RBCD)
 * - Constrained Delegation (CD)
 * - Unconstrained Delegation (UD)
 */
class LdapApi
{
public:
    /**
     * @brief Constructor
     * @param host LDAP server hostname or IP address
     * @param userName Username for authentication
     * @param password Password for authentication
     * @param delegFile File handle for saving results
     */
    LdapApi(const std::wstring& host, PWCHAR userName, PWCHAR password, HANDLE delegFile);

    /**
     * @brief Destructor - ensures proper cleanup
     */
    ~LdapApi();

    /**
     * @brief Connect to LDAP server
     * @return true if connection successful, false otherwise
     */
    bool Connect();

    /**
     * @brief Disconnect from LDAP server
     */
    void Disconnect();

    /**
     * @brief Query Resource-Based Constrained Delegation vulnerabilities
     * 
     * Searches for computers with mS-DS-CreatorSID attribute set
     */
    void QueryResourceBasedConstrainedDelegation();

    /**
     * @brief Query Constrained Delegation vulnerabilities
     * 
     * Searches for accounts with msds-allowedtodelegateto attribute set
     */
    void QueryConstrainedDelegation();

    /**
     * @brief Query Unconstrained Delegation vulnerabilities
     * 
     * Searches for computers with TRUSTED_FOR_DELEGATION flag set
     */
    void QueryUnconstrainedDelegation();

    /**
     * @brief Query delegation vulnerabilities with custom filter
     * @param filter LDAP search filter
     * @param attributes Array of attribute names to retrieve
     * @return true if query successful, false otherwise
     */
    bool QueryDelegationVulnerabilities(PWSTR filter, PWCHAR attributes[]);

private:
    /**
     * @brief Convert binary SID to string format
     * @param binarySid Binary SID data
     * @param length Length of binary data
     * @return String representation of SID (e.g., "S-1-5-21-...")
     */
    static std::string ConvertBinarySidToString(const unsigned char* binarySid, int length);

    /**
     * @brief Convert SID to account name
     * @param sid Security Identifier
     * @param systemName System name for lookup
     * @return Domain\Username format string
     */
    static std::wstring ConvertSidToAccountName(PSID sid, LPCWSTR systemName);

    /**
     * @brief Save delegation information to file
     * @param fileHandle Handle to output file
     * @param delegationInfo Information to save
     * @return true if save successful, false otherwise
     */
    static bool SaveDelegationInfo(HANDLE fileHandle, const std::wstring& delegationInfo);

    /**
     * @brief Build Distinguished Name from hostname
     * @param host Hostname (e.g., "domain.local")
     * @return Distinguished Name (e.g., "DC=domain,DC=local")
     */
    static std::wstring BuildDistinguishedName(const std::wstring& host);

    /**
     * @brief Process LDAP search results
     * @param searchResult Search result message
     * @param entryCount Number of entries to process
     */
    void ProcessSearchResults(LDAPMessage* searchResult, ULONG entryCount);

    /**
     * @brief Process a single LDAP entry
     * @param entry LDAP entry to process
     */
    void ProcessSingleEntry(LDAPMessage* entry);

    /**
     * @brief Process attribute value based on attribute name
     * @param attributeName Name of the attribute
     * @param entry LDAP entry containing the attribute
     * @return Formatted string with attribute value
     */
    std::wstring ProcessAttributeValue(const std::wstring& attributeName, LDAPMessage* entry);

    /**
     * @brief Process Creator SID attribute for RBCD
     * @param entry LDAP entry
     * @param attributeName Attribute name
     * @return Formatted string with SID and account information
     */
    std::wstring ProcessCreatorSidAttribute(LDAPMessage* entry, LPCWSTR attributeName);

private:
    std::wstring m_host;                    ///< LDAP server hostname
    PWCHAR m_userName;                      ///< Username for authentication
    PWCHAR m_password;                      ///< Password for authentication
    HANDLE m_delegFile;                     ///< File handle for saving results
    std::wstring m_distinguishedName;       ///< Distinguished Name for searches
    LDAP* m_ldapConnection;                 ///< LDAP connection handle
};