#include "LdapApi.h"
#include "CommonApi.h"
#include <sstream>
#include <iomanip>
#include <winldap.h>
#include <rpc.h>
#include <windows.h>

// Constructor
LdapApi::LdapApi(const std::wstring& host, PWCHAR userName, PWCHAR password, HANDLE delegFile)
    : m_host(host)
    , m_userName(userName)
    , m_password(password)
    , m_delegFile(delegFile)
    , m_ldapConnection(nullptr)
    , m_distinguishedName(L"")
{
}

// Destructor
LdapApi::~LdapApi()
{
    Disconnect();
}

// Convert binary SID from LDAP to string format
std::string LdapApi::ConvertBinarySidToString(const unsigned char* binarySid, int length)
{
    if (!binarySid || length < 8)
    {
        return "";
    }

    std::ostringstream sidStream;
    sidStream << "S";

    // Revision (1 byte)
    int revision = binarySid[0];
    sidStream << "-" << revision;

    // Authority (6 bytes, big-endian)
    unsigned long long authority = 0;
    for (int i = 0; i < 6; ++i)
    {
        authority = (authority << 8) | binarySid[2 + i];
    }
    sidStream << "-" << authority;

    // Sub-authorities (4 bytes each, little-endian)
    int subAuthCount = binarySid[1];
    
    if (subAuthCount * 4 != length - 8)
    {
        return ""; // Invalid format
    }

    for (int i = 0; i < subAuthCount; ++i)
    {
        unsigned int subAuth = 0;
        memcpy(&subAuth, binarySid + 8 + i * 4, 4);
        sidStream << "-" << subAuth;
    }

    return sidStream.str();
}

// Convert SID to user account name
std::wstring LdapApi::ConvertSidToAccountName(PSID sid, LPCWSTR systemName)
{
    if (!sid)
    {
        return L"";
    }

    WCHAR accountName[BUFFSIZE] = {0};
    WCHAR domainName[BUFFSIZE] = {0};
    DWORD accountNameSize = BUFFSIZE;
    DWORD domainNameSize = BUFFSIZE;
    SID_NAME_USE sidType;

    BOOL result = LookupAccountSid(
        systemName,
        sid,
        accountName,
        &accountNameSize,
        domainName,
        &domainNameSize,
        &sidType
    );

    if (result)
    {
        std::wstring fullName = std::wstring(domainName) + L"\\" + std::wstring(accountName);
        return fullName;
    }

    return L"";
}

// Save delegation vulnerability information to file
bool LdapApi::SaveDelegationInfo(HANDLE fileHandle, const std::wstring& delegationInfo)
{
    if (fileHandle == INVALID_HANDLE_VALUE || delegationInfo.empty())
    {
        return false;
    }

    CommonApi commonApi;
    return commonApi.WriteFileApi(fileHandle, delegationInfo);
}

// Build Distinguished Name from host
std::wstring LdapApi::BuildDistinguishedName(const std::wstring& host)
{
    CommonApi commonApi;
    std::vector<std::wstring> domainParts = commonApi.SplitString(host, L".");
    
    if (domainParts.empty())
    {
        return L"";
    }

    std::wstring dn = L"DC=" + domainParts[0];
    for (size_t i = 1; i < domainParts.size(); ++i)
    {
        dn += L",DC=" + domainParts[i];
    }

    return dn;
}

// Connect to LDAP server
bool LdapApi::Connect()
{
    if (m_ldapConnection)
    {
        Disconnect();
    }

    PWSTR host = const_cast<PWSTR>(m_host.c_str());
    ULONG port = LDAP_PORT;
    ULONG version = LDAP_VERSION3;

    // Initialize LDAP connection
    m_ldapConnection = ldap_init(host, port);
    if (!m_ldapConnection)
    {
        fprintf(stderr, "[Error] LDAP initialization failed\n");
        return false;
    }

    // Set protocol version to 3.0
    ULONG result = ldap_set_option(m_ldapConnection, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (result != LDAP_SUCCESS)
    {
        fprintf(stderr, "[Error] Setting LDAP protocol version failed: %d\n", result);
        Disconnect();
        return false;
    }

    // Connect to LDAP server
    result = ldap_connect(m_ldapConnection, nullptr);
    if (result != LDAP_SUCCESS)
    {
        fprintf(stderr, "[Error] LDAP connection failed: %d\n", result);
        Disconnect();
        return false;
    }

    // Prepare authentication credentials
    SEC_WINNT_AUTH_IDENTITY_W authIdentity = {0};
    authIdentity.User = reinterpret_cast<unsigned short*>(m_userName);
    authIdentity.UserLength = lstrlenW(m_userName);
    authIdentity.Password = reinterpret_cast<unsigned short*>(m_password);
    authIdentity.PasswordLength = lstrlenW(m_password);
    authIdentity.Domain = reinterpret_cast<unsigned short*>(host);
    authIdentity.DomainLength = lstrlenW(host);
    authIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    // Build Distinguished Name
    m_distinguishedName = BuildDistinguishedName(m_host);
    PWSTR dn = const_cast<PWSTR>(m_distinguishedName.c_str());

    // Bind to LDAP server
    result = ldap_bind_s(
        m_ldapConnection,
        nullptr,
        nullptr,
        LDAP_AUTH_NEGOTIATE
    );

    if (result != LDAP_SUCCESS)
    {
        fprintf(stderr, "[Error] LDAP bind failed: %d\n", result);
        Disconnect();
        return false;
    }

    printf("[Success] Connected to LDAP server: %ws\n", m_host.c_str());
    return true;
}

// Disconnect from LDAP server
void LdapApi::Disconnect()
{
    if (m_ldapConnection)
    {
        ldap_unbind_s(m_ldapConnection);
        m_ldapConnection = nullptr;
    }
}

// Query Resource-Based Constrained Delegation vulnerabilities
void LdapApi::QueryResourceBasedConstrainedDelegation()
{
    PWSTR filter = const_cast<PWSTR>(L"(&(ObjectClass=computer)(mS-DS-CreatorSID=*))");
    PWCHAR attributes[] = { 
        const_cast<PWCHAR>(L"mS-DS-CreatorSID"),
        const_cast<PWCHAR>(L"cn"),
        nullptr 
    };
    
    QueryDelegationVulnerabilities(filter, attributes);
}

// Query Constrained Delegation vulnerabilities
void LdapApi::QueryConstrainedDelegation()
{
    PWSTR filter = const_cast<PWSTR>(L"(&(samAccountType=805306368)(msds-allowedtodelegateto=*))");
    PWCHAR attributes[] = { 
        const_cast<PWCHAR>(L"msds-allowedtodelegateto"),
        const_cast<PWCHAR>(L"cn"),
        nullptr 
    };
    
    QueryDelegationVulnerabilities(filter, attributes);
}

// Query Unconstrained Delegation vulnerabilities
void LdapApi::QueryUnconstrainedDelegation()
{
    PWSTR filter = const_cast<PWSTR>(L"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))");
    PWCHAR attributes[] = { 
        const_cast<PWCHAR>(L"userAccountControl"),
        const_cast<PWCHAR>(L"cn"),
        nullptr 
    };
    
    QueryDelegationVulnerabilities(filter, attributes);
}

// Process LDAP attribute value
// Process LDAP attribute value
std::wstring LdapApi::ProcessAttributeValue(
    const std::wstring& attributeName,
    LDAPMessage* entry)
{
    std::wstring result;

    // Process Resource-Based Constrained Delegation
    if (_wcsicmp(attributeName.c_str(), L"mS-DS-CreatorSID") == 0)
    {
        result = ProcessCreatorSidAttribute(entry, attributeName.c_str());
    }
    // Process Constrained Delegation
    else if (_wcsicmp(attributeName.c_str(), L"msds-allowedtodelegateto") == 0)
    {
        PWCHAR attr = const_cast<PWCHAR>(attributeName.c_str());
        PWCHAR* values = ldap_get_values(m_ldapConnection, entry, attr);
        if (values && values[0])
        {
            result = std::wstring(values[0]) + L"\tConstrained delegation\n";
            ldap_value_free(values);
        }
    }
    // Process Unconstrained Delegation
    else if (_wcsicmp(attributeName.c_str(), L"userAccountControl") == 0)
    {
        PWCHAR attr = const_cast<PWCHAR>(attributeName.c_str());
        PWCHAR* values = ldap_get_values(m_ldapConnection, entry, attr);
        if (values && values[0])
        {
            result = std::wstring(values[0]) + L"\tUnconstrained delegation\n";
            ldap_value_free(values);
        }
    }
    // Process other attributes (like cn)
    else
    {
        PWCHAR attr = const_cast<PWCHAR>(attributeName.c_str());
        PWCHAR* values = ldap_get_values(m_ldapConnection, entry, attr);
        if (values && values[0])
        {
            result = std::wstring(values[0]) + L" --> ";
            ldap_value_free(values);
        }
    }

    return result;
}


// Process Creator SID attribute (for RBCD)
std::wstring LdapApi::ProcessCreatorSidAttribute(LDAPMessage* entry, LPCWSTR attributeName)
{
    std::wstring result;
    // ldap_get_values_lenW expects PWSTR (wchar_t*)
    PWCHAR attr = const_cast<PWCHAR>(attributeName);
    berval** attrList = ldap_get_values_lenW(m_ldapConnection, entry, attr);

    if (attrList)
    {
        for (int i = 0; attrList[i]; ++i)
        {
            std::string stringSid = ConvertBinarySidToString(
                reinterpret_cast<const unsigned char*>(attrList[i]->bv_val),
                attrList[i]->bv_len
            );

            if (!stringSid.empty())
            {
                std::wstring wideSid(stringSid.begin(), stringSid.end());
                PSID sid = nullptr;

                if (ConvertStringSidToSid(wideSid.c_str(), &sid))
                {
                    std::wstring accountName = ConvertSidToAccountName(sid, m_host.c_str());
                    LocalFree(sid);

                    if (!accountName.empty())
                    {
                        result += accountName + L"\t";
                        result += wideSid + L"\t";
                        result += L"Resource-based constrained delegation\n";
                    }
                }
            }
        }
        ldap_value_free_len(attrList);
    }

    return result;
}


// Query delegation vulnerabilities with custom filter and attributes
bool LdapApi::QueryDelegationVulnerabilities(PWSTR filter, PWCHAR attributes[])
{
    wprintf(L"\n[Query] Filter: %s\n", filter);
    wprintf(L"========================================\n");

    if (!Connect())
    {
        return false;
    }

    LDAPMessage* searchResult = nullptr;
    PWSTR dn = const_cast<PWSTR>(m_distinguishedName.c_str());

    // Execute LDAP search
    ULONG errorCode = ldap_search_s(
        m_ldapConnection,
        dn,
        LDAP_SCOPE_SUBTREE,
        filter,
        attributes,
        0,
        &searchResult
    );

    if (errorCode != LDAP_SUCCESS)
    {
        fprintf(stderr, "[Error] LDAP search failed: 0x%0lx\n", errorCode);
        Disconnect();
        return false;
    }

    // Count entries
    ULONG entryCount = ldap_count_entries(m_ldapConnection, searchResult);
    printf("[Info] Found %d entries\n\n", entryCount);

    if (entryCount == 0)
    {
        ldap_msgfree(searchResult);
        Disconnect();
        return true;
    }

    // Process each entry
    ProcessSearchResults(searchResult, entryCount);

    // Cleanup
    ldap_msgfree(searchResult);
    Disconnect();
    
    wprintf(L"========================================\n");
    return true;
}

// Process LDAP search results
void LdapApi::ProcessSearchResults(LDAPMessage* searchResult, ULONG entryCount)
{
    LDAPMessage* entry = nullptr;
    
    for (ULONG i = 0; i < entryCount; ++i)
    {
        // Get first or next entry
        entry = (i == 0) 
            ? ldap_first_entry(m_ldapConnection, searchResult)
            : ldap_next_entry(m_ldapConnection, entry);

        if (!entry)
        {
            fprintf(stderr, "[Error] Failed to get entry %d: 0x%0lx\n", i, LdapGetLastError());
            continue;
        }

        ProcessSingleEntry(entry);
    }
}

// Process a single LDAP entry
void LdapApi::ProcessSingleEntry(LDAPMessage* entry)
{
    BerElement* ber = nullptr;
    PWCHAR attribute = ldap_first_attributeW(m_ldapConnection, entry, &ber);
    std::wstring delegationInfo;

    while (attribute)
    {
        std::wstring attrValue = ProcessAttributeValue(attribute, entry);
        delegationInfo += attrValue;

        ldap_memfree(attribute);
        attribute = ldap_next_attribute(m_ldapConnection, entry, ber);
    }

    if (ber)
    {
        // ber_free(ber, 0);
    }

    if (!delegationInfo.empty())
    {
        wprintf(L"%s", delegationInfo.c_str());
        SaveDelegationInfo(m_delegFile, delegationInfo);
    }
}