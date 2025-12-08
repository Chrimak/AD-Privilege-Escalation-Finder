#include "CommonApi.h"
#include <memory>
#include <stdexcept>

// Convert Unicode to ANSI
std::unique_ptr<char[]> CommonApi::UnicodeToAnsi(const wchar_t* szStr)
{
    if (!szStr)
    {
        return nullptr;
    }

    int nLen = WideCharToMultiByte(CP_ACP, 0, szStr, -1, nullptr, 0, nullptr, nullptr);
    if (nLen == 0)
    {
        return nullptr;
    }

    auto pResult = std::make_unique<char[]>(nLen);
    WideCharToMultiByte(CP_ACP, 0, szStr, -1, pResult.get(), nLen, nullptr, nullptr);
    
    return pResult;
}

// Convert ANSI to Unicode
std::unique_ptr<wchar_t[]> CommonApi::AnsiToUnicode(const char* str)
{
    if (!str)
    {
        return nullptr;
    }

    int textlen = MultiByteToWideChar(CP_ACP, 0, str, -1, nullptr, 0);
    if (textlen == 0)
    {
        return nullptr;
    }

    auto result = std::make_unique<wchar_t[]>(textlen + 1);
    MultiByteToWideChar(CP_ACP, 0, str, -1, result.get(), textlen);
    
    return result;
}

// Split string by the specified pattern
std::vector<std::wstring> CommonApi::SplitString(const std::wstring& strSrc, const std::wstring& pattern)
{
    std::vector<std::wstring> result;
    
    if (pattern.empty())
    {
        result.push_back(strSrc);
        return result;
    }

    std::wstring temp = strSrc;
    size_t pos = 0;

    while ((pos = temp.find(pattern)) != std::wstring::npos)
    {
        std::wstring token = temp.substr(0, pos);
        if (!token.empty())
        {
            result.push_back(token);
        }
        temp.erase(0, pos + pattern.length());
    }

    // Add the remaining part
    if (!temp.empty())
    {
        result.push_back(temp);
    }

    return result;
}

// Create file
HANDLE CommonApi::CreateFileApi(LPCWSTR fileName)
{
    if (!fileName)
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFile = CreateFile(
        fileName,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    return hFile;
}

// Write to file
bool CommonApi::WriteFileApi(HANDLE hFile, const std::wstring& content)
{
    if (hFile == INVALID_HANDLE_VALUE || content.empty())
    {
        return false;
    }

    auto lpContent = UnicodeToAnsi(content.c_str());
    if (!lpContent)
    {
        return false;
    }

    DWORD dwBytesToWrite = static_cast<DWORD>(strlen(lpContent.get()));
    DWORD dwBytesWritten = 0;

    BOOL bResult = WriteFile(
        hFile,
        lpContent.get(),
        dwBytesToWrite,
        &dwBytesWritten,
        nullptr
    );

    if (!bResult)
    {
        printf("Error: Failed to write to file.\n");
        return false;
    }

    if (dwBytesWritten != dwBytesToWrite)
    {
        printf("Warning: Incomplete write (%d/%d bytes)\n", 
               dwBytesWritten, dwBytesToWrite);
        return false;
    }

    return true;
}

// Save successful IPC connection
bool CommonApi::SaveIPCSuccess(
    HANDLE successFile,
    const std::wstring& uncComputerName,
    const std::wstring& administratorName,
    const std::wstring& password)
{
    if (successFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    wchar_t buffer[MAX_PATH];
    HRESULT hr = StringCchPrintfW(
        buffer,
        MAX_PATH,
        L"net use %s /u:%s %s\n",
        uncComputerName.c_str(),
        administratorName.c_str(),
        password.c_str()
    );

    if (FAILED(hr))
    {
        printf("Error: Failed to format string.\n");
        return false;
    }

    wprintf(L"[OK] %s", buffer);
    
    return WriteFileApi(successFile, buffer);
}