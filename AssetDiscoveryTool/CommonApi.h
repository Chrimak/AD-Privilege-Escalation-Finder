#pragma once
#include "tou.h"
#include <string>
#include <vector>
#include <memory>

class CommonApi
{
public:
    // Convert Unicode to ANSI
    // Return: A char array managed by unique_ptr
    std::unique_ptr<char[]> UnicodeToAnsi(const wchar_t* szStr);

    // Convert ANSI to Unicode
    // Return: A wchar_t array managed by unique_ptr
    std::unique_ptr<wchar_t[]> AnsiToUnicode(const char* str);

    // Split a string using the specified pattern
    // Param: strSrc - Source string
    // Param: pattern - Delimiter string
    // Return: Vector of split substrings
    std::vector<std::wstring> SplitString(
        const std::wstring& strSrc, 
        const std::wstring& pattern
    );

    // Create a file
    // Param: fileName - Path of the file to create
    // Return: File handle (INVALID_HANDLE_VALUE on failure)
    HANDLE CreateFileApi(LPCWSTR fileName);

    // Write content to a file
    // Param: hFile - File handle
    // Param: content - Content to write
    // Return: true on success, false on failure
    bool WriteFileApi(HANDLE hFile, const std::wstring& content);

    // Save a successful IPC connection
    // Param: successFile - Handle to the log file
    // Param: uncComputerName - UNC computer name
    // Param: administratorName - Administrator username
    // Param: password - Password
    // Return: true on success, false on failure
    bool SaveIPCSuccess(
        HANDLE successFile,
        const std::wstring& uncComputerName,
        const std::wstring& administratorName,
        const std::wstring& password
    );
};