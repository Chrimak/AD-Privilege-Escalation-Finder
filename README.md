# AssetDiscoveryTool

## Overview
AssetDiscoveryTool is a Windows-native, domain-aware network assessment utility written in modern C++ (Unicode build). It automates the noisy, repetitive parts of internal penetration tests by harvesting Active Directory computer objects, validating host reachability, inspecting remote administrator groups, enumerating network sessions, and attempting lightweight weak-password checks (e.g., `username == password`, administrator defaults). The tool also inspects LDAP delegation configurations (RBCD, constrained, unconstrained) to surface privilege-escalation paths early in an engagement.

## Features
- **Domain Computer Harvesting:** Collects members of `Domain Computers` via `NetGroupGetUsers`, normalizes hostnames, and prepares a consolidated target list.
- **ARP-Based Liveness Detection:** Uses `SendARP` to quickly skip offline or filtered hosts before attempting expensive network actions.
- **Credentialed Share Probing:** Establishes IPC$ sessions with supplied domain or machine credentials, handling credential conflicts automatically.
- **Local Administrator Enumeration:** Dumps each host’s local `Administrators` group and persists the findings to `local.txt`.
- **Weak Password Discovery:** Multi-threaded worker pool attempts operator-supplied weak passwords, username-as-password, and `123456` against discovered local accounts.
- **Network Session Logging:** Captures `NetSessionEnum` results (client, user, active time) for situational awareness.
- **Delegation Assessment:** LDAP module inspects RBCD (`mS-DS-CreatorSID`), constrained (`msds-AllowedToDelegateTo`), and unconstrained (`userAccountControl`) exposures, saving artifacts to `Deleg.txt`.
- **Result Artifacting:** Stores alive hosts, local admins, successful authentications, network sessions, and delegation issues in discrete text files ready for reporting.
- **Thread-Safe Worker Queue:** Configurable (1–50) worker threads with mutex-protected host scheduling for stable long-running scans.

## Architecture & Key Components
| Module | Responsibility |
| ------ | -------------- |
| `Main.cpp` | Argument parsing, orchestration, execution timeline, and summary logging. |
| `CommonApi` | Unicode/ANSI helpers, file IO abstraction, IPC success logging helpers. |
| `WNetApi` | Wrapper for Win32 networking APIs (`WNetAddConnection2`, `NetGroupGetUsers`, `NetLocalGroupGetMembers`, `SendARP`). |
| `MultiThread` | Thread pool controller that resolves hosts, tracks liveness, enumerates sessions/admins, and runs weak-password attempts. |
| `LdapApi` | LDAP queries for RBCD/CD/UD along with SID parsing and output serialization. |

All modules rely on Windows SDK headers (`<winnetwk.h>`, `<lmaccess.h>`, `<winldap.h>`, etc.) and link against `mpr`, `netapi32`, `iphlpapi`, and `ws2_32`.

## Installation
### Prerequisites
- Windows 10 or later with administrative privileges.
- Visual Studio 2022 with Desktop development with C++ workload.
- Windows SDK 10.0 (ships with Visual Studio workloads).

### Build Steps
1. Clone or download this repository on a Windows system.
2. Open `AssetDiscoveryTool.sln` in Visual Studio.
3. Select the configuration (e.g., `Release | x64`).
4. Build the solution (`Ctrl+Shift+B`). The binary will be emitted under `AssetDiscoveryTool/x64/Release/`.
5. Copy the executable and required runtime dependencies (if any) to your operator workstation.

## Configuration
| Parameter | Description |
| --------- | ----------- |
| `DC-IP` | UNC-style path to the Domain Controller (e.g., `\\192.168.1.10`). |
| `DC-Name` | FQDN of the Domain Controller (e.g., `corp.local`). |
| `Domain\Username` | Credential in `DOMAIN\user` (or `DOMAIN\HOST$`) form. |
| `Password` | Password for the supplied account. Use literal `NULL` for machine accounts. |
| `WeakPassword` | Candidate weak password to seed the password list (defaults to `123456` if unspecified). |
| `ThreadCount` | Number of concurrent worker threads (1–50). |

Additional runtime configuration is controlled by editing constants in `Main.cpp` (output filenames) or `MultiThread.cpp` (sleep timing, password list logic).

## Usage
Display help by running the binary with insufficient parameters; the tool will print usage instructions similar to:

```powershell
AssetDiscoveryTool.exe \\192.168.159.149 Motoo.nc Motoo\liwei lw123!@# 123456 10
```

### Example Workflow
```powershell
# 1. Run tool with domain credentials
AssetDiscoveryTool.exe \\192.168.1.15 corp.local CORP\auditor SuperSecret! 123456 8

# 2. Monitor console progress for liveness, admin names, and failures

# 3. Review output artifacts
Get-Content .\alive.txt
Get-Content .\local.txt
Get-Content .\success.txt

# 4. Correlate LDAP delegation issues from Deleg.txt with BloodHound or manual analysis
```

### Output Files
- `alive.txt` – Hosts responding to ARP.
- `local.txt` – Enumerated `Administrators` group members per host.
- `success.txt` – Successful `net use` command lines for later replay.
- `NetSessions.txt` – Active network sessions (client, user, duration).
- `Deleg.txt` – LDAP delegation findings (RBCD/CD/UD).

## Code Sample
```cpp
MultiThread multiThread(
    domainUserName,
    domainPassword,
    passwordList,
    aliveFile,
    localFile,
    successFile,
    sessionsFile);

// Spawn worker pool
std::vector<std::thread> threads(threadCount);
for (int i = 0; i < threadCount; ++i)
{
    threads[i] = std::thread(&MultiThread::AttackWorker, &multiThread, i, &hostList);
}
```

## License
This project is distributed under the MIT License. Refer to `LICENSE`
