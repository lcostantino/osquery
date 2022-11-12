/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// clang-format off
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
// clang-format on
#include <iomanip>
#include <psapi.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <osquery/utils/system/system.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/system/windows/processes.h>
#include <osquery/logger/logger.h>
#include <map>

namespace osquery {
namespace ProcessHelper {
// Note: This is the same code from
// https://raw.githubusercontent.com/osquery/osquery/d8537abe36e81617ea15cf468192ef1612760d24/osquery/tables/system/windows/processes.cpp
// It requires cleanup to resue this util now.

const unsigned long kMaxPathSize = 0x1000;

// See the Process Hacker implementation for more details on the hard coded 60
// https://github.com/processhacker/processhacker/blob/master/phnt/include/ntpsapi.h#L160
const PROCESSINFOCLASS ProcessCommandLine = static_cast<PROCESSINFOCLASS>(60);
// See the ZwQueryInformatioNprocess docs for more details on the hard coded 61
// https://docs.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess
const PROCESSINFOCLASS ProcessProtectionInformation =
    static_cast<PROCESSINFOCLASS>(61);

typedef struct {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  ULONG MaximumLength;
  ULONG Length;
  ULONG Flags;
  ULONG DebugFlags;
  PVOID ConsoleHandle;
  ULONG ConsoleFlags;
  HANDLE StdInputHandle;
  HANDLE StdOutputHandle;
  HANDLE StdErrorHandle;
  UNICODE_STRING CurrentDirectoryPath;
  HANDLE CurrentDirectoryHandle;
  UNICODE_STRING DllPath;
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
  BYTE Reserved1[2];
  BYTE BeingDebugged;
  BYTE Reserved2[1];
  PVOID Reserved3[2];
  PPEB_LDR_DATA Ldr;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  PVOID Reserved4[3];
  PVOID AtlThunkSListPtr;
  PVOID Reserved5;
  ULONG Reserved6;
  PVOID Reserved7;
  ULONG Reserved8;
  ULONG AtlThunkSListPtr32;
  PVOID Reserved9[45];
  BYTE Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE Reserved11[128];
  PVOID Reserved12[1];
  ULONG SessionId;
} PEB, *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
  PVOID Reserved1;
  PPEB PebBaseAddress;
  PVOID Reserved2[2];
  ULONG_PTR UniqueProcessId;
  PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;


typedef struct _PROCESS_EXTENDED_BASIC_INFORMATION {
  SIZE_T Size; // Ignored as input, written with structure size on output
  PROCESS_BASIC_INFORMATION BasicInfo;
  union {
    ULONG Flags;
    struct {
      ULONG IsProtectedProcess : 1;
      ULONG IsWow64Process : 1;
      ULONG IsProcessDeleting : 1;
      ULONG IsCrossSessionCreate : 1;
      ULONG IsFrozen : 1;
      ULONG IsBackground : 1;
      ULONG IsStronglyNamed : 1;
      ULONG IsSecureProcess : 1;
      ULONG IsSubsystemProcess : 1;
      ULONG SpareBits : 23;
    } s;
  };
} PROCESS_EXTENDED_BASIC_INFORMATION, *PPROCESS_EXTENDED_BASIC_INFORMATION;


const std::map<PS_PROTECTED_TYPE, std::string> kProtectedTypes = {
    {PsProtectedTypeNone, "PsProtectedTypeNone"},
    {PsProtectedTypeProtectedLight, "PsProtectedTypeProtectedLight"},
    {PsProtectedTypeProtected, "PsProtectedTypeProtected"},
    {PsProtectedTypeMax, "PsProtectedTypeMax"},
};

typedef enum _PS_PROTECTED_SIGNER : UCHAR {
  PsProtectedSignerNone,
  PsProtectedSignerAuthenticode,
  PsProtectedSignerCodeGen,
  PsProtectedSignerAntimalware,
  PsProtectedSignerLsa,
  PsProtectedSignerWindows,
  PsProtectedSignerWinTcb,
  PsProtectedSignerWinSystem,
  PsProtectedSignerApp,
  PsProtectedSignerMax
} PS_PROTECTED_SIGNER;

typedef struct _PS_PROTECTION {
  union {
    struct {
      PS_PROTECTED_TYPE Type : 3;
      BOOLEAN Audit : 1;
      PS_PROTECTED_SIGNER Signer : 4;
    } s;
    UCHAR Level;
  };
} PS_PROTECTION, *PPS_PROTECTION;

std::string getProtectedTypeAsString(PS_PROTECTED_TYPE psType) {
  auto it = kProtectedTypes.find(psType);
  if (it != kProtectedTypes.end()) {
    return it->second;
  }
  return "";
}
Status getUserProcessParameters(HANDLE proc,
                                RTL_USER_PROCESS_PARAMETERS& out,
                                const unsigned long pid) {
  PROCESS_BASIC_INFORMATION pbi;
  unsigned long len{0};
  NTSTATUS status = NtQueryInformationProcess(
      proc, ProcessBasicInformation, &pbi, sizeof(pbi), &len);

  SetLastError(RtlNtStatusToDosError(status));
  if (NT_ERROR(status) || !pbi.PebBaseAddress) {
    return Status::failure("NtQueryInformationProcess failed for " +
                           std::to_string(pid) + " with " +
                           std::to_string(status));
  }

  SIZE_T bytes_read = 0;
  PEB peb;
  if (!ReadProcessMemory(
          proc, pbi.PebBaseAddress, &peb, sizeof(peb), &bytes_read)) {
    return Status::failure("Reading PEB failed for " + std::to_string(pid) +
                           " with " + std::to_string(GetLastError()));
  }

  if (!ReadProcessMemory(
          proc, peb.ProcessParameters, &out, sizeof(out), &bytes_read)) {
    return Status::failure("Reading USER_PROCESS_PARAMETERS failed for " +
                           std::to_string(pid) + " with " +
                           std::to_string(GetLastError()));
  }
  return Status::success();
}

Status getProcessCommandLineLegacy(HANDLE proc,
                                   std::string& out,
                                   const unsigned long pid) {
  RTL_USER_PROCESS_PARAMETERS upp;
  auto s = getUserProcessParameters(proc, upp, pid);
  if (!s.ok()) {
    VLOG(1) << "Failed to get PEB UPP for " << pid << " with "
            << GetLastError();
    return s;
  }

  SIZE_T bytes_read = 0;
  std::vector<wchar_t> command_line(kMaxPathSize, 0x0);
  SecureZeroMemory(command_line.data(), kMaxPathSize);
  if (!ReadProcessMemory(proc,
                         upp.CommandLine.Buffer,
                         command_line.data(),
                         upp.CommandLine.Length,
                         &bytes_read)) {
    return Status::failure("Failed to read command line for " +
                           std::to_string(pid));
  }
  out = wstringToString(command_line.data());

  return Status::success();
}

Status getProcessCommandLine(HANDLE proc,
                             std::string& out,
                             const unsigned long pid) {
  unsigned long size_out = 0;
  auto ret =
      NtQueryInformationProcess(proc, ProcessCommandLine, NULL, 0, &size_out);

  if (ret != STATUS_BUFFER_OVERFLOW && ret != STATUS_BUFFER_TOO_SMALL &&
      ret != STATUS_INFO_LENGTH_MISMATCH) {
    return Status::failure("NtQueryInformationProcess failed for " +
                           std::to_string(pid) + " with " +
                           std::to_string(ret));
  }

  std::vector<char> cmdline(size_out, 0x0);
  ret = NtQueryInformationProcess(
      proc, ProcessCommandLine, cmdline.data(), size_out, &size_out);

  if (!NT_SUCCESS(ret)) {
    return Status::failure("NtQueryInformationProcess failed for " +
                           std::to_string(pid) + " with " +
                           std::to_string(ret));
  }
  auto ustr = reinterpret_cast<PUNICODE_STRING>(cmdline.data());
  out = wstringToString(ustr->Buffer);
  return Status::success();
}

Status getProcessCurrentDirectory(HANDLE proc,
                                  std::string& out,
                                  const unsigned long pid) {
  RTL_USER_PROCESS_PARAMETERS upp;
  auto s = getUserProcessParameters(proc, upp, pid);
  if (!s.ok()) {
    VLOG(1) << "Failed to get PEB UPP for " << pid << " with "
            << GetLastError();
    return s;
  }

  SIZE_T bytes_read = 0;
  std::vector<wchar_t> current_directory(kMaxPathSize, 0x0);
  SecureZeroMemory(current_directory.data(), kMaxPathSize);
  if (!ReadProcessMemory(proc,
                         upp.CurrentDirectoryPath.Buffer,
                         current_directory.data(),
                         upp.CurrentDirectoryPath.Length,
                         &bytes_read)) {
    return Status::failure("Failed to read current working directory for " +
                           std::to_string(pid));
  }
  out = wstringToString(current_directory.data());
  return Status::success();
}


Status getProcessUserInfo(HANDLE proc,
                          PSID *sid,
                          int& is_elevated,
                          const unsigned long pid){
  HANDLE tok = nullptr;
  std::vector<char> tok_user(sizeof(TOKEN_USER), 0x0);

  auto ret = OpenProcessToken(proc, TOKEN_READ, &tok);
  if (ret != 0 && tok != nullptr) {
    unsigned long tokOwnerBuffLen;
    ret = GetTokenInformation(tok, TokenUser, nullptr, 0, &tokOwnerBuffLen);
    if (ret == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
      tok_user.resize(tokOwnerBuffLen);
      ret = GetTokenInformation(
          tok, TokenUser, tok_user.data(), tokOwnerBuffLen, &tokOwnerBuffLen);
    }

    /// Check if the process is using an elevated token
    TOKEN_ELEVATION elevation;
    DWORD cb_size = sizeof(TOKEN_ELEVATION);
    if (GetTokenInformation(tok,
                            TokenElevation,
                            &elevation,
                            sizeof(TOKEN_ELEVATION),
                            &cb_size)) {
      is_elevated = elevation.TokenIsElevated;
    }
  }
  if (ret != 0 && !tok_user.empty()) {
    auto dwLength = GetLengthSid(PTOKEN_OWNER(tok_user.data())->Owner);
    *sid = (PSID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
    if (*sid != NULL) {
      if (!CopySid(dwLength, *sid, PTOKEN_OWNER(tok_user.data())->Owner)) {
        HeapFree(GetProcessHeap(), 0, (LPVOID)*sid);
        sid = NULL;
      }
    }
  }
  if (tok == nullptr) {
    return Status::failure("Fail to open token handle for " +
                           std::to_string(pid));
  }
  CloseHandle(tok);
  return Status::success();
}

Status getProcessPathInfo(HANDLE proc,
    std::string& outPath,
    const unsigned long pid) {

  auto out = kMaxPathSize;
  std::vector<WCHAR> path(kMaxPathSize, 0x0);
  SecureZeroMemory(path.data(), kMaxPathSize);
  auto ret = QueryFullProcessImageNameW(proc, 0, path.data(), &out);
  if (ret != TRUE) {
    ret = QueryFullProcessImageNameW(
        proc, PROCESS_NAME_NATIVE, path.data(), &out);
  }
  if (ret != TRUE) {
    return Status::failure("Failed to lookup path information for process "
                           + std::to_string(pid) + " With " + std::to_string(GetLastError()));
  } 
  outPath = wstringToString(path.data());
  return Status::success();
}


Status getProcessProtectedType(HANDLE& proc,
                               PS_PROTECTED_TYPE& psType,
                               const unsigned long pid) {
  PS_PROTECTION psp{0};
  unsigned long len{0};
  PROCESS_EXTENDED_BASIC_INFORMATION pebi{0};
  NTSTATUS status = NtQueryInformationProcess(
      proc, ProcessProtectionInformation, &psp, sizeof(psp), &len);
  if (!NT_SUCCESS(status)) {
    psType = PS_PROTECTED_TYPE::PsProtectedTypeNone; 
    return Status::failure("Failed to get process protection type " +
                           std::to_string(pid) + " with " +
                           std::to_string(status));
  }
  
  psType = psp.s.Type;
  return Status::success();
}


Status getProcessExtendedInfo(HANDLE& proc,
    EXTENDED_INFO& extInfo,
    const unsigned long pid) {

    PROCESS_EXTENDED_BASIC_INFORMATION pebi{0};
    unsigned long len{0};
    NTSTATUS status = NtQueryInformationProcess(
        proc, ProcessBasicInformation, &pebi, sizeof(pebi), &len);
    // Handle return on pre Windows 8.1 and just populate the non extended
    // ProcessBasicInformation variant
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
      status = NtQueryInformationProcess(proc,
                                         ProcessBasicInformation,
                                         &pebi.BasicInfo,
                                         sizeof(pebi.BasicInfo),
                                         &len);
    }
    if (!NT_SUCCESS(status)) {
      return Status::failure("Failed to query ProcessBasicInformation for pid " +
             std::to_string(pid) + " with " + std::to_string(status));
    }
    extInfo.isSecure = pebi.s.IsSecureProcess;
    extInfo.isVirtual = pebi.BasicInfo.PebBaseAddress == NULL;
    return Status::success();
}

HANDLE getProcessHandle(const unsigned long pid) {
  HANDLE proc_handle = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  // If we fail to get all privs, open with less permissions
  if (proc_handle == NULL) {
    proc_handle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  }

  if (proc_handle == NULL) {
    VLOG(1) << "Failed to open handle to process " << pid << " with "
            << GetLastError();
  }
  return proc_handle;
}

void closeProcessHandle(HANDLE proc) {
  CloseHandle(proc);
}

} // namespace ProcessHelper
} // namespace osquery