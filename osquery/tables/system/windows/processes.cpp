/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <map>
#include <string>

#define _WIN32_DCOM

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

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

#include <osquery/core/windows/wmi.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/scope_guard.h>
#include <osquery/utils/system/windows/processes.h>
#include <osquery/utils/system/windows/users_groups_helpers.h>

namespace osquery {
namespace tables {

const std::map<unsigned long, std::string> kMemoryConstants = {
    {PAGE_EXECUTE, "PAGE_EXECUTE"},
    {PAGE_EXECUTE_READ, "PAGE_EXECUTE_READ"},
    {PAGE_EXECUTE_READWRITE, "PAGE_EXECUTE_READWRITE"},
    {PAGE_EXECUTE_WRITECOPY, "PAGE_EXECUTE_WRITECOPY"},
    {PAGE_NOACCESS, "PAGE_NOACCESS"},
    {PAGE_READONLY, "PAGE_READONLY"},
    {PAGE_READWRITE, "PAGE_READWRITE"},
    {PAGE_WRITECOPY, "PAGE_WRITECOPY"},
    {PAGE_GUARD, "PAGE_GUARD"},
    {PAGE_NOCACHE, "PAGE_NOCACHE"},
    {PAGE_WRITECOMBINE, "PAGE_WRITECOMBINE"},
};


/// Given a pid, enumerates all loaded modules and memory pages for that process
Status genMemoryMap(unsigned long pid, QueryData& results) {
  auto proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (proc == nullptr) {
    Row r;
    r["pid"] = INTEGER(pid);
    r["start"] = INTEGER(-1);
    r["end"] = INTEGER(-1);
    r["permissions"] = "";
    r["offset"] = INTEGER(-1);
    r["device"] = INTEGER(-1);
    r["inode"] = INTEGER(-1);
    r["path"] = "";
    r["pseudo"] = INTEGER(-1);
    results.push_back(r);
    return Status::failure("Failed to open handle to process " +
                           std::to_string(pid));
  }
  auto modSnap =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (modSnap == INVALID_HANDLE_VALUE) {
    CloseHandle(proc);
    return Status::failure("Failed to enumerate modules for " +
                           std::to_string(pid));
  }

  auto formatMemPerms = [](unsigned long perm) {
    std::vector<std::string> perms;
    for (const auto& kv : kMemoryConstants) {
      if (kv.first & perm) {
        perms.push_back(kv.second);
      }
    }
    return osquery::join(perms, " | ");
  };

  MODULEENTRY32W me;
  MEMORY_BASIC_INFORMATION mInfo;
  me.dwSize = sizeof(MODULEENTRY32W);
  auto ret = Module32FirstW(modSnap, &me);
  while (ret != FALSE) {
    for (auto p = me.modBaseAddr;
         VirtualQueryEx(proc, p, &mInfo, sizeof(mInfo)) == sizeof(mInfo) &&
         p < (me.modBaseAddr + me.modBaseSize);
         p += mInfo.RegionSize) {
      Row r;
      r["pid"] = INTEGER(pid);
      std::stringstream ssStart;
      ssStart << std::hex << mInfo.BaseAddress;
      r["start"] = "0x" + ssStart.str();
      std::stringstream ssEnd;
      ssEnd << std::hex << std::setfill('0') << std::setw(16)
            << reinterpret_cast<unsigned long long>(mInfo.BaseAddress) +
                   mInfo.RegionSize;
      r["end"] = "0x" + ssEnd.str();
      r["permissions"] = formatMemPerms(mInfo.Protect);
      r["offset"] =
          BIGINT(reinterpret_cast<unsigned long long>(mInfo.AllocationBase));
      r["device"] = "-1";
      r["inode"] = INTEGER(-1);
      r["path"] = wstringToString(me.szExePath);
      r["pseudo"] = INTEGER(-1);
      results.push_back(r);
    }
    ret = Module32NextW(modSnap, &me);
  }
  CloseHandle(proc);
  CloseHandle(modSnap);
  return Status::success();
}

/// Helper function for enumerating all active processes on the system
Status getProcList(std::set<long>& pids) {
  auto procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (procSnap == INVALID_HANDLE_VALUE) {
    return Status::failure("Failed to open process snapshot");
  }

  PROCESSENTRY32W procEntry;
  procEntry.dwSize = sizeof(PROCESSENTRY32W);
  auto ret = Process32FirstW(procSnap, &procEntry);

  if (ret == FALSE) {
    CloseHandle(procSnap);
    return Status::failure("Failed to open first process");
  }

  while (ret != FALSE) {
    pids.insert(procEntry.th32ProcessID);
    ret = Process32NextW(procSnap, &procEntry);
  }

  CloseHandle(procSnap);
  return Status::success();
}

/// Helper function for getting the User Process Parameters from the PEB
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



void getProcessPathInfo(HANDLE& proc,
                        const unsigned long pid,
                        DynamicTableRowHolder& r) {
  std::string procPath;
  auto st = ProcessHelper::getProcessCurrentDirectory(proc, procPath, pid);
 
  if (!st.success()) {
    VLOG(1) << "Failed to lookup path information for process " << pid
            << " with " << GetLastError();
  } else {
    r["path"] = SQL_TEXT(procPath);
    auto const boost_path = boost::filesystem::path{procPath.data()};
    r["on_disk"] = INTEGER(
        boost_path.empty() ? -1 : osquery::pathExists(procPath.data()).ok());
  }

}

void getProcessCurrentDirectoryInfo(HANDLE& proc,
                                    const unsigned long pid,
                                    DynamicTableRowHolder& r) {
  std::string currDir{""};

  auto s = ProcessHelper::getProcessCurrentDirectory(proc, currDir, pid);
  if (!s.ok()) {
    VLOG(1) << "Failed to get cwd for " << pid << " with " << GetLastError();
  } else {
    r["cwd"] = SQL_TEXT(currDir);
  }
  r["root"] = r["cwd"];
}

void genProcessUserTokenInfo(HANDLE& proc,
                             const unsigned long pid, 
                             DynamicTableRowHolder& r) {
  /// Get the process UID and GID from its SID
  PSID processSid;
  int elevated = -1;
  auto st = ProcessHelper::getProcessUserInfo(proc, &processSid, elevated, pid);
  if (st.ok() && processSid) {
    r["elevated_token"] = INTEGER(elevated);
    r["uid"] = BIGINT(getRidFromSid(processSid));
    r["gid"] = BIGINT(getGidFromUserSid(processSid).value_or(-1));
    HeapFree(GetProcessHeap(), 0, (LPVOID)processSid);
   }
  
}

void genProcessTimeInfo(HANDLE& proc, DynamicTableRowHolder& r) {
  FILETIME create_time;
  FILETIME exit_time;
  FILETIME kernel_time;
  FILETIME user_time;
  auto ret =
      GetProcessTimes(proc, &create_time, &exit_time, &kernel_time, &user_time);
  if (ret == FALSE) {
    LOG(ERROR) << "Failed to lookup time data for process "
               << GetProcessId(proc);
  } else {
    // Windows stores proc times in 100 nanosecond ticks
    ULARGE_INTEGER utime;
    utime.HighPart = user_time.dwHighDateTime;
    utime.LowPart = user_time.dwLowDateTime;
    auto user_time_total = utime.QuadPart;
    r["user_time"] = BIGINT(user_time_total / 10000);
    utime.HighPart = kernel_time.dwHighDateTime;
    utime.LowPart = kernel_time.dwLowDateTime;
    r["system_time"] = BIGINT(utime.QuadPart / 10000);
    r["percent_processor_time"] = BIGINT(user_time_total + utime.QuadPart);

    auto proc_create_time = osquery::filetimeToUnixtime(create_time);
    r["start_time"] = BIGINT(proc_create_time);

    FILETIME curr_ft_time;
    SYSTEMTIME curr_sys_time;
    GetSystemTime(&curr_sys_time);
    SystemTimeToFileTime(&curr_sys_time, &curr_ft_time);
    r["elapsed_time"] =
        BIGINT(osquery::filetimeToUnixtime(curr_ft_time) - proc_create_time);
  }
}

void genProcRssInfo(HANDLE& proc, DynamicTableRowHolder& r) {
  PROCESS_MEMORY_COUNTERS_EX mem_ctr;
  auto ret =
      GetProcessMemoryInfo(proc,
                           reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&mem_ctr),
                           sizeof(PROCESS_MEMORY_COUNTERS_EX));

  if (ret != TRUE) {
    LOG(ERROR) << "Failed to lookup RSS stats for process "
               << GetProcessId(proc);
  }
  r["wired_size"] =
      ret == TRUE ? BIGINT(mem_ctr.QuotaNonPagedPoolUsage) : BIGINT(-1);
  r["resident_size"] =
      ret == TRUE ? BIGINT(mem_ctr.WorkingSetSize) : BIGINT(-1);
  r["total_size"] = ret == TRUE ? BIGINT(mem_ctr.PrivateUsage) : BIGINT(-1);
}



TableRows genProcesses(QueryContext& context) {
  TableRows results;

  // Check for pid filtering in constraints.
  // We use a list here, but sqlite3 will usually call this with
  // a single pid for each item in JOIN or IN() list.

  std::set<int> pidlist;
  if (context.constraints.count("pid") > 0 &&
      context.constraints.at("pid").exists(EQUALS)) {
    for (const auto& pid : context.constraints.at("pid").getAll<int>(EQUALS)) {
      pidlist.insert(pid);
    }
  }

  auto proc_snap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
  auto const proc_snap_manager =
      scope_guard::create([&proc_snap]() { CloseHandle(proc_snap); });
  if (proc_snap == INVALID_HANDLE_VALUE) {
    LOG(ERROR) << "Failed to create snapshot of processes with "
               << std::to_string(GetLastError());
    return {};
  }

  PROCESSENTRY32W proc;
  proc.dwSize = sizeof(PROCESSENTRY32W);

  auto ret = Process32FirstW(proc_snap, &proc);
  if (ret == FALSE) {
    LOG(ERROR) << "Failed to acquire first process information with "
               << std::to_string(GetLastError());
    return {};
  }

  while (ret != FALSE) {
    auto pid = proc.th32ProcessID;

    bool wanted_pid = (pidlist.empty() || pidlist.count(pid) > 0);
    if (!wanted_pid) {
      ret = Process32NextW(proc_snap, &proc);
      continue;
    }

    auto r = make_table_row();
    r["pid"] = BIGINT(pid);
    r["parent"] = BIGINT(proc.th32ParentProcessID);
    r["name"] = SQL_TEXT(wstringToString(proc.szExeFile));
    r["threads"] = INTEGER(proc.cntThreads);

    // Set default values for columns, in the event opening the process fails
    r["pgroup"] = BIGINT(-1);
    r["euid"] = BIGINT(-1);
    r["suid"] = BIGINT(-1);
    r["egid"] = BIGINT(-1);
    r["sgid"] = BIGINT(-1);
    r["uid"] = BIGINT(-1);
    r["gid"] = BIGINT(-1);

    r["user_time"] = BIGINT(-1);
    r["system_time"] = BIGINT(-1);
    r["start_time"] = BIGINT(-1);
    r["elapsed_time"] = BIGINT(-1);
    r["percent_processor_time"] = BIGINT(-1);

    r["nice"] = BIGINT(-1);
    r["wired_size"] = BIGINT(-1);
    r["resident_size"] = BIGINT(-1);
    r["total_size"] = BIGINT(-1);
    r["disk_bytes_read"] = BIGINT(-1);
    r["disk_bytes_written"] = BIGINT(-1);
    r["handle_count"] = BIGINT(-1);

    r["on_disk"] = BIGINT(-1);
    r["elevated_token"] = BIGINT(-1);
    r["secure_process"] = BIGINT(-1);
    r["protection_type"] = SQL_TEXT("");
    r["virtual_process"] = BIGINT(-1);

    if (pid == 0) {
      results.push_back(r);
      ret = Process32NextW(proc_snap, &proc);
      continue;
    }

    auto proc_handle = ProcessHelper::getProcessHandle(pid);
    auto const proc_handle_manager =
        scope_guard::create([&proc_handle]() { CloseHandle(proc_handle); });

    if (proc_handle == NULL) {
      VLOG(1) << "Failed to open handle to process " << pid << " with "
              << GetLastError();
      results.push_back(r);
      ret = Process32NextW(proc_snap, &proc);
      continue;
    }

    auto nice = GetPriorityClass(proc_handle);
    r["nice"] = nice != FALSE ? INTEGER(nice) : "-1";

    ProcessHelper::PS_PROTECTED_TYPE protectionType =
        ProcessHelper::PS_PROTECTED_TYPE::PsProtectedTypeNone;
    auto st = ProcessHelper::getProcessProtectedType(proc_handle, protectionType, pid);
    if (st.ok()) {
      r["protection_type"] =
            SQL_TEXT(ProcessHelper::getProtectedTypeAsString(protectionType));
    }

    bool isProtectedProcess =
          protectionType != ProcessHelper::PS_PROTECTED_TYPE::PsProtectedTypeNone;

    ProcessHelper::EXTENDED_INFO extInfo;
    st = ProcessHelper::getProcessExtendedInfo(proc_handle, extInfo, pid);
    if (st.ok()) {
      r["secure_process"] = BIGINT(extInfo.isSecure);
      r["virtual_process"] = BIGINT(extInfo.isVirtual);
    }
    if (context.isAnyColumnUsed({"path", "on_disk"})) {
      getProcessPathInfo(proc_handle, pid, r);
    }

    if (context.isAnyColumnUsed({"cwd", "root"}) && !isProtectedProcess &&
        !extInfo.isSecure && !extInfo.isVirtual) {
      getProcessCurrentDirectoryInfo(proc_handle, pid, r);
    }

    if (context.isColumnUsed("cmdline") && !extInfo.isSecure &&
        !extInfo.isVirtual) {
      std::string cmd{""};
      auto s = ProcessHelper::getProcessCommandLine(
          proc_handle, cmd, static_cast<unsigned long>(proc.th32ProcessID));
      if (!s.ok()) {
        s = ProcessHelper::getProcessCommandLineLegacy(
            proc_handle, cmd, static_cast<unsigned long>(proc.th32ProcessID));
      }
      r["cmdline"] = cmd;
    }

    if (context.isAnyColumnUsed({"uid", "gid", "elevated_token"})) {
      genProcessUserTokenInfo(proc_handle,
                              static_cast<unsigned long>(proc.th32ProcessID), r);
    }

    if (context.isAnyColumnUsed({"user_time",
                                 "system_time",
                                 "start_time",
                                 "elapsed_time",
                                 "percent_processor_time"})) {
      genProcessTimeInfo(proc_handle, r);
    }

    if (context.isAnyColumnUsed(
            {"wired_size", "resident_size", "total_size"})) {
      genProcRssInfo(proc_handle, r);
    }

    if (context.isAnyColumnUsed({"disk_bytes_read", "disk_bytes_written"})) {
      IO_COUNTERS io_ctrs;
      ret = GetProcessIoCounters(proc_handle, &io_ctrs);
      r["disk_bytes_read"] =
          ret == TRUE ? BIGINT(io_ctrs.ReadTransferCount) : BIGINT(-1);
      r["disk_bytes_written"] =
          ret == TRUE ? BIGINT(io_ctrs.WriteTransferCount) : BIGINT(-1);
    }

    if (context.isColumnUsed("handle_count")) {
      unsigned long handle_count;
      ret = GetProcessHandleCount(proc_handle, &handle_count);
      r["handle_count"] = ret == TRUE ? INTEGER(handle_count) : "-1";
    }

    /*
     * Note: On windows the concept of the process state isn't as clear as on
     * posix. The state value from WMI isn't currently returning anything, and
     * the most common way to get the state is as follows.
     */
    if (context.isColumnUsed("state")) {
      unsigned long exit_code = 0;
      GetExitCodeProcess(proc_handle, &exit_code);
      r["state"] = exit_code == STILL_ACTIVE ? "STILL_ACTIVE" : "EXITED";
    }

    results.push_back(r);
    ret = Process32NextW(proc_snap, &proc);
  }

  return results;
}

QueryData genProcessMemoryMap(QueryContext& context) {
  QueryData results;

  std::set<long> pidlist;
  if (context.constraints.count("pid") > 0 &&
      context.constraints.at("pid").exists(EQUALS)) {
    for (const auto& pid : context.constraints.at("pid").getAll<int>(EQUALS)) {
      if (pid > 0) {
        pidlist.insert(pid);
      }
    }
  }
  if (pidlist.empty()) {
    getProcList(pidlist);
  }

  for (const auto& pid : pidlist) {
    auto s = genMemoryMap(pid, results);
    if (!s.ok()) {
      VLOG(1) << s.getMessage();
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery
