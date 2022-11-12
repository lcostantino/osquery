/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <ctime>
#include <tuple>
#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef _WIN32_WINNT
#error "_WIN32_WINNT must be defined, see tools/build_defs/oss/osquery/cxx.bzl"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif


#include <osquery/utils/status/status.h>
#include <windows.h>

namespace osquery {

namespace ProcessHelper {

typedef enum _PS_PROTECTED_TYPE : UCHAR {
  PsProtectedTypeNone,
  PsProtectedTypeProtectedLight,
  PsProtectedTypeProtected,
  PsProtectedTypeMax
} PS_PROTECTED_TYPE;

typedef struct _EXTENDED_INFO {
  bool isVirtual;
  bool isSecure;
} EXTENDED_INFO;

/**
 * @brief Retrieve process command line
 *
 */
Status getProcessCommandLineLegacy(HANDLE proc,
                                   std::string& out,
                                   const unsigned long pid);

Status getProcessCommandLine(HANDLE proc,
                             std::string& out,
                             const unsigned long pid);

Status getProcessCurrentDirectory(HANDLE proc,
                                  std::string& out,
                                  const unsigned long pid);

Status getProcessPathInfo(HANDLE proc,
                          std::string& out,
                          const unsigned long pid);
/**
 * @brief Retrieve process uer info. SID is allocated by this function and need to be freed by the caller
 */
Status getProcessUserInfo(HANDLE proc,
                          PSID *sid,
                          int& is_elevated,
                          const unsigned long pid);

Status getProcessProtectedType(HANDLE& proc,
                               PS_PROTECTED_TYPE& psType,
                               const unsigned long pid);

Status getProcessExtendedInfo(HANDLE& proc,
                              EXTENDED_INFO &extInfo,
                              const unsigned long pid);

std::string getProtectedTypeAsString(PS_PROTECTED_TYPE psType);

HANDLE getProcessHandle(const unsigned long pid);
void closeProcessHandle(HANDLE proc);


} // namespace ProcessHelper

} // namespace osquery
