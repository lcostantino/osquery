/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>

#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/tables/events/windows/process_events.h>
#include <osquery/utils/system/windows/processes.h>
#include <osquery/utils/system/uptime.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/events/windows/etweventpublisher.h>
#include <osquery/utils/system/windows/users_groups_helpers.h>

namespace osquery {

FLAG(bool,
     etw_process_events,
     false,
     "Use ETW to capture process events");
DECLARE_bool(etw_process_events);

REGISTER(EtwProcessEventSubscriber, "event_subscriber", "process_events");

Status EtwProcessEventSubscriber::init() {

  if (!FLAGS_etw_process_events) {
    return Status(1, "Subscriber disabled via configuration");
  }
  
  auto sc = createSubscriptionContext();
  subscribe(&EtwProcessEventSubscriber::Callback, sc);
  return Status::success();
}

Status EtwProcessEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {

     std::vector<Row> emitted_row_list;
     for (const auto& processEvent : ec->events) {
       Row row = {};
       row["parent"] = std::to_string(processEvent.parentPid);
       row["pid"] = std::to_string(processEvent.pid);
       row["path"] = processEvent.imageName;
       auto prHandle = ProcessHelper::getProcessHandle(processEvent.pid);
       if (prHandle) {
         auto st = ProcessHelper::getProcessCommandLine(prHandle, row["cmdline"], processEvent.pid);
         if (!st.ok()) {
           ProcessHelper::getProcessCommandLineLegacy(prHandle, row["cmdline"], processEvent.pid);
         }
         std::string data;
         st = ProcessHelper::getProcessCurrentDirectory(prHandle, data, processEvent.pid);
         if (st.ok()) {
           row["cwd"] = SQL_TEXT(data);
         }
         PSID targetSid;
         int isElevated = 0;
         st = ProcessHelper::getProcessUserInfo(
             prHandle, &targetSid, isElevated, processEvent.pid);
         if (st.ok()) {
           row["uid"] = BIGINT(getRidFromSid(targetSid));
           row["gid"] = BIGINT(getGidFromUserSid(targetSid).value_or(-1));
           HeapFree(GetProcessHeap(), 0, (LPVOID)targetSid);
         } 
         data = "";
         ProcessHelper::getProcessPathInfo(prHandle, data, processEvent.pid);
         row["path"] = SQL_TEXT(data);  
         ProcessHelper::closeProcessHandle(prHandle);
       }
       
       row["ctime"] = BIGINT(processEvent.createTime);
       // Unused fields
       row["overflows"] = "";
       row["env"] = "";
       row["env_size"] = "0";
       row["env_count"] = "0";
       emitted_row_list.push_back(std::move(row));
     }
    addBatch(emitted_row_list);
    return Status::success();
}

} // namespace osquery
