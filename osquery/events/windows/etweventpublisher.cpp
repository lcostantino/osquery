/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/events/windows/etweventpublisher.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>

namespace osquery {

#define PROCESS_PROVIDER_GUID L"{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"

FLAG(bool,
     enable_windows_etw_publisher,
     false,
     "Enables the Windows ETW publisher");

REGISTER(EtwEventPublisher,
         "event_publisher",
         "EtwEventPublisher");

struct EtwEventPublisher::PrivateData final {};

EtwEventPublisher::EtwEventPublisher() : d_(new PrivateData) {}

EtwEventPublisher::~EtwEventPublisher() {}

void EtwEventPublisher::configure() {
  if (!FLAGS_enable_windows_etw_publisher) {
    return;
  }
  tearDown();
  if (!trace) {
   //Yes, i'm using the user_trace instead of kernel_trace 
    trace = std::make_unique<krabs::user_trace>(L"OsQuery Etw Process"); 
  }

}

Status EtwEventPublisher::run() {
  if (!FLAGS_enable_windows_etw_publisher) {
    return Status::failure("Publisher etw disabled by configuration");
  }
  //The kernel provider is not providing all the fields (or the same) than when using the kernel provider id. 
  //ImagePath & CreateTime for instance. CMDLine is provided by the kernel provider, but we can obtain that with post-processing.

  krabs::provider<> provider(krabs::guid(PROCESS_PROVIDER_GUID));

  provider.add_on_event_callback(
      [&](const EVENT_RECORD& record,
          const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);

        if (schema.event_id() != 1) {
          return;
        }
        try {
          krabs::parser parser(schema);
          struct ProcessData p;

          if (schema.event_id() == 1) {
  
            p.pid = parser.parse<uint32_t>(L"ProcessID");
            p.parentPid = parser.parse<uint32_t>(L"ParentProcessID");
            p.imageName =
                wstringToString(parser.parse<std::wstring>(L"ImageName"));
            p.sessionId = parser.parse<uint32_t>(L"SessionID");
            p.createTime = filetimeToUnixtime(parser.parse<FILETIME>(L"CreateTime"));
          
            const std::lock_guard<std::mutex> lock(queue_events_mutex);
            this->queue_events.push_back(std::move(p));
            this->queue_events_cv.notify_one();
           
          }
        } catch (const std::exception& e) {
          LOG(ERROR) << "Exception " << e.what();
        }
      });
  // From here on out, a kernel_trace is indistinguishable from a user_trace in
  // how it is used.
    auto procStartId = krabs::predicates::id_is(1);
    auto procFinishId = krabs::predicates::id_is(2);

    provider.add_filter(krabs::event_filter(
      krabs::predicates::any_of({&procStartId, &procFinishId})));

    trace->enable(provider);
    std::thread ts([&]() {
      trace->start();
    });
    ts.detach();
   
    std::unique_lock<std::mutex> queue_lock(queue_events_mutex);
    bool should_process_events = false;
    while (!isEnding()) {
        should_process_events = this->queue_events_cv.wait_for(
                queue_lock, std::chrono::seconds(5), [this]() {
                    return !this->queue_events.empty();
                });
        if (should_process_events) {
                auto event_context = createEventContext();
                event_context->events = std::move(this->queue_events);
                this->queue_events.clear();
                fire(event_context);  
        }
  }
  return Status::success();
}


void EtwEventPublisher::tearDown() {
  if (!FLAGS_enable_windows_etw_publisher) {
    return;
  }
  if (trace) {
    trace->stop();
  }
}

bool EtwEventPublisher::shouldFire(const SCRef& subscription,
                                          const ECRef& event) const {
  return true;
}
} // namespace osquery
