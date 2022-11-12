/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <memory>
#include <unordered_set>
#include <osquery/events/windows/krabs/krabs.hpp>
#include <osquery/events/eventpublisher.h>


namespace osquery {
struct EtwSubscriptionContext : public SubscriptionContext {
  std::unordered_set<std::string> channel_list;
  std::vector<double> character_frequency_map;

 private:
  friend class EtwPublisher;
};

struct ProcessData final {
  DWORD pid;
  DWORD parentPid;
  DWORD sessionId;
  std::string imageName;
  std::string commandLine;
  LONGLONG createTime;
};

// This POC is just for Process Events, but it can be a template or a generic
// ETW event (using a map..)
struct EtwEventEC : public EventContext {
  std::vector<ProcessData> events;
};
using EtwEventECRef = std::shared_ptr<EtwEventEC>;

using EtwSubscriptionSCRef =
    std::shared_ptr<EtwSubscriptionContext>;

class EtwEventPublisher
    : public EventPublisher<EtwSubscriptionContext,
                            EtwEventEC> {
 public:
  EtwEventPublisher();
  virtual ~EtwEventPublisher() override;

  bool shouldFire(const SCRef& subscription, const ECRef& event) const override;
  void configure() override;
  void tearDown() override;
  Status run() override;

  static double cosineSimilarity(const std::string& buffer,
                                 const std::vector<double>& global_freqs);

 private:
  DECLARE_PUBLISHER("EtwEventPublisher");

  struct PrivateData;
  std::unique_ptr<PrivateData> d_;
  std::unique_ptr<krabs::user_trace> trace;
  std::vector<ProcessData> queue_events;
  std::mutex queue_events_mutex;

  std::condition_variable queue_events_cv;

};
} // namespace osquery
