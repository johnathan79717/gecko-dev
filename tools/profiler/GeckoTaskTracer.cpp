/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "GeckoTaskTracer.h"
#include "GeckoTaskTracerImpl.h"

#include "jsapi.h"
#include "mozilla/ThreadLocal.h"
#include "nsThreadUtils.h"
#include "prenv.h"
#include "prthread.h"

#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef MOZ_WIDGET_GONK
#include <android/log.h>
#define LOG(args...)  __android_log_print(ANDROID_LOG_INFO, "Task", args)
#else
#define LOG(args...) do {} while (0)
#endif

#ifdef PR_LOGGING
PRLogModuleInfo* gTaskTracerLog;
#define TT_LOG(type, msg) PR_LOG(gTaskTracerLog, type, msg)
#else
#define TT_LOG(type, msg)
#endif

static bool sDebugRunnable = false;

#if defined(__GLIBC__)
// glibc doesn't implement gettid(2).
#include <sys/syscall.h>
static pid_t gettid()
{
  return (pid_t) syscall(SYS_gettid);
}
#endif

#define MAX_THREAD_NUM 64

namespace mozilla {
namespace tasktracer {

static TraceInfo sAllTraceInfo[MAX_THREAD_NUM];
static mozilla::ThreadLocal<TraceInfo*> sTraceInfo;
static pthread_mutex_t sTraceInfoLock = PTHREAD_MUTEX_INITIALIZER;

static TraceInfo*
AllocTraceInfo(int aTid)
{
  pthread_mutex_lock(&sTraceInfoLock);
  for (int i = 0; i < MAX_THREAD_NUM; i++) {
    if (sAllTraceInfo[i].mThreadId == 0) {
      TraceInfo *info = sAllTraceInfo + i;
      info->mThreadId = aTid;
      pthread_mutex_unlock(&sTraceInfoLock);
      return info;
    }
  }

  NS_ABORT();
  return NULL;
}

static void
_FreeTraceInfo(uint64_t aTid)
{
  pthread_mutex_lock(&sTraceInfoLock);
  for (int i = 0; i < MAX_THREAD_NUM; i++) {
    if (sAllTraceInfo[i].mThreadId == aTid) {
      TraceInfo *info = sAllTraceInfo + i;
      memset(info, 0, sizeof(TraceInfo));
      break;
    }
  }
  pthread_mutex_unlock(&sTraceInfoLock);
}

static const char*
GetCurrentThreadName()
{
  if (gettid() == getpid()) {
    return "main";
  } else if (const char *threadName = PR_GetThreadName(PR_GetCurrentThread())) {
    return threadName;
  } else {
    return "unknown";
  }
}

void
InitTaskTracer()
{
  if (!sTraceInfo.initialized()) {
    sTraceInfo.init();
  }

  if (PR_GetEnv("MOZ_DEBUG_RUNNABLE")) {
    sDebugRunnable = true;
  }
}

TraceInfo*
GetTraceInfo()
{
  if (!sTraceInfo.get()) {
    sTraceInfo.set(AllocTraceInfo(gettid()));
  }
  return sTraceInfo.get();
}

uint64_t
GenNewUniqueTaskId()
{
  pid_t tid = gettid();
  uint64_t taskid = ((uint64_t)tid << 32) | ++GetTraceInfo()->mLastUniqueTaskId;
  return taskid;
}

void SetCurTraceId(uint64_t aTaskId)
{
  TraceInfo* info = GetTraceInfo();
  info->mCurTraceTaskId = aTaskId;
}

uint64_t GetCurTraceId()
{
  TraceInfo* info = GetTraceInfo();
  return info->mCurTraceTaskId;
}

void SetCurTraceType(SourceEventType aType)
{
  TraceInfo* info = GetTraceInfo();
  info->mCurTraceTaskType = aType;
}

SourceEventType GetCurTraceType()
{
  TraceInfo* info = GetTraceInfo();
  return info->mCurTraceTaskType;
}

void
LogTaskAction(ActionType aActionType, uint64_t aTaskId, uint64_t aSourceEventId,
              SourceEventType aSourceEventType)
{
  // Avoid spewing warning message in debug build.
  if (!(sDebugRunnable && aSourceEventId)) {
    return;
  }

  if (aSourceEventType == TOUCH) {
    LOG("[TouchEvent:%d] thread-id:%d (%s), Task id:%ld, SourceEvent id:%ld",
        aActionType, gettid(), GetCurrentThreadName(), aTaskId, aSourceEventId);
  }
}

void
FreeTraceInfo()
{
  _FreeTraceInfo(gettid());
}

void
CreateSETouch(int aX, int aY)
{
  TraceInfo* info = GetTraceInfo();
  info->mCurTraceTaskId = GenNewUniqueTaskId();
  info->mCurTraceTaskType = TOUCH;
  LOG("[Create SE Touch] (x:%d, y:%d), Task id:%d (%s), SourceEvent id:%d",
      aX, aY, info->mThreadId, GetCurrentThreadName(), info->mCurTraceTaskId);
}

void SaveCurTraceInfo()
{
  TraceInfo* info = GetTraceInfo();
  info->mSavedTraceTaskId = info->mCurTraceTaskId;
  info->mSavedTraceTaskType = info->mCurTraceTaskType;
}

void RestorePrevTraceInfo()
{
  TraceInfo* info = GetTraceInfo();
  info->mCurTraceTaskId = info->mSavedTraceTaskId;
  info->mCurTraceTaskType = info->mSavedTraceTaskType;
}

} // namespace tasktracer
} // namespace mozilla
