/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "nsICacheStorage.h"
#include "nsICacheStorageService.h"
#include "../../cache2/CacheFileUtils.h"
#include "mozilla/Logging.h"
#include "mozilla/DebugOnly.h"
#include "nsThreadUtils.h"
#include "PackagedAppVerifier.h"
#include "nsITimer.h"
#include "nsICryptoHash.h"

// Defined in PackagedAppService.cpp
extern PRLogModuleInfo *gPASLog;

#undef LOG
#define LOG(args) MOZ_LOG(gPASLog, mozilla::LogLevel::Debug, args)

#ifdef MOZ_WIDGET_GONK
  #undef LOG
  #define LOG(args) printf_stderr args
#endif

namespace {

nsCString UriToString(nsIURI* aURI);

}

const short kResourceHashType = nsICryptoHash::SHA256;

namespace mozilla {
namespace net {

///////////////////////////////////////////////////////////////////////////////

PackagedAppVerifier::PackagedAppVerifier(PackagedAppVerifierListener* aListener,
                                         const nsACString& aPackageOrigin,
                                         const nsACString& aSignature,
                                         nsIPackagedAppCacheInfoChannel* aCacheInfoChannel)
  : mListener(aListener)
  , mState(STATE_UNKNOWN)
  , mPackageOrigin(aPackageOrigin)
  , mSignature(aSignature)
  , mIsPackageSigned(false)
  , mCacheInfoChannel(aCacheInfoChannel)
{
  nsresult rv;
  mHasher = do_CreateInstance("@mozilla.org/security/hash;1", &rv);
}

nsresult
PackagedAppVerifier::BeginResourceHash(const nsACString& aResourceURI)
{
  mHashingResourceURI = aResourceURI;
  return mHasher->Init(kResourceHashType);
}

nsresult
PackagedAppVerifier::UpdateResourceHash(const uint8_t* aData, uint32_t aLen)
{
  MOZ_ASSERT(!mHashingResourceURI.IsEmpty(), "MUST call BeginResourceHash first.");
  return mHasher->Update(aData, aLen);
}

nsresult
PackagedAppVerifier::EndResourceHash()
{
  MOZ_ASSERT(!mHashingResourceURI.IsEmpty(), "MUST call BeginResourceHash first.");
  nsAutoCString hash;
  nsresult rv = mHasher->Finish(true, hash);
  NS_ENSURE_SUCCESS(rv, rv);

  LOG(("Hash of %s is %s", mHashingResourceURI.get(), hash.get()));

  // Store the hash for the resource.
  mResourceHashHash.Put(mHashingResourceURI, new nsCString(hash));
  mHashingResourceURI = "";
  return NS_OK;
}

void
PackagedAppVerifier::ProcessResourceCache(ResourceCacheInfo* aInfo)
{
  MOZ_RELEASE_ASSERT(NS_IsMainThread(), "OnResourceCached must be on main thread");

  LOG(("PackagedAppVerifier::ProcessResourceCache: %s. State: %d", UriToString(aInfo->mURI).get(), mState));

  QueueResource(aInfo);

  switch (mState) {
  case STATE_UNKNOWN:
    // The first resource has to be the manifest.
    VerifyManifest(aInfo);
    break;

  case STATE_MANIFEST_VERIFYING:
    // A resource is cached in the middle of manifest verification. Queue it and
    // verify it until we make sure the manifest is verified.
    break;

  case STATE_MANIFEST_VERIFIED_OK:
    VerifyResource(aInfo);
    break;

  case STATE_MANIFEST_VERIFIED_FAILED:
    OnResourceVerified(false);
    break;

  default:
    MOZ_CRASH("Unexpected PackagedAppVerifier state."); // Shouldn't get here.
    break;
  }
}

void
PackagedAppVerifier::FireFakeSuccessEvent(bool aForManifest)
{
  nsCOMPtr<nsIRunnable> r;

  if (aForManifest) {
    r = NS_NewNonOwningRunnableMethodWithArgs<bool>(this, 
                                                    &PackagedAppVerifier::OnManifestVerified, 
                                                    true);
  } else {
    r = NS_NewNonOwningRunnableMethodWithArgs<bool>(this, 
                                                    &PackagedAppVerifier::OnResourceVerified, 
                                                    true);
  }
    
  NS_DispatchToMainThread(r);
}

void
PackagedAppVerifier::VerifyManifest(ResourceCacheInfo* aInfo)
{
  MOZ_RELEASE_ASSERT(NS_IsMainThread(), "Manifest verification must be on main thread");

  LOG(("PackagedAppVerifier::VerifyManifest: %s", UriToString(aInfo->mURI).get()));

  mState = STATE_MANIFEST_VERIFYING;

  FireFakeSuccessEvent(true);

#if 0
  mTimer = do_CreateInstance(NS_TIMER_CONTRACTID);
  
  nsTimerCallbackFunc cb = [](nsITimer* aTimer, void* aClosure) {
    LOG(("Fake VerifyManifest timer called back. Fire event for OnManifestVerified now."));
    auto self = static_cast<PackagedAppVerifier*>(aClosure);
    // FIXME: Fire a fake successful OnManifestVerified event.
    self->FireFakeSuccessEvent(true);
  };

  mTimer->InitWithFuncCallback(cb, this, 5000, nsITimer::TYPE_ONE_SHOT);
#endif

  // TODO: Call the manifest verification function implemented in Bug 1178518.
}

void
PackagedAppVerifier::VerifyResource(ResourceCacheInfo* aInfo)
{
  MOZ_RELEASE_ASSERT(NS_IsMainThread(), "Resource resource must be on main thread");

  LOG(("PackagedAppVerifier::VerifyResource: %s", UriToString(aInfo->mURI).get()));

  nsAutoCString uriAsAscii;
  aInfo->mURI->GetAsciiSpec(uriAsAscii);
  nsCString* resourceHash = mResourceHashHash.Get(uriAsAscii);
     
  if (!resourceHash) {
    LOG(("Hash value for %s is not computed. ERROR!", uriAsAscii.get()));
    MOZ_CRASH();
  }

  LOG(("Checking the resource integrity. '%s'", resourceHash->get()));
  // TODO: Call the integrity check function implemented in Bug 1178518.

  // FIXME: Fire a fake successful OnResourceVerified event.
  FireFakeSuccessEvent(false);
}

void
PackagedAppVerifier::OnManifestVerified(bool aSuccess)
{
  LOG(("PackagedAppVerifier::OnManifestVerified: %d", aSuccess));

  // Only when the manifest verified and package has signature would we
  // regard this package is signed.
  mIsPackageSigned = (aSuccess && !mSignature.IsEmpty());

  mState = aSuccess ? STATE_MANIFEST_VERIFIED_OK
                    : STATE_MANIFEST_VERIFIED_FAILED;

  // TODO: Update mPackageOrigin.

  // If the package is signed, add related info to the package cache.
  if (mIsPackageSigned && mCacheInfoChannel) {
    LOG(("This package is signed. Add this info to the cache channel."));
    mCacheInfoChannel->SetIsSignedPackage(true);
    mCacheInfoChannel->SetSignedPackageOrigin(mPackageOrigin);
    mCacheInfoChannel = nullptr; // the cache channel is no longer needed.
  }

  ResourceCacheInfo* info = mPendingResourceCacheInfoList.popFirst();
  MOZ_ASSERT(info);

  mListener->OnManifestVerified(info, aSuccess);

  if (!aSuccess) {
    return;
  }

  LOG(("Ready to verify resources that were cached during verification"));
  // Verify the resources which were cached during verification accordingly.
  info = mPendingResourceCacheInfoList.getFirst();
  for (; info; info = info->getNext()) {
    VerifyResource(info);
  }
}

void
PackagedAppVerifier::OnResourceVerified(bool aSuccess)
{
  ResourceCacheInfo* info = mPendingResourceCacheInfoList.popFirst();
  MOZ_ASSERT(info);

  LOG(("PackagedAppVerifier::OnResourceVerified: %s has been verified: %d",
       UriToString(info->mURI).get(), aSuccess));

  // Must be called on main thread.
  mListener->OnResourceVerified(info, aSuccess);
}

void
PackagedAppVerifier::QueueResource(ResourceCacheInfo* aInfo)
{
  LOG(("PackagedAppVerifier::QueueResource: %s", UriToString(aInfo->mURI).get()));
  mPendingResourceCacheInfoList.insertBack(aInfo);
}

nsCString
PackagedAppVerifier::GetPackageOrigin() const
{
  return mPackageOrigin;
}

bool
PackagedAppVerifier::IsPackageSigned() const
{
  return mIsPackageSigned;
}

} // namespace net
} // namespace mozilla
