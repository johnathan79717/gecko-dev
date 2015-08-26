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

static const short kResourceHashType = nsICryptoHash::SHA256;
static const char* kTestingSignature = "THIS.IS.TESTING.SIGNATURE";

namespace mozilla {
namespace net {

///////////////////////////////////////////////////////////////////////////////

const char* PackagedAppVerifier::kSignedPakOriginMetadataKey = "signed-pak-origin";

PackagedAppVerifier::PackagedAppVerifier(PackagedAppVerifierListener* aListener,
                                         const nsACString& aPackageOrigin,
                                         const nsACString& aSignature,
                                         nsICacheEntry* aPackageCacheEntry,
                                         bool aDeveloperMode)
  : mListener(aListener)
  , mState(STATE_UNKNOWN)
  , mPackageOrigin(aPackageOrigin)
  , mSignature(aSignature)
  , mIsPackageSigned(false)
  , mPackageCacheEntry(aPackageCacheEntry)
  , mDeveloperMode(aDeveloperMode)
{
  if (mDeveloperMode && mSignature.IsEmpty()) {
    LOG(("No signature but in developer mode ==> Assign a testing signature."));
    mSignature.Assign(kTestingSignature);
  }
}

nsresult
PackagedAppVerifier::BeginResourceHash(const nsACString& aResourceURI)
{
  if (!mHasher) {
    mHasher = do_CreateInstance("@mozilla.org/security/hash;1");
  }

  NS_ENSURE_TRUE(mHasher, NS_ERROR_FAILURE);

  mHashingResourceURI = aResourceURI;
  return mHasher->Init(kResourceHashType);
}

nsresult
PackagedAppVerifier::UpdateResourceHash(const uint8_t* aData, uint32_t aLen)
{
  MOZ_ASSERT(!mHashingResourceURI.IsEmpty(), "MUST call BeginResourceHash first.");
  NS_ENSURE_TRUE(mHasher, NS_ERROR_FAILURE);
  return mHasher->Update(aData, aLen);
}

nsresult
PackagedAppVerifier::EndResourceHash()
{
  MOZ_ASSERT(!mHashingResourceURI.IsEmpty(), "MUST call BeginResourceHash first.");
  NS_ENSURE_TRUE(mHasher, NS_ERROR_FAILURE);

  nsresult rv = mHasher->Finish(true, mLastComputedResourceHash);
  NS_ENSURE_SUCCESS(rv, rv);

  LOG(("Hash of %s is %s", mHashingResourceURI.get(),
                           mLastComputedResourceHash.get()));

  return NS_OK;
}

void
PackagedAppVerifier::ProcessResourceCache(const ResourceCacheInfo& aInfo)
{
  MOZ_RELEASE_ASSERT(NS_IsMainThread(), "OnResourceCached must be on main thread");

  switch (mState) {
  case STATE_UNKNOWN:
    // The first resource has to be the manifest.
    VerifyManifest(aInfo);
    break;

  case STATE_MANIFEST_VERIFIED_OK:
    VerifyResource(aInfo);
    break;

  case STATE_MANIFEST_VERIFIED_FAILED:
    OnResourceVerified(aInfo, false);
    break;

  default:
    MOZ_CRASH("Unexpected PackagedAppVerifier state."); // Shouldn't get here.
    break;
  }
}

void
PackagedAppVerifier::VerifyManifest(const ResourceCacheInfo& aInfo)
{
  MOZ_RELEASE_ASSERT(NS_IsMainThread(), "Manifest verification must be on main thread");

  LOG(("Ready to verify manifest."));

  if (mDeveloperMode) {
    LOG(("Developer mode! Bypass verification."));
    OnManifestVerified(aInfo, true);
    return;
  }

  if (mSignature.IsEmpty()) {
    LOG(("No signature. No need to do verification."));
    OnManifestVerified(aInfo, true);
    return;
  }

  // TODO: Implement manifest verification.
  LOG(("Manifest verification not implemented yet. See Bug 1178518."));
  OnManifestVerified(aInfo, false);
}

void
PackagedAppVerifier::VerifyResource(const ResourceCacheInfo& aInfo)
{
  MOZ_RELEASE_ASSERT(NS_IsMainThread(), "Resource verification must be on main thread");

  LOG(("Checking the resource integrity. '%s'", mLastComputedResourceHash.get()));

  if (mDeveloperMode) {
    LOG(("Developer mode! Bypass integrity check."));
    OnResourceVerified(aInfo, true);
    return;
  }

  if (mSignature.IsEmpty()) {
    LOG(("No signature. No need to do resource integrity check."));
    OnResourceVerified(aInfo, true);
    return;
  }

  // TODO: Implement resource integrity check.
  LOG(("Resource integrity check not implemented yet. See Bug 1178518."));
  OnResourceVerified(aInfo, false);
}

void
PackagedAppVerifier::OnManifestVerified(const ResourceCacheInfo& aInfo, bool aSuccess)
{
  LOG(("PackagedAppVerifier::OnManifestVerified: %d", aSuccess));

  // Only when the manifest verified and package has signature would we
  // regard this package is signed.
  mIsPackageSigned = (aSuccess && !mSignature.IsEmpty());

  mState = aSuccess ? STATE_MANIFEST_VERIFIED_OK
                    : STATE_MANIFEST_VERIFIED_FAILED;

  // TODO: Update mPackageOrigin.

  // If the package is signed, add related info to the package cache.
  if (mIsPackageSigned && mPackageCacheEntry) {
    LOG(("This package is signed. Add this info to the cache channel."));
    if (mPackageCacheEntry) {
      mPackageCacheEntry->SetMetaDataElement(kSignedPakOriginMetadataKey,
                                             mPackageOrigin.get());
      mPackageCacheEntry = nullptr; // the cache entry is no longer needed.
    }
  }

  mListener->OnManifestVerified(aInfo, aSuccess);
}

void
PackagedAppVerifier::OnResourceVerified(const ResourceCacheInfo& aInfo, bool aSuccess)
{
  MOZ_RELEASE_ASSERT(NS_IsMainThread(),
                     "PackagedAppVerifier::OnResourceVerified must be on main thread");
  mListener->OnResourceVerified(aInfo, aSuccess);
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
