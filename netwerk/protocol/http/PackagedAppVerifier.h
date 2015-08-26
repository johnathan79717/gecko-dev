/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_net_PackagedAppVerifier_h
#define mozilla_net_PackagedAppVerifier_h

#include "nsICacheEntry.h"
#include "nsIURI.h"
#include "nsClassHashtable.h"
#include "nsHashKeys.h"
#include "nsICryptoHash.h"

class nsITimer;

namespace mozilla {
namespace net {

class PackagedAppVerifierListener;

class PackagedAppVerifier final
{
public:
  enum EState {
    // The initial state.
    STATE_UNKNOWN,

    // Either the package has no signature or the manifest is verified
    // successfully will we be in this state.
    STATE_MANIFEST_VERIFIED_OK,

    // iff the package has signature but the manifest is not well signed.
    STATE_MANIFEST_VERIFIED_FAILED,

    // The manifest is well signed but the resource integrity check failed.
    STATE_RESOURCE_VERIFIED_FAILED,
  };

public:
  struct ResourceCacheInfo : public mozilla::LinkedListElement<ResourceCacheInfo>
  {
    nsCOMPtr<nsIURI> mURI;
    nsCOMPtr<nsICacheEntry> mCacheEntry;
    nsresult mStatusCode;
    bool mIsLastPart;

    ResourceCacheInfo(nsIURI* aURI,
                      nsICacheEntry* aCacheEntry,
                      nsresult aStatusCode,
                      bool aIsLastPart)
      : mURI(aURI)
      , mCacheEntry(aCacheEntry)
      , mStatusCode(aStatusCode)
      , mIsLastPart(aIsLastPart)
    {
    }
  };

public:
  PackagedAppVerifier(PackagedAppVerifierListener* aListener,
                      const nsACString& aPackageOrigin,
                      const nsACString& aSignature,
                      nsICacheEntry* aPackageCacheEntry,
                      bool aDeveloperMode = false);

  ~PackagedAppVerifier() { }

  //---------------------------------------------------------------------------
  // Resource hash utility functions.
  //---------------------------------------------------------------------------
  nsresult BeginResourceHash(const nsACString& aResourceURI);
  nsresult UpdateResourceHash(const uint8_t* aData, uint32_t aLen);
  nsresult EndResourceHash();

  // Called when a resource is already fully written in the cache. This resource
  // will be processed and is guaranteed to be called back in either:
  //
  // 1) PackagedAppVerifierListener::OnManifestVerified:
  //    ------------------------------------------------------------------------
  //    If the resource is the first one in the package, it will be called
  //    back in OnManifestVerified no matter this package has signature or not.
  //
  // 2) PackagedAppVerifierListener::OnResourceVerified.
  //    ------------------------------------------------------------------------
  //    Otherwise, the resource will be called back here.
  //
  void ProcessResourceCache(const ResourceCacheInfo& aInfo);

  // Returns the origin with the signed package verifier taking into account.
  nsCString GetPackageOrigin() const;

  bool IsPackageSigned() const;

  static const char* kSignedPakOriginMetadataKey;

private:
  // This two functions would call the actual verifier.
  void VerifyManifest(const ResourceCacheInfo& aInfo);
  void VerifyResource(const ResourceCacheInfo& aInfo);

  void OnManifestVerified(const ResourceCacheInfo& aInfo, bool aSuccess);
  void OnResourceVerified(const ResourceCacheInfo& aInfo, bool aSuccess);

  // To notify that either manifest or resource check is done.
  PackagedAppVerifierListener* mListener;

  // The internal verification state.
  EState mState;

  // Initialized as a normal origin. Will be updated once we verified the manifest.
  nsCString mPackageOrigin;

  // The signature of the package.
  nsCString mSignature;

  // Whether this package app is signed.
  bool mIsPackageSigned;

  // The package cache entry (e.g. http://foo.com/app.pak) used to store
  // any necessarry signed package information.
  nsCOMPtr<nsICacheEntry> mPackageCacheEntry;

  // The resource URI that we are computing its hash.
  nsCString mHashingResourceURI;

  // Used to compute resource's hash value.
  nsCOMPtr<nsICryptoHash> mHasher;

  // The last computed hash value for a resource. It will be set on every
  // |EndResourceHash| call.
  nsCString mLastComputedResourceHash;

  // If it's true, all the verification will be skipped and the package will
  // be treated signed.
  bool mDeveloperMode;
}; // class PackagedAppVerifier

class PackagedAppVerifierListener
{
public:
	typedef PackagedAppVerifier::ResourceCacheInfo ResourceCacheInfo;

public:
	virtual void OnManifestVerified(const ResourceCacheInfo& aInfo, bool aSuccess) = 0;
	virtual void OnResourceVerified(const ResourceCacheInfo& aInfo, bool aSuccess) = 0;
};

} // namespace net
} // namespace mozilla

#endif // mozilla_net_PackagedAppVerifier_h
