/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "nsISignedPackageVerifier.h"
#include "nsIStringStream.h"
#include "nsICacheStorage.h"
#include "nsICacheStorageService.h"
#include "../../cache2/CacheFileUtils.h"
#include "mozilla/Logging.h"
#include "mozilla/DebugOnly.h"
#include "nsThreadUtils.h"
#include "PackagedAppVerifier.h"
#include "nsITimer.h"
#include "nsIPackagedAppVerifier.h"
#include "mozilla/Preferences.h"
#undef LOG
#define LOG(args) MOZ_LOG(gPASLog, mozilla::LogLevel::Debug, args)

PRLogModuleInfo* gPASLog;

static const short kResourceHashType = nsICryptoHash::SHA256;
static const char* kTestingManifest = R"({
  "name": "My App",
  "moz-resources": [
    {
      "src": "page2.html",
      "integrity": "JREF3JbXGvZ+I1KHtoz3f46ZkeIPrvXtG4VyFQrJ7II="
    },
    {
      "src": "index.html",
      "integrity": "B5Phw8L1tpyRBkI0gwg/evy1fgtMlMq3BIY3Q8X0rYU="
    },
    {
      "src": "scripts/script.js",
      "integrity": "6TqtNArQKrrsXEQWu3D9ZD8xvDRIkhyV6zVdTcmsT5Q="
    },
    {
      "src": "scripts/library.js",
      "integrity": "TN2ByXZiaBiBCvS4MeZ02UyNi44vED+KjdjLInUl4o8="
    }
  ],
  "moz-permissions": [
    {
      "systemXHR": {
        "description": "Needed to download stuff"
      },
      "devicestorage:pictures": {
        "description": "Need to load pictures"
      }
    }
  ],
  "moz-uuid": "some-uuid",
  "moz-package-location": "https://example.com/myapp/app.pak",
  "description": "A great app!"
})";
static const char* kTestingSignature = "manifest-signature: MIIF0gYJKoZIhvcNAQcCoIIFwzCCBb8CAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3DQEHAaCCA5wwggOYMIICgKADAgECAgECMA0GCSqGSIb3DQEBCwUAMHMxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEkMCIGA1UEChMbRXhhbXBsZSBUcnVzdGVkIENvcnBvcmF0aW9uMRkwFwYDVQQDExBUcnVzdGVkIFZhbGlkIENBMB4XDTE1MDkwNzA5MzU0OVoXDTM1MDkwNzA5MzU0OVowdDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MSQwIgYDVQQKExtFeGFtcGxlIFRydXN0ZWQgQ29ycG9yYXRpb24xGjAYBgNVBAMTEVRydXN0ZWQgQ29ycCBDZXJ0MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA3UfgRY0p4F0shg3ArwvKjTUVnHTlD6ipUeJa3KLXejmp7pi37AlsYNba1lbcynoIYzK/jg+8PsTcFJHiVSrSV9ihNGPC40bKM9x5kEwYOHkBSnszMatYAa7bTwcHe90aiUolSvhmO37Tj1c3g1cKAYNEY6cYk0u3n6iN8EnqhETzfBlpLVVaQcEwspcSFNvkm8r0GU0vldVz6Xfsnw5zfq1nkQ1Pri1Y4SV5S3sPNuWQa/7wQmmGmBnckQhtk9Jga8ymOqINaf0GBrSk++YQf5CTuMjrmjnH0813YuC/QHP2pKVrxSl9vVJyt0226jCe+7ZEm8C3XPpU2mRmMMyaYQIBA6M4MDYwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggEBACP9RcwB8xbI/4JUvPO2i5UXkYTek+uczG6URqoSuug9PhuIdHcBeUQG3BAmpj2hF8LxzEAlChesKGPKhCXKYDzy+8T1MkYQzruAx7w0xVJ4NE+4L1PJKT5zfO7NBcGTaYmVwT79arAAha1p+gH8w5JgEK5CueBzospNaRek+JW9FmtGrn+WjtMwlYbEx/w9IYByQsCqGqKaqrIFromr6S++h8BSagyqo6xc5YMp43KVzAm/vio9lCKcpUGxm6+3sosbOd32jX7zg9+Cq1MR6PmUkOWv+KPTL+/5CfNNQ4OGMbM3bmOvpZjPoDAMi9IRKl4Bvic4XBBoQi+58RkDdHExggH+MIIB+gIBATB4MHMxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEkMCIGA1UEChMbRXhhbXBsZSBUcnVzdGVkIENvcnBvcmF0aW9uMRkwFwYDVQQDExBUcnVzdGVkIFZhbGlkIENBAgECMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNTA5MDkwMjIwMzJaMCMGCSqGSIb3DQEJBDEWBBSaNkK4BAXiE028nDHLnPO4y5V6SDANBgkqhkiG9w0BAQEFAASCAQDKEsETWSPf9vvm9sK1Ky8PfBRX+YKoSMbHfhHP9FeI3cR0oPTLNUoEnjw+lkFRmcd8e0sw540fDov86o6WCOuf4YU4zVgLa7Tx7e7cuMWDttoAUSZJO2Bt3VbJqEhhBcCxRGWoOA1LlsdJHNe7P1aVWzVGwLBZY4CE6xJSLUiehQTkC7z/2dk23KZ5jkDfw0uCVYlPkYhPOYdmxUBa7Q+sYBxuSDy4Ay9JGKBU6hHNHFFOD0xbKiH3yx1vRZphNBUM8MrTz6bYLBcRTUUMGwp1pSQ4VVvIP2oIS5E8tF4j9B1R9KzQa+c6gfa/g4qBHLoH0FI6ql+DSIX3odAalcsp\r\n";

// If it's true, all the verification will be skipped and the package will
// be treated signed.
static bool gDeveloperMode = false;

namespace mozilla {
namespace net {

///////////////////////////////////////////////////////////////////////////////

NS_IMPL_ISUPPORTS(PackagedAppVerifier, nsIPackagedAppVerifier)

NS_IMPL_ISUPPORTS(PackagedAppVerifier::ResourceCacheInfo, nsISupports)

const char* PackagedAppVerifier::kSignedPakOriginMetadataKey = "signed-pak-origin";

PackagedAppVerifier::PackagedAppVerifier()
{
  MOZ_RELEASE_ASSERT(NS_IsMainThread(),
                     "PackagedAppVerifier::OnResourceVerified must be on main thread");

  Init(nullptr, EmptyCString(), EmptyCString(), nullptr);
}

PackagedAppVerifier::PackagedAppVerifier(nsIPackagedAppVerifierListener* aListener,
                                         const nsACString& aPackageOrigin,
                                         const nsACString& aSignature,
                                         nsICacheEntry* aPackageCacheEntry)
{
  Init(aListener, aPackageOrigin, aSignature, aPackageCacheEntry);
}

NS_IMETHODIMP PackagedAppVerifier::Init(nsIPackagedAppVerifierListener* aListener,
                                        const nsACString& aPackageOrigin,
                                        const nsACString& aSignature,
                                        nsICacheEntry* aPackageCacheEntry)
{
  static bool onceThru = false;
  if (!onceThru) {
    Preferences::AddBoolVarCache(&gDeveloperMode,
                                 "network.http.packaged-apps-developer-mode", false);
    onceThru = true;
  }

  mListener = aListener;
  mState = STATE_UNKNOWN;
  mPackageOrigin = aPackageOrigin;
  mSignature = aSignature;
  mIsPackageSigned = false;
  mPackageCacheEntry = aPackageCacheEntry;
  mIsFirstResource = true;

  mTestingSignature.Assign(kTestingSignature);
  mTestingManifest.Assign(kTestingManifest);
  nsresult rv;
  mVerifierUtil = do_CreateInstance(NS_SIGNEDPACKAGEVERIFIER_CONTRACTID, &rv);
  if (NS_FAILED(rv)) {
    LOG(("create verifier failed"));
  }

  return NS_OK;
}

//----------------------------------------------------------------------
// nsIStreamListener
//----------------------------------------------------------------------

// @param aRequest nullptr.
// @param aContext The URI of the resource. (nsIURI)
NS_IMETHODIMP
PackagedAppVerifier::OnStartRequest(nsIRequest *aRequest,
                                    nsISupports *aContext)
{
  if (mIsFirstResource) {
    // First resource must be the manifest, we don't calculate its hash value
    return NS_OK;
  }

  if (!mHasher) {
    mHasher = do_CreateInstance("@mozilla.org/security/hash;1");
  }

  NS_ENSURE_TRUE(mHasher, NS_ERROR_FAILURE);

  nsCOMPtr<nsIURI> uri = do_QueryInterface(aContext);
  NS_ENSURE_TRUE(uri, NS_ERROR_FAILURE);
  uri->GetAsciiSpec(mHashingResourceURI);

  return mHasher->Init(kResourceHashType);
}

NS_METHOD
PackagedAppVerifier::WriteManifest(nsIInputStream *aStream,
                                   void *aClosure,
                                   const char *aFromRawSegment,
                                   uint32_t aToOffset,
                                   uint32_t aCount,
                                   uint32_t *aWriteCount)
{
  nsCString *manifest = static_cast<nsCString*>(aClosure);
  manifest->AppendASCII(aFromRawSegment, aCount);
  *aWriteCount = aCount;
  return NS_OK;
}

// @param aRequest nullptr.
// @param aContext nullptr.
// @param aInputStream as-is.
// @param aOffset as-is.
// @param aCount as-is.
NS_IMETHODIMP
PackagedAppVerifier::OnDataAvailable(nsIRequest *aRequest,
                                     nsISupports *aContext,
                                     nsIInputStream *aInputStream,
                                     uint64_t aOffset,
                                     uint32_t aCount)
{
  if (mIsFirstResource) {
    // First resource must be the manifest, we don't calculate its hash value.
    // Instead, we read from the input stream and append it to mManifest
    uint32_t count;
    nsresult rv = aInputStream->ReadSegments(WriteManifest, &mManifest, aCount, &count);
    MOZ_ASSERT(count == aCount, "ReadSegments should read %d bytes", aCount);
    return rv;
  }

  MOZ_ASSERT(!mHashingResourceURI.IsEmpty(), "MUST call BeginResourceHash first.");
  NS_ENSURE_TRUE(mHasher, NS_ERROR_FAILURE);
  return mHasher->UpdateFromStream(aInputStream, aCount);
}

// @param aRequest nullptr.
// @param aContext The resource cache info.
// @param aStatusCode as-is,
NS_IMETHODIMP
PackagedAppVerifier::OnStopRequest(nsIRequest* aRequest,
                                    nsISupports* aContext,
                                    nsresult aStatusCode)
{
  if (mIsFirstResource) {
    // First resource must be the manifest, we don't calculate its hash value.
    mIsFirstResource = false;
  } else {
    NS_ENSURE_TRUE(mHasher, NS_ERROR_FAILURE);

    nsresult rv = mHasher->Finish(true, mLastComputedResourceHash);
    NS_ENSURE_SUCCESS(rv, rv);

    LOG(("Hash of %s is %s", mHashingResourceURI.get(),
                             mLastComputedResourceHash.get()));
  }

  ProcessResourceCache(static_cast<ResourceCacheInfo*>(aContext));

  return NS_OK;
}

void
PackagedAppVerifier::ProcessResourceCache(const ResourceCacheInfo* aInfo)
{
  MOZ_RELEASE_ASSERT(NS_IsMainThread(), "ProcessResourceCache must be on main thread");

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
PackagedAppVerifier::VerifyManifest(const ResourceCacheInfo* aInfo)
{
  MOZ_RELEASE_ASSERT(NS_IsMainThread(), "Manifest verification must be on main thread");

  LOG(("Ready to verify manifest."));

  if (gDeveloperMode) {
    LOG(("Developer mode! Bypass verification."));
    OnManifestVerified(aInfo, true);
    return;
  }

  if (mSignature.IsEmpty()) {
    LOG(("No signature. No need to do verification."));
    OnManifestVerified(aInfo, true);
    return;
  }

  bool success;
  nsresult rv = mVerifierUtil->VerifyManifest(mTestingSignature, mTestingManifest, &success);
  //nsresult rv = mVerifierUtil->VerifyManifest(mSignature, mManifest, &success);
  if (NS_FAILED(rv)) {
    LOG(("error in verification"));
    OnManifestVerified(aInfo, false);
    return;
  }
  LOG(("verification result: %d", success));
  OnManifestVerified(aInfo, success);
}

void
PackagedAppVerifier::VerifyResource(const ResourceCacheInfo* aInfo)
{
  MOZ_RELEASE_ASSERT(NS_IsMainThread(), "Resource verification must be on main thread");

  LOG(("Checking the resource integrity. '%s'", mLastComputedResourceHash.get()));

  if (gDeveloperMode) {
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
  nsCString path;
  aInfo->mURI->GetPath(path);

  // Cut the part before and including "!//"
  uint32_t index = path.Find("!//");
  if (index + 3 >= path.Length()) {
    LOG(("Invalid URI"));
    OnResourceVerified(aInfo, false);
    return;
  }
  path.Cut(0, index + 3);
  bool success;
  mVerifierUtil->CheckIntegrity(path, mLastComputedResourceHash, &success);
  LOG(("CheckIntegrity %s %d", path.get(), success));

  OnResourceVerified(aInfo, success);
}

void
PackagedAppVerifier::OnManifestVerified(const ResourceCacheInfo* aInfo, bool aSuccess)
{
  LOG(("PackagedAppVerifier::OnManifestVerified: %d", aSuccess));

  // Only when the manifest verified and package has signature would we
  // regard this package is signed.
  mIsPackageSigned = aSuccess && !mSignature.IsEmpty();

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

  mListener->OnVerified(true, // aIsManifest.
                        aInfo->mURI,
                        aInfo->mCacheEntry,
                        aInfo->mStatusCode,
                        aInfo->mIsLastPart,
                        aSuccess);

  LOG(("PackagedAppVerifier::OnManifestVerified done"));
}

void
PackagedAppVerifier::OnResourceVerified(const ResourceCacheInfo* aInfo, bool aSuccess)
{
  MOZ_RELEASE_ASSERT(NS_IsMainThread(),
                     "PackagedAppVerifier::OnResourceVerified must be on main thread");

  mListener->OnVerified(false, // aIsManifest.
                        aInfo->mURI,
                        aInfo->mCacheEntry,
                        aInfo->mStatusCode,
                        aInfo->mIsLastPart,
                        aSuccess);
}

//---------------------------------------------------------------
// nsIPackagedAppVerifier.
//---------------------------------------------------------------

NS_IMETHODIMP
PackagedAppVerifier::GetPackageOrigin(nsACString& aPackageOrigin)
{
  aPackageOrigin = mPackageOrigin;
  return NS_OK;
}

NS_IMETHODIMP
PackagedAppVerifier::GetIsPackageSigned(bool* aIsPackagedSigned)
{
  *aIsPackagedSigned = mIsPackageSigned;
  return NS_OK;
}

NS_IMETHODIMP
PackagedAppVerifier::CreateResourceCacheInfo(nsIURI* aUri,
                                             nsICacheEntry* aCacheEntry,
                                             nsresult aStatusCode,
                                             bool aIsLastPart,
                                             nsISupports** aReturn)
{
  nsCOMPtr<nsISupports> info =
    new ResourceCacheInfo(aUri, aCacheEntry, aStatusCode, aIsLastPart);

  info.forget(aReturn);

  return NS_OK;
}


} // namespace net
} // namespace mozilla
