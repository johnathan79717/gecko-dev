/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/Base64.h"
#include "nsISignedPackageVerifier.h"
#include "nsIX509Cert.h"
#include "nsIX509CertDB.h"
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

static const short kResourceHashType = nsICryptoHash::SHA256;
static const char* kTestingManifest = R"({
  "name": "My App",
  "description": "A great app!",
  "moz-uuid": "some-uuid",
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
  "moz-resources": [
    {
      "src": "/index.html",
      "integrity": "sha256-kass...eoirW-e"
    },
    {
      "src": "/page2.html",
      "integrity": "sha256-kasguie...ngeW-e"
    },
    {
      "src": "/script.js",
      "integrity": "sha256-agjdia2...wgda"
    },
    {
      "src": "/library.js",
       "integrity": "sha256-geijfi...ae3W"
    }
  ],
  "moz-package-location": "https://example.com/myapp/app.pak"
}
)";
static const char* kTestingSignature = "manifest-signature: MIIF0gYJKoZIhvcNAQcCoIIFwzCCBb8CAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3DQEHAaCCA5wwggOYMIICgKADAgECAgECMA0GCSqGSIb3DQEBCwUAMHMxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEkMCIGA1UEChMbRXhhbXBsZSBUcnVzdGVkIENvcnBvcmF0aW9uMRkwFwYDVQQDExBUcnVzdGVkIFZhbGlkIENBMB4XDTE1MDgyNDA5MTEzOFoXDTM1MDgyNDA5MTEzOFowdDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MSQwIgYDVQQKExtFeGFtcGxlIFRydXN0ZWQgQ29ycG9yYXRpb24xGjAYBgNVBAMTEVRydXN0ZWQgQ29ycCBDZXJ0MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA2qMp97njHVXbnafne6qIx5D+j2AUC6j2159DK6PnL78L5UxD2KgjQZvkOaIZJe11KPYTf7upftat4Shs1c0SsMbHzDY7K0E/lSslD4zmb4TckOGPZzxtEIl7v3+yCjKqMRRMcBnaB20LrxTPQ3PS9iBCzTVbWlosbqmK/+1Pkv4Cmp3sXWJm9QA1QAgJu0dm8sTCyW0F8M3t9zIRNkZoQCERiLYQ/zIDC62B1iS6pOswz2MX3lh05O1FYKJ/y+lM+U7Wv/Ml87cpDNztmNbS1LET1wFjxiXNrc9kuqveT1Ccb4XG3x7KykXTfAnGGJb1mTM1YK84drfVmbgbNixgvwIBA6M4MDYwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggEBAGEqlAKtBMFSalloBdQBR0KODIhzAJfkzp0FIokZwF4YsXsAZdPpdZ4rwLTfdI1IhF2vLkW3KAuV0fEtShuqTIZVFqszEy/N2mLIZ5bjqJzqDT3/az4/vn/UBBgEiVvkSYYn0WlypRsGtpax9XSZvmXJ7PW9VKokJ5xIuFT87oyhdz3e5NgymmK2KGuBLUWKNNxap9GU2CEHVvsETcjqeELhH2LXd7H4xWVBu54tmuAIGa9Q16OenhMejEkAdbHzth0X/M/KNIEoucXRLtK8xVxdN4wcYZCXwQR1dgej7G4ZzcKtzJqN12msyKaeaJnhHBWYCCRaziH8q4Cswyp3BHwxggH+MIIB+gIBATB4MHMxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEkMCIGA1UEChMbRXhhbXBsZSBUcnVzdGVkIENvcnBvcmF0aW9uMRkwFwYDVQQDExBUcnVzdGVkIFZhbGlkIENBAgECMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNTA4MjQwOTExMzhaMCMGCSqGSIb3DQEJBDEWBBTtO4QkpGTDLlHwE3ltN+RQpJn30DANBgkqhkiG9w0BAQEFAASCAQAKh/cWKYNqR6gBxY2HM7k5fZTePu4Lo73A0yjEDalKmywrWQ9x88d+dIZNlxfeQ1Uk+RNNVkNNjKkFBLHEP6HHAVYaevRFAqBG4Z2n+jY9Pjko7vqcF3cseg5p4vx7Emb7GMU0V/9Mfvfpw1tST/rn9iUnruIQGkFEnG7VkSBrOJHuQYwXuzd2LHEoj9OhrsNRKccjy9vzX0+1zKBVqRJ4x+TQU19/KED5LW59btStEJhGdmcPgs2QC4rwymvTZiOyd5L2vWtZm2FdAUGpINSnptIA+3m23RtNkeWUoE2H45EWPgCWwQeYSZibxw3Zn1tG9FznTtSCWrsgXXWNBomc";

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

  //if (gDeveloperMode) {
    mSignature.Assign(kTestingSignature);
    mManifest.Assign(kTestingManifest);
  //}

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
  if (!mHasher) {
    mHasher = do_CreateInstance("@mozilla.org/security/hash;1");
  }

  NS_ENSURE_TRUE(mHasher, NS_ERROR_FAILURE);

  nsCOMPtr<nsIURI> uri = do_QueryInterface(aContext);
  NS_ENSURE_TRUE(uri, NS_ERROR_FAILURE);
  uri->GetAsciiSpec(mHashingResourceURI);

  return mHasher->Init(kResourceHashType);
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
  NS_ENSURE_TRUE(mHasher, NS_ERROR_FAILURE);

  nsresult rv = mHasher->Finish(true, mLastComputedResourceHash);
  NS_ENSURE_SUCCESS(rv, rv);

  LOG(("Hash of %s is %s", mHashingResourceURI.get(),
                           mLastComputedResourceHash.get()));

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

  // TODO: Implement manifest verification.
  LOG(("Manifest verification not implemented yet. See Bug 1178518."));
  nsresult rv;
  nsCOMPtr<nsISignedPackageVerifier> verifier =
    do_CreateInstance(NS_SIGNEDPACKAGEVERIFIER_CONTRACTID, &rv);
  if (NS_FAILED(rv)) {
    LOG(("create verifier failed"));
    OnManifestVerified(aInfo, false);
    return;
  }
  bool success;
  rv = verifier->VerifyManifest(mSignature, mManifest, &success);
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
  OnResourceVerified(aInfo, true);
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
