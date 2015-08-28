//
// This file tests the packaged app verifier - nsIPackagedAppVerifier
//
// ----------------------------------------------------------------------------
//
// All the test cases will ensure the callback order and args are exact the
// same as how and what we feed into the verifier. We also check if verifier
// gives the correct verification result like "is package signed", the
// "package origin", etc.
//
// Note that the actual signature verification is not done yet. If we claim a
// non-empty signature, the verifier will regard the verification as failed.
// The actual verification process is addressed by Bug 1178518. Non-developer mode
// test cases have to be modified once Bug 1178518 lands.
//
// We also test the developer mode here. In developer mode, no matter what kind
// of signautre do we initialize the verifier, the package is always said signed.
//

Cu.import("resource://gre/modules/Services.jsm");

////////////////////////////////////////////////////////////////
let gIoService = Cc["@mozilla.org/network/io-service;1"]
                   .getService(Ci.nsIIOService);

let gPrefs = Cc["@mozilla.org/preferences-service;1"]
               .getService(Components.interfaces.nsIPrefBranch);

let gVerifier = Cc["@mozilla.org/network/packaged-app-verifier;1"]
                  .createInstance(Ci.nsIPackagedAppVerifier);;

const kUriIdx                 = 0;
const kCacheEntryIdx          = 1;
const kStatusCodeIdx          = 2;
const kVerificationSuccessIdx = 3;

function enable_developer_mode()
{
  gPrefs.setBoolPref("network.http.packaged-apps-developer-mode", true);
}

function reset_developer_mode()
{
  gPrefs.clearUserPref("network.http.packaged-apps-developer-mode");
}

function createVerifierListener(aExpecetedCallbacks,
                                aExpectedOrigin,
                                aExpectedIsSigned) {
  let cnt = 0;
  return {
    onVerified: function(aIsManifest,
                         aUri,
                         aCacheEntry,
                         aStatusCode,
                         aIsLastPart,
                         aVerificationSuccess) {
      cnt++;

      let expectedCallback = aExpecetedCallbacks[cnt - 1];
      let isManifest = (cnt === 1);
      let isLastPart = (cnt === aExpecetedCallbacks.length);

      equal(aIsManifest,          isManifest);
      equal(aUri.asciiSpec,       expectedCallback[kUriIdx]);
      equal(aCacheEntry,          expectedCallback[kCacheEntryIdx]);
      equal(aStatusCode,          expectedCallback[kStatusCodeIdx]);
      equal(aIsLastPart,          isLastPart);
      equal(aVerificationSuccess, expectedCallback[kVerificationSuccessIdx]);

      if (isManifest) {
        equal(gVerifier.packageOrigin, aExpectedOrigin);
        equal(gVerifier.isPackageSigned, aExpectedIsSigned);
      }

      if (isLastPart) {
        reset_developer_mode();
        run_next_test();
      }
    },
  };
};

function feedResources(aExpectedCallbacks) {
  for (let i = 0; i < aExpectedCallbacks.length; i++) {
    let expectedCallback = aExpectedCallbacks[i];
    let isLastPart = (i === aExpectedCallbacks.length - 1);

    let uri = gIoService.newURI(expectedCallback[kUriIdx], null, null);
    gVerifier.onStartRequest(null, uri);

    let info = gVerifier.createResourceCacheInfo(uri, null, 0, isLastPart);
    gVerifier.onStopRequest(null, info, expectedCallback[kStatusCodeIdx]);
  }
}

function test_no_signature(aDeveloperMode) {
  const kOrigin = 'http://foo.com';

  aDeveloperMode = !!aDeveloperMode;

  // If the package has no signature and not in developer mode, the package is unsigned
  // but the verification result is always true.

  const expectedCallbacks = [
  // URL                      cacheEntry     statusCode   verificationResult
    [kOrigin + '/manifest',   null,          Cr.NS_OK,    true],
    [kOrigin + '/1.html',     null,          Cr.NS_OK,    true],
    [kOrigin + '/2.js',       null,          Cr.NS_OK,    true],
    [kOrigin + '/3.jpg',      null,          Cr.NS_OK,    true],
    [kOrigin + '/4.html',     null,          Cr.NS_OK,    true],
    [kOrigin + '/5.css',      null,          Cr.NS_OK,    true],
  ];

  let isPackageSigned = aDeveloperMode; // Package is always considered as signed in developer mode.
  let verifierListener = createVerifierListener(expectedCallbacks,
                                                kOrigin,
                                                isPackageSigned);

  gVerifier.init(verifierListener, kOrigin, '', null);

  feedResources(expectedCallbacks);
}

function test_invalid_signature(aDeveloperMode) {
  const kOrigin = 'http://foo.com';

  aDeveloperMode = !!aDeveloperMode;

  // Since we haven't implemented signature verification, the verification always
  // fails if the signature exists.

  let verificationResult = aDeveloperMode; // Verification always success in developer mode.
  let isPackageSigned = aDeveloperMode;   // Package is always considered as signed in developer mode.

  const expectedCallbacks = [
  // URL                      cacheEntry     statusCode   verificationResult
    [kOrigin + '/manifest',   null,          Cr.NS_OK,    verificationResult],
    [kOrigin + '/1.html',     null,          Cr.NS_OK,    verificationResult],
    [kOrigin + '/2.js',       null,          Cr.NS_OK,    verificationResult],
    [kOrigin + '/3.jpg',      null,          Cr.NS_OK,    verificationResult],
    [kOrigin + '/4.html',     null,          Cr.NS_OK,    verificationResult],
    [kOrigin + '/5.css',      null,          Cr.NS_OK,    verificationResult],
  ];

  let verifierListener = createVerifierListener(expectedCallbacks,
                                                kOrigin,
                                                isPackageSigned);

  gVerifier.init(verifierListener, kOrigin, 'invalid signature', null);

  feedResources(expectedCallbacks);
}

function test_no_signature_developer_mode()
{
  enable_developer_mode()
  test_no_signature(true);
}

function test_invalid_signature_developer_mode()
{
  enable_developer_mode()
  test_invalid_signature(true);
}

function run_test()
{

  ok(!!gVerifier);

  add_test(test_no_signature);
  add_test(test_invalid_signature);

  add_test(test_no_signature_developer_mode);
  add_test(test_invalid_signature_developer_mode);

  // run tests
  run_next_test();
}
