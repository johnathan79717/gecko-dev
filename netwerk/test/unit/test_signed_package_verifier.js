const header_missing_signature = "header1: content1";
const header_invalid_signature = `header1: content1
manifest-signature: invalid-signature`;
const header = "manifest-signature: MIIF0gYJKoZIhvcNAQcCoIIFwzCCBb8CAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3DQEHAaCCA5wwggOYMIICgKADAgECAgECMA0GCSqGSIb3DQEBCwUAMHMxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEkMCIGA1UEChMbRXhhbXBsZSBUcnVzdGVkIENvcnBvcmF0aW9uMRkwFwYDVQQDExBUcnVzdGVkIFZhbGlkIENBMB4XDTE1MDkwNzA5MzU0OVoXDTM1MDkwNzA5MzU0OVowdDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MSQwIgYDVQQKExtFeGFtcGxlIFRydXN0ZWQgQ29ycG9yYXRpb24xGjAYBgNVBAMTEVRydXN0ZWQgQ29ycCBDZXJ0MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA3UfgRY0p4F0shg3ArwvKjTUVnHTlD6ipUeJa3KLXejmp7pi37AlsYNba1lbcynoIYzK/jg+8PsTcFJHiVSrSV9ihNGPC40bKM9x5kEwYOHkBSnszMatYAa7bTwcHe90aiUolSvhmO37Tj1c3g1cKAYNEY6cYk0u3n6iN8EnqhETzfBlpLVVaQcEwspcSFNvkm8r0GU0vldVz6Xfsnw5zfq1nkQ1Pri1Y4SV5S3sPNuWQa/7wQmmGmBnckQhtk9Jga8ymOqINaf0GBrSk++YQf5CTuMjrmjnH0813YuC/QHP2pKVrxSl9vVJyt0226jCe+7ZEm8C3XPpU2mRmMMyaYQIBA6M4MDYwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggEBACP9RcwB8xbI/4JUvPO2i5UXkYTek+uczG6URqoSuug9PhuIdHcBeUQG3BAmpj2hF8LxzEAlChesKGPKhCXKYDzy+8T1MkYQzruAx7w0xVJ4NE+4L1PJKT5zfO7NBcGTaYmVwT79arAAha1p+gH8w5JgEK5CueBzospNaRek+JW9FmtGrn+WjtMwlYbEx/w9IYByQsCqGqKaqrIFromr6S++h8BSagyqo6xc5YMp43KVzAm/vio9lCKcpUGxm6+3sosbOd32jX7zg9+Cq1MR6PmUkOWv+KPTL+/5CfNNQ4OGMbM3bmOvpZjPoDAMi9IRKl4Bvic4XBBoQi+58RkDdHExggH+MIIB+gIBATB4MHMxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEkMCIGA1UEChMbRXhhbXBsZSBUcnVzdGVkIENvcnBvcmF0aW9uMRkwFwYDVQQDExBUcnVzdGVkIFZhbGlkIENBAgECMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNTA5MDkwNzQxNTVaMCMGCSqGSIb3DQEJBDEWBBTYOpRrVfWyWy9oQNHOQ3TnrgkOpTANBgkqhkiG9w0BAQEFAASCAQBrGGQLNuipWX2bpVbb7LQuFtJMmEmX1ljuks60klFZUt8a+b3+deW8F4TLizcUUcGoxEr63dDJzEe9+Nn0IS6+u1qycb943jImRQwTwI4E6WmaF0OP/dpiYQMECiq7OSrR3HFSsbBeE6wh/qHkVHTvrrZjkJN9sVxsdww9Ab8rx85wQFDSzomQZgocJ4+np44Sp+MqgjfDj4AtBrF7sIvziXgWhqZKT2KjrzsZtNmR+a3wfY40eXBQxP+4xtl2c5fRBuURBPpmWu+HoaIb9/GM1ymyYkzxRIwlgcQLguvUCn+qP574t5rEZxJVixxm66TOt70MVWjKbr8LVX6OqCvD\r\n";

const manifest = "Content-Location: manifest.webapp\r\n" +
  "Content-Type: application/x-web-app-manifest+json\r\n\r\n" +
`{
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
}`;

const manifest_missing_moz_resources = `{
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
  "moz-package-location": "https://example.com/myapp/app.pak"
}
`;

const manifest_malformed_json = "}";

let callback, verifier;

function run_test() {
  add_test(test_verify_manifest_missing_signature);
  add_test(test_verify_manifest_invalid_signature);
  add_test(test_verify_manifest_malformed_json);
  add_test(test_verify_manifest_missing_moz_resources);
  add_test(test_verify_manifest_success);
  // The last verification must succeed, because check_integrity use that object;
  add_test(test_check_integrity_success);
  add_test(test_check_integrity_filename_not_matched);
  add_test(test_check_integrity_hashvalue_not_matched);

  run_next_test();
}

function test_verify_manifest_missing_signature() {
  verifier = Cc["@mozilla.org/network/signed-package-verifier;1"]
               .createInstance(Ci.nsISignedPackageVerifier);
  ok(!verifier.verifyManifest(header_missing_signature, manifest),
     "header without signature should fail to verify");
  run_next_test();
}

function test_verify_manifest_invalid_signature() {
  verifier = Cc["@mozilla.org/network/signed-package-verifier;1"]
               .createInstance(Ci.nsISignedPackageVerifier);
  ok(!verifier.verifyManifest(header_invalid_signature, manifest),
     "header with invalid signature should fail to verify");
  run_next_test();
}

function test_verify_manifest_malformed_json() {
  verifier = Cc["@mozilla.org/network/signed-package-verifier;1"]
               .createInstance(Ci.nsISignedPackageVerifier);
  ok(!verifier.verifyManifest(header, manifest_malformed_json),
     "manifest with malformed json should fail to verify");
  run_next_test();
}

function test_verify_manifest_missing_moz_resources() {
  verifier = Cc["@mozilla.org/network/signed-package-verifier;1"]
               .createInstance(Ci.nsISignedPackageVerifier);
  ok(!verifier.verifyManifest(header, manifest_missing_moz_resources),
     "manifest without moz-resources attribute should fail to verify");
  run_next_test();
}

function test_verify_manifest_success() {
  verifier = Cc["@mozilla.org/network/signed-package-verifier;1"]
               .createInstance(Ci.nsISignedPackageVerifier);
  ok(verifier.verifyManifest(header, manifest),
     "valid manifest and header should verify successfully");
  run_next_test();
}

function test_check_integrity_success() {
  let manifestBody = manifest.substr(manifest.indexOf('\r\n\r\n') + 4);
  for (let resource of JSON.parse(manifestBody)["moz-resources"]) {
    ok(verifier.checkIntegrity(resource.src, resource.integrity),
       "resource " + resource.src + " should pass integrity check");
  }
  run_next_test();
}

function test_check_integrity_filename_not_matched() {
  ok(!verifier.checkIntegrity("/nosuchfile.html", "sha256-kass...eoirW-e"),
     "mismatched filename should fail integrity check");
  run_next_test();
}

function test_check_integrity_hashvalue_not_matched() {
  ok(!verifier.checkIntegrity("/index.html", "kass...eoirW-e"),
     "mismatched hashvalue should fail integrity check");
  run_next_test();
}
