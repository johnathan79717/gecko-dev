const header_missing_signature = "header1: content1";
const header_invalid_signature = `header1: content1
manifest-signature: invalid-signature`;
const header = `header1: content1
manifest-signature: MIIF0gYJKoZIhvcNAQcCoIIFwzCCBb8CAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3DQEHAaCCA5wwggOYMIICgKADAgECAgECMA0GCSqGSIb3DQEBCwUAMHMxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEkMCIGA1UEChMbRXhhbXBsZSBUcnVzdGVkIENvcnBvcmF0aW9uMRkwFwYDVQQDExBUcnVzdGVkIFZhbGlkIENBMB4XDTE1MDgyNDA5MTEzOFoXDTM1MDgyNDA5MTEzOFowdDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MSQwIgYDVQQKExtFeGFtcGxlIFRydXN0ZWQgQ29ycG9yYXRpb24xGjAYBgNVBAMTEVRydXN0ZWQgQ29ycCBDZXJ0MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA2qMp97njHVXbnafne6qIx5D+j2AUC6j2159DK6PnL78L5UxD2KgjQZvkOaIZJe11KPYTf7upftat4Shs1c0SsMbHzDY7K0E/lSslD4zmb4TckOGPZzxtEIl7v3+yCjKqMRRMcBnaB20LrxTPQ3PS9iBCzTVbWlosbqmK/+1Pkv4Cmp3sXWJm9QA1QAgJu0dm8sTCyW0F8M3t9zIRNkZoQCERiLYQ/zIDC62B1iS6pOswz2MX3lh05O1FYKJ/y+lM+U7Wv/Ml87cpDNztmNbS1LET1wFjxiXNrc9kuqveT1Ccb4XG3x7KykXTfAnGGJb1mTM1YK84drfVmbgbNixgvwIBA6M4MDYwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggEBAGEqlAKtBMFSalloBdQBR0KODIhzAJfkzp0FIokZwF4YsXsAZdPpdZ4rwLTfdI1IhF2vLkW3KAuV0fEtShuqTIZVFqszEy/N2mLIZ5bjqJzqDT3/az4/vn/UBBgEiVvkSYYn0WlypRsGtpax9XSZvmXJ7PW9VKokJ5xIuFT87oyhdz3e5NgymmK2KGuBLUWKNNxap9GU2CEHVvsETcjqeELhH2LXd7H4xWVBu54tmuAIGa9Q16OenhMejEkAdbHzth0X/M/KNIEoucXRLtK8xVxdN4wcYZCXwQR1dgej7G4ZzcKtzJqN12msyKaeaJnhHBWYCCRaziH8q4Cswyp3BHwxggH+MIIB+gIBATB4MHMxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEkMCIGA1UEChMbRXhhbXBsZSBUcnVzdGVkIENvcnBvcmF0aW9uMRkwFwYDVQQDExBUcnVzdGVkIFZhbGlkIENBAgECMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNTA4MjQwOTExMzhaMCMGCSqGSIb3DQEJBDEWBBTtO4QkpGTDLlHwE3ltN+RQpJn30DANBgkqhkiG9w0BAQEFAASCAQAKh/cWKYNqR6gBxY2HM7k5fZTePu4Lo73A0yjEDalKmywrWQ9x88d+dIZNlxfeQ1Uk+RNNVkNNjKkFBLHEP6HHAVYaevRFAqBG4Z2n+jY9Pjko7vqcF3cseg5p4vx7Emb7GMU0V/9Mfvfpw1tST/rn9iUnruIQGkFEnG7VkSBrOJHuQYwXuzd2LHEoj9OhrsNRKccjy9vzX0+1zKBVqRJ4x+TQU19/KED5LW59btStEJhGdmcPgs2QC4rwymvTZiOyd5L2vWtZm2FdAUGpINSnptIA+3m23RtNkeWUoE2H45EWPgCWwQeYSZibxw3Zn1tG9FznTtSCWrsgXXWNBomc
`;

const manifest = `{
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
`;

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
  for (let resource of JSON.parse(manifest)["moz-resources"]) {
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
