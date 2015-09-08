/* -*- indent-tabs-mode: nil; js-indent-level: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
* You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict';

const { classes: Cc, interfaces: Ci, utils: Cu } = Components;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");

const SIGNEDPACKAGEVERIFIER_CONTRACTID = "@mozilla.org/network/signed-package-verifier;1";
const SIGNEDPACKAGEVERIFIER_CID = Components.ID("{fe8f1c2e-3c13-11e5-9a3f-bbf47d1e6697}");

function SignedPackageVerifier() {

}

let DEBUG = 1
function debug(s) {
  if (DEBUG) {
    dump("-*- SignedPackageVerifier: " + s + "\n");
  }
}

SignedPackageVerifier.prototype = {
  classID: SIGNEDPACKAGEVERIFIER_CID,
  contractID: SIGNEDPACKAGEVERIFIER_CONTRACTID,
  classDescription: "Signed Package Verifier",
  QueryInterface: XPCOMUtils.generateQI([Ci.nsISignedPackageVerifier]),

  verifyManifest: function(aHeader, aManifest) {
    let signature;
    const signatureField = "manifest-signature: ";
    for (let item of aHeader.split('\n')) {
      if (item.substr(0, signatureField.length) == signatureField) {
        signature = item.substr(signatureField.length);
        break;
      }
    }
    if (!signature) {
      return false;
    }
    try {
      signature = atob(signature);
      this.resources = JSON.parse(aManifest)["moz-resources"];
      debug(aManifest);
    } catch (e) {
      return false;
    }

    let manifestStream = Cc["@mozilla.org/io/string-input-stream;1"]
                           .createInstance(Ci.nsIStringInputStream);
    let signatureStream = Cc["@mozilla.org/io/string-input-stream;1"]
                            .createInstance(Ci.nsIStringInputStream);
    manifestStream.setData(aManifest, aManifest.length);
    signatureStream.setData(signature, signature.length);

    let certDb;
    try {
      certDb = Cc["@mozilla.org/security/x509certdb;1"]
                 .getService(Ci.nsIX509CertDB);
    } catch (e) {
      debug("nsIX509CertDB error: " + e);
      // unrecoverable error, don't bug the user
      throw "CERTDB_ERROR";
    }

    let aSignerCert = certDb.verifySignedManifestSync(
      Ci.nsIX509CertDB.PrivilegedPackageRoot, manifestStream, signatureStream);

    return aSignerCert !== null;
  },

  checkIntegrity: function(aFileName, aHashValue) {
    debug("checkIntegrity() " + aFileName + ": " + aHashValue + "\n");
    if (!this.resources) {
      debug("this.resource not found");
      return false;
    }
    for (let r of this.resources) {
      if (r.src === aFileName) {
        debug("found integrity = " + r.integrity);
        return r.integrity === aHashValue;
      }
    }
    return false;
  },
};

this.NSGetFactory = XPCOMUtils.generateNSGetFactory([SignedPackageVerifier]);
