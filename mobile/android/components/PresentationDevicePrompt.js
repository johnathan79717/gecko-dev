/* -*- indent-tabs-mode: nil; js-indent-level: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

const { classes: Cc, interfaces: Ci, utils: Cu } = Components;

Cu.import('resource://gre/modules/XPCOMUtils.jsm');
Cu.import('resource://gre/modules/Services.jsm');

const kPRESENTATIONDEVICEPROMPT_CONTRACTID = "@mozilla.org/presentation-device/prompt;1";
const kPRESENTATIONDEVICEPROMPT_CID        = Components.ID("{388bd149-c919-4a43-b646-d7ec57877689}");

function debug(aMsg) {
  //dump("-*- PresentationDevicePrompt: " + aMsg + "\n");
  dump("Casting: " + aMsg);
}

function PresentationDevicePrompt() {
  debug("PresentationDevicePrompt init");
  // Services.obs.addObserver(this, "presentation-select-device", false);
}

PresentationDevicePrompt.prototype = {
  classID: kPRESENTATIONDEVICEPROMPT_CID,
  contractID: kPRESENTATIONDEVICEPROMPT_CONTRACTID,
  classDescription: "Presentation Device Prompt",
  QueryInterface: XPCOMUtils.generateQI([Ci.nsIPresentationDevicePrompt, Ci.nsIObserver]),

  _selectedDevice: null,

  // nsIPresentationDevicePrompt
  promptDeviceSelection: function(aRequest) {
    debug("promptDeviceSelection");
    if (this._selectedDevice) {
      debug("selected device id = " + this._selectedDevice.name);
      aRequest.select(this._selectedDevice);
    } else {
      debug("_selectedDevice is null");
      aRequest.cancel();
    }
  },

  observe: function(aSubject, aTopic, aDeviceId) {
    // this observer will be added in CastingApps
    if (aTopic === "presentation-select-device") {
      Services.obs.removeObserver(this, "presentation-select-device");
      debug("observe presentation-select-device: id = " + aDeviceId);
      this._selectedDevice = this._getDeviceById(aDeviceId);
      Services.obs.notifyObservers(this, "presentation-prompt-ready", aDeviceId);
    } else {
      debug("unrecognized topic");
    }
  },

  _getDeviceById: function(aDeviceId) {
    let deviceManager = Cc["@mozilla.org/presentation-device/manager;1"]
                          .getService(Ci.nsIPresentationDeviceManager);
    let devices = deviceManager.getAvailableDevices().QueryInterface(Ci.nsIArray);

    for (let i = 0; i < devices.length; i++) {
      let device = devices.queryElementAt(i, Ci.nsIPresentationDevice);
      if (device.id === aDeviceId) {
        return device;
      }
    }

    return null;
  },
};

this.NSGetFactory = XPCOMUtils.generateNSGetFactory([PresentationDevicePrompt]);
