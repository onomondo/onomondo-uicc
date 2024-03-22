Onomondo software SIM/USIM implementation
=========================================

This repository contains a pure software
implementation/emulation of the most relevant SIM/UICC/USIM functionalities.

You can run the code contained in this repository to implement the functionality
normally done in a phsical SIM/USIM, covering:

* ETSI UICC (Universal Integrated Chip Card) multi-application card as described in ETSI TS 102 221
* 3GPP USIM (UMTS Subscriber Identity Module) as described in 3GPP TS 31.102


Supported Features
------------------

* APDU command parser / encoder
* BER-TLV encoder/decoder (ETSI TS 101 220 Section 7)
* Smart Card File System with support for
  * MF, DF, EF (linear fixed, transparent)
  * ADF for applications like USIM
  * access rules (Access Rule Referencing)
* File system commands (CREATE FILE, SELECT FILE, STATUS, READ BINARY, UPDATE BINARY, READ RECORD, UPDATE RECORD, SEARCH RECORD)
* PIN management commands (VERIFY PIN, CHANGE PIN, ENABLE PIN, DISABLE PIN, UNBLOCK PIN)
* USIM Authentication + Key Agreement using MILENAGE
* CAT / Proactive SIM (TERMINAL PROFILE / ENVELOPE / FETCH (REFRESH)) as far as required for OTA
* OTA (Over The Air) acccess
  * Secured Packet Structure as per ETSI TS 102 225
  * Compact Remote APDU Format as per ETSI TS 102 226
  * Shared FS RFM (Remote File Management)
  * ADF.USIM RFM (Remote File Management)

Unsupported Features
--------------------

* CAT / STK / PROACTIVE support beyond what's required for OTA RFM + REFRESH
* Any kind of applets, whether native or Java applets
* Global Platform and/or SCP (Secure Channel Protocols)
* Cyclic Files
* BER-TLV Files
* ACTIVATION/DEACTIVATION of files
* logical channels (beyond native/default channel and OTA)
* Secure Messaging (ISO 7816-7)
* ISIM application

License
-------

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

The Onomondo UICC Repository is provided under:

- SPDX-License-Identifier: GPL-3.0-only

Being under the terms of the GNU General Public License version 3 only,
according with:

- LICENSE

For files licensed under BSD license, refer to BSD-3-Clause file in the root directory of this source tree.


GIT Repository
--------------

The canonical https access of the repository is https://github.com/onomondo/onomondo-uicc

The canonical git+ssh access of the repository is `git@github.com:onomondo/onomondo-uicc.git`


External Dependencies
---------------------

We try to not create any external dependencies.  This has both technical and licensing
reasons:  We cannot expect to cross-compile most external dependencies to the deep embedded
"close to bare iron" environments of a cellular modem or microcontroller.

If we reuse existing code, it must be under a permissive license (e.g. BSD, MIT), such
as for example the MILENAGE implementation, which we can take from wpa_supplicant, which is
BSD/GPL dual-licensed.


Testing
-------

We expect to have both

* unit tests for individual low-level functions using cunit or autotest in this very repository.
* higher level integration tests written in python, based on pySim, interfacing with the
  virtual SIM card via the TCP based **vpcd** as can be found as part of the open source
  [vsmartcard project](https://frankmorgner.github.io/vsmartcard/virtualsmartcard/README.html)

Getting Started
---------------

### Building from source

Install cmake, make and a c compiler.
(on debian: `apt install build-essential cmake`),
then run:

```
$ cmake -s . -b build -dconfig_use_system_heap=y
$ cmake --build build
$ make
```

### Installing run time dependencies

* Install the VPCD, which links smartsim into the PC/SC smart card APIs and pcsc-tools to for `gscriptor` and `pcsc_scan` (used for interacting with the sim card).
  (On Debian: `apt install vsmartcard-vpcd pcsc-tools`)
* Install pysim [according to its description](https://git.osmocom.org/pysim/about/).

### Running smartsim

Wake up PC/SC, by briefly (or even permanently) running `pcsc_scan`, or a brief run of `socat - /run/pcscd/pcscd.comm`.

```
$ ./src/softsim/softsim
    VPCD     INFO softsim!
    VPCD     INFO connected.
      FS     INFO no file selected
 STORAGE     INFO requested file definition for 3f00 rom host file system: ./files/3f00.def
      FS     INFO no file selected
 STORAGE     INFO requested file definition for 3f00 rom host file system: ./files/3f00.def
...
```

When the program is running, `pcsc_scan` should show the presence of a card in the Virtual PCD reader:

```
 Reader 0: Virtual PCD 00 00
  Event number: 19
  Card state: Card inserted, Shared Mode,
  ATR: 3B 9F 96 80 1F 87 80 31 E0 73 FE 21 1B 67 4A 4C 75 30 34 05 4B A9
[...]
```

With `gscriptor`, selecting the Virtual PCD enables running the test scripts in `./gscriptor/`.

pySim offers interaction with the running softsim card:

```
$ pySim-shell.py -p 0
Using PC/SC reader interface
Waiting for card...
Autodetected card type: sysmoISIM-SJA2
Info: Card is of type: UICC-SIM
[...]
pySIM-shell (MF)>
```

Operation compared to ETSI specifications
-----------------------------------------

The SoftSIM largely operates as described by the relevant specifications
(ETSI TS 102 series and ISO 7816)
to the extent implemented and necessary.

Aspects of its operation that the specifications do not describe are outlined here,
with details in the code's in-line documentation:

* The life cycle of the card is expressed in the master file's life cycle bit:
  while it is in creation or initialization state, access controls are suspended to allow bottstrapping the file system.
  Consequently, the master file needs to be in one of these two states when it is created,
  and the initialization is finished by executing the ACTIVATE command on the master file.

  This is aligned with how ISO 7816 expresses privileges (in that termination of the master file is equated to termination of card usage).

* Data that needs to be persisted on the card
  but is not accessed by the applications through the file system
  still utilizes the file system as a consistent layer of abstraction for all the SoftSIM's persistent storage requirements.

  Data such as PINs and key material is stored in files whose access controls never allow access.
  (Access control does not apply to read and write operations originating within the SoftSIM).
  These files may use an extended range of file IDs (32bit rather than 16bit) that is in acccessible through regular file commands such as SELECT.

* Requirements on the file system, summarized:

  * All files: Access control is exclusively managed through EF.ARR references.
  * MF: At creation, life cycle is set to 3.
  * ADF.USIM / EF.UST: Service 27 needs (GSM access) to be enabled.

* Overview of proprietary files:
  * A001: SIM authentication keys
  * A1xx: SIM authentication sequence numbers
  * A003: PINs and their state
  * A004: TARs and keys for remote commands (OTA RFM)

* Permissions granted to the remotes in OTA RFM are expressed in terms of PINs (CHVs) to allow unified management of permissions.
  The PINs active with any given OTA TAR are hard-coded in `setup_ctx_from_tar` until the need for further customization arises;
  by default, the ADM1 PIN is set.
