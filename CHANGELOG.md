# Changelog

## [2.3.1](https://github.com/onomondo/onomondo-uicc/compare/v2.3.0...v2.3.1) (2026-08-27)


### Bug Fixes

* address the current record when P1 is zero in absolute/current mode ([#165](https://github.com/onomondo/onomondo-uicc/issues/165)) ([a1d19ad](https://github.com/onomondo/onomondo-uicc/commit/a1d19ade181726d84a7c9fb3715a378511fc8971))
* refuse to execute an APDU with malformed length fields ([#142](https://github.com/onomondo/onomondo-uicc/issues/142)) ([d010c0a](https://github.com/onomondo/onomondo-uicc/commit/d010c0a6d186affe4272cbf90cae5906e63fa6f4))
* reject out-of-range record numbers in READ/UPDATE/SEARCH RECORD ([#162](https://github.com/onomondo/onomondo-uicc/issues/162)) ([c410b84](https://github.com/onomondo/onomondo-uicc/commit/c410b849f88702fae478fcb4fea86b8c42fc9ac6))
* report 6982 (not 6900) on access-condition denial, gate SEARCH RECORD by READ access ([#161](https://github.com/onomondo/onomondo-uicc/issues/161)) ([6d1d6f4](https://github.com/onomondo/onomondo-uicc/commit/6d1d6f49d268866066944f3be0c12e7156ac5775))
* report 6986 (not 6981) when a DF is selected for a file-structure command ([#163](https://github.com/onomondo/onomondo-uicc/issues/163)) ([41b7f24](https://github.com/onomondo/onomondo-uicc/commit/41b7f24dcc5f3a52b98851560b90c8d0f78121fc))


### Performance Improvements

* drop the duplicate SEQ_MS lookup in milenage_usim_check ([#157](https://github.com/onomondo/onomondo-uicc/issues/157)) ([6bcf1b8](https://github.com/onomondo/onomondo-uicc/commit/6bcf1b80ff0dfee3c7725bf6cbcadcba7ee92dfc))

## [2.3.0](https://github.com/onomondo/onomondo-uicc/compare/v2.2.1...v2.3.0) (2026-08-25)


### Features

* verify an optional profile CRC32 ([#131](https://github.com/onomondo/onomondo-uicc/issues/131)) ([d0fdbff](https://github.com/onomondo/onomondo-uicc/commit/d0fdbff2553b205b625363e6c2e300f8e9b1995a))


### Bug Fixes

* add missing CONFIG_ALT_FILE_SEPARATOR option to CMakeLists.txt ([#129](https://github.com/onomondo/onomondo-uicc/issues/129)) ([6e0fd57](https://github.com/onomondo/onomondo-uicc/commit/6e0fd57276d61c5d81fb6d19828753631c33f5d5))
* bound APDU reads, free rejected APDUs ([#127](https://github.com/onomondo/onomondo-uicc/issues/127)) ([78bc7e9](https://github.com/onomondo/onomondo-uicc/commit/78bc7e9669e1cbbb49a999978296a8a3717986e2))
* bound the profile parser ([#126](https://github.com/onomondo/onomondo-uicc/issues/126)) ([b1e3ac3](https://github.com/onomondo/onomondo-uicc/commit/b1e3ac355d1f63ac1b472bde89ab45e5c8f7ea76))
* bound the READ BINARY response ([#128](https://github.com/onomondo/onomondo-uicc/issues/128)) ([cf5d267](https://github.com/onomondo/onomondo-uicc/commit/cf5d267f728ba6fee685483684ad7fc8b26ef963))
* check the response buffer before writing the first byte ([#134](https://github.com/onomondo/onomondo-uicc/issues/134)) ([f16ea38](https://github.com/onomondo/onomondo-uicc/commit/f16ea38951da65a058e1dde1e10633421f1b0366))
* check the SEARCH RECORD data length before reading the search mode ([#118](https://github.com/onomondo/onomondo-uicc/issues/118)) ([d56bcef](https://github.com/onomondo/onomondo-uicc/commit/d56bcef9176b0ed5a67c8bb5bcded474c6824edf))
* clear Milenage key material before releasing buffers ([#123](https://github.com/onomondo/onomondo-uicc/issues/123)) ([ade81c2](https://github.com/onomondo/onomondo-uicc/commit/ade81c2d03af5233f2d268fe8b97b79d7e9c47bb))
* correct SFI assignments for EF_AD and EF_EPSLOCI ([#151](https://github.com/onomondo/onomondo-uicc/issues/151)) ([ce5c70f](https://github.com/onomondo/onomondo-uicc/commit/ce5c70fcf6a1dfe5e3f4b02fa78a1a0b2fe0b867))
* enforce the MF check in ss_access_check_command() at runtime ([#119](https://github.com/onomondo/onomondo-uicc/issues/119)) ([292e198](https://github.com/onomondo/onomondo-uicc/commit/292e198f2c2a10d6fae07e97222ff3ac881c0bf3))
* free the COMPREHENSION-TLV and TLV8 list heads when the list decodes empty ([#120](https://github.com/onomondo/onomondo-uicc/issues/120)) ([1e85f87](https://github.com/onomondo/onomondo-uicc/commit/1e85f8753b876cd0841fb9ab04f23dad16569448))
* free the FID record read while resolving an SFI ([#102](https://github.com/onomondo/onomondo-uicc/issues/102)) ([82a1e09](https://github.com/onomondo/onomondo-uicc/commit/82a1e09d4a5dc7b68f0157eec2cb6ff65efdf8b9))
* guard NULL apdu-&gt;lchan on unsuccessful response to prevent segfault ([#96](https://github.com/onomondo/onomondo-uicc/issues/96)) ([02de906](https://github.com/onomondo/onomondo-uicc/commit/02de906af4b6e2d24db2fcb6b1f39e1fb5da6191))
* guard NULL lifecycle status IE in active ACTIVATE FILE ([#121](https://github.com/onomondo/onomondo-uicc/issues/121)) ([4c888ba](https://github.com/onomondo/onomondo-uicc/commit/4c888ba69556ea824bcc9829d942c2c55b1a7572))
* provision the whole profile, or none of it ([#132](https://github.com/onomondo/onomondo-uicc/issues/132)) ([fe2b606](https://github.com/onomondo/onomondo-uicc/commit/fe2b6066586efc6433480e496dbf97dbd1dc9993))
* report an unknown class as 6e00 instead of 6d00 ([#125](https://github.com/onomondo/onomondo-uicc/issues/125)) ([65ba0fe](https://github.com/onomondo/onomondo-uicc/commit/65ba0fefab75f06cf532d10b445ec8441b632608))
* report failure from ss_fs_utils_create_record_file ([#117](https://github.com/onomondo/onomondo-uicc/issues/117)) ([cfa4972](https://github.com/onomondo/onomondo-uicc/commit/cfa49727c1fd02bf1bc726cf18d4e77abfe9eecb))
* reset the PIN retry counter after a successful CHANGE PIN ([#150](https://github.com/onomondo/onomondo-uicc/issues/150)) ([e1cc9bc](https://github.com/onomondo/onomondo-uicc/commit/e1cc9bcd042f377461117dfb6e16b0a6235bd34b))
* scrub OTA key material on every exit and bound the ciphertext header ([#116](https://github.com/onomondo/onomondo-uicc/issues/116)) ([bfddc1d](https://github.com/onomondo/onomondo-uicc/commit/bfddc1d5e5d8476a2fb8691e4a15580670b11b3a))
* survive out-of-memory during SMS reassembly ([#154](https://github.com/onomondo/onomondo-uicc/issues/154)) ([70c8387](https://github.com/onomondo/onomondo-uicc/commit/70c8387f26c823fb8b39b0666ecfe129df9e6e20))
* update only the selected file with the SEQ_MS ([#95](https://github.com/onomondo/onomondo-uicc/issues/95)) ([f3de7b0](https://github.com/onomondo/onomondo-uicc/commit/f3de7b0b2938e34771bf286539ae3d824eea40d6))
* verify AUTN MAC before SQN and report incorrect MAC as 9862 ([#103](https://github.com/onomondo/onomondo-uicc/issues/103)) ([60ff570](https://github.com/onomondo/onomondo-uicc/commit/60ff570c2d295315092ad75f31e6f97c438dbc7d))


### Performance Improvements

* compile the TLV dump helpers out when logging is off ([#155](https://github.com/onomondo/onomondo-uicc/issues/155)) ([506ae2f](https://github.com/onomondo/onomondo-uicc/commit/506ae2fc058f7f5eda7eacff93a09af5feb5923c))
* make the REFRESH file-list sizing overridable ([#156](https://github.com/onomondo/onomondo-uicc/issues/156)) ([768f920](https://github.com/onomondo/onomondo-uicc/commit/768f920e9c57860c317abe2418e39fa51ec79f69))

## [2.2.1](https://github.com/onomondo/onomondo-uicc/compare/v2.2.0...v2.2.1) (2026-07-06)


### Bug Fixes

* correct address extension bit decoding for SMS ([#57](https://github.com/onomondo/onomondo-uicc/issues/57)) ([3cce311](https://github.com/onomondo/onomondo-uicc/commit/3cce31157e67d0490d2d01a131dd9e331c28c1aa))
* propagate SMS-RX error from SMS-PP ENVELOPE handler ([#74](https://github.com/onomondo/onomondo-uicc/issues/74)) ([6c66125](https://github.com/onomondo/onomondo-uicc/commit/6c66125808e3b9017d8e9480c3918f63bdab90f2))
* return negative SW from parse_cmd_hdr_clrtxt on packet-too-short ([#73](https://github.com/onomondo/onomondo-uicc/issues/73)) ([28b9da5](https://github.com/onomondo/onomondo-uicc/commit/28b9da5d1c2d6f7c77bc92a2320aceee159fee50))
* return success from GSM-context AUTHENTICATE ([#82](https://github.com/onomondo/onomondo-uicc/issues/82)) ([7da767e](https://github.com/onomondo/onomondo-uicc/commit/7da767ed3b6570ca6bbd9aef06646f5b94456f4e))

## [2.2.0](https://github.com/onomondo/onomondo-uicc/compare/v2.1.0...v2.2.0) (2026-06-02)


### Features

* add storage_compact.c ([#39](https://github.com/onomondo/onomondo-uicc/issues/39)) ([4d4b900](https://github.com/onomondo/onomondo-uicc/commit/4d4b9000b1976d4a01ade941a9b03e88976627ee))


### Bug Fixes

* allow APDU responses shorter than requested Le ([#59](https://github.com/onomondo/onomondo-uicc/issues/59)) ([0dfa2cc](https://github.com/onomondo/onomondo-uicc/commit/0dfa2cc8229b6c068b57a30f0e30864b072ce950))
* clamp in_len to key buffer size in ss_load_key_external ([#63](https://github.com/onomondo/onomondo-uicc/issues/63)) ([41c1ac7](https://github.com/onomondo/onomondo-uicc/commit/41c1ac7a384181cb29b90f2e61fd7b81cc820c1b))
* ENVELOPE returns SW=6A81 and prevent abort on 256-byte returns ([#53](https://github.com/onomondo/onomondo-uicc/issues/53)) ([a051df3](https://github.com/onomondo/onomondo-uicc/commit/a051df38e7788061ee5b9c18f1eb5e529e412edb))
* get proper value for ss_dirs_len ([#20](https://github.com/onomondo/onomondo-uicc/issues/20)) ([dc77cf8](https://github.com/onomondo/onomondo-uicc/commit/dc77cf8c64caead22588a0fe6f7943b775553b00))
* storage compact matching nrf-softsim ([#43](https://github.com/onomondo/onomondo-uicc/issues/43)) ([e6ebde1](https://github.com/onomondo/onomondo-uicc/commit/e6ebde1e6fe4d10e95d1e6f0098efb62475dc524))
* support Case 1 APDUs and STATUS Le handling for nRF91 modem ([#36](https://github.com/onomondo/onomondo-uicc/issues/36)) ([d9809ed](https://github.com/onomondo/onomondo-uicc/commit/d9809edb4dfb20697f0fd3498b31169dbfddbeca))
* VERIFY PIN returns SW=6700 via ss_application_apdu_transact ([#52](https://github.com/onomondo/onomondo-uicc/issues/52)) ([058fa9c](https://github.com/onomondo/onomondo-uicc/commit/058fa9cc2d68b26a4354ee46fc24f41e61f3174d))

## [2.1.0](https://github.com/onomondo/onomondo-uicc/compare/v2.0.1...v2.1.0) (2025-12-05)


### Features

* configurable softsim storage path ([#22](https://github.com/onomondo/onomondo-uicc/issues/22)) ([31918a5](https://github.com/onomondo/onomondo-uicc/commit/31918a547c9fc168c2959ec1cd8e6ad25b1d6dc4))
* introduce new smsc tag ([#30](https://github.com/onomondo/onomondo-uicc/issues/30)) ([43be4c8](https://github.com/onomondo/onomondo-uicc/commit/43be4c8b7d870137078a5175c002b8ceb67c1ebd))
* use PROJECT_SOURCE_DIR to ease CMake project integration ([#34](https://github.com/onomondo/onomondo-uicc/issues/34)) ([e3a5a0d](https://github.com/onomondo/onomondo-uicc/commit/e3a5a0d31bb829ad8a4bd7b75c51a7f34856a4c3))
* utility function to assist profile provisioning ([#29](https://github.com/onomondo/onomondo-uicc/issues/29)) ([770ff6e](https://github.com/onomondo/onomondo-uicc/commit/770ff6ebe6b4332bca05bd83ada26b95a5189a1f))


### Bug Fixes

* EF FCP response not to include tag C6 (PIN Status Template) ([#26](https://github.com/onomondo/onomondo-uicc/issues/26)) ([57b0c82](https://github.com/onomondo/onomondo-uicc/commit/57b0c82801bcd6fc5b29c726aef42bb55d84d3df))

## [2.0.1](https://github.com/onomondo/onomondo-uicc/compare/v2.0.0...v2.0.1) (2025-12-01)


### Bug Fixes

* parsed EF.SMSP length of tlv hex profile ([#28](https://github.com/onomondo/onomondo-uicc/issues/28)) ([d326ad9](https://github.com/onomondo/onomondo-uicc/commit/d326ad9164b86e3eb32e2b51ed1ffdcb397a9460))
* prevent double tag skipping in case of unknown tag ([#25](https://github.com/onomondo/onomondo-uicc/issues/25)) ([cba9823](https://github.com/onomondo/onomondo-uicc/commit/cba9823c6121dc23bdfcbd31f8d51d40c647fe9a))
* properly initialize argument 'fdset' of select() ([#16](https://github.com/onomondo/onomondo-uicc/issues/16)) ([adf43b2](https://github.com/onomondo/onomondo-uicc/commit/adf43b26de65ed59371e3b4af9bee680791a5b96))
* use max proposed suspend duration ([#24](https://github.com/onomondo/onomondo-uicc/issues/24)) ([c694458](https://github.com/onomondo/onomondo-uicc/commit/c6944589acb83ce075c691ee6585233627410c27))
* use proper variable to retrieve SFI ([#14](https://github.com/onomondo/onomondo-uicc/issues/14)) ([55c0385](https://github.com/onomondo/onomondo-uicc/commit/55c0385a6c64feded928b952497a137e2d9c846e))

## [2.0.0](https://github.com/onomondo/onomondo-uicc/compare/v1.0.0...v2.0.0) (2024-07-30)


### Features

* CMake build system for softsim UICC, new `utils` library and test targets ([#7](https://github.com/onomondo/onomondo-uicc/pull/7))
* add optional external heap allocator ([e323c51](https://github.com/onomondo/onomondo-uicc/commit/e323c5189911434e30d3014cf2954bed880934b9))
* add pseudo support for uicc suspend ([d0195b5](https://github.com/onomondo/onomondo-uicc/commit/d0195b57b5a24995f745eabcd8ddb08c9f385716))
* cmake build tests with address sanitizer ([593de0c](https://github.com/onomondo/onomondo-uicc/commit/593de0c4a613766501d9b3f417b06c4f607fe42e))
* use a file for each seq and delta value ([de1408a](https://github.com/onomondo/onomondo-uicc/commit/de1408a55a5e131273489d1fb58f0924891b4d5f))
* add support for application layer APDU ([51ef10a](https://github.com/onomondo/onomondo-uicc/commit/51ef10ae21af9a19e98e73e02a75c8f6451a67a6))
* onomondo profile decoding functionality ([ccfb88d](https://github.com/onomondo/onomondo-uicc/commit/ccfb88d17cbd8afe3058d5c560dc758cd18139ad))
* add option to link against custom crypto implementations ([c8608df](https://github.com/onomondo/onomondo-uicc/commit/c8608dfe422a60a08e2a51849a61b12faa0e8438))
* optional default impl, option to build lib only, remove ctype ([473f88b](https://github.com/onomondo/onomondo-uicc/commit/473f88ba8e23867d4cc12d1930b4de56462d317d))
* export files to c-arrays and validate ([71bbfa4](https://github.com/onomondo/onomondo-uicc/commit/71bbfa40a00ea7f8c65b5721bbe3bcb9d314ce6f))
* make the utils part of the installed targets if enabled ([8fe7797](https://github.com/onomondo/onomondo-uicc/commit/8fe7797d7acca400a134e8a5f1489ce20846d05d))
* move filesystem create to utils folder ([236b186](https://github.com/onomondo/onomondo-uicc/commit/236b18623c5573ecb6ba7a82f8d5f05cec0c18a4))

### Bug Fixes

* make uicc suspend an optional build flag ([d8a8d29](https://github.com/onomondo/onomondo-uicc/commit/d8a8d2994b94dd451efec8492ba7d9425c0dc477))
* bad python version breaks unit testing ([de08053](https://github.com/onomondo/onomondo-uicc/commit/de080538c6092c5dc079101066aed959d9f120d8))
* use c89 style for loops to keep older compilers happy ([1df09ab](https://github.com/onomondo/onomondo-uicc/commit/1df09abf4284c50b28f76cdda5435ad8674953c0))
* check for bad lc in apdu handler ([27fabb3](https://github.com/onomondo/onomondo-uicc/commit/27fabb3b8f0479d71ce115253d57804b0a4a9193))
* cmake preprocessor define syntax ([b0969b7](https://github.com/onomondo/onomondo-uicc/commit/b0969b78af1089a1e93a8128613d07c50d1a8fa6))

## [1.0.0](https://github.com/onomondo/onomondo-uicc/releases/tag/v1.0.0) (2024-02-14)


### Initial Version

* Initial project commit, adding the core UICC softsim source tree, include headers, initial tests, and examples. ([1e956d0](https://github.com/onomondo/onomondo-uicc/commit/1e956d053c3f5dab9be367d8407ed8caf75ea871))

### Features

* Basic UICC softsim implementation, test-suite scaffolding, and README.
