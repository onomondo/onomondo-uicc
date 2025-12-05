# Changelog

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
