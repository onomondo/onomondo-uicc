# Onomondo UICC documentation

A portable, dependency-free C implementation of a SIM/UICC/USIM. These pages document
what the code cannot say on its own — contracts, hazards and design. The
[top-level README](../README.md) stays authoritative for the feature summary, license,
external-dependency policy, contributing rules, and the demo/test setup.

## Which page

| You are | Read |
|---|---|
| Consuming the library as-is, on a unix or embedded host | [integration.md](integration.md) — API and buffer contracts, CMake, the port surface, storage backends, provisioning |
| Changing the library | [architecture.md](architecture.md) — code map, state model, storage encoding, testing |

## Sources of truth

| Topic | Where |
|---|---|
| Public API | [`include/onomondo/softsim/softsim.h`](../include/onomondo/softsim/softsim.h) — eight functions |
| Build options | root [`CMakeLists.txt`](../CMakeLists.txt), echoed by [`config.h`](../include/onomondo/softsim/config.h) |
| Feature boundaries, spec deviations, demo setup | [README](../README.md) |
| Fuzzing | [`tests/fuzz/README.md`](../tests/fuzz/README.md) |

## Conventions

Spec claims carry their clause ("TS 102 221 §11.1.1"). "Unix host" means the default
POSIX build; "embedded host" means a flash-backed target supplying the port layer.
Paths are repository-relative.
