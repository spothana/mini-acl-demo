# mini_acl

A standalone, **dependency-free** reimplementation of the core concepts of the
[DPDK Access Control (ACL) library](https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html):
N-tuple packet classification with priority resolution and parallel
multi-category lookup.

No DPDK, no kernel modules — just a C11 compiler and CMake.

## Layout

```
mini_acl/
├── CMakeLists.txt        build configuration
├── include/mini_acl.h    public API
├── src/mini_acl.c        the classification engine (library)
├── src/demo.c            reproduces the DPDK docs example
├── src/test_acl.c        unit + integration tests
└── docs/index.html       animated explanation of acl_classify()
```

## Build & run

```sh
cmake -S . -B build
cmake --build build
./build/acl_demo        # run the demo
ctest --test-dir build  # run the tests
```

## What it does

The library mirrors the DPDK ACL lifecycle:

| mini_acl              | DPDK equivalent      |
|-----------------------|----------------------|
| `acl_create()`        | `rte_acl_create()`   |
| `acl_add_rules()`     | `rte_acl_add_rules()`|
| `acl_build()`         | `rte_acl_build()`    |
| `acl_classify()`      | `rte_acl_classify()` |

It supports the three field-match types — `MASK` (value + prefix length),
`RANGE` (low/high bounds), and `BITMASK` (value + bit mask) — and rules
carry `priority`, a `category_mask`, and `userdata`.

The demo reproduces the documentation's IPv4 5-tuple example and prints the
same per-category result arrays: `{2,3,0,0}`, `{1,1,0,0}`, `{0,3,0,0}`.

## What it simplifies

DPDK compiles rules into multi-bit tries at `build()` time for line-rate
classification across SIMD-parallel packet batches. mini_acl's `build()`
just marks the context ready and `classify()` does a transparent linear
scan. The *observable behaviour* — matches, priority resolution, per-category
results — is identical; only the runtime data structure differs.

## Docs

Open `docs/index.html` in a browser for an animated walkthrough of how a
packet is tested against the rule set field by field, and how the four
category results fill in independently.
