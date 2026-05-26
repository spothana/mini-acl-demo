# mini_acl

A standalone, **dependency-free** reimplementation of the core concepts of
the [DPDK Access Control (ACL) library](https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html):
N-tuple packet classification with priority resolution and parallel
multi-category lookup.

No DPDK, no kernel modules — just a C11 compiler and CMake.

## Layout

```
mini-acl-demo/
├── CMakeLists.txt        build configuration
├── include/mini_acl.h    public API
├── src/mini_acl.c        the classification engine (library)
├── src/demo.c            reproduces the DPDK docs example
├── src/test_acl.c        unit tests + scalar/trie equivalence sweep
└── docs/index.html       animated explanation of the loop AND the trie
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

| mini-acl-demo          | DPDK equivalent      |
|-------------------|----------------------|
| `acl_create()`    | `rte_acl_create()`   |
| `acl_add_rules()` | `rte_acl_add_rules()`|
| `acl_build()`     | `rte_acl_build()`    |
| `acl_classify()`  | `rte_acl_classify()` |
| `acl_free()`      | `rte_acl_free()`     |

It supports the three field-match types — `MASK` (value + prefix length),
`RANGE` (low/high bounds), and `BITMASK` (value + bit mask) — and rules
carry `priority`, a `category_mask`, and `userdata`.

## Two classification backends

This is the heart of the project. There is one rule set and two ways to
classify against it:

* **`ACL_CLASSIFY_SCALAR`** — a linear scan: for each packet, test every
  rule. Simple and obvious, but O(rules) per packet.

* **`ACL_CLASSIFY_TRIE`** — a **multi-bit trie** (stride 8) compiled by
  `acl_build()`. One trie level per key byte; a lookup walks the key one
  byte at a time, following the `[lo,hi]` byte-range branch, to a leaf
  that holds the pre-resolved per-category results. Lookup cost is the
  **key length**, independent of how many rules exist — the same shape
  DPDK uses to reach line rate.

`acl_build()` compiles the trie and makes it the default backend. It also
fills an `acl_build_stats` struct (node count, depth, approximate RT
memory) so the **space/time trade-off is visible** — this is why DPDK
exposes a `max_size` knob on the build.

Both backends return identical results. `demo.c` runs *both* for every
packet and prints `[agree]`; `test_acl.c` proves it the hard way by
sweeping 40 keys and asserting `SCALAR` and `TRIE` match on each one. The
trie is a faster data structure for the same algorithm, never a different
answer.

The demo reproduces the documentation's IPv4 5-tuple example and prints
the same per-category result arrays: `{2,3,0,0}`, `{1,1,0,0}`,
`{0,3,0,0}`.

## What it still simplifies

DPDK additionally splits rules into non-intersecting subsets (multiple
tries) to bound memory, and walks several packets in parallel with SIMD
(SSE / AVX2 / AVX-512 / NEON). mini_acl builds a single trie and walks one
packet at a time. The data-structure shape and the build-time trade-off
are faithful; the production-grade subset-splitting and vectorization are
not implemented.

## Docs

Open `docs/index.html` in a browser for an animated walkthrough: the
classification loop tested field by field, the parallel category results,
and an interactive **trie walk** that consumes the key one byte per level
down to the resolved leaf.
