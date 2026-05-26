/*
 * mini_acl.h -- Public API for the mini ACL library.
 *
 * A standalone, dependency-free reimplementation of the core concepts of
 * the DPDK Access Control (ACL) library: N-tuple packet classification
 * with priority resolution and parallel multi-category lookup.
 *
 * Two classification backends are provided:
 *   - SCALAR : a linear scan over the rules (simple, O(rules) per packet).
 *   - TRIE   : a multi-bit trie (stride 8) compiled at build() time, the
 *              same shape DPDK uses; a lookup walks the key byte by byte.
 * Both produce identical results -- the trie is a faster data structure,
 * not a different algorithm.
 */
#ifndef MINI_ACL_H
#define MINI_ACL_H

#include <stdint.h>

#define ACL_MAX_FIELDS      8
#define ACL_MAX_RULES      64
#define ACL_MAX_CATEGORIES 32

/* Field-match semantics. The meaning of a rule field's two numbers
 * (value, range) depends on which type is chosen. */
enum acl_field_type {
    ACL_FIELD_TYPE_MASK,     /* value = base, range = prefix length  */
    ACL_FIELD_TYPE_RANGE,    /* value = low bound, range = high bound */
    ACL_FIELD_TYPE_BITMASK,  /* value = bits, range = mask of bits    */
};

/* Describes one field of the search key: how to find and read it. */
struct acl_field_def {
    enum acl_field_type type;
    uint8_t size;     /* 1, 2 or 4 bytes                              */
    uint8_t offset;   /* byte offset of this field inside the key buf */
};

struct acl_field_val {
    uint32_t value;
    uint32_t range;
};

/* One classification rule. */
struct acl_rule {
    struct acl_field_val field[ACL_MAX_FIELDS];
    int32_t  priority;        /* higher wins on a tie              */
    uint32_t category_mask;   /* which categories this rule serves */
    uint32_t userdata;        /* returned on a match (0 == none)   */
};

/* Which classification backend acl_classify() should use. */
enum acl_classify_method {
    ACL_CLASSIFY_SCALAR,   /* linear scan over the rules            */
    ACL_CLASSIFY_TRIE,     /* walk the compiled multi-bit trie      */
};

/* --- trie internals (opaque to callers, declared here for sizeof) ---
 *
 * A trie node is a compressed multi-bit node: instead of a dense array
 * of 256 child pointers, it stores a short list of transitions, each
 * covering an inclusive byte range [lo, hi] that leads to one child.
 * This compression is what keeps range/mask fields from exploding the
 * node count -- it is the same idea DPDK's trie compression uses.
 */
#define ACL_TRIE_MAX_TRANS 256

struct acl_trie_node;   /* forward decl */

struct acl_trie_trans {
    uint8_t lo, hi;                 /* inclusive byte range          */
    struct acl_trie_node *child;    /* node reached for that range   */
};

struct acl_trie_node {
    int is_leaf;
    /* leaf payload: resolved result per category (0 == no match) */
    uint32_t result[ACL_MAX_CATEGORIES];
    /* inner payload: byte-range transitions to children */
    struct acl_trie_trans trans[ACL_TRIE_MAX_TRANS];
    int num_trans;
};

/* Statistics gathered during build(), so callers can see the tradeoff. */
struct acl_build_stats {
    int   trie_nodes;       /* total nodes allocated                 */
    int   trie_leaves;      /* of which, leaves                      */
    int   max_depth;        /* deepest path (== key length in bytes) */
    long  bytes;            /* approximate RT memory used by the trie */
};

/* Classification context. */
struct acl_ctx {
    const struct acl_field_def *defs;
    int num_fields;
    int num_categories;
    int key_len;                       /* total key bytes (sum of sizes) */
    struct acl_rule rules[ACL_MAX_RULES];
    int num_rules;
    int built;

    enum acl_classify_method method;   /* default backend (set at build) */
    struct acl_trie_node *trie_root;   /* NULL until build() runs        */
    struct acl_build_stats stats;

    /* Maps trie depth (0..key_len-1) to the actual key byte offset.
     * Field defs may declare non-contiguous offsets (e.g. padding), but
     * the trie consumes one key byte per level; this bridges the two. */
    uint8_t depth_offset[16];
};

/* --- lifecycle: mirrors rte_acl_create / add_rules / build / classify --- */

void acl_create(struct acl_ctx *ctx, const struct acl_field_def *defs,
                int num_fields, int num_categories);

int  acl_add_rules(struct acl_ctx *ctx,
                   const struct acl_rule *rules, int n);

/* Compiles the rule set into a multi-bit trie and records build stats.
 * Returns 0 on success, -1 on misuse, -2 if the trie outgrows limits. */
int  acl_build(struct acl_ctx *ctx);

/* Frees the compiled trie. Safe to call on an unbuilt context. */
void acl_free(struct acl_ctx *ctx);

/* Classify with the context's default backend (TRIE after a build). */
void acl_classify(const struct acl_ctx *ctx,
                  const uint8_t **keys, int num_keys,
                  uint32_t *results);

/* Classify with an explicitly chosen backend -- used to prove the two
 * agree. results layout: results[k * num_categories + c]. */
void acl_classify_with(const struct acl_ctx *ctx,
                       enum acl_classify_method method,
                       const uint8_t **keys, int num_keys,
                       uint32_t *results);

/* --- lower-level helpers, exposed for testing and reuse --- */

uint32_t acl_extract_field(const uint8_t *key,
                           const struct acl_field_def *def);

int acl_field_matches(enum acl_field_type type, uint32_t key_val,
                      const struct acl_field_val *rf, uint8_t size);

const char *acl_method_name(enum acl_classify_method m);

#endif /* MINI_ACL_H */
