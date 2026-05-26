/*
 * mini_acl.h -- Public API for the mini ACL library.
 *
 * A standalone, dependency-free reimplementation of the core concepts of
 * the DPDK Access Control (ACL) library: N-tuple packet classification
 * with priority resolution and parallel multi-category lookup.
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

/* Opaque-ish classification context. */
struct acl_ctx {
    const struct acl_field_def *defs;
    int num_fields;
    int num_categories;
    struct acl_rule rules[ACL_MAX_RULES];
    int num_rules;
    int built;
};

/* Lifecycle -- mirrors rte_acl_create / add_rules / build / classify. */
void acl_create(struct acl_ctx *ctx, const struct acl_field_def *defs,
                int num_fields, int num_categories);

int  acl_add_rules(struct acl_ctx *ctx,
                   const struct acl_rule *rules, int n);

int  acl_build(struct acl_ctx *ctx);

/* For each key, writes num_categories results: results[k*ncat + c]. */
void acl_classify(const struct acl_ctx *ctx,
                  const uint8_t **keys, int num_keys,
                  uint32_t *results);

/* Lower-level helpers, exposed for testing and reuse. */
uint32_t acl_extract_field(const uint8_t *key,
                           const struct acl_field_def *def);

int acl_field_matches(enum acl_field_type type, uint32_t key_val,
                      const struct acl_field_val *rf, uint8_t size);

#endif /* MINI_ACL_H */
