/*
 * mini_acl.c -- Implementation of the mini ACL library.
 *
 * The real DPDK library compiles rules into multi-bit tries for line-rate
 * classification. This implementation keeps the matching logic transparent:
 * build() simply marks the context ready and classify() does a linear scan.
 * The observable behaviour (priority resolution, per-category results) is
 * identical to DPDK's.
 */
#include "mini_acl.h"
#include <string.h>

void acl_create(struct acl_ctx *ctx, const struct acl_field_def *defs,
                int num_fields, int num_categories)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->defs           = defs;
    ctx->num_fields     = num_fields;
    ctx->num_categories = num_categories;
}

int acl_add_rules(struct acl_ctx *ctx, const struct acl_rule *rules, int n)
{
    if (n < 0 || ctx->num_rules + n > ACL_MAX_RULES)
        return -1;
    memcpy(&ctx->rules[ctx->num_rules], rules, n * sizeof(*rules));
    ctx->num_rules += n;
    return 0;
}

int acl_build(struct acl_ctx *ctx)
{
    if (ctx->num_fields <= 0 || ctx->num_categories <= 0)
        return -1;
    ctx->built = 1;
    return 0;
}

/* Pull `size` bytes from the key at the field offset and interpret them
 * big-endian (network byte order) -- what DPDK expects of input tuples. */
uint32_t acl_extract_field(const uint8_t *key,
                           const struct acl_field_def *def)
{
    uint32_t v = 0;
    for (int i = 0; i < def->size; i++)
        v = (v << 8) | key[def->offset + i];
    return v;
}

int acl_field_matches(enum acl_field_type type, uint32_t key_val,
                      const struct acl_field_val *rf, uint8_t size)
{
    switch (type) {
    case ACL_FIELD_TYPE_MASK: {
        int bits  = (int)rf->range;        /* prefix length             */
        int total = size * 8;
        if (bits == 0) return 1;           /* /0 == wildcard            */
        if (bits >= total) return key_val == rf->value;
        uint32_t mask = ~((uint32_t)0) << (total - bits);
        return (key_val & mask) == (rf->value & mask);
    }
    case ACL_FIELD_TYPE_RANGE:
        return key_val >= rf->value && key_val <= rf->range;

    case ACL_FIELD_TYPE_BITMASK:
        return (key_val & rf->range) == (rf->value & rf->range);
    }
    return 0;
}

static int rule_matches(const struct acl_ctx *ctx,
                        const struct acl_rule *r, const uint8_t *key)
{
    for (int f = 0; f < ctx->num_fields; f++) {
        uint32_t kv = acl_extract_field(key, &ctx->defs[f]);
        if (!acl_field_matches(ctx->defs[f].type, kv,
                               &r->field[f], ctx->defs[f].size))
            return 0;
    }
    return 1;
}

void acl_classify(const struct acl_ctx *ctx,
                  const uint8_t **keys, int num_keys,
                  uint32_t *results)
{
    for (int k = 0; k < num_keys; k++) {
        uint32_t *res = &results[k * ctx->num_categories];
        int32_t  best_pri[ACL_MAX_CATEGORIES];

        for (int c = 0; c < ctx->num_categories; c++) {
            res[c]      = 0;
            best_pri[c] = INT32_MIN;
        }
        for (int i = 0; i < ctx->num_rules; i++) {
            const struct acl_rule *r = &ctx->rules[i];
            if (!rule_matches(ctx, r, keys[k]))
                continue;
            for (int c = 0; c < ctx->num_categories; c++) {
                if (!(r->category_mask & (1u << c)))
                    continue;
                if (r->priority > best_pri[c]) {
                    best_pri[c] = r->priority;
                    res[c]      = r->userdata;
                }
            }
        }
    }
}
