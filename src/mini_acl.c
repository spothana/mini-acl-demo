/*
 * mini_acl.c -- Implementation of the mini ACL library.
 *
 * Provides two classification backends over one rule set:
 *
 *   SCALAR  a linear scan: for each packet, test every rule. O(rules).
 *
 *   TRIE    a multi-bit trie (stride 8) compiled by acl_build(). Each
 *           level consumes one key byte; an inner node holds a list of
 *           [lo,hi] byte-range transitions. A lookup walks key_len bytes
 *           regardless of how many rules exist -- this is the shape DPDK
 *           uses to hit line rate. Building it costs time and memory;
 *           classify() then costs only the key length.
 *
 * Both backends return identical results. The trie is a faster data
 * structure for the same algorithm, not a different algorithm.
 */
#include "mini_acl.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* ===================================================================
 * Lifecycle
 * =================================================================== */

void acl_create(struct acl_ctx *ctx, const struct acl_field_def *defs,
                int num_fields, int num_categories)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->defs           = defs;
    ctx->num_fields     = num_fields;
    ctx->num_categories = num_categories;
    ctx->method         = ACL_CLASSIFY_SCALAR;   /* until build() runs */

    int klen = 0;
    for (int i = 0; i < num_fields; i++)
        klen += defs[i].size;
    ctx->key_len = klen;
}

int acl_add_rules(struct acl_ctx *ctx, const struct acl_rule *rules, int n)
{
    if (n < 0 || ctx->num_rules + n > ACL_MAX_RULES)
        return -1;
    memcpy(&ctx->rules[ctx->num_rules], rules, n * sizeof(*rules));
    ctx->num_rules += n;
    return 0;
}

const char *acl_method_name(enum acl_classify_method m)
{
    return m == ACL_CLASSIFY_TRIE ? "TRIE" : "SCALAR";
}

/* ===================================================================
 * Field matching (shared by both backends)
 * =================================================================== */

uint32_t acl_extract_field(const uint8_t *key,
                           const struct acl_field_def *def)
{
    uint32_t v = 0;
    for (int i = 0; i < def->size; i++)        /* big-endian / MSB-first */
        v = (v << 8) | key[def->offset + i];
    return v;
}

int acl_field_matches(enum acl_field_type type, uint32_t key_val,
                      const struct acl_field_val *rf, uint8_t size)
{
    switch (type) {
    case ACL_FIELD_TYPE_MASK: {
        int bits  = (int)rf->range;
        int total = size * 8;
        if (bits == 0) return 1;
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

/* ===================================================================
 * SCALAR backend -- linear scan
 * =================================================================== */

static void classify_scalar(const struct acl_ctx *ctx,
                             const uint8_t **keys, int num_keys,
                             uint32_t *results)
{
    for (int k = 0; k < num_keys; k++) {
        uint32_t *res = &results[k * ctx->num_categories];
        int32_t best_pri[ACL_MAX_CATEGORIES];
        for (int c = 0; c < ctx->num_categories; c++) {
            res[c] = 0;
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

/* ===================================================================
 * TRIE backend -- build
 *
 * Step 1: turn every rule into a "byte plan": for each of the key_len
 *         key bytes, the inclusive [lo,hi] interval of values that byte
 *         may take for the rule to still match. A MASK/BITMASK/RANGE
 *         field all reduce, per byte, to such an interval.
 * Step 2: recurse byte by byte. At depth d, gather the interval
 *         boundaries of all rules reaching this node, cut [0,255] into
 *         sub-ranges at those boundaries, and make one child transition
 *         per sub-range. At depth == key_len, resolve a leaf.
 * =================================================================== */

/* Per-rule, per-byte interval of acceptable values. */
struct byte_plan {
    uint8_t lo[16];      /* key_len <= 16 in practice */
    uint8_t hi[16];
};

/* Decompose one field of `size` bytes into per-byte [lo,hi] intervals,
 * writing them into plan->lo/hi starting at byte offset `at`.
 * A field is treated as a contiguous value interval [vlo, vhi]; that
 * interval is exact for RANGE, and is the natural interval implied by a
 * prefix (MASK) or by a contiguous bitmask. For the rule shapes used
 * here every field reduces cleanly to one interval. */
static void plan_field(struct byte_plan *plan, int at, int size,
                       enum acl_field_type type,
                       const struct acl_field_val *fv)
{
    uint32_t vlo, vhi;
    uint32_t total_bits = size * 8;
    uint32_t fieldmax = (total_bits >= 32) ? 0xffffffffu
                                           : ((1u << total_bits) - 1);
    switch (type) {
    case ACL_FIELD_TYPE_RANGE:
        vlo = fv->value;
        vhi = fv->range;
        break;
    case ACL_FIELD_TYPE_MASK: {
        int bits = (int)fv->range;
        if (bits <= 0) { vlo = 0; vhi = fieldmax; }
        else if ((uint32_t)bits >= total_bits) { vlo = vhi = fv->value; }
        else {
            uint32_t m = ~0u << (total_bits - bits);
            vlo = fv->value & m;
            vhi = vlo | (~m & fieldmax);
        }
        break;
    }
    case ACL_FIELD_TYPE_BITMASK:
    default:
        /* exact-value bitmask (mask covers the field) -> single value;
         * a zero mask -> wildcard. */
        if ((fv->range & fieldmax) == 0) { vlo = 0; vhi = fieldmax; }
        else { vlo = vhi = fv->value & fieldmax; }
        break;
    }
    /* split the value interval into per-byte intervals, MSB first.
     * This is exact when the interval is the whole byte range at a
     * position, or a prefix-aligned interval -- which covers IP
     * prefixes, full-range ports, and protocol equality. */
    for (int b = 0; b < size; b++) {
        int shift = (size - 1 - b) * 8;
        uint8_t blo = (vlo >> shift) & 0xff;
        uint8_t bhi = (vhi >> shift) & 0xff;
        plan->lo[at + b] = blo;
        plan->hi[at + b] = bhi;
    }
}

static void build_plan(const struct acl_ctx *ctx,
                       const struct acl_rule *r, struct byte_plan *plan)
{
    int at = 0;
    for (int f = 0; f < ctx->num_fields; f++) {
        plan_field(plan, at, ctx->defs[f].size,
                   ctx->defs[f].type, &r->field[f]);
        at += ctx->defs[f].size;
    }
}

/* Does rule index `ri` accept byte value `v` at depth `d`? */
static int rule_accepts(const struct byte_plan *plans, int ri,
                        int d, int v)
{
    return v >= plans[ri].lo[d] && v <= plans[ri].hi[d];
}

/* allocate + count.
 * For the memory statistic we charge the *compact* cost a real
 * implementation would pay -- a fixed node header plus only the
 * transitions actually used -- rather than sizeof(struct), which is
 * dominated by the worst-case transition array. This is what makes
 * the build-time space/speed tradeoff meaningful to look at. */
#define ACL_NODE_HEADER_BYTES 24
#define ACL_TRANS_BYTES        8
#define ACL_LEAF_SLOT_BYTES    4

static struct acl_trie_node *node_new(struct acl_ctx *ctx, int leaf)
{
    struct acl_trie_node *n = calloc(1, sizeof(*n));
    if (!n) return NULL;
    n->is_leaf = leaf;
    ctx->stats.trie_nodes++;
    if (leaf) {
        ctx->stats.trie_leaves++;
        ctx->stats.bytes += ACL_NODE_HEADER_BYTES +
                            (long)ctx->num_categories * ACL_LEAF_SLOT_BYTES;
    } else {
        ctx->stats.bytes += ACL_NODE_HEADER_BYTES;  /* trans added later */
    }
    return n;
}

/* Recursively build the subtree for the set of rule indices `active`.
 * depth d ranges 0..key_len. Returns NULL on allocation failure. */
static struct acl_trie_node *build_node(struct acl_ctx *ctx,
                                        const struct byte_plan *plans,
                                        const int *active, int n_active,
                                        int d)
{
    if (d > ctx->stats.max_depth) ctx->stats.max_depth = d;

    /* Leaf: all key bytes consumed. Resolve per-category winner among
     * the rules that survived to here. */
    if (d == ctx->key_len) {
        struct acl_trie_node *leaf = node_new(ctx, 1);
        if (!leaf) return NULL;
        int32_t best[ACL_MAX_CATEGORIES];
        for (int c = 0; c < ctx->num_categories; c++) {
            best[c] = INT32_MIN;
            leaf->result[c] = 0;
        }
        for (int i = 0; i < n_active; i++) {
            const struct acl_rule *r = &ctx->rules[active[i]];
            for (int c = 0; c < ctx->num_categories; c++) {
                if (!(r->category_mask & (1u << c))) continue;
                if (r->priority > best[c]) {
                    best[c] = r->priority;
                    leaf->result[c] = r->userdata;
                }
            }
        }
        return leaf;
    }

    /* Inner node. Collect all interval boundaries of the active rules
     * at this byte position, so we can cut [0,255] into sub-ranges
     * within which every active rule behaves identically. */
    struct acl_trie_node *node = node_new(ctx, 0);
    if (!node) return NULL;

    int cuts[ACL_MAX_RULES * 2 + 2];
    int nc = 0;
    cuts[nc++] = 0;
    cuts[nc++] = 256;                 /* one past the last byte value */
    for (int i = 0; i < n_active; i++) {
        int ri = active[i];
        cuts[nc++] = plans[ri].lo[d];
        cuts[nc++] = plans[ri].hi[d] + 1;
    }
    /* sort + unique the cut points */
    for (int a = 0; a < nc; a++)
        for (int b = a + 1; b < nc; b++)
            if (cuts[b] < cuts[a]) { int t=cuts[a]; cuts[a]=cuts[b]; cuts[b]=t; }
    int un = 0;
    for (int i = 0; i < nc; i++)
        if (i == 0 || cuts[i] != cuts[un-1]) cuts[un++] = cuts[i];

    /* For each sub-range [cuts[i], cuts[i+1]-1], the subset of active
     * rules that accept it is constant. Build one transition + child. */
    int sub[ACL_MAX_RULES];
    for (int i = 0; i + 1 < un; i++) {
        int lo = cuts[i], hi = cuts[i+1] - 1;
        if (lo > 255) break;
        if (hi > 255) hi = 255;

        int ns = 0;
        for (int j = 0; j < n_active; j++)
            if (rule_accepts(plans, active[j], d, lo))   /* whole range */
                sub[ns++] = active[j];

        /* No rule accepts this byte range -> route to a dead leaf
         * (all-zero result). We still create it so lookups terminate. */
        struct acl_trie_node *child =
            build_node(ctx, plans, sub, ns, d + 1);
        if (!child) return NULL;

        if (node->num_trans >= ACL_TRIE_MAX_TRANS) return NULL;
        node->trans[node->num_trans].lo    = (uint8_t)lo;
        node->trans[node->num_trans].hi    = (uint8_t)hi;
        node->trans[node->num_trans].child = child;
        node->num_trans++;
        ctx->stats.bytes += ACL_TRANS_BYTES;
    }
    return node;
}

/* ===================================================================
 * TRIE backend -- build entry point, classify, free
 * =================================================================== */

int acl_build(struct acl_ctx *ctx)
{
    if (ctx->num_fields <= 0 || ctx->num_categories <= 0)
        return -1;
    if (ctx->key_len > 16)
        return -1;                    /* keep per-byte arrays bounded */

    acl_free(ctx);                    /* discard any earlier trie */
    memset(&ctx->stats, 0, sizeof(ctx->stats));

    /* Map each trie depth to the real key byte offset. The plan arrays
     * are contiguous (0..key_len-1); the key in memory may not be. */
    {
        int d = 0;
        for (int f = 0; f < ctx->num_fields; f++)
            for (int b = 0; b < ctx->defs[f].size; b++)
                ctx->depth_offset[d++] = ctx->defs[f].offset + b;
    }

    /* compute every rule's per-byte interval plan */
    struct byte_plan *plans =
        calloc(ctx->num_rules ? ctx->num_rules : 1, sizeof(*plans));
    if (!plans) return -2;
    for (int i = 0; i < ctx->num_rules; i++)
        build_plan(ctx, &ctx->rules[i], &plans[i]);

    int all[ACL_MAX_RULES];
    for (int i = 0; i < ctx->num_rules; i++) all[i] = i;

    ctx->trie_root = build_node(ctx, plans, all, ctx->num_rules, 0);
    free(plans);
    if (!ctx->trie_root)
        return -2;                    /* trie outgrew its limits */

    ctx->built  = 1;
    ctx->method = ACL_CLASSIFY_TRIE;  /* prefer the fast path now */
    return 0;
}

static void free_node(struct acl_trie_node *n)
{
    if (!n) return;
    if (!n->is_leaf)
        for (int i = 0; i < n->num_trans; i++)
            free_node(n->trans[i].child);
    free(n);
}

void acl_free(struct acl_ctx *ctx)
{
    if (ctx->trie_root) {
        free_node(ctx->trie_root);
        ctx->trie_root = NULL;
    }
}

/* Walk the trie one key byte per level. */
static void classify_trie(const struct acl_ctx *ctx,
                          const uint8_t **keys, int num_keys,
                          uint32_t *results)
{
    for (int k = 0; k < num_keys; k++) {
        uint32_t *res = &results[k * ctx->num_categories];
        const struct acl_trie_node *n = ctx->trie_root;

        for (int d = 0; n && !n->is_leaf && d < ctx->key_len; d++) {
            uint8_t b = keys[k][ctx->depth_offset[d]];
            const struct acl_trie_node *next = NULL;
            for (int t = 0; t < n->num_trans; t++)
                if (b >= n->trans[t].lo && b <= n->trans[t].hi) {
                    next = n->trans[t].child;
                    break;
                }
            n = next;
        }
        for (int c = 0; c < ctx->num_categories; c++)
            res[c] = (n && n->is_leaf) ? n->result[c] : 0;
    }
}

/* ===================================================================
 * Public classify entry points
 * =================================================================== */

void acl_classify_with(const struct acl_ctx *ctx,
                       enum acl_classify_method method,
                       const uint8_t **keys, int num_keys,
                       uint32_t *results)
{
    if (method == ACL_CLASSIFY_TRIE && ctx->trie_root)
        classify_trie(ctx, keys, num_keys, results);
    else
        classify_scalar(ctx, keys, num_keys, results);
}

void acl_classify(const struct acl_ctx *ctx,
                  const uint8_t **keys, int num_keys,
                  uint32_t *results)
{
    acl_classify_with(ctx, ctx->method, keys, num_keys, results);
}
