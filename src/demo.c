/*
 * demo.c -- Reproduces the IPv4 5-tuple example from the DPDK ACL docs
 *           using the mini ACL library, and shows the trade-off the
 *           trie backend makes: build() compiles a multi-bit trie, and
 *           classify() then walks a fixed number of bytes per packet
 *           instead of scanning every rule.
 *
 * Expected per-category results: {2,3,0,0}, {1,1,0,0}, {0,3,0,0}.
 */
#include "mini_acl.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>   /* htonl / htons -- only to build test packets */

/* Packet key laid out the DPDK way: a 1-byte field first, then 4-byte
 * groups. The two 16-bit ports share the final 4-byte group. */
struct ipv4_key {
    uint8_t  proto;       /* offset 0  */
    uint8_t  _pad[3];     /* keep src_ip 4-aligned */
    uint32_t src_ip;      /* offset 4  (network byte order) */
    uint32_t dst_ip;      /* offset 8  */
    uint16_t src_port;    /* offset 12 */
    uint16_t dst_port;    /* offset 14 */
};

/* field index: 0=proto 1=src_ip 2=dst_ip 3=src_port 4=dst_port.
 * NOTE: offsets here skip the 3 pad bytes so the key the trie sees is
 * 13 contiguous bytes (1 + 4 + 4 + 2 + 2). */
static const struct acl_field_def ipv4_defs[5] = {
    { ACL_FIELD_TYPE_BITMASK, 1, 0  },
    { ACL_FIELD_TYPE_MASK,    4, 4  },
    { ACL_FIELD_TYPE_MASK,    4, 8  },
    { ACL_FIELD_TYPE_RANGE,   2, 12 },
    { ACL_FIELD_TYPE_RANGE,   2, 14 },
};

#define IPV4(a,b,c,d) (((uint32_t)(a)<<24)|((b)<<16)|((c)<<8)|(d))

static const struct acl_rule demo_rules[] = {
    /* rule 1: dst 192.168.0.0/16 -> categories 0 & 1, userdata 1 */
    { .priority = 1, .category_mask = 0x3, .userdata = 1, .field = {
        [0] = {0,0}, [1] = {0,0}, [2] = {IPV4(192,168,0,0),16},
        [3] = {0,0xffff}, [4] = {0,0xffff} } },
    /* rule 2: dst 192.168.1.0/24 -> category 0, userdata 2 */
    { .priority = 2, .category_mask = 0x1, .userdata = 2, .field = {
        [0] = {0,0}, [1] = {0,0}, [2] = {IPV4(192,168,1,0),24},
        [3] = {0,0xffff}, [4] = {0,0xffff} } },
    /* rule 3: src 10.1.1.1 -> category 1, userdata 3 */
    { .priority = 3, .category_mask = 0x2, .userdata = 3, .field = {
        [0] = {0,0}, [1] = {IPV4(10,1,1,1),32}, [2] = {0,0},
        [3] = {0,0xffff}, [4] = {0,0xffff} } },
};

/* Build the 13-byte contiguous key the field defs expect. */
static void fill_key(uint8_t *buf, uint8_t proto,
                     uint32_t src, uint32_t dst, uint16_t sp, uint16_t dp)
{
    uint32_t s = htonl(src), d = htonl(dst);
    uint16_t a = htons(sp),  b = htons(dp);
    buf[0] = proto;
    memcpy(buf + 4,  &s, 4);
    memcpy(buf + 8,  &d, 4);
    memcpy(buf + 12, &a, 2);
    memcpy(buf + 14, &b, 2);
    (void)0;
}

static void run_case(struct acl_ctx *ctx, const char *label,
                      uint32_t src, uint32_t dst)
{
    uint8_t key[16] = {0};
    fill_key(key, 6 /*TCP*/, src, dst, 1024, 80);
    const uint8_t *keys[1] = { key };

    uint32_t r_scalar[4] = {0}, r_trie[4] = {0};
    acl_classify_with(ctx, ACL_CLASSIFY_SCALAR, keys, 1, r_scalar);
    acl_classify_with(ctx, ACL_CLASSIFY_TRIE,   keys, 1, r_trie);

    int agree = memcmp(r_scalar, r_trie, sizeof(r_scalar)) == 0;
    printf("  %-42s scalar={%u,%u,%u,%u}  trie={%u,%u,%u,%u}  %s\n",
           label,
           r_scalar[0],r_scalar[1],r_scalar[2],r_scalar[3],
           r_trie[0],  r_trie[1],  r_trie[2],  r_trie[3],
           agree ? "[agree]" : "[MISMATCH]");
}

int main(void)
{
    struct acl_ctx ctx;

    acl_create(&ctx, ipv4_defs, 5, /* num_categories */ 4);
    if (acl_add_rules(&ctx, demo_rules,
                      sizeof(demo_rules)/sizeof(demo_rules[0])) != 0) {
        fprintf(stderr, "add_rules failed\n");
        return 1;
    }

    int rc = acl_build(&ctx);
    if (rc != 0) {
        fprintf(stderr, "build failed (%d)\n", rc);
        return 1;
    }

    puts("mini-ACL: reproducing the DPDK ACL documentation example");
    puts("");
    puts("rules: 1) dst 192.168.0.0/16  cat{0,1}  pri1  -> userdata 1");
    puts("       2) dst 192.168.1.0/24  cat{0}    pri2  -> userdata 2");
    puts("       3) src 10.1.1.1        cat{1}    pri3  -> userdata 3");
    puts("");

    printf("build(): compiled %d rules into a multi-bit trie\n",
           ctx.num_rules);
    printf("  key length    : %d bytes  (one trie level per byte)\n",
           ctx.key_len);
    printf("  trie nodes    : %d  (%d inner, %d leaves)\n",
           ctx.stats.trie_nodes,
           ctx.stats.trie_nodes - ctx.stats.trie_leaves,
           ctx.stats.trie_leaves);
    printf("  max depth     : %d  (== key length: lookup is O(key), not O(rules))\n",
           ctx.stats.max_depth);
    printf("  RT memory     : ~%ld bytes\n", ctx.stats.bytes);
    printf("  default method: %s\n\n", acl_method_name(ctx.method));

    puts("results array is per-category: [cat0 cat1 cat2 cat3], 0 == no match");
    puts("both backends are run for every packet and must agree:\n");

    run_case(&ctx, "src 10.1.1.1   dst 192.168.1.15   (docs 2,3,0,0)",
             IPV4(10,1,1,1),    IPV4(192,168,1,15));
    run_case(&ctx, "src 192.168.1.1 dst 192.168.2.11  (docs 1,1,0,0)",
             IPV4(192,168,1,1), IPV4(192,168,2,11));
    run_case(&ctx, "src 10.1.1.1   dst 201.212.111.12 (docs 0,3,0,0)",
             IPV4(10,1,1,1),    IPV4(201,212,111,12));

    acl_free(&ctx);
    return 0;
}
