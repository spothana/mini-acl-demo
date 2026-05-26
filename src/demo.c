/*
 * demo.c -- Reproduces the IPv4 5-tuple example from the DPDK ACL docs
 *           using the mini ACL library. Expected output matches the
 *           documentation's result arrays: {2,3,0,0}, {1,1,0,0}, {0,3,0,0}.
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

/* field index: 0=proto 1=src_ip 2=dst_ip 3=src_port 4=dst_port */
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

static void fill_key(struct ipv4_key *k, uint8_t proto,
                     uint32_t src, uint32_t dst, uint16_t sp, uint16_t dp)
{
    memset(k, 0, sizeof(*k));
    k->proto    = proto;
    k->src_ip   = htonl(src);
    k->dst_ip   = htonl(dst);
    k->src_port = htons(sp);
    k->dst_port = htons(dp);
}

static void run_case(struct acl_ctx *ctx, const char *label,
                     uint32_t src, uint32_t dst)
{
    struct ipv4_key key;
    fill_key(&key, 6 /*TCP*/, src, dst, 1024, 80);

    const uint8_t *keys[1] = { (const uint8_t *)&key };
    uint32_t results[4] = {0};
    acl_classify(ctx, keys, 1, results);

    printf("%-48s -> results = {%u, %u, %u, %u}\n",
           label, results[0], results[1], results[2], results[3]);
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
    if (acl_build(&ctx) != 0) {
        fprintf(stderr, "build failed\n");
        return 1;
    }

    puts("mini-ACL: reproducing the DPDK ACL documentation example");
    puts("rules: 1) dst 192.168.0.0/16 cat{0,1} pri1");
    puts("       2) dst 192.168.1.0/24 cat{0}   pri2");
    puts("       3) src 10.1.1.1       cat{1}   pri3");
    puts("results array is per-category: [cat0 cat1 cat2 cat3]\n");

    run_case(&ctx, "src 10.1.1.1   dst 192.168.1.15  (docs: 2,3,0,0)",
             IPV4(10,1,1,1),    IPV4(192,168,1,15));
    run_case(&ctx, "src 192.168.1.1 dst 192.168.2.11 (docs: 1,1,0,0)",
             IPV4(192,168,1,1), IPV4(192,168,2,11));
    run_case(&ctx, "src 10.1.1.1   dst 201.212.111.12 (docs: 0,3,0,0)",
             IPV4(10,1,1,1),    IPV4(201,212,111,12));

    return 0;
}
