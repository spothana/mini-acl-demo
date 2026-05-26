/*
 * test_acl.c -- Self-checking tests for the mini ACL library.
 * Covers field matching, priority resolution, the trie backend, and
 * crucially that the SCALAR and TRIE backends always agree.
 * Exits non-zero on the first failure so ctest reports pass/fail.
 */
#include "mini_acl.h"
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, msg) do {                                   \
    if (!(cond)) { printf("FAIL: %s\n", msg); failures++; }      \
    else         { printf("ok:   %s\n", msg); }                  \
} while (0)

#define IPV4(a,b,c,d) (((uint32_t)(a)<<24)|((b)<<16)|((c)<<8)|(d))

/* shared rule set: a 5-tuple-like context over a 13-byte contiguous key */
static const struct acl_field_def defs5[5] = {
    { ACL_FIELD_TYPE_BITMASK, 1, 0  },
    { ACL_FIELD_TYPE_MASK,    4, 1  },
    { ACL_FIELD_TYPE_MASK,    4, 5  },
    { ACL_FIELD_TYPE_RANGE,   2, 9  },
    { ACL_FIELD_TYPE_RANGE,   2, 11 },
};
static const struct acl_rule rules5[] = {
    { .priority = 1, .category_mask = 0x3, .userdata = 1, .field = {
        [0]={0,0},[1]={0,0},[2]={IPV4(192,168,0,0),16},
        [3]={0,0xffff},[4]={0,0xffff} } },
    { .priority = 2, .category_mask = 0x1, .userdata = 2, .field = {
        [0]={0,0},[1]={0,0},[2]={IPV4(192,168,1,0),24},
        [3]={0,0xffff},[4]={0,0xffff} } },
    { .priority = 3, .category_mask = 0x2, .userdata = 3, .field = {
        [0]={0,0},[1]={IPV4(10,1,1,1),32},[2]={0,0},
        [3]={0,0xffff},[4]={0,0xffff} } },
};

static void put_be(uint8_t *p, uint32_t v, int n) {
    for (int i = 0; i < n; i++) p[i] = (v >> ((n-1-i)*8)) & 0xff;
}
static void make_key(uint8_t *k, uint8_t proto,
                     uint32_t src, uint32_t dst, uint16_t sp, uint16_t dp) {
    memset(k, 0, 13);
    k[0] = proto;
    put_be(k+1, src, 4); put_be(k+5, dst, 4);
    put_be(k+9, sp, 2);  put_be(k+11, dp, 2);
}

int main(void)
{
    /* --- field type: MASK --- */
    struct acl_field_val ip = { 0xC0A80000u, 16 };
    CHECK( acl_field_matches(ACL_FIELD_TYPE_MASK, 0xC0A80105u, &ip, 4),
           "MASK /16 matches 192.168.1.5");
    CHECK(!acl_field_matches(ACL_FIELD_TYPE_MASK, 0xC0A90105u, &ip, 4),
           "MASK /16 rejects 192.169.1.5");

    /* --- field type: RANGE --- */
    struct acl_field_val ports = { 1024, 2048 };
    CHECK( acl_field_matches(ACL_FIELD_TYPE_RANGE, 1500, &ports, 2),
           "RANGE [1024,2048] matches 1500");
    CHECK(!acl_field_matches(ACL_FIELD_TYPE_RANGE, 80, &ports, 2),
           "RANGE [1024,2048] rejects 80");

    /* --- field type: BITMASK --- */
    struct acl_field_val proto = { 6, 0xff };
    CHECK( acl_field_matches(ACL_FIELD_TYPE_BITMASK, 6, &proto, 1),
           "BITMASK matches protocol 6");
    CHECK(!acl_field_matches(ACL_FIELD_TYPE_BITMASK, 17, &proto, 1),
           "BITMASK rejects protocol 17");

    /* --- build the trie --- */
    struct acl_ctx ctx;
    acl_create(&ctx, defs5, 5, 4);
    acl_add_rules(&ctx, rules5, 3);
    int rc = acl_build(&ctx);
    CHECK(rc == 0, "acl_build() succeeds");
    CHECK(ctx.method == ACL_CLASSIFY_TRIE,
          "build() sets the default method to TRIE");
    CHECK(ctx.stats.trie_nodes > 0, "build() produced a non-empty trie");
    CHECK(ctx.stats.max_depth == ctx.key_len,
          "trie depth equals key length");

    /* --- the three documented cases, both backends --- */
    struct { const char *n; uint32_t s,d; uint32_t exp[4]; } cases[] = {
        { "10.1.1.1 -> 192.168.1.15",  IPV4(10,1,1,1), IPV4(192,168,1,15),
          {2,3,0,0} },
        { "192.168.1.1 -> 192.168.2.11", IPV4(192,168,1,1), IPV4(192,168,2,11),
          {1,1,0,0} },
        { "10.1.1.1 -> 201.212.111.12", IPV4(10,1,1,1), IPV4(201,212,111,12),
          {0,3,0,0} },
    };
    for (int i = 0; i < 3; i++) {
        uint8_t key[13];
        make_key(key, 6, cases[i].s, cases[i].d, 1024, 80);
        const uint8_t *keys[1] = { key };
        uint32_t rs[4] = {0}, rt[4] = {0};
        acl_classify_with(&ctx, ACL_CLASSIFY_SCALAR, keys, 1, rs);
        acl_classify_with(&ctx, ACL_CLASSIFY_TRIE,   keys, 1, rt);

        char m[96];
        snprintf(m, sizeof(m), "scalar matches docs: %s", cases[i].n);
        CHECK(memcmp(rs, cases[i].exp, sizeof(rs)) == 0, m);
        snprintf(m, sizeof(m), "trie matches docs:   %s", cases[i].n);
        CHECK(memcmp(rt, cases[i].exp, sizeof(rt)) == 0, m);
        snprintf(m, sizeof(m), "scalar and trie agree: %s", cases[i].n);
        CHECK(memcmp(rs, rt, sizeof(rs)) == 0, m);
    }

    /* --- exhaustive equivalence sweep: the two backends must agree on
     *     a broad spread of keys, not just the three documented ones --- */
    int sweep_mismatch = 0, sweep_n = 0;
    uint32_t dsts[] = {
        IPV4(192,168,1,1), IPV4(192,168,2,200), IPV4(192,168,255,255),
        IPV4(10,0,0,1),    IPV4(172,16,5,5),    IPV4(8,8,8,8),
        IPV4(192,167,1,1), IPV4(193,168,1,1),
    };
    uint32_t srcs[] = {
        IPV4(10,1,1,1), IPV4(10,1,1,2), IPV4(10,1,2,1),
        IPV4(192,168,1,1), IPV4(0,0,0,0),
    };
    for (size_t a = 0; a < sizeof(srcs)/sizeof(srcs[0]); a++)
    for (size_t b = 0; b < sizeof(dsts)/sizeof(dsts[0]); b++) {
        uint8_t key[13];
        make_key(key, 6, srcs[a], dsts[b], 1024, 80);
        const uint8_t *keys[1] = { key };
        uint32_t rs[4] = {0}, rt[4] = {0};
        acl_classify_with(&ctx, ACL_CLASSIFY_SCALAR, keys, 1, rs);
        acl_classify_with(&ctx, ACL_CLASSIFY_TRIE,   keys, 1, rt);
        sweep_n++;
        if (memcmp(rs, rt, sizeof(rs)) != 0) sweep_mismatch++;
    }
    {
        char m[96];
        snprintf(m, sizeof(m),
                 "backends agree on all %d swept keys", sweep_n);
        CHECK(sweep_mismatch == 0, m);
    }

    acl_free(&ctx);

    if (failures) {
        printf("\n%d test(s) FAILED\n", failures);
        return 1;
    }
    puts("\nall tests passed");
    return 0;
}
