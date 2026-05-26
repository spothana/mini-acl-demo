/*
 * test_acl.c -- Minimal self-checking tests for the mini ACL library.
 * Exits non-zero on the first failure so ctest can report pass/fail.
 */
#include "mini_acl.h"
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, msg) do {                                   \
    if (!(cond)) { printf("FAIL: %s\n", msg); failures++; }      \
    else         { printf("ok:   %s\n", msg); }                  \
} while (0)

int main(void)
{
    /* --- field type: MASK (prefix matching) --- */
    struct acl_field_val ip = { 0xC0A80000u, 16 };  /* 192.168.0.0/16 */
    CHECK( acl_field_matches(ACL_FIELD_TYPE_MASK, 0xC0A80105u, &ip, 4),
           "MASK /16 matches 192.168.1.5");
    CHECK(!acl_field_matches(ACL_FIELD_TYPE_MASK, 0xC0A90105u, &ip, 4),
           "MASK /16 rejects 192.169.1.5");

    struct acl_field_val any = { 0, 0 };            /* /0 wildcard */
    CHECK( acl_field_matches(ACL_FIELD_TYPE_MASK, 0xDEADBEEFu, &any, 4),
           "MASK /0 matches anything");

    /* --- field type: RANGE --- */
    struct acl_field_val ports = { 1024, 2048 };
    CHECK( acl_field_matches(ACL_FIELD_TYPE_RANGE, 1500, &ports, 2),
           "RANGE [1024,2048] matches 1500");
    CHECK(!acl_field_matches(ACL_FIELD_TYPE_RANGE, 80, &ports, 2),
           "RANGE [1024,2048] rejects 80");

    /* --- field type: BITMASK --- */
    struct acl_field_val proto = { 6, 0xff };       /* exactly TCP */
    CHECK( acl_field_matches(ACL_FIELD_TYPE_BITMASK, 6, &proto, 1),
           "BITMASK matches protocol 6");
    CHECK(!acl_field_matches(ACL_FIELD_TYPE_BITMASK, 17, &proto, 1),
           "BITMASK rejects protocol 17");

    /* --- end-to-end: priority resolution + categories --- */
    static const struct acl_field_def defs[1] = {
        { ACL_FIELD_TYPE_MASK, 4, 0 },
    };
    static const struct acl_rule rules[] = {
        { .priority = 1, .category_mask = 0x3, .userdata = 10,
          .field = { [0] = {0, 0} } },               /* low pri, cat0+1 */
        { .priority = 5, .category_mask = 0x1, .userdata = 20,
          .field = { [0] = {0, 0} } },               /* high pri, cat0  */
    };
    struct acl_ctx ctx;
    acl_create(&ctx, defs, 1, 2);
    acl_add_rules(&ctx, rules, 2);
    acl_build(&ctx);

    uint8_t key[4] = { 1, 2, 3, 4 };
    const uint8_t *keys[1] = { key };
    uint32_t results[2] = { 0, 0 };
    acl_classify(&ctx, keys, 1, results);

    CHECK(results[0] == 20, "category 0 -> higher-priority rule wins (20)");
    CHECK(results[1] == 10, "category 1 -> only matching rule wins (10)");

    if (failures) {
        printf("\n%d test(s) FAILED\n", failures);
        return 1;
    }
    puts("\nall tests passed");
    return 0;
}
