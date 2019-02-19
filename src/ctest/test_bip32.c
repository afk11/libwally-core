#include "config.h"

#include <wally_core.h>
#include <wally_bip32.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

extern struct version_def bitcoin_version_p2wsh;
extern struct version_def bitcoin_version_p2pkh_or_p2sh;
extern struct version_def testnet_version_p2pkh_or_p2sh;
extern const struct version_def* bitcoin_versions[];
extern const struct version_def* testnet_versions[];

int check_versioned(const char* base58key, size_t num_versions, const struct version_def* key_versions[], struct ext_key *key) {
    if (WALLY_OK != slip132_key_from_base58(base58key, num_versions, key_versions, key)) {
        printf("failed to unserialize key\n");
        return 0;
    }
    char* serialized;
    if (WALLY_OK != bip32_key_to_base58(key, BIP32_FLAG_KEY_PUBLIC, &serialized)) {
        printf("failed to serialize to base58\n");
        return 0;
    }
    if (0 != strcmp(serialized, base58key)) {
        printf("serialized key didn't match\n");
        return 0;
    }
    return 1;
}

int check_versioned_alloc(const char* base58key, size_t num_versions, const struct version_def* key_versions[]) {
    struct ext_key* key;
    if (WALLY_OK != slip132_key_from_base58_alloc(base58key, num_versions, key_versions, &key)) {
        printf("failed to unserialize key\n");
        return 0;
    }
    char* serialized;
    if (WALLY_OK != bip32_key_to_base58(key, BIP32_FLAG_KEY_PUBLIC, &serialized)) {
        printf("failed to serialize to base58\n");
        return 0;
    }
    if (0 != strcmp(serialized, base58key)) {
        printf("serialized key didn't match\n");
        return 0;
    }
    if (WALLY_OK != bip32_key_free(key)) {
        printf("failed to free key\n");
        return 0;
    }

    return 1;
}

int check_versioned_parse_and_serialize(const char* base58key, size_t num_versions, const struct version_def* key_versions[]) {
    if (!check_versioned_alloc(base58key, num_versions, key_versions)) {
        printf("failed to unserialize key (alloc)");
        return 0;
    }
    struct ext_key key;
    if (!check_versioned(base58key, num_versions, key_versions, &key)) {
        printf("failed to unserialize key");
	return 0;
    }

    return 1;
}

int test_bip32_with_versions(void) {
    const char* Zpub = "Zpub74qd5RNQomhXkYCzxSU1QUcLjpN72EV3FRJXNXWbTTiLxwtXhK6jrAccYri3iEZzhzUvBRMMfFvjfWkeXrdj3ft23y2DqcVhPqz6f1LQjXE";
    const char* xpub = "xpub661MyMwAqRbcH14ZzryyXgeWj5pSqsbHAeoYkFL7QSMhFTysPctuEvvo79Pe6N772HVzQnsnN6P7WebKRm4wcQToRy6LEwBVDjrMZ5bvnAw";
    const char* tpub = "tpubD6NzVbkrYhZ4Wa9a5XdMTwo2NogkNnbtwwypHRuTpEMTji7pbmoayPUbY4BAu2cYuoLParxvBz9fmBbcyYYRk7JApoK6AZRdyUec269S7ya";
    const struct version_def* Zpubonly[] = {&bitcoin_version_p2wsh};
    const struct version_def* xpubonly[] = {&bitcoin_version_p2pkh_or_p2sh};
    const struct version_def* tpubonly[] = {&testnet_version_p2pkh_or_p2sh};

    if (!check_versioned_parse_and_serialize(Zpub, 1, Zpubonly)) {
        printf("failed parsing/serializing zpub key with correct prefix");
        return 0;
    }
    if (!check_versioned_parse_and_serialize(Zpub, 5, bitcoin_versions)) {
        printf("failed parsing/serializing zpub key using all prefixes");
        return 0;
    }

    if (!check_versioned_parse_and_serialize(xpub, 1, xpubonly)) {
        printf("failed parsing/serializing xpub key with correct prefix");
        return 0;
    }
    if (!check_versioned_parse_and_serialize(xpub, 5, bitcoin_versions)) {
        printf("failed parsing/serializing xpub using all prefixes");
        return 0;
    }

    if (!check_versioned_parse_and_serialize(tpub, 1, tpubonly)) {
        printf("failed parsing/serializing tpub key with correct prefix");
        return 0;
    }
    if (!check_versioned_parse_and_serialize(tpub, 1, testnet_versions)) {
	printf("failed parsing/serializing tpub using all prefixes");
	return 0;
    }

    return 1;
}

int main(void)
{
    bool tests_ok = true;

    if (!test_bip32_with_versions()) {
        printf("test bip32 with versions - failed!\n");
        tests_ok = false;
    }

    return tests_ok ? 0 : 1;
}
