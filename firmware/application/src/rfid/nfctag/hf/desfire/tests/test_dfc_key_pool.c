#include "munit/munit.h"
#include "dfc_credential.h"

#include <string.h>

static DfcApplication* add_app(DfcCredential* c, uint8_t aid0, uint8_t key_settings_2) {
    const uint8_t aid[] = {aid0, 0x02, 0x03};
    return dfc_credential_create_application_desfire_order(c, aid, 0x0F, key_settings_2);
}

static void fill_keys(DfcCredential* c, DfcApplication* app, uint8_t pattern) {
    size_t n = app ? app->num_keys : c->picc_num_keys;
    size_t len = app ? app->key_len : c->picc_key_len;
    for(size_t i = 0; i < n; i++) {
        uint8_t* key = dfc_credential_key(c, app, i);
        munit_assert_not_null(key);
        memset(key, (int)(pattern + i), dfc_credential_stored_key_length(len));
    }
}

static MunitResult test_resize_allocate_and_release(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential c;
    memset(&c, 0, sizeof(c));
    dfc_credential_clear(&c);

    // A cleared credential already holds the PICC master key.
    munit_assert_size(c.picc_num_keys, ==, 1);
    munit_assert_size(c.key_pool_used, ==, 16);

    DfcApplication* a = add_app(&c, 0x01, DFC_KEY_TYPE_AES | 3);
    munit_assert_not_null(a);
    munit_assert_size(a->num_keys, ==, 3);
    munit_assert_size(c.key_pool_used, ==, 16 + 3 * 16);

    DfcApplication* b = add_app(&c, 0x04, DFC_KEY_TYPE_3K3DES | 2);
    munit_assert_not_null(b);
    munit_assert_size(c.key_pool_used, ==, 16 + 3 * 16 + 2 * 24);

    fill_keys(&c, NULL, 0x10);
    fill_keys(&c, a, 0xA0);
    fill_keys(&c, b, 0xB0);

    // Slices do not overlap: each key reads back exactly what was written.
    munit_assert_uint8(dfc_credential_key(&c, NULL, 0)[0], ==, 0x10);
    munit_assert_uint8(dfc_credential_key(&c, a, 2)[15], ==, 0xA2);
    munit_assert_uint8(dfc_credential_key(&c, b, 1)[23], ==, 0xB1);

    // Deleting the first application compacts the pool and leaves the survivors
    // pointing at their own material.
    munit_assert_true(dfc_credential_delete_application_at(&c, 0));
    munit_assert_size(c.num_apps, ==, 1);
    munit_assert_size(c.key_pool_used, ==, 16 + 2 * 24);
    munit_assert_uint8(dfc_credential_key(&c, NULL, 0)[0], ==, 0x10);
    DfcApplication* survivor = dfc_credential_get_application(&c, 0);
    munit_assert_not_null(survivor);
    munit_assert_uint8(dfc_credential_key(&c, survivor, 0)[0], ==, 0xB0);
    munit_assert_uint8(dfc_credential_key(&c, survivor, 1)[23], ==, 0xB1);

    // Out-of-range slots are refused rather than reaching into a neighbour.
    munit_assert_null(dfc_credential_key(&c, survivor, 2));
    munit_assert_null(dfc_credential_key(&c, NULL, 1));

    return MUNIT_OK;
}

static MunitResult
    test_resize_accepts_zero_initialized_model(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    for(size_t app_first = 0; app_first < 2; app_first++) {
        DfcCredential credential = {0};
        DfcApplication app = {0};
        DfcApplication* first = app_first ? &app : NULL;
        DfcApplication* second = app_first ? NULL : &app;

        munit_assert_true(dfc_credential_keys_resize(&credential, first, 1, 16));
        uint8_t* first_key = dfc_credential_key(&credential, first, 0);
        munit_assert_not_null(first_key);
        memset(first_key, 0xA5, 16);

        munit_assert_true(dfc_credential_keys_resize(&credential, second, 1, 16));
        uint8_t* second_key = dfc_credential_key(&credential, second, 0);
        munit_assert_not_null(second_key);
        memset(second_key, 0x5A, 16);
        munit_assert_size(credential.key_pool_used, ==, 32);
        munit_assert_uint8(dfc_credential_key(&credential, first, 0)[0], ==, 0xA5);
        munit_assert_uint8(dfc_credential_key(&credential, first, 0)[15], ==, 0xA5);
        munit_assert_uint8(dfc_credential_key(&credential, second, 0)[0], ==, 0x5A);
        munit_assert_uint8(dfc_credential_key(&credential, second, 0)[15], ==, 0x5A);

        uint8_t guard[32];
        memcpy(guard, credential.key_pool, sizeof(guard));
        DfcApplication empty = {0};
        munit_assert_true(dfc_credential_keys_resize(&credential, &empty, 0, 16));
        munit_assert_size(empty.key_offset, ==, DFC_KEY_POOL_NONE);
        munit_assert_size(empty.key_pool_len, ==, 0);
        munit_assert_size(credential.key_pool_used, ==, sizeof(guard));
        munit_assert_memory_equal(sizeof(guard), guard, credential.key_pool);

        DfcApplication oversized = {0};
        munit_assert_false(
            dfc_credential_keys_resize(&credential, &oversized, DFC_MAX_KEYS + 1, 16));
        munit_assert_size(oversized.key_offset, ==, 0);
        munit_assert_size(oversized.key_pool_len, ==, 0);
        munit_assert_size(credential.key_pool_used, ==, sizeof(guard));
        munit_assert_memory_equal(sizeof(guard), guard, credential.key_pool);
    }

    return MUNIT_OK;
}

static MunitResult test_format_picc_keeps_picc_keys(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential c;
    memset(&c, 0, sizeof(c));
    dfc_credential_clear(&c);

    fill_keys(&c, NULL, 0x77);
    DfcApplication* a = add_app(&c, 0x01, DFC_KEY_TYPE_AES | 4);
    munit_assert_not_null(a);
    fill_keys(&c, a, 0xC0);

    dfc_credential_format_picc(&c);
    munit_assert_size(c.num_apps, ==, 0);
    // The PICC record survives a format, so its slice has to survive with it.
    munit_assert_size(c.key_pool_used, ==, 16);
    const uint8_t* picc_key = dfc_credential_key_const(&c, NULL, 0);
    munit_assert_not_null(picc_key);
    munit_assert_uint8(picc_key[0], ==, 0x77);

    return MUNIT_OK;
}

static MunitResult test_pool_exhaustion(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential c;
    memset(&c, 0, sizeof(c));
    dfc_credential_clear(&c);

    size_t created = 0;
    for(size_t i = 0; i < DFC_MAX_APPS; i++) {
        DfcApplication* app = add_app(&c, (uint8_t)(0x10 + i), DFC_KEY_TYPE_3K3DES | DFC_MAX_KEYS);
        if(!app) break;
        created++;
    }
    // Either the application limit or the pool stops it, and whichever it was,
    // the refusal is clean: nothing was half-created.
    munit_assert_size(c.num_apps, ==, created);
    munit_assert_size(c.key_pool_used, <=, DFC_KEY_POOL_SIZE);
    for(size_t i = 0; i < c.num_apps; i++) {
        munit_assert_not_null(dfc_credential_key(&c, &c.apps[i], 0));
        munit_assert_not_null(dfc_credential_key(&c, &c.apps[i], DFC_MAX_KEYS - 1));
    }

    return MUNIT_OK;
}

// A copy of the model has to bring the key pool with it, for the same reason the
// file pool does: applications hold offsets, not keys.
static MunitResult test_copy_model_carries_pool(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential src;
    memset(&src, 0, sizeof(src));
    dfc_credential_clear(&src);

    munit_assert_true(dfc_credential_keys_resize(&src, NULL, 2, 24));
    fill_keys(&src, NULL, 0x55);
    DfcApplication* app = add_app(&src, 0x01, DFC_KEY_TYPE_AES | 2);
    munit_assert_not_null(app);
    fill_keys(&src, app, 0xD0);
    src.picc_has_auth_commands = true;
    src.picc_auth_commands = DFC_AUTH_COMMAND_D40 | DFC_AUTH_COMMAND_ISO_NATIVE;
    src.picc_has_preferred_auth_command = true;
    src.picc_preferred_auth_command = DFC_AUTH_COMMAND_ISO_NATIVE;

    DfcCredential dst;
    memset(&dst, 0, sizeof(dst));
    dfc_credential_clear(&dst);
    dfc_credential_copy_model(&dst, &src);

    munit_assert_size(dst.num_apps, ==, 1);
    munit_assert_size(dst.key_pool_used, ==, src.key_pool_used);
    munit_assert_size(dst.picc_key_offset, ==, src.picc_key_offset);
    munit_assert_size(dst.picc_key_pool_len, ==, src.picc_key_pool_len);
    munit_assert_true(dst.picc_has_auth_commands);
    munit_assert_uint8(dst.picc_auth_commands, ==, src.picc_auth_commands);
    munit_assert_true(dst.picc_has_preferred_auth_command);
    munit_assert_uint8(dst.picc_preferred_auth_command, ==, src.picc_preferred_auth_command);

    for(size_t i = 0; i < 2; i++) {
        const uint8_t* copied_picc = dfc_credential_key_const(&dst, NULL, i);
        munit_assert_not_null(copied_picc);
        munit_assert_memory_equal(24, copied_picc, dfc_credential_key_const(&src, NULL, i));
    }

    for(size_t i = 0; i < 2; i++) {
        const uint8_t* copied = dfc_credential_key_const(&dst, &dst.apps[0], i);
        munit_assert_not_null(copied);
        munit_assert_memory_equal(16, copied, dfc_credential_key_const(&src, &src.apps[0], i));
    }

    return MUNIT_OK;
}

// Growing a slice in place has to keep the records that follow it addressable,
// and shrinking has to give the space back.
static MunitResult test_resize_moves_slice(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential c;
    memset(&c, 0, sizeof(c));
    dfc_credential_clear(&c);

    DfcApplication* a = add_app(&c, 0x01, DFC_KEY_TYPE_AES | 1);
    DfcApplication* b = add_app(&c, 0x04, DFC_KEY_TYPE_AES | 1);
    munit_assert_not_null(a);
    munit_assert_not_null(b);
    fill_keys(&c, b, 0xB0);
    size_t used = c.key_pool_used;

    munit_assert_true(dfc_credential_keys_resize(&c, a, 5, 16));
    munit_assert_size(a->num_keys, ==, 5);
    munit_assert_size(c.key_pool_used, ==, used - 16 + 5 * 16);
    munit_assert_uint8(dfc_credential_key(&c, b, 0)[0], ==, 0xB0);

    munit_assert_true(dfc_credential_keys_resize(&c, a, 1, 16));
    munit_assert_size(c.key_pool_used, ==, used);
    munit_assert_uint8(dfc_credential_key(&c, b, 0)[0], ==, 0xB0);

    dfc_credential_keys_release(&c, a);
    munit_assert_null(dfc_credential_key(&c, a, 0));
    munit_assert_uint8(dfc_credential_key(&c, b, 0)[0], ==, 0xB0);

    return MUNIT_OK;
}

// A capacity failure must leave the old slice intact. Callers can then report
// the failed update without losing the keys that still back the live model.
static MunitResult test_failed_resize_preserves_slice(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential c;
    memset(&c, 0, sizeof(c));
    dfc_credential_clear(&c);

    DfcApplication* app = add_app(&c, 0x01, DFC_KEY_TYPE_AES | 1);
    munit_assert_not_null(app);
    fill_keys(&c, app, 0xA5);
    app->key_versions[0] = 0x5A;

    size_t fillers = 0;
    for(size_t i = 1; i < DFC_MAX_APPS; i++) {
        DfcApplication* filler =
            add_app(&c, (uint8_t)(0x20 + i), DFC_KEY_TYPE_3K3DES | DFC_MAX_KEYS);
        if(!filler) break;
        fillers++;
    }
    munit_assert_size(fillers, >, 0);

    size_t used = c.key_pool_used;
    size_t offset = app->key_offset;
    size_t pool_len = app->key_pool_len;
    uint8_t saved_key[16];
    memcpy(saved_key, dfc_credential_key_const(&c, app, 0), sizeof(saved_key));

    munit_assert_false(dfc_credential_keys_resize(&c, app, DFC_MAX_KEYS, DFC_MAX_KEY_LEN));
    munit_assert_size(c.key_pool_used, ==, used);
    munit_assert_size(app->key_offset, ==, offset);
    munit_assert_size(app->key_pool_len, ==, pool_len);
    munit_assert_size(app->num_keys, ==, 1);
    munit_assert_size(app->key_len, ==, 16);
    munit_assert_uint8(app->key_versions[0], ==, 0x5A);
    munit_assert_memory_equal(sizeof(saved_key), saved_key, dfc_credential_key_const(&c, app, 0));

    // Freeing one maximum-width filler makes the same resize valid, proving
    // the rejection was capacity-only and did not poison the model.
    munit_assert_true(dfc_credential_delete_application_at(&c, c.num_apps - 1));
    munit_assert_true(dfc_credential_keys_resize(&c, app, DFC_MAX_KEYS, DFC_MAX_KEY_LEN));

    return MUNIT_OK;
}

static MunitResult
    test_resize_rejects_malformed_pool_metadata(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential c;
    memset(&c, 0, sizeof(c));
    dfc_credential_clear(&c);
    DfcApplication* app = add_app(&c, 0x01, DFC_KEY_TYPE_AES | 1);
    munit_assert_not_null(app);

    size_t used = c.key_pool_used;
    size_t offset = app->key_offset;
    size_t pool_len = app->key_pool_len;
    c.key_pool_used = DFC_KEY_POOL_SIZE + 1;
    munit_assert_false(dfc_credential_keys_resize(&c, app, 1, 16));
    c.key_pool_used = used;

    app->key_offset = used + 1;
    munit_assert_false(dfc_credential_keys_resize(&c, app, 1, 16));
    app->key_offset = used;
    app->key_pool_len = 1;
    munit_assert_false(dfc_credential_keys_resize(&c, app, 1, 16));
    app->key_offset = DFC_KEY_POOL_NONE;
    app->key_pool_len = 1;
    munit_assert_false(dfc_credential_keys_resize(&c, app, 1, 16));
    app->key_offset = offset;
    app->key_pool_len = 0;
    munit_assert_false(dfc_credential_keys_resize(&c, app, 0, 16));

    app->key_offset = offset;
    app->key_pool_len = pool_len;
    munit_assert_true(dfc_credential_keys_resize(&c, app, 1, 16));
    return MUNIT_OK;
}

#if DFC_ENABLE_KEY_SETS
static MunitResult
    test_failed_resize_preserves_key_set_metadata(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential c;
    memset(&c, 0, sizeof(c));
    dfc_credential_clear(&c);

    DfcApplication* app = add_app(&c, 0x01, DFC_KEY_TYPE_AES | 1);
    munit_assert_not_null(app);
    munit_assert_true(dfc_credential_key_sets_resize(&c, app, 2, 1, 16, 16));
    *dfc_credential_key_set_version(&c, app, 0) = 0x31;
    *dfc_credential_key_set_version(&c, app, 1) = 0x42;
    *dfc_credential_key_set_type(&c, app, 0) = DFC_KEY_SET_TYPE_AES;
    *dfc_credential_key_set_type(&c, app, 1) = DFC_KEY_SET_TYPE_AES;
    munit_assert_true(dfc_credential_key_set_set_initialized(&c, app, 0, true));
    munit_assert_true(dfc_credential_key_set_set_initialized(&c, app, 1, false));
    *dfc_credential_key_version_in_set(&c, app, 1, 0) = 0x53;
    memset(dfc_credential_key(&c, app, 0), 0xA5, 16);

    for(size_t i = 1; i < DFC_MAX_APPS; i++) {
        DfcApplication* filler =
            add_app(&c, (uint8_t)(0x20 + i), DFC_KEY_TYPE_3K3DES | DFC_MAX_KEYS);
        if(!filler) break;
    }
    size_t free = dfc_credential_key_pool_free(&c);
    if(free >= 304) {
        size_t keys = (free - 303 + 15) / 16;
        DfcApplication* filler = add_app(&c, 0x70, (uint8_t)(DFC_KEY_TYPE_AES | keys));
        munit_assert_not_null(filler);
    }
    munit_assert_size(dfc_credential_key_pool_free(&c), <, 304);

    size_t used = c.key_pool_used;
    size_t offset = app->key_offset;
    size_t pool_len = app->key_pool_len;
    uint8_t key[16];
    memcpy(key, dfc_credential_key_const(&c, app, 0), sizeof(key));
    uint8_t metadata[32];
    size_t metadata_len = app->key_set_metadata_len;
    munit_assert_size(metadata_len, <=, sizeof(metadata));
    memcpy(metadata, c.key_set_metadata_pool + app->key_set_metadata_offset, metadata_len);

    munit_assert_false(dfc_credential_keys_resize(&c, app, DFC_MAX_KEYS, DFC_MAX_KEY_LEN));
    munit_assert_size(c.key_pool_used, ==, used);
    munit_assert_size(app->key_offset, ==, offset);
    munit_assert_size(app->key_pool_len, ==, pool_len);
    munit_assert_size(app->num_key_sets, ==, 2);
    munit_assert_size(app->max_key_size, ==, 16);
    munit_assert_memory_equal(sizeof(key), key, dfc_credential_key_const(&c, app, 0));
    munit_assert_size(app->key_set_metadata_len, ==, metadata_len);
    munit_assert_memory_equal(
        metadata_len, metadata, c.key_set_metadata_pool + app->key_set_metadata_offset);

    return MUNIT_OK;
}

static MunitResult
    test_full_key_pool_metadata_capacity(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential c;
    memset(&c, 0, sizeof(c));
    dfc_credential_clear(&c);
    munit_assert_true(dfc_credential_keys_resize(&c, NULL, 0, 0));

    size_t expected_key_bytes = 0;
    size_t remaining = DFC_KEY_POOL_SIZE;
    for(size_t i = 0; i < DFC_MAX_APPS && remaining >= 2u * DFC_AES_KEY_LENGTH; i++) {
        size_t sets = remaining / DFC_AES_KEY_LENGTH;
        if(sets > DFC_MAX_KEY_SETS) sets = DFC_MAX_KEY_SETS;
        DfcApplication* app = add_app(&c, (uint8_t)(0x40 + i), DFC_KEY_TYPE_AES | 1);
        munit_assert_not_null(app);
        munit_assert_true(dfc_credential_key_sets_resize(
            &c, app, sets, 1, DFC_AES_KEY_LENGTH, DFC_AES_KEY_LENGTH));
        for(size_t set = 0; set < sets; set++) {
            *dfc_credential_key_set_type(&c, app, set) = DFC_KEY_SET_TYPE_AES;
            *dfc_credential_key_set_version(&c, app, set) = (uint8_t)(i + set);
        }
        size_t consumed = sets * DFC_AES_KEY_LENGTH;
        expected_key_bytes += consumed;
        remaining -= consumed;
    }
    munit_assert_size(c.key_pool_used, ==, expected_key_bytes);
    munit_assert_true(
        DFC_KEY_POOL_SIZE - c.key_pool_used < 2u * DFC_AES_KEY_LENGTH ||
        c.num_apps == DFC_MAX_APPS);
    munit_assert_size(c.key_set_metadata_pool_used, <=, DFC_KEY_SET_METADATA_POOL_SIZE);
    for(size_t keys = 1; keys <= DFC_MAX_KEYS; keys++) {
        for(size_t sets = DFC_KEY_SET_MINIMUM_COUNT; sets <= DFC_MAX_KEY_SETS; sets++) {
            size_t metadata = 2u * sets + sizeof(uint16_t) + keys * (sets - 1u);
            size_t key_bytes = keys * sets * DFC_AES_KEY_LENGTH;
            munit_assert_size(metadata * 32u, <=, key_bytes * 7u);
        }
    }
    return MUNIT_OK;
}

static MunitResult
    test_corrupt_metadata_bounds_are_rejected(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential c;
    memset(&c, 0, sizeof(c));
    dfc_credential_clear(&c);
    DfcApplication* app = add_app(&c, 0x01, DFC_KEY_TYPE_AES | 1);
    munit_assert_not_null(app);
    munit_assert_true(dfc_credential_key_sets_resize(&c, app, 2, 1, 16, 16));
    uint8_t before[DFC_KEY_SET_METADATA_POOL_SIZE];
    memcpy(before, c.key_set_metadata_pool, sizeof(before));

    c.key_set_metadata_pool_used = DFC_KEY_SET_METADATA_POOL_SIZE + 1u;
    munit_assert_null(dfc_credential_key_set_version(&c, app, 0));
    munit_assert_null(dfc_credential_key_set_type(&c, app, 0));
    munit_assert_null(dfc_credential_key_version_in_set(&c, app, 1, 0));
    munit_assert_false(dfc_credential_key_set_is_initialized(&c, app, 0));
    munit_assert_false(dfc_credential_key_set_set_initialized(&c, app, 0, false));
    munit_assert_memory_equal(sizeof(before), before, c.key_set_metadata_pool);

    c.key_set_metadata_pool_used = DFC_KEY_SET_METADATA_POOL_SIZE;
    app->key_set_metadata_offset = (uint16_t)DFC_KEY_SET_METADATA_POOL_SIZE;
    munit_assert_null(dfc_credential_key_set_version(&c, app, 0));
    munit_assert_false(dfc_credential_key_set_set_initialized(&c, app, 0, false));
    munit_assert_memory_equal(sizeof(before), before, c.key_set_metadata_pool);
    return MUNIT_OK;
}

static MunitResult test_metadata_boundary_layouts(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential c;
    memset(&c, 0, sizeof(c));
    dfc_credential_clear(&c);
    munit_assert_true(dfc_credential_keys_resize(&c, NULL, 0, 0));
    DfcApplication* app = add_app(&c, 0x01, DFC_KEY_TYPE_AES | 1);
    munit_assert_not_null(app);

    // One key and two sets has the highest metadata-to-key-storage ratio.
    munit_assert_true(dfc_credential_key_sets_resize(&c, app, 2, 1, 16, 16));
    munit_assert_uint16(app->key_set_metadata_len, ==, 7);
    munit_assert_size(c.key_set_metadata_pool_used, ==, 7);

    // Exercise the maximum key count with as many complete sets as the
    // configured pool can represent.
    size_t max_key_sets = DFC_KEY_POOL_SIZE / (DFC_MAX_KEYS * DFC_AES_KEY_LENGTH);
    if(max_key_sets > DFC_MAX_KEY_SETS) max_key_sets = DFC_MAX_KEY_SETS;
    if(max_key_sets >= DFC_KEY_SET_MINIMUM_COUNT) {
        munit_assert_true(dfc_credential_key_sets_resize(
            &c, app, max_key_sets, DFC_MAX_KEYS, DFC_AES_KEY_LENGTH, DFC_AES_KEY_LENGTH));
        size_t expected_metadata =
            2u * max_key_sets + sizeof(uint16_t) + DFC_MAX_KEYS * (max_key_sets - 1u);
        munit_assert_uint16(app->key_set_metadata_len, ==, expected_metadata);
        munit_assert_size(c.key_pool_used, ==, max_key_sets * DFC_MAX_KEYS * DFC_AES_KEY_LENGTH);
    }
    return MUNIT_OK;
}

static MunitResult test_metadata_exhaustion_is_atomic(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static DfcCredential before;
    DfcCredential c;
    memset(&c, 0, sizeof(c));
    dfc_credential_clear(&c);
    DfcApplication* app = add_app(&c, 0x01, DFC_KEY_TYPE_AES | 1);
    munit_assert_not_null(app);
    c.key_set_metadata_pool_used = DFC_KEY_SET_METADATA_POOL_SIZE;
    memset(c.key_set_metadata_pool, 0xA5, sizeof(c.key_set_metadata_pool));
    dfc_credential_copy_model(&before, &c);

    munit_assert_false(dfc_credential_key_sets_resize(&c, app, 2, 1, 16, 16));
    munit_assert_memory_equal(sizeof(c), &before, &c);
    return MUNIT_OK;
}

static MunitResult test_metadata_compacts_on_delete(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential c;
    memset(&c, 0, sizeof(c));
    dfc_credential_clear(&c);
    for(size_t i = 0; i < 3; i++) {
        DfcApplication* app = add_app(&c, (uint8_t)(0x10 + i), DFC_KEY_TYPE_AES | 1);
        munit_assert_not_null(app);
        munit_assert_true(dfc_credential_key_sets_resize(&c, app, 2, 1, 16, 16));
        *dfc_credential_key_set_version(&c, app, 1) = (uint8_t)(0xA0 + i);
    }
    size_t used = c.key_set_metadata_pool_used;
    size_t removed = c.apps[1].key_set_metadata_len;
    munit_assert_true(dfc_credential_delete_application_at(&c, 1));
    munit_assert_size(c.key_set_metadata_pool_used, ==, used - removed);
    munit_assert_uint8(*dfc_credential_key_set_version(&c, &c.apps[1], 1), ==, 0xA2);
    return MUNIT_OK;
}

static MunitResult test_copy_and_clear_metadata_pool(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static DfcCredential copy;
    DfcCredential c;
    memset(&c, 0, sizeof(c));
    dfc_credential_clear(&c);
    DfcApplication* app = add_app(&c, 0x01, DFC_KEY_TYPE_AES | 2);
    munit_assert_not_null(app);
    munit_assert_true(dfc_credential_key_sets_resize(&c, app, 3, 2, 16, 24));
    *dfc_credential_key_set_version(&c, app, 2) = 0x5A;
    *dfc_credential_key_set_type(&c, app, 2) = DFC_KEY_SET_TYPE_3K3DES;
    *dfc_credential_key_version_in_set(&c, app, 2, 1) = 0xC3;

    dfc_credential_copy_model(&copy, &c);
    munit_assert_uint8(*dfc_credential_key_set_version(&copy, &copy.apps[0], 2), ==, 0x5A);
    munit_assert_uint8(
        *dfc_credential_key_set_type(&copy, &copy.apps[0], 2), ==, DFC_KEY_SET_TYPE_3K3DES);
    munit_assert_uint8(*dfc_credential_key_version_in_set(&copy, &copy.apps[0], 2, 1), ==, 0xC3);

    dfc_credential_clear(&c);
    munit_assert_size(c.key_set_metadata_pool_used, ==, 0);
    for(size_t i = 0; i < sizeof(c.key_set_metadata_pool); i++)
        munit_assert_uint8(c.key_set_metadata_pool[i], ==, 0);
    for(size_t i = 0; i < DFC_MAX_APPS; i++) {
        munit_assert_uint16(c.apps[i].key_set_metadata_offset, ==, DFC_KEY_SET_METADATA_POOL_NONE);
        munit_assert_uint16(c.apps[i].key_set_metadata_len, ==, 0);
    }
    return MUNIT_OK;
}
#endif

static MunitTest tests[] = {
    {"/resize-allocate-and-release",
     test_resize_allocate_and_release,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/resize-accepts-zero-initialized-model",
     test_resize_accepts_zero_initialized_model,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/format-picc-keeps-picc-keys",
     test_format_picc_keeps_picc_keys,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/pool-exhaustion", test_pool_exhaustion, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/copy-model-carries-pool",
     test_copy_model_carries_pool,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/resize-moves-slice", test_resize_moves_slice, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/failed-resize-preserves-slice",
     test_failed_resize_preserves_slice,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/resize-rejects-malformed-pool-metadata",
     test_resize_rejects_malformed_pool_metadata,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#if DFC_ENABLE_KEY_SETS
    {"/failed-resize-preserves-key-set-metadata",
     test_failed_resize_preserves_key_set_metadata,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/full-key-pool-metadata-capacity",
     test_full_key_pool_metadata_capacity,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/corrupt-metadata-bounds-are-rejected",
     test_corrupt_metadata_bounds_are_rejected,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/metadata-boundary-layouts",
     test_metadata_boundary_layouts,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/metadata-exhaustion-is-atomic",
     test_metadata_exhaustion_is_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/metadata-compacts-on-delete",
     test_metadata_compacts_on_delete,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/copy-and-clear-metadata-pool",
     test_copy_and_clear_metadata_pool,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {
    "/dfc_key_pool",
    tests,
    NULL,
    1,
    MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
