#include "munit/munit.h"
#include "dfc_credential.h"

#include <string.h>

static void assert_released_pool_bytes_are_zero(const DfcCredential* credential, size_t old_used) {
    munit_assert_size(credential->file_pool_used, <=, old_used);
    for(size_t i = credential->file_pool_used; i < old_used; i++) {
        munit_assert_uint8(credential->file_pool[i], ==, 0);
    }
}

static MunitResult test_resize_allocate_and_release(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential credential;
    memset(&credential, 0, sizeof(credential));
    dfc_credential_clear(&credential);

    const uint8_t aid[] = {0x01, 0x02, 0x03};
    munit_assert_not_null(
        dfc_credential_create_application_desfire_order(&credential, aid, 0x0F, 0x01));

    DfcFile* a = dfc_credential_create_file(&credential, 0, 0x01);
    DfcFile* b = dfc_credential_create_file(&credential, 0, 0x02);
    munit_assert_not_null(a);
    munit_assert_not_null(b);

    munit_assert_true(dfc_file_resize(&credential, a, 100));
    munit_assert_true(dfc_file_resize(&credential, b, 200));
    munit_assert_size(credential.file_pool_used, ==, 300);
    munit_assert_size(dfc_credential_file_pool_free(&credential), ==, DFC_FILE_POOL_SIZE - 300);

    uint8_t* pa = dfc_file_data(&credential, a);
    uint8_t* pb = dfc_file_data(&credential, b);
    munit_assert_not_null(pa);
    munit_assert_not_null(pb);
    memset(pa, 0xAA, 100);
    memset(pb, 0xBB, 200);

    munit_assert_true(dfc_credential_delete_file(&credential, 0, 0x01));
    munit_assert_size(credential.file_pool_used, ==, 200);
    // Surviving file keeps its payload after compact.
    pb = dfc_file_data(&credential, dfc_credential_find_file_in_app(&credential, 0, 0x02));
    munit_assert_not_null(pb);
    munit_assert_uint8(pb[0], ==, 0xBB);
    munit_assert_uint8(pb[199], ==, 0xBB);

    return MUNIT_OK;
}

static MunitResult
    test_release_wipes_compacted_and_cloned_pool_bytes(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential credential;
    memset(&credential, 0, sizeof(credential));
    dfc_credential_clear(&credential);

    const uint8_t aid[] = {0x01, 0x02, 0x03};
    munit_assert_not_null(
        dfc_credential_create_application_desfire_order(&credential, aid, 0x0F, 0x01));

    DfcFile* first = dfc_credential_create_file(&credential, 0, 0x01);
    DfcFile* second = dfc_credential_create_file(&credential, 0, 0x02);
    munit_assert_not_null(first);
    munit_assert_not_null(second);
    munit_assert_true(dfc_file_resize(&credential, first, 32));
    munit_assert_true(dfc_file_resize(&credential, second, 32));
    memset(dfc_file_data(&credential, first), 0x11, 32);
    memset(dfc_file_data(&credential, second), 0xEE, 32);

    size_t old_used = credential.file_pool_used;
    munit_assert_true(dfc_credential_delete_file(&credential, 0, 0x02));
    munit_assert_size(credential.file_pool_used, ==, 32);
    first = dfc_credential_find_file_in_app(&credential, 0, 0x01);
    munit_assert_not_null(first);
    munit_assert_size(first->data_offset, ==, 0);
    for(size_t i = 0; i < first->data_len; i++) {
        munit_assert_uint8(dfc_file_data(&credential, first)[i], ==, 0x11);
    }
    assert_released_pool_bytes_are_zero(&credential, old_used);

    second = dfc_credential_create_file(&credential, 0, 0x02);
    munit_assert_not_null(second);
    munit_assert_true(dfc_file_resize(&credential, second, 32));
    memset(dfc_file_data(&credential, second), 0xEE, 32);

    old_used = credential.file_pool_used;
    munit_assert_true(dfc_credential_delete_file(&credential, 0, 0x01));
    second = dfc_credential_find_file_in_app(&credential, 0, 0x02);
    munit_assert_not_null(second);
    munit_assert_size(second->data_offset, ==, 0);
    munit_assert_size(second->data_len, ==, 32);
    for(size_t i = 0; i < second->data_len; i++) {
        munit_assert_uint8(dfc_file_data(&credential, second)[i], ==, 0xEE);
    }
    assert_released_pool_bytes_are_zero(&credential, old_used);

    old_used = credential.file_pool_used;
    munit_assert_true(dfc_file_resize(&credential, second, 8));
    munit_assert_size(second->data_offset, ==, 0);
    munit_assert_size(second->data_len, ==, 8);
    munit_assert_size(credential.file_pool_used, ==, 8);
    assert_released_pool_bytes_are_zero(&credential, old_used);

    DfcCredential clone;
    memset(&clone, 0xA5, sizeof(clone));
    dfc_credential_copy_model(&clone, &credential);
    munit_assert_size(clone.file_pool_used, ==, credential.file_pool_used);
    munit_assert_size(clone.files[0].data_offset, ==, credential.files[0].data_offset);
    munit_assert_memory_equal(credential.file_pool_used, clone.file_pool, credential.file_pool);
    assert_released_pool_bytes_are_zero(&clone, old_used);

    return MUNIT_OK;
}

static MunitResult
    test_resize_accepts_zero_initialized_model(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    for(size_t first_index = 0; first_index < 2; first_index++) {
        DfcCredential credential = {0};
        DfcFile files[2] = {{0}};
        DfcFile* first = &files[first_index];
        DfcFile* second = &files[first_index ^ 1];

        munit_assert_true(dfc_file_resize(&credential, first, 8));
        uint8_t* first_data = dfc_file_data(&credential, first);
        munit_assert_not_null(first_data);
        memset(first_data, 0xA5, 8);

        munit_assert_true(dfc_file_resize(&credential, second, 12));
        uint8_t* second_data = dfc_file_data(&credential, second);
        munit_assert_not_null(second_data);
        memset(second_data, 0x5A, 12);
        munit_assert_size(first->data_offset, ==, 0);
        munit_assert_size(second->data_offset, ==, 8);
        munit_assert_size(credential.file_pool_used, ==, 20);
        munit_assert_uint8(dfc_file_data(&credential, first)[0], ==, 0xA5);
        munit_assert_uint8(dfc_file_data(&credential, first)[7], ==, 0xA5);
        munit_assert_uint8(dfc_file_data(&credential, second)[0], ==, 0x5A);
        munit_assert_uint8(dfc_file_data(&credential, second)[11], ==, 0x5A);

        uint8_t guard[20];
        memcpy(guard, credential.file_pool, sizeof(guard));
        DfcFile empty = {0};
        munit_assert_true(dfc_file_resize(&credential, &empty, 0));
        munit_assert_size(empty.data_offset, ==, DFC_FILE_POOL_NONE);
        munit_assert_size(empty.data_len, ==, 0);
        munit_assert_size(credential.file_pool_used, ==, sizeof(guard));
        munit_assert_memory_equal(sizeof(guard), guard, credential.file_pool);

        DfcFile oversized = {0};
        munit_assert_false(
            dfc_file_resize(&credential, &oversized, (size_t)DFC_MAX_FILE_DATA + 1));
        munit_assert_size(oversized.data_offset, ==, 0);
        munit_assert_size(oversized.data_len, ==, 0);
        munit_assert_size(credential.file_pool_used, ==, sizeof(guard));
        munit_assert_memory_equal(sizeof(guard), guard, credential.file_pool);
    }

    return MUNIT_OK;
}

static MunitResult test_pool_exhaustion(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential credential;
    memset(&credential, 0, sizeof(credential));
    dfc_credential_clear(&credential);
    const uint8_t aid[] = {0x01, 0x02, 0x03};
    munit_assert_not_null(
        dfc_credential_create_application_desfire_order(&credential, aid, 0x0F, 0x01));

    // Fill the pool with as many max-sized slices as fit (single-file cap may
    // be smaller than the pool).
    size_t chunk = DFC_MAX_FILE_DATA;
    if(chunk > DFC_FILE_POOL_SIZE) {
        chunk = DFC_FILE_POOL_SIZE;
    }
    uint8_t next_no = 0;
    while(dfc_credential_file_pool_free(&credential) >= chunk && next_no < DFC_MAX_FILES) {
        DfcFile* file = dfc_credential_create_file(&credential, 0, next_no++);
        munit_assert_not_null(file);
        munit_assert_true(dfc_file_resize(&credential, file, chunk));
    }
    // Leftover smaller than chunk, or full: one more byte must fail.
    if(dfc_credential_file_pool_free(&credential) > 0 && next_no < DFC_MAX_FILES) {
        size_t rem = dfc_credential_file_pool_free(&credential);
        DfcFile* mid = dfc_credential_create_file(&credential, 0, next_no++);
        munit_assert_not_null(mid);
        munit_assert_true(dfc_file_resize(&credential, mid, rem));
    }
    munit_assert_size(dfc_credential_file_pool_free(&credential), ==, 0);
    if(next_no < DFC_MAX_FILES) {
        DfcFile* other = dfc_credential_create_file(&credential, 0, next_no);
        munit_assert_not_null(other);
        munit_assert_false(dfc_file_resize(&credential, other, 1));
    }

    return MUNIT_OK;
}

static MunitResult test_failed_resize_preserves_slice(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential credential;
    memset(&credential, 0, sizeof(credential));
    dfc_credential_clear(&credential);
    const uint8_t aid[] = {0x01, 0x02, 0x03};
    munit_assert_not_null(
        dfc_credential_create_application_desfire_order(&credential, aid, 0x0F, 0x01));

    DfcFile* target = dfc_credential_create_file(&credential, 0, 0x01);
    munit_assert_not_null(target);
    munit_assert_true(dfc_file_resize(&credential, target, 16));
    memset(dfc_file_data(&credential, target), 0xA5, 16);

    uint8_t next_no = 0x10;
    size_t fillers = 0;
    while(dfc_credential_file_pool_free(&credential) > 0 && credential.num_files < DFC_MAX_FILES) {
        size_t chunk = dfc_credential_file_pool_free(&credential);
        if(chunk > DFC_MAX_FILE_DATA) chunk = DFC_MAX_FILE_DATA;
        DfcFile* filler = dfc_credential_create_file(&credential, 0, next_no++);
        munit_assert_not_null(filler);
        munit_assert_true(dfc_file_resize(&credential, filler, chunk));
        fillers++;
    }
    munit_assert_size(fillers, >, 0);
    munit_assert_size(dfc_credential_file_pool_free(&credential), ==, 0);

    size_t used = credential.file_pool_used;
    size_t offset = target->data_offset;
    munit_assert_false(dfc_file_resize(&credential, target, 17));
    munit_assert_size(credential.file_pool_used, ==, used);
    munit_assert_size(target->data_offset, ==, offset);
    munit_assert_size(target->data_len, ==, 16);
    const uint8_t expected[16] = {
        0xA5,
        0xA5,
        0xA5,
        0xA5,
        0xA5,
        0xA5,
        0xA5,
        0xA5,
        0xA5,
        0xA5,
        0xA5,
        0xA5,
        0xA5,
        0xA5,
        0xA5,
        0xA5,
    };
    munit_assert_memory_equal(16, expected, dfc_file_data_const(&credential, target));

    DfcFile* last = &credential.files[credential.num_files - 1];
    uint8_t last_number = last->number;
    munit_assert_true(dfc_credential_delete_file(&credential, 0, last_number));
    munit_assert_true(dfc_file_resize(&credential, target, 17));

    return MUNIT_OK;
}

static MunitResult
    test_resize_rejects_malformed_pool_metadata(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential credential;
    memset(&credential, 0, sizeof(credential));
    dfc_credential_clear(&credential);
    const uint8_t aid[] = {0x01, 0x02, 0x03};
    munit_assert_not_null(
        dfc_credential_create_application_desfire_order(&credential, aid, 0x0F, 0x01));
    DfcFile* file = dfc_credential_create_file(&credential, 0, 0x01);
    munit_assert_not_null(file);
    munit_assert_true(dfc_file_resize(&credential, file, 8));

    size_t used = credential.file_pool_used;
    size_t offset = file->data_offset;
    size_t len = file->data_len;
    credential.file_pool_used = DFC_FILE_POOL_SIZE + 1;
    munit_assert_false(dfc_file_resize(&credential, file, len));
    credential.file_pool_used = used;

    file->data_offset = used + 1;
    munit_assert_false(dfc_file_resize(&credential, file, len));
    file->data_offset = used;
    file->data_len = 1;
    munit_assert_false(dfc_file_resize(&credential, file, 1));
    file->data_offset = DFC_FILE_POOL_NONE;
    file->data_len = 1;
    munit_assert_false(dfc_file_resize(&credential, file, 1));
    file->data_offset = offset + 1;
    file->data_len = 0;
    munit_assert_false(dfc_file_resize(&credential, file, 0));

    file->data_offset = offset;
    file->data_len = len;
    munit_assert_true(dfc_file_resize(&credential, file, len));
    return MUNIT_OK;
}

// A copy of the model has to bring the pool with it. Copying files[] alone
// leaves every data_offset pointing into a pool that was never populated, and
// dfc_file_data then fails its bounds check and hands back NULL, which reads as
// "this file is empty" rather than as an error.
static MunitResult test_copy_model_carries_pool(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential src;
    memset(&src, 0, sizeof(src));
    dfc_credential_clear(&src);

    const uint8_t aid[] = {0x01, 0x02, 0x03};
    munit_assert_not_null(dfc_credential_create_application_desfire_order(&src, aid, 0x0F, 0x01));
    DfcFile* file = dfc_credential_create_file(&src, 0, 0x01);
    munit_assert_not_null(file);
    munit_assert_true(dfc_file_resize(&src, file, 8));
    uint8_t* payload = dfc_file_data(&src, file);
    munit_assert_not_null(payload);
    memcpy(payload, "\xDE\xAD\xBE\xEF\x01\x02\x03\x04", 8);

    DfcCredential dst;
    memset(&dst, 0, sizeof(dst));
    dfc_credential_clear(&dst);
    dfc_credential_copy_model(&dst, &src);

    munit_assert_size(dst.num_apps, ==, 1);
    munit_assert_size(dst.num_files, ==, 1);
    munit_assert_size(dst.file_pool_used, ==, src.file_pool_used);

    const DfcFile* copied = dfc_credential_find_file_in_app(&dst, 0, 0x01);
    munit_assert_not_null(copied);
    munit_assert_size(copied->data_len, ==, 8);
    const uint8_t* copied_payload = dfc_file_data_const(&dst, copied);
    munit_assert_not_null(copied_payload);
    munit_assert_memory_equal(8, copied_payload, payload);

    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/resize-allocate-and-release",
     test_resize_allocate_and_release,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/release-wipes-compacted-and-cloned-pool-bytes",
     test_release_wipes_compacted_and_cloned_pool_bytes,
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
    {"/pool-exhaustion", test_pool_exhaustion, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
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
    {"/copy-model-carries-pool",
     test_copy_model_carries_pool,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {
    "/dfc_file_pool",
    tests,
    NULL,
    1,
    MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
