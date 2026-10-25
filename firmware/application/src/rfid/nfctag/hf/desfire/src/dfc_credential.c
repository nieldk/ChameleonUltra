#include "dfc_credential_i.h"

#include <stdio.h>

DfcFile* dfc_credential_find_transaction_mac_file(DfcCredential* credential, size_t app_index) {
#if DFC_ENABLE_TRANSACTION_MAC
    for(size_t i = 0; i < credential->num_files; i++) {
        DfcFile* file = &credential->files[i];
        if(file->app_index == app_index && file->type == DFC_FILE_TYPE_TRANSACTION_MAC)
            return file;
    }
#else
    DFC_UNUSED(credential);
    DFC_UNUSED(app_index);
#endif
    return NULL;
}

#define TAG "DfcCredential"

uint8_t dfc_credential_compiled_auth_commands(void) {
    uint8_t commands = 0;
#if DFC_ENABLE_AUTH_D40
    commands |= DFC_AUTH_COMMAND_D40;
#endif
#if DFC_ENABLE_AUTH_ISO
    commands |= DFC_AUTH_COMMAND_ISO_NATIVE;
#endif
#if DFC_ENABLE_AUTH_AES
    commands |= DFC_AUTH_COMMAND_AES;
#endif
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    commands |= DFC_AUTH_COMMAND_EV2_FIRST | DFC_AUTH_COMMAND_EV2_NON_FIRST;
#endif
#if DFC_ENABLE_ISO7816_AUTH
    commands |= DFC_AUTH_COMMAND_ISO7816;
#endif
    return commands;
}

uint8_t dfc_credential_possible_auth_commands(uint8_t key_settings_2, DfcGeneration generation) {
    uint8_t commands;
    switch(key_settings_2 & DFC_KEY_TYPE_MASK) {
    case DFC_KEY_TYPE_AES:
        commands = DFC_AUTH_COMMAND_AES |
                   (generation >= DfcGenerationEv2 ?
                        DFC_AUTH_COMMAND_EV2_FIRST | DFC_AUTH_COMMAND_EV2_NON_FIRST :
                        0);
        break;
    case DFC_KEY_TYPE_3K3DES:
        commands = DFC_AUTH_COMMAND_ISO_NATIVE;
        break;
    default:
        commands = DFC_AUTH_COMMAND_D40 | DFC_AUTH_COMMAND_ISO_NATIVE;
        break;
    }
    return commands;
}

uint8_t dfc_credential_default_auth_commands(uint8_t key_settings_2, DfcGeneration generation) {
    return dfc_credential_possible_auth_commands(key_settings_2, generation) &
           dfc_credential_compiled_auth_commands();
}

uint8_t dfc_credential_picc_auth_commands(const DfcCredential* credential) {
    if(credential->picc_has_auth_commands) return credential->picc_auth_commands;
    return dfc_credential_default_auth_commands(
        credential->picc_key_settings_2, credential->card.generation);
}

uint8_t
    dfc_credential_app_auth_commands(const DfcCredential* credential, const DfcApplication* app) {
    if(app->has_auth_commands) return app->auth_commands;
    return dfc_credential_default_auth_commands(app->key_settings_2, credential->card.generation);
}

void dfc_credential_reset_application(DfcApplication* app) {
    if(!app) return;
    memset(app, 0, sizeof(DfcApplication));
    app->key_offset = DFC_KEY_POOL_NONE;
#if DFC_ENABLE_KEY_SETS
    app->num_key_sets = 1;
    app->key_set_initialized[0] = true;
#endif
}

static void dfc_application_clear(DfcApplication* app) {
    dfc_credential_reset_application(app);
}

DfcApplication* dfc_credential_get_application(DfcCredential* credential, size_t app_index) {
    if(app_index >= credential->num_apps) return NULL;
    return &credential->apps[app_index];
}

const DfcApplication*
    dfc_credential_get_application_const(const DfcCredential* credential, size_t app_index) {
    if(app_index >= credential->num_apps) return NULL;
    return &credential->apps[app_index];
}

DfcApplication* dfc_credential_get_primary_application(DfcCredential* credential) {
    return dfc_credential_get_application(credential, 0);
}

const DfcApplication*
    dfc_credential_get_primary_application_const(const DfcCredential* credential) {
    return dfc_credential_get_application_const(credential, 0);
}

DfcApplication* dfc_credential_find_application(DfcCredential* credential, const uint8_t aid[3]) {
    for(size_t i = 0; i < credential->num_apps; i++) {
        if(memcmp(credential->apps[i].aid, aid, 3) == 0) return &credential->apps[i];
    }
    return NULL;
}

DfcApplication*
    dfc_credential_find_application_desfire_order(DfcCredential* credential, const uint8_t aid[3]) {
    for(size_t i = 0; i < credential->num_apps; i++) {
        DfcApplication* app = &credential->apps[i];
        if(aid[0] == app->aid[2] && aid[1] == app->aid[1] && aid[2] == app->aid[0]) {
            return app;
        }
    }
    return NULL;
}

size_t dfc_credential_application_index(DfcCredential* credential, DfcApplication* application) {
    if(!application) return SIZE_MAX;
    for(size_t i = 0; i < credential->num_apps; i++) {
        if(&credential->apps[i] == application) return i;
    }
    return SIZE_MAX;
}

DfcApplication* dfc_credential_create_application_desfire_order(
    DfcCredential* credential,
    const uint8_t aid[3],
    uint8_t key_settings_1,
    uint8_t key_settings_2) {
    if(credential->num_apps >= DFC_MAX_APPS) return NULL;
    if(dfc_credential_find_application_desfire_order(credential, aid)) return NULL;

    size_t num_keys = key_settings_2 & DFC_NUM_KEYS_MASK;
    if(num_keys == 0 || num_keys > DFC_EV1_MAX_KEYS_PER_APP || num_keys > DFC_MAX_KEYS) {
        return NULL;
    }

    DfcApplication* app = &credential->apps[credential->num_apps];
    dfc_application_clear(app);
    // Key material has to be reserved before the application counts as created,
    // so a pool that cannot hold it leaves the credential untouched.
    if(!dfc_credential_keys_resize(
           credential, app, num_keys, dfc_credential_key_length(key_settings_2))) {
        return NULL;
    }
    credential->num_apps++;
    app->aid[0] = aid[2];
    app->aid[1] = aid[1];
    app->aid[2] = aid[0];
    app->key_settings_1 = key_settings_1;
    app->key_settings_2 = key_settings_2;
    uint8_t key_type = key_settings_2 & DFC_KEY_TYPE_MASK;
    if(key_type == DFC_KEY_TYPE_AES) {
        app->auth_command = DFC_CMD_AUTHENTICATE_AES;
    } else if(key_type == DFC_KEY_TYPE_3K3DES) {
        app->auth_command = DFC_CMD_AUTHENTICATE_ISO;
    } else {
        app->auth_command = DFC_CMD_AUTHENTICATE_LEGACY;
    }
    return app;
}

bool dfc_credential_delete_application_at(DfcCredential* credential, size_t app_index) {
    if(app_index >= credential->num_apps) return false;

    // Release before the array shifts: the release fixes up the offsets held by
    // the other records, which is only correct while they are still in place.
    dfc_credential_keys_release(credential, &credential->apps[app_index]);

    for(size_t i = 0; i < credential->num_files;) {
        if(credential->files[i].app_index == app_index) {
            dfc_file_release(credential, &credential->files[i]);
            if(i + 1 < credential->num_files) {
                memmove(
                    &credential->files[i],
                    &credential->files[i + 1],
                    (credential->num_files - i - 1) * sizeof(DfcFile));
            }
            credential->num_files--;
            memset(&credential->files[credential->num_files], 0, sizeof(DfcFile));
            continue;
        }
        // Only real application indices shift. DFC_FILE_OWNER_PICC is larger
        // than any of them, so renumbering it would quietly turn a PICC-level
        // file into a file of an application that does not exist.
        if(credential->files[i].app_index != DFC_FILE_OWNER_PICC &&
           credential->files[i].app_index > app_index) {
            credential->files[i].app_index--;
        }
        i++;
    }

    if(app_index + 1 < credential->num_apps) {
        memmove(
            &credential->apps[app_index],
            &credential->apps[app_index + 1],
            (credential->num_apps - app_index - 1) * sizeof(DfcApplication));
    }
    credential->num_apps--;
    dfc_credential_reset_application(&credential->apps[credential->num_apps]);
    return true;
}

void dfc_credential_format_picc(DfcCredential* credential) {
    // The PICC record survives a format; move its key slice to the head of the
    // pool in one pass and wipe whatever application key material trailed it.
    size_t old_key_used = credential->key_pool_used;
    if(credential->picc_key_offset != DFC_KEY_POOL_NONE && credential->picc_key_pool_len > 0 &&
       credential->picc_key_offset <= old_key_used &&
       credential->picc_key_pool_len <= old_key_used - credential->picc_key_offset) {
        if(credential->picc_key_offset > 0) {
            memmove(
                credential->key_pool,
                credential->key_pool + credential->picc_key_offset,
                credential->picc_key_pool_len);
        }
        credential->picc_key_offset = 0;
        credential->key_pool_used = credential->picc_key_pool_len;
    } else {
        credential->picc_key_offset = DFC_KEY_POOL_NONE;
        credential->picc_key_pool_len = 0;
        credential->key_pool_used = 0;
    }
    if(old_key_used > credential->key_pool_used) {
        dfc_secure_wipe(
            credential->key_pool + credential->key_pool_used,
            old_key_used - credential->key_pool_used);
    }
    for(size_t i = 0; i < DFC_MAX_APPS; i++) {
        dfc_credential_reset_application(&credential->apps[i]);
    }
    if(credential->num_files > 0) {
        dfc_secure_wipe(credential->files, credential->num_files * sizeof(DfcFile));
    }
    if(credential->file_pool_used > 0) {
        dfc_secure_wipe(credential->file_pool, credential->file_pool_used);
    }
    credential->num_apps = 0;
    credential->num_files = 0;
    credential->file_pool_used = 0;
}

DfcFile* dfc_credential_find_file(DfcCredential* credential, uint8_t number) {
    return dfc_credential_find_file_in_app(credential, 0, number);
}

DfcFile*
    dfc_credential_find_file_in_app(DfcCredential* credential, size_t app_index, uint8_t number) {
    for(size_t i = 0; i < credential->num_files; i++) {
        if(credential->files[i].app_index == app_index && credential->files[i].number == number) {
            return &credential->files[i];
        }
    }
    return NULL;
}

DfcFile* dfc_credential_create_file(DfcCredential* credential, size_t app_index, uint8_t number) {
    if(app_index >= credential->num_apps) return NULL;
    if(credential->num_files >= DFC_MAX_FILES) return NULL;
    if(dfc_credential_find_file_in_app(credential, app_index, number)) return NULL;

    DfcFile* file = &credential->files[credential->num_files++];
    memset(file, 0, sizeof(DfcFile));
    file->app_index = app_index;
    file->number = number;
    file->data_offset = DFC_FILE_POOL_NONE;
    file->data_len = 0;
    return file;
}

static void dfc_file_pool_compact_after_release(
    DfcCredential* credential,
    size_t freed_offset,
    size_t freed_len) {
    if(freed_len == 0 || freed_offset == DFC_FILE_POOL_NONE) return;
    size_t tail = credential->file_pool_used - (freed_offset + freed_len);
    if(tail > 0) {
        memmove(
            credential->file_pool + freed_offset,
            credential->file_pool + freed_offset + freed_len,
            tail);
    }
    credential->file_pool_used -= freed_len;
    dfc_secure_wipe(credential->file_pool + credential->file_pool_used, freed_len);
    for(size_t i = 0; i < credential->num_files; i++) {
        DfcFile* other = &credential->files[i];
        if(other->data_offset != DFC_FILE_POOL_NONE && other->data_offset > freed_offset) {
            other->data_offset -= freed_len;
        }
    }
}

static bool dfc_pool_slice_resolve(
    size_t offset,
    size_t length,
    size_t used,
    size_t none,
    size_t* resolved_offset) {
    if(length == 0) {
        if(offset != 0 && offset != none) return false;
        *resolved_offset = none;
        return true;
    }
    if(offset == none || offset > used || length > used - offset) return false;
    *resolved_offset = offset;
    return true;
}

uint8_t* dfc_file_data(DfcCredential* credential, DfcFile* file) {
    if(!credential || !file || file->data_offset == DFC_FILE_POOL_NONE || file->data_len == 0) {
        return NULL;
    }
    if(file->data_offset + file->data_len > credential->file_pool_used) return NULL;
    return credential->file_pool + file->data_offset;
}

const uint8_t* dfc_file_data_const(const DfcCredential* credential, const DfcFile* file) {
    if(!credential || !file || file->data_offset == DFC_FILE_POOL_NONE || file->data_len == 0) {
        return NULL;
    }
    if(file->data_offset + file->data_len > credential->file_pool_used) return NULL;
    return credential->file_pool + file->data_offset;
}

bool dfc_file_resize(DfcCredential* credential, DfcFile* file, size_t data_len) {
    if(!credential || !file) return false;
    if(data_len > DFC_MAX_FILE_DATA) return false;
    if(data_len > DFC_FILE_POOL_SIZE) return false;
    if(credential->file_pool_used > DFC_FILE_POOL_SIZE) return false;
    size_t old_offset;
    if(!dfc_pool_slice_resolve(
           file->data_offset,
           file->data_len,
           credential->file_pool_used,
           DFC_FILE_POOL_NONE,
           &old_offset)) {
        return false;
    }

    if(old_offset != DFC_FILE_POOL_NONE && file->data_len == data_len) {
        return true;
    }

    size_t used_without_old = credential->file_pool_used;
    if(old_offset != DFC_FILE_POOL_NONE) {
        if(file->data_len > used_without_old) return false;
        used_without_old -= file->data_len;
    }
    if(data_len > DFC_FILE_POOL_SIZE - used_without_old) return false;

    // Capacity is known before releasing the old slice, so a failed resize
    // never destroys file data that still backs the live model.
    if(old_offset != DFC_FILE_POOL_NONE) {
        size_t old_len = file->data_len;
        file->data_offset = DFC_FILE_POOL_NONE;
        file->data_len = 0;
        dfc_file_pool_compact_after_release(credential, old_offset, old_len);
    }

    if(data_len == 0) {
        file->data_offset = DFC_FILE_POOL_NONE;
        file->data_len = 0;
        return true;
    }

    file->data_offset = credential->file_pool_used;
    file->data_len = data_len;
    memset(credential->file_pool + file->data_offset, 0, data_len);
    credential->file_pool_used += data_len;
    return true;
}

void dfc_file_release(DfcCredential* credential, DfcFile* file) {
    if(!credential || !file) return;
    if(file->data_offset == DFC_FILE_POOL_NONE) {
        file->data_len = 0;
        return;
    }
    size_t off = file->data_offset;
    size_t len = file->data_len;
    file->data_offset = DFC_FILE_POOL_NONE;
    file->data_len = 0;
    dfc_file_pool_compact_after_release(credential, off, len);
}

size_t dfc_credential_file_pool_free(const DfcCredential* credential) {
    if(!credential) return 0;
    if(credential->file_pool_used >= DFC_FILE_POOL_SIZE) return 0;
    return DFC_FILE_POOL_SIZE - credential->file_pool_used;
}

size_t dfc_credential_stored_key_length(size_t key_len) {
    return key_len == 24 ? 24 : 16;
}

// Slice bookkeeping lives on the application, or on the credential itself for
// the PICC record; these three pick whichever the caller selected.
static size_t* key_offset_of(DfcCredential* credential, DfcApplication* app) {
    return app ? &app->key_offset : &credential->picc_key_offset;
}

static size_t* num_keys_of(DfcCredential* credential, DfcApplication* app) {
    return app ? &app->num_keys : &credential->picc_num_keys;
}

static size_t* key_len_of(DfcCredential* credential, DfcApplication* app) {
    return app ? &app->key_len : &credential->picc_key_len;
}

static size_t* key_pool_len_of(DfcCredential* credential, DfcApplication* app) {
    return app ? &app->key_pool_len : &credential->picc_key_pool_len;
}

static void dfc_key_pool_compact_after_release(
    DfcCredential* credential,
    size_t freed_offset,
    size_t freed_len) {
    if(freed_len == 0 || freed_offset == DFC_KEY_POOL_NONE) return;
    size_t tail = credential->key_pool_used - (freed_offset + freed_len);
    if(tail > 0) {
        memmove(
            credential->key_pool + freed_offset,
            credential->key_pool + freed_offset + freed_len,
            tail);
    }
    credential->key_pool_used -= freed_len;
    dfc_secure_wipe(credential->key_pool + credential->key_pool_used, freed_len);
    // Every record that indexes past the hole, not only the created ones: an
    // application is given its slice before it is counted.
    for(size_t i = 0; i < DFC_MAX_APPS; i++) {
        size_t* off = &credential->apps[i].key_offset;
        if(*off != DFC_KEY_POOL_NONE && *off > freed_offset) *off -= freed_len;
    }

    if(credential->picc_key_offset != DFC_KEY_POOL_NONE &&
       credential->picc_key_offset > freed_offset) {
        credential->picc_key_offset -= freed_len;
    }
}

static const uint8_t* dfc_credential_key_at(
    const DfcCredential* credential,
    size_t offset,
    size_t pool_len,
    size_t num_keys,
    size_t key_len,
    size_t slot) {
    if(!credential || offset == DFC_KEY_POOL_NONE || pool_len == 0) return NULL;
    if(slot >= num_keys) return NULL;
    size_t stride = dfc_credential_stored_key_length(key_len);
    if((slot + 1) * stride > pool_len) return NULL;
    if(offset + pool_len > credential->key_pool_used) return NULL;
    return credential->key_pool + offset + slot * stride;
}

uint8_t* dfc_credential_key(DfcCredential* credential, DfcApplication* app, size_t slot) {
    if(!credential) return NULL;
    size_t storage_key_len = *key_len_of(credential, app);
#if DFC_ENABLE_KEY_SETS
    if(app) storage_key_len = app->key_storage_len;
#endif
    const uint8_t* p = dfc_credential_key_at(
        credential,
        *key_offset_of(credential, app),
        *key_pool_len_of(credential, app),
        *num_keys_of(credential, app),
        storage_key_len,
        slot);
    // Cast back: the const form exists for const credentials, not to make the
    // pool read-only. ChangeKey writes through this pointer.
    return (uint8_t*)p;
}

const uint8_t* dfc_credential_key_const(
    const DfcCredential* credential,
    const DfcApplication* app,
    size_t slot) {
    if(!credential) return NULL;
    size_t storage_key_len = app ? app->key_len : credential->picc_key_len;
#if DFC_ENABLE_KEY_SETS
    if(app) storage_key_len = app->key_storage_len;
#endif
    return dfc_credential_key_at(
        credential,
        app ? app->key_offset : credential->picc_key_offset,
        app ? app->key_pool_len : credential->picc_key_pool_len,
        app ? app->num_keys : credential->picc_num_keys,
        storage_key_len,
        slot);
}

static bool dfc_credential_keys_resize_total(
    DfcCredential* credential,
    DfcApplication* app,
    size_t num_keys,
    size_t allocated_keys,
    size_t key_len,
    size_t storage_key_len) {
    if(!credential) return false;
    if(num_keys > DFC_MAX_KEYS) return false;
    if(allocated_keys < num_keys) return false;

    size_t* offset = key_offset_of(credential, app);
    size_t* pool_len = key_pool_len_of(credential, app);
    size_t* stored_num = num_keys_of(credential, app);
    size_t* stored_len = key_len_of(credential, app);

    size_t stride = dfc_credential_stored_key_length(storage_key_len);
    if(allocated_keys > DFC_KEY_POOL_SIZE / stride) return false;
    size_t want = allocated_keys * stride;
    if(want > DFC_KEY_POOL_SIZE) return false;
    if(credential->key_pool_used > DFC_KEY_POOL_SIZE) return false;
    size_t old_offset;
    if(!dfc_pool_slice_resolve(
           *offset, *pool_len, credential->key_pool_used, DFC_KEY_POOL_NONE, &old_offset)) {
        return false;
    }

    if(old_offset != DFC_KEY_POOL_NONE && *pool_len == want && want > 0) {
        // Same footprint: keep the material, only the counts can change.
        *stored_num = num_keys;
        *stored_len = key_len;
#if DFC_ENABLE_KEY_SETS
        if(app) app->key_storage_len = storage_key_len;
#endif
        return true;
    }

    size_t used_without_old = credential->key_pool_used;
    if(old_offset != DFC_KEY_POOL_NONE) {
        if(*pool_len > used_without_old) return false;
        used_without_old -= *pool_len;
    }
    if(want > DFC_KEY_POOL_SIZE - used_without_old) return false;

    // Capacity is known before releasing the old slice, so a failed resize
    // never destroys the existing key material.
    dfc_credential_keys_release(credential, app);

    if(want == 0) {
        *stored_num = num_keys;
        *stored_len = key_len;
        return true;
    }

    *offset = credential->key_pool_used;
    *pool_len = want;
    memset(credential->key_pool + *offset, 0, want);
    credential->key_pool_used += want;
    *stored_num = num_keys;
    *stored_len = key_len;
#if DFC_ENABLE_KEY_SETS
    if(app) app->key_storage_len = storage_key_len;
#endif
    return true;
}

bool dfc_credential_keys_resize(
    DfcCredential* credential,
    DfcApplication* app,
    size_t num_keys,
    size_t key_len) {
    if(!dfc_credential_keys_resize_total(credential, app, num_keys, num_keys, key_len, key_len))
        return false;
#if DFC_ENABLE_KEY_SETS
    if(app) {
        app->num_key_sets = 1;
        app->key_set_initialized[0] = true;
        memset(app->key_set_versions, 0, sizeof(app->key_set_versions));
        memset(app->key_set_types, 0, sizeof(app->key_set_types));
        memset(app->additional_key_versions, 0, sizeof(app->additional_key_versions));
    }
#endif
    return true;
}

#if DFC_ENABLE_KEY_SETS
bool dfc_credential_key_sets_resize(
    DfcCredential* credential,
    DfcApplication* app,
    size_t num_key_sets,
    size_t num_keys,
    size_t active_key_len,
    size_t max_key_size) {
    if(!app || num_key_sets < DFC_KEY_SET_MINIMUM_COUNT || num_key_sets > DFC_MAX_KEY_SETS)
        return false;
    if(num_keys > SIZE_MAX / num_key_sets) return false;
    if(!dfc_credential_keys_resize_total(
           credential, app, num_keys, num_keys * num_key_sets, active_key_len, max_key_size))
        return false;
    app->num_key_sets = (uint8_t)num_key_sets;
    app->max_key_size = (uint8_t)max_key_size;
    memset(app->key_set_versions, 0, sizeof(app->key_set_versions));
    memset(app->key_set_types, 0, sizeof(app->key_set_types));
    memset(app->key_set_initialized, 0, sizeof(app->key_set_initialized));
    memset(app->additional_key_versions, 0, sizeof(app->additional_key_versions));
    for(size_t index = 0; index < num_key_sets; index++)
        app->key_set_initialized[index] = true;
    return true;
}

const uint8_t* dfc_credential_key_in_set_const(
    const DfcCredential* credential,
    const DfcApplication* app,
    size_t key_set_number,
    size_t slot) {
    if(!credential || !app || key_set_number >= app->num_key_sets || slot >= app->num_keys)
        return NULL;
    size_t allocated_keys = app->num_keys * app->num_key_sets;
    return dfc_credential_key_at(
        credential,
        app->key_offset,
        app->key_pool_len,
        allocated_keys,
        app->key_storage_len,
        key_set_number * app->num_keys + slot);
}

uint8_t* dfc_credential_key_in_set(
    DfcCredential* credential,
    DfcApplication* app,
    size_t key_set_number,
    size_t slot) {
    return (uint8_t*)dfc_credential_key_in_set_const(credential, app, key_set_number, slot);
}

uint8_t*
    dfc_credential_key_version_in_set(DfcApplication* app, size_t key_set_number, size_t slot) {
    if(!app || key_set_number >= app->num_key_sets || slot >= app->num_keys) return NULL;
    return key_set_number == 0 ? &app->key_versions[slot] :
                                 &app->additional_key_versions[key_set_number - 1][slot];
}

static void dfc_credential_rotate_key_set_metadata(DfcApplication* app) {
    uint8_t first_versions[DFC_MAX_KEYS];
    memcpy(first_versions, app->key_versions, sizeof(first_versions));
    memcpy(app->key_versions, app->additional_key_versions[0], sizeof(app->key_versions));
    if(app->num_key_sets > DFC_KEY_SET_MINIMUM_COUNT) {
        memmove(
            app->additional_key_versions[0],
            app->additional_key_versions[1],
            (app->num_key_sets - DFC_KEY_SET_MINIMUM_COUNT) *
                sizeof(app->additional_key_versions[0]));
    }
    memcpy(
        app->additional_key_versions[app->num_key_sets - DFC_KEY_SET_MINIMUM_COUNT],
        first_versions,
        sizeof(first_versions));

    uint8_t first_set_version = app->key_set_versions[0];
    uint8_t first_set_type = app->key_set_types[0];
    bool first_initialized = app->key_set_initialized[0];
    memmove(
        app->key_set_versions,
        app->key_set_versions + 1,
        (app->num_key_sets - 1) * sizeof(app->key_set_versions[0]));
    memmove(
        app->key_set_types,
        app->key_set_types + 1,
        (app->num_key_sets - 1) * sizeof(app->key_set_types[0]));
    memmove(
        app->key_set_initialized,
        app->key_set_initialized + 1,
        (app->num_key_sets - 1) * sizeof(app->key_set_initialized[0]));
    app->key_set_versions[app->num_key_sets - 1] = first_set_version;
    app->key_set_types[app->num_key_sets - 1] = first_set_type;
    app->key_set_initialized[app->num_key_sets - 1] = first_initialized;
}

static size_t dfc_greatest_common_divisor(size_t a, size_t b) {
    while(b != 0) {
        size_t remainder = a % b;
        a = b;
        b = remainder;
    }
    return a;
}

// Rotate fixed-width key blocks without copying a complete key set onto the
// embedded stack. Each cycle wipes the one-key scratch after restoring it.
static void dfc_rotate_key_blocks_left(
    uint8_t* blocks,
    size_t block_count,
    size_t block_width,
    size_t shift,
    uint8_t scratch[DFC_MAX_KEY_LEN]) {
    size_t cycles = dfc_greatest_common_divisor(block_count, shift);
    for(size_t cycle = 0; cycle < cycles; cycle++) {
        size_t current = cycle;
        memcpy(scratch, blocks + current * block_width, block_width);
        while(true) {
            size_t next = (current + shift) % block_count;
            if(next == cycle) break;
            memcpy(blocks + current * block_width, blocks + next * block_width, block_width);
            current = next;
        }
        memcpy(blocks + current * block_width, scratch, block_width);
        dfc_secure_wipe(scratch, DFC_MAX_KEY_LEN);
    }
}

bool dfc_credential_roll_key_set(
    DfcCredential* credential,
    DfcApplication* app,
    size_t key_set_number) {
    if(!credential || !app || key_set_number == 0 || key_set_number >= app->num_key_sets)
        return false;
    size_t key_width = dfc_credential_stored_key_length(app->key_storage_len);
    size_t block_count = app->num_keys * app->num_key_sets;
    size_t shift = key_set_number * app->num_keys;
    uint8_t scratch[DFC_MAX_KEY_LEN];
    dfc_rotate_key_blocks_left(
        credential->key_pool + app->key_offset, block_count, key_width, shift, scratch);
    for(size_t rotation = 0; rotation < key_set_number; rotation++) {
        dfc_credential_rotate_key_set_metadata(app);
    }
    app->key_len = dfc_key_set_type_length(app->key_set_types[0]);
    app->key_settings_2 = (uint8_t)((app->key_settings_2 & ~DFC_KEY_TYPE_MASK) |
                                    dfc_key_type_for_set_type(app->key_set_types[0]));
    return true;
}
#endif

void dfc_credential_keys_release(DfcCredential* credential, DfcApplication* app) {
    if(!credential) return;
    size_t* offset = key_offset_of(credential, app);
    size_t* pool_len = key_pool_len_of(credential, app);

    size_t old_offset = *offset;
    size_t old_len = *pool_len;
    *offset = DFC_KEY_POOL_NONE;
    *pool_len = 0;
    *num_keys_of(credential, app) = 0;
    *key_len_of(credential, app) = 0;
#if DFC_ENABLE_KEY_SETS
    if(app) app->key_storage_len = 0;
#endif
    if(old_offset != DFC_KEY_POOL_NONE && old_len > 0) {
        dfc_key_pool_compact_after_release(credential, old_offset, old_len);
    }
}

size_t dfc_credential_key_pool_free(const DfcCredential* credential) {
    if(!credential) return 0;
    if(credential->key_pool_used >= DFC_KEY_POOL_SIZE) return 0;
    return DFC_KEY_POOL_SIZE - credential->key_pool_used;
}

bool dfc_credential_delete_file(DfcCredential* credential, size_t app_index, uint8_t number) {
    for(size_t i = 0; i < credential->num_files; i++) {
        if(credential->files[i].app_index == app_index && credential->files[i].number == number) {
            dfc_file_release(credential, &credential->files[i]);
            if(i + 1 < credential->num_files) {
                memmove(
                    &credential->files[i],
                    &credential->files[i + 1],
                    (credential->num_files - i - 1) * sizeof(DfcFile));
            }
            credential->num_files--;
            memset(&credential->files[credential->num_files], 0, sizeof(DfcFile));
            return true;
        }
    }
    return false;
}

size_t dfc_credential_count_files_in_app(const DfcCredential* credential, size_t app_index) {
    size_t count = 0;
    for(size_t i = 0; i < credential->num_files; i++) {
        if(credential->files[i].app_index == app_index) count++;
    }
    return count;
}

void dfc_credential_copy_model(DfcCredential* credential, const DfcCredential* loaded) {
    if(!credential || !loaded) return;
    // DfcCredential is deliberately a pointer-free value type. Assignment
    // includes every current and future inline field, including pool metadata.
    *credential = *loaded;
}

bool dfc_file_set_data_size(DfcCredential* credential, DfcFile* file, uint32_t size) {
    if(!credential || !file) return false;
    if(!dfc_file_resize(credential, file, size)) return false;
    file->declared_size = size;
    file->contents_complete = true;
    return true;
}

bool dfc_credential_materialize_contents(
    DfcCredential* credential,
    uint8_t* scratch,
    size_t scratch_len) {
    if(!credential || !scratch) return false;
    bool complete = true;
    for(size_t i = 0; i < credential->num_files; i++) {
        DfcFile* file = &credential->files[i];
        size_t want;
        if(file->type == 0x00 || file->type == 0x01) {
            want = file->declared_size;
        } else if(file->type == 0x03 || file->type == 0x04) {
            want = (size_t)file->record_count * (size_t)file->record_size;
        } else {
            continue; // value files hold no pool slice
        }
        if(file->data_len >= want) {
            file->contents_complete = true;
            continue;
        }
        // The known prefix has to survive the grow: dfc_file_resize releases the
        // old slice first, and the compaction that follows moves the pool tail
        // down over it. Park the bytes in the caller's scratch, which is the
        // transfer buffer the encoding arrived in and is free by now.
        size_t known_len = file->data_len;
        if(known_len > scratch_len) {
            complete = false;
            continue;
        }
        if(known_len > 0 && file->data_offset != DFC_FILE_POOL_NONE &&
           file->data_offset + known_len == credential->file_pool_used &&
           want <= DFC_MAX_FILE_DATA &&
           want - known_len <= dfc_credential_file_pool_free(credential)) {
            size_t grow = want - known_len;
            memset(credential->file_pool + credential->file_pool_used, 0, grow);
            credential->file_pool_used += grow;
            file->data_len = want;
            file->contents_complete = true;
            continue;
        }
        const uint8_t* src = dfc_file_data_const(credential, file);
        if(src && known_len) memcpy(scratch, src, known_len);

        if(!dfc_file_resize(credential, file, want)) {
            complete = false;
            continue;
        }
        uint8_t* dst = dfc_file_data(credential, file);
        if(dst && known_len) memcpy(dst, scratch, known_len);
        file->contents_complete = true;
    }
    return complete;
}

void dfc_credential_mark_dirty(DfcCredential* credential) {
    credential->dirty = true;
}

void dfc_credential_clear_dirty(DfcCredential* credential) {
    credential->dirty = false;
}

bool dfc_credential_picc_ats_is_consistent(const DfcCredential* credential) {
    if(!credential) return false;
    if(credential->picc_ats_len == 0) return true;
    if(credential->picc_ats_len > DFC_PICC_ATS_MAX) return false;
    // An ATS is self-describing: its first octet is the length of the whole
    // answer. One that contradicts itself cannot be transmitted, only clamped or
    // padded, and either would put a frame on the wire that no card would send.
    return credential->picc_ats[0] == (uint8_t)credential->picc_ats_len;
}

DfcCredential* dfc_credential_alloc(void) {
    DfcCredential* credential = malloc(sizeof(DfcCredential));
    if(credential) memset(credential, 0, sizeof(DfcCredential));
    return credential;
}

bool dfc_credential_clear(DfcCredential* credential) {
    // Whatever the credential held, key material included, is wiped first: this
    // is also how a decoder discards a credential it only partly filled.
    dfc_secure_wipe(credential, sizeof(DfcCredential));
    credential->picc_key_settings_1 = 0x0F;
    credential->picc_key_settings_2 = DFC_KEY_TYPE_DES_2K3DES | 1;
    credential->picc_auth_command = DFC_CMD_AUTHENTICATE_LEGACY;
    credential->card.generation = DfcGenerationEv1;
    credential->card.storage = DFC_DEFAULT_CARD_STORAGE;
    credential->card.uid_provenance = DfcUidProvenanceReal;
    for(size_t i = 0; i < DFC_MAX_APPS; i++) {
        credential->apps[i].key_offset = DFC_KEY_POOL_NONE;
#if DFC_ENABLE_KEY_SETS
        credential->apps[i].num_key_sets = 1;
        credential->apps[i].key_set_initialized[0] = true;
#endif
    }
    credential->picc_key_offset = DFC_KEY_POOL_NONE;
    dfc_credential_keys_resize(credential, NULL, 1, 8);
    return true;
}

bool dfc_credential_init_factory(DfcCredential* credential) {
    uint8_t uid[DFC_DESFIRE_UID_LEN];
    if(!dfc_random_fill(uid, sizeof(uid))) return false;
    dfc_credential_clear(credential);

    credential->uid_len = DFC_DESFIRE_UID_LEN;
    memcpy(credential->uid, uid, sizeof(uid));
    credential->uid[0] = DFC_DESFIRE_UID_FIRST_BYTE;
    return true;
}

bool dfc_credential_init_blank(DfcCredential* credential) {
    if(!dfc_credential_init_factory(credential)) return false;
    const uint8_t aid_desfire_order[3] = {0x01, 0x00, 0x00};
    DfcApplication* app = dfc_credential_create_application_desfire_order(
        credential, aid_desfire_order, 0x0F, DFC_KEY_TYPE_DES_2K3DES | 1);
    if(!app) return false;

    DfcFile* file = dfc_credential_create_file(credential, 0, 0x00);
    if(!file) return false;
    file->number = 0x00;
    file->type = 0x00;
    file->comm_settings = DFC_COMM_PLAIN;
    file->access_rights = 0x0000;
    file->data_offset = DFC_FILE_POOL_NONE;
    file->data_len = 0;
    if(!dfc_file_set_data_size(credential, file, DFC_BLANK_FILE_SIZE)) {
        file->data_offset = DFC_FILE_POOL_NONE;
        file->data_len = 0;
        file->declared_size = 0;
        return false;
    }
    return true;
}

void dfc_credential_free(DfcCredential* credential) {
    DFC_ASSERT(credential);
    dfc_secure_wipe(credential, sizeof(*credential));
    free(credential);
}

size_t dfc_credential_key_length(uint8_t key_settings_2) {
    switch(key_settings_2 & DFC_KEY_TYPE_MASK) {
    case DFC_KEY_TYPE_3K3DES:
        return 24;
    case DFC_KEY_TYPE_AES:
        return 16;
    case DFC_KEY_TYPE_DES_2K3DES:
    default:
        return 16;
    }
}

bool dfc_credential_uid_is_detectable(DfcCredential* credential) {
    return dfc_desfire_uid_is_detectable(credential->uid, credential->uid_len);
}
