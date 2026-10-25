/* Host implementation of the platform interface.
 *
 * Randomness is replayable so a recorded session reproduces exactly.
 * Allocation is the C library heap, because a host has one.
 */
#include "dfc_port.h"

#include <stdlib.h>
#include <string.h>

#include "dfc_port_host.h"

static uint8_t queue[DFC_HOST_RANDOM_BUFFER_MAX];
static size_t queue_len;
static size_t queue_offset;
static bool queue_set;
static bool random_failure_retryable;
static DfcHostFreeObserver free_observer;
static void* free_observer_context;
static bool fail_next_allocation;
static DfcAllocTag fail_next_allocation_tag;
static size_t allocations_before_failure;

void dfc_host_fail_next_allocation(DfcAllocTag tag) {
    dfc_host_fail_allocation_after(tag, 0);
}

void dfc_host_fail_allocation_after(DfcAllocTag tag, size_t successful_allocations) {
    fail_next_allocation = true;
    fail_next_allocation_tag = tag;
    allocations_before_failure = successful_allocations;
}

void dfc_host_set_free_observer(DfcHostFreeObserver observer, void* context) {
    free_observer = observer;
    free_observer_context = context;
}

void dfc_host_clear_random_buffer(void) {
    queue_len = 0;
    queue_offset = 0;
    queue_set = false;
    random_failure_retryable = false;
}

void dfc_host_set_random_buffer(const uint8_t* data, size_t len) {
    // Injections accumulate: a vector may queue the octets for one exchange
    // while the octets for an earlier one are still unread.
    size_t remaining = queue_len - queue_offset;
    if(queue_offset > 0 && remaining > 0) {
        memmove(queue, queue + queue_offset, remaining);
    }
    queue_offset = 0;
    queue_len = remaining;
    size_t room = sizeof(queue) - remaining;
    if(len > room) len = room;
    memcpy(queue + remaining, data, len);
    queue_len += len;
    queue_set = true;
    random_failure_retryable = false;
}

size_t dfc_host_random_remaining(void) {
    return queue_len - queue_offset;
}

bool dfc_random_fill(uint8_t* buf, size_t len) {
    if(queue_set) {
        size_t remaining = queue_len - queue_offset;
        if(len > remaining) {
            // A caller can append the missing scripted bytes and retry.
            random_failure_retryable = true;
            return false;
        }
        memcpy(buf, queue + queue_offset, len);
        queue_offset += len;
        random_failure_retryable = false;
        return true;
    }

    // No queue: a deterministic ramp, so an unscripted session is still
    // reproducible.
    for(size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)i;
    }
    random_failure_retryable = false;
    return true;
}

void dfc_random_operation_begin(void) {
    random_failure_retryable = false;
}

bool dfc_random_failure_is_retryable(void) {
    return random_failure_retryable;
}

void* dfc_platform_alloc(size_t size, DfcAllocTag tag) {
    if(fail_next_allocation && tag == fail_next_allocation_tag) {
        if(allocations_before_failure > 0) {
            allocations_before_failure--;
        } else {
            fail_next_allocation = false;
            return NULL;
        }
    }
    return calloc(1, size);
}

void dfc_platform_free(void* ptr) {
    if(ptr && free_observer) free_observer(ptr, free_observer_context);
    free(ptr);
}

void dfc_port_notify(void* context, DfcEvent event) {
    DFC_UNUSED(context);
    DFC_UNUSED(event);
}
