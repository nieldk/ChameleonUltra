/* Test control over the host platform implementation. */
#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "dfc_port.h"

#define DFC_HOST_RANDOM_BUFFER_MAX 64

// Queues the octets dfc_random_fill returns, so a session replays exactly. A
// request larger than the remaining script fails without consuming any bytes.
void dfc_host_set_random_buffer(const uint8_t* data, size_t len);
void dfc_host_clear_random_buffer(void);
// Octets still queued. Zero after a session consumed everything it was given.
size_t dfc_host_random_remaining(void);

// Test hook invoked immediately before the host allocator releases a block.
typedef void (*DfcHostFreeObserver)(const void* ptr, void* context);
void dfc_host_set_free_observer(DfcHostFreeObserver observer, void* context);

// Makes exactly the next allocation with this tag fail.
void dfc_host_fail_next_allocation(DfcAllocTag tag);
void dfc_host_fail_allocation_after(DfcAllocTag tag, size_t successful_allocations);
// Successful allocations since process start, separated by engine allocation tag.
size_t dfc_host_allocation_count(DfcAllocTag tag);
