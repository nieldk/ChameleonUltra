#include <errno.h>
#undef errno
extern int errno;

extern char end;
extern char __StackLimit;

// Bounded heap: fail malloc at the stack limit instead of growing into the stack.
void *_sbrk(int incr) {
    static char *heap_end = &end;
    char *prev = heap_end;
    if (incr > 0 && (heap_end + incr > &__StackLimit || heap_end + incr < heap_end)) {
        errno = ENOMEM;
        return (void *) -1;
    }
    heap_end += incr;
    return prev;
}
