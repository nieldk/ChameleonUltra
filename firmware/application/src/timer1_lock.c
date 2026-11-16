#include "timer1_lock.h"

static volatile bool m_held = false;

bool timer1_lock_try_acquire(void) {
    if (m_held) {
        return false;
    }
    m_held = true;
    return true;
}

void timer1_lock_release(void) {
    m_held = false;
}
