#ifndef BL_EGG_H__
#define BL_EGG_H__

/* Slot LEDs: red scan (the watchdog on patrol), three barks, then the
 * bootloader version in binary. Blocks for about 2.5 s. */
void bl_egg_play(void);

#endif
