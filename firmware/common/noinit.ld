/* Linker script to configure memory regions. */

SEARCH_DIR(.)
GROUP(-lgcc -lc -lnosys)

MEMORY
{
  /* Put a noinit region at RAM. 0x5800 (22KB) holds the current retained users (MIFARE auth logs, logflash,
   * the interactive LF trace) with ~1.7KB headroom -- actual usage is ~20.3KB, confirmed via the map file. The
   * freed 0x2800 (10KB) goes to the application's own RAM region below, which is what standalone builds overflow. */
  NOINIT (rwx) : ORIGIN = 0x2003a800, LENGTH = 0x5800
}

SECTIONS
{
  .noinit (NOLOAD):
  {
    /* place all symbols in input sections that start with .noinit */
    KEEP(*(*.noinit*))
  } > NOINIT
}