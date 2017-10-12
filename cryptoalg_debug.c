#include "cryptoalg_debug.h"

void dump_mem(uint8_t *addr, uint32_t len)
{
    const uint32_t ITEM_PER_LINE = 16;

    int i = 0;

    for (i=0; i<len; i++) {
        printf("%2.2x", addr[i]);
        if ((i%ITEM_PER_LINE) == (ITEM_PER_LINE-1)) {
            printf("\n");
        } else {
            printf(" ");
        }
    }

    if ((i%ITEM_PER_LINE) != (0)) {
        printf("\n");
    }
}
