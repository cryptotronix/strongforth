#include <string.h>

static int
hydro_random_init(void)
{
    memset(hydro_random_context.state, 0x42, sizeof(hydro_random_context.state));
    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);
    return 0;
}
