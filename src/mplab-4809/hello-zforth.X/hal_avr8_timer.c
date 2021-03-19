
#include <avr/io.h>

void hal_delay_us(uint32_t delay)
{
    if (0 == delay)
    {
        return;
    }
    
    // load compare to delay 1us
    TCB0.CCMP = (uint16_t)(F_CPU/1000000);
    TCB0.CTRLA |= TCB_ENABLE_bm;
    
    do
    {
        while(!(TCB0.INTFLAGS & TCB_CAPT_bm));
        TCB0.INTFLAGS = TCB_CAPT_bm; // clear flag
    } while (--delay > 0);
    
    TCB0.CTRLA &= ~(TCB_ENABLE_bm);
}

void hal_delay_ms(uint32_t delay)
{
    if (0 == delay)
    {
        return;
    }
    
    // load compare to delay 1ms
    TCB0.CCMP = (uint16_t)(F_CPU/10000);
    TCB0.CTRLA |= TCB_ENABLE_bm;
    
    do
    {
        while(!(TCB0.INTFLAGS & TCB_CAPT_bm));
        TCB0.INTFLAGS = TCB_CAPT_bm; // clear flag
    } while (--delay > 0);
    
    TCB0.CTRLA &= ~(TCB_ENABLE_bm);
}
