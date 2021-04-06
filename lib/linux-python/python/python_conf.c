#include "strongforth.h"

ATCAIfaceCfg cfg_ateccx08a_kithid_default = {
    .iface_type                  = ATCA_HID_IFACE,
    .devtype                     = ATECC608,
    {
        .atcahid.dev_interface   = ATCA_KIT_I2C_IFACE,
        .atcahid.dev_identity    = 0x6C,
        .atcahid.idx             = 0,
        .atcahid.vid             = 0x03EB,
        .atcahid.pid             = 0x2312,
        .atcahid.packetsize      = 64,
    }
};

void stf_py_callback_set_atcacfg(ATCAIfaceCfg **cfg)
{
	*cfg = &cfg_ateccx08a_kithid_default;
}
