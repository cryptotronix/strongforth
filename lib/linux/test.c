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

int main(int argc, char **argv)
{
	ATCA_STATUS status = stf_init("../../forth/strongforth.zf", &cfg_ateccx08a_kithid_default);
	if (status != ATCA_SUCCESS)
	{
        	fprintf(stderr, "init failed: %02x\r\n", status);
		exit(status);
	}
	stf_eval_resp_t resp = stf_eval("see dup 32< N6BC66LWUABO7ABJFBWNXS4SBIYP2DX7 ran pub rot1c");
	printf("%s", (char *)stf_get_retbuf());
	printf("\n%i", resp.rc);
	printf("\n%i", resp.stf_status);
	return 0;
}

