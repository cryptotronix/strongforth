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
	stf_eval_resp_t resp = stf_eval("ran getrand ran 32> ");
	printf("%s", (char *)stf_get_retbuf());
	printf("\nzf status: %i", resp.rc);
	printf("\nstrongforth status: %i\n", resp.stf_status);
	return 0;
}

