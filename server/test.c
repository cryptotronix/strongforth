#include "strongforth.h"

int main(int argc, char **argv)
{
	ATCA_STATUS status = stf_init("../forth/strongforth.zf", NULL);
	if (status != ATCA_SUCCESS)
	{
        	fprintf(stderr, "init failed: %02x\r\n", status);
		exit(status);
	}
	//stf_eval_resp_t resp = stf_eval("0 see 32< N6BC66LWUABO7ABJFBWN ran 32< J3VKKK6FMAJJOMBWZ6NJFMJMBM32GUNL pub 32< RBFPZAGSQ6TUMUT2TRTGSHL4YGJNRNTTQ7AWBHZBAMDWSDB7SKJWUHGVSS7FHK26 ser 32< AERQ4V42P 18 7949 gen ver dig rot2");
	stf_eval_resp_t resp = stf_eval("dig 32< J3VKKK6FMAJJOMBWZ6NJFMJMBM32GUNL pri 32< FBHJFKGHPUUIYS7MOI2WU35T7KVWZC34GHCC7VGK5CFZUCYHGNFQ sig sign sig 32>");
	printf("%s", (char *)stf_get_retbuf());
	printf("\n%i", resp.rc);
	printf("\n%i", resp.stf_status);
	return 0;
}

