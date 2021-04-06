#ifndef _CAMODULE_H_
#define _CAMODULE_H_

#include "strongforth.h"

PyMODINIT_FUNC
PyInit_stf(void);

void
stf_py_callback_set_atcacfg(ATCAIfaceCfg **cfg);

#endif
