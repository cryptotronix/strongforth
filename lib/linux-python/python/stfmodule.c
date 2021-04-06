//NOTE: python MUST be included first due to preprocessor
#include <Python.h>
#include <stdlib.h>

#include "stfmodule.h"

static PyObject *SFError;

static ATCAIfaceCfg *atca_cfg = NULL;

static PyObject *
stf_stf_init(__attribute__ ((unused)) PyObject *self,
                           PyObject *args)
{
	char *fname = NULL;

	uint32_t ok = PyArg_ParseTuple(args, "z", &fname);
    	if(!ok)
    	{
        	PyErr_SetString(SFError, "Could not parse arguments to stf_init.\n");
        	return NULL;
   	}

	if (atca_cfg == NULL)
		printf("BOOOOO");
	fflush(stdout);
	ATCA_STATUS stat = stf_init(fname, atca_cfg);

	/* making sure we do not overflow */
	if (sizeof(int) == sizeof(ATCA_STATUS))
		return Py_BuildValue("I", stat);
	else
		return Py_BuildValue("k", stat);

}

static PyObject *
stf_stf_eval(__attribute__ ((unused)) PyObject *self,
                           PyObject *args)
{
    PyObject *command_list = NULL;


    uint32_t ok = PyArg_ParseTuple(args, "O", &command_list);
    if(!ok)
    {
        PyErr_SetString(SFError,
                "Could not parse arguments to stf_eval\n");
        return NULL;
    }

    uint32_t is_a_list = PyList_Check(command_list);
    if (!is_a_list)
    {
        PyErr_SetString(SFError,
                "argument to stf_eval is not a list\n");
        return NULL;
    }

    Py_ssize_t listlen = PyList_Size(command_list);
    PyObject* py_resps = PyList_New(listlen);

    uint32_t i = 0;
    while (i < listlen)
    {
	PyObject *cmd = PyList_GetItem(command_list, i);
	if (cmd == NULL)
	{
		// IndexError has been set
		return NULL;
	}

	uint32_t is_a_string = PyBytes_Check(cmd);
    	if (!is_a_string)
    	{
    	    PyErr_SetString(SFError,
    	            "stf_eval imput list must be all byte strings\n");
    	    return NULL;
    	}

	char *cmd_string = (char *) PyBytes_AsString(cmd);
	if (cmd_string == NULL)
	{
		return NULL;
	}

	stf_eval_resp_t resp = stf_eval(cmd_string);

	char retbuf[STF_RETURN_BUF_LEN] = {0};
	stf_retbuf_copy(retbuf, STF_RETURN_BUF_LEN);

	PyList_SetItem(py_resps, i, Py_BuildValue("(iis)", resp.rc, resp.stf_status, retbuf));

	i++;
    }

    return py_resps;
}

static
 PyMethodDef SFMethods[] = {
    {"stf_eval", stf_stf_eval, METH_VARARGS, "Send commands to strongforth and receive responses."},
    {"stf_init", stf_stf_init, METH_VARARGS, "Initialize strongforth."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef stfmodule = {
    PyModuleDef_HEAD_INIT,
    "stf",
    "module to interface with strongforth",
    -1,
    SFMethods,
    NULL,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC
PyInit_stf(void)
{
    PyObject *m;

    m = PyModule_Create(&stfmodule);
    if(m == NULL){
	    return NULL;
    }

    SFError = PyErr_NewException("stf.error", NULL, NULL);
    Py_XINCREF(SFError);
    if(PyModule_AddObject(m, "error", SFError) < 0){
	    Py_XINCREF(SFError);
	    Py_CLEAR(SFError);
	    Py_DECREF(m);
	    return NULL;
    }

    stf_py_callback_set_atcacfg(&atca_cfg);

    return m;
}
