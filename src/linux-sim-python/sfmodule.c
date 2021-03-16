//NOTE: python MUST be included first due to preprocessor
#include <Python.h>
#include <stdlib.h>

#include "sys.h"

static PyObject *SFError;

static const char *
read_zf_result(zf_result rv)
{
	const char *msg = NULL;

	switch(rv)
	{
		case ZF_OK: break;
		case ZF_ABORT_INTERNAL_ERROR: msg = "internal error"; break;
		case ZF_ABORT_OUTSIDE_MEM: msg = "outside memory"; break;
		case ZF_ABORT_DSTACK_OVERRUN: msg = "dstack overrun"; break;
		case ZF_ABORT_DSTACK_UNDERRUN: msg = "dstack underrun"; break;
		case ZF_ABORT_RSTACK_OVERRUN: msg = "rstack overrun"; break;
		case ZF_ABORT_RSTACK_UNDERRUN: msg = "rstack underrun"; break;
		case ZF_ABORT_NOT_A_WORD: msg = "not a word"; break;
		case ZF_ABORT_COMPILE_ONLY_WORD: msg = "compile-only word"; break;
		case ZF_ABORT_INVALID_SIZE: msg = "invalid size"; break;
		case ZF_ABORT_DIVISION_BY_ZERO: msg = "division by zero"; break;
		default: msg = "unknown error";
	}

	return msg;
}

static PyObject *
sf_sf_init(__attribute__ ((unused)) PyObject *self,
                           PyObject *args)
{
	zf_init(0);
	zf_bootstrap();
	char resp[256] = {0};
	get_retbuf((char *) resp, 256);
	reset_retbuf();
	return Py_BuildValue("s", resp);
}

static PyObject *
sf_sf_include(__attribute__ ((unused)) PyObject *self,
                           PyObject *args)
{
	const char *fname = NULL;

	uint32_t ok = PyArg_ParseTuple(args, "s", &fname);
    	if(!ok)
    	{
        	PyErr_SetString(SFError, "Could not parse arguments to sf_include.\n");
        	return NULL;
   	 }

	char buf[256];

	FILE *f = fopen(fname, "rb");
	int line = 1;
	zf_result rv = -1;
	if(f) {
		while(fgets(buf, sizeof(buf), f)) {
			rv = zf_eval(buf);
			if (rv != ZF_OK)
			{
				fclose(f);
        			return PyErr_Format(SFError, "error %s:%d %s",
					        fname,
						line,
						read_zf_result(rv));
			}
		}
		fclose(f);
	} else
        	return PyErr_Format(SFError, "error opening file '%s': %s\n", fname, strerror(errno));
	Py_INCREF(Py_None);
        return Py_None;
}

static PyObject *
sf_sf_eval(__attribute__ ((unused)) PyObject *self,
                           PyObject *args)
{
    PyObject *command_list = NULL;


    uint32_t ok = PyArg_ParseTuple(args, "O", &command_list);
    if(!ok)
    {
        PyErr_SetString(SFError,
                "Could not parse arguments to sf_eval\n");
        return NULL;
    }

    uint32_t is_a_list = PyList_Check(command_list);
    if (!is_a_list)
    {
        PyErr_SetString(SFError,
                "argument to sf_eval is not a list\n");
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
    	            "sf_eval imput list must be all byte strings\n");
    	    return NULL;
    	}

	char *cmd_string = (char *) PyBytes_AsString(cmd);
	if (cmd_string == NULL)
	{
		return NULL;
	}

	reset_retbuf();

	zf_result rv = zf_eval(cmd_string);

	const char *errmsg = read_zf_result(rv);
	char retbuf[256] = {0};
	get_retbuf((char *) retbuf, 256);

	if (errmsg)
	{
		PyList_SetItem(py_resps, i, Py_BuildValue("s", errmsg));
		i = listlen;
	}
	else
		PyList_SetItem(py_resps, i, Py_BuildValue("s", retbuf));

	reset_retbuf();

	i++;
    }

    return py_resps;
}

static
 PyMethodDef SFMethods[] = {
    {"sf_eval", sf_sf_eval, METH_VARARGS, "Send commands to strongforth and receive responses."},
    {"sf_init", sf_sf_init, METH_VARARGS, "Initialize strongforth."},
    {"sf_include", sf_sf_include, METH_VARARGS, "Load in a .zf file."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef sfmodule = {
    PyModuleDef_HEAD_INIT,
    "sf",
    "module to interface with strongforth",
    -1,
    SFMethods,
    NULL,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC
PyInit_sf(void)
{
    PyObject *m;

    m = PyModule_Create(&sfmodule);
    if(m == NULL){
	    return NULL;
    }

    SFError = PyErr_NewException("sf.error", NULL, NULL);
    Py_XINCREF(SFError);
    if(PyModule_AddObject(m, "error", SFError) < 0){
	    Py_XINCREF(SFError);
	    Py_CLEAR(SFError);
	    Py_DECREF(m);
	    return NULL;
    }

    return m;
}
