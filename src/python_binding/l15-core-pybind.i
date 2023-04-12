%module libl15_core_pybind

%include "std_shared_ptr.i"
%include "std_string.i"
%include "std_vector.i"
%include "std_map.i"
%include "exception.i"

%apply unsigned int { uint32_t }
%apply unsigned long long { uint64_t }

%template(StringVector) std::vector<std::string>;
%template(SharedL15Error) std::shared_ptr<l15::Error>;

%{

#include "transaction.hpp"
#include "create_inscription.hpp"
#include "common_error.hpp"

const std::string build_time = __DATE__ " " __TIME__;

const std::string Version() {
    return build_time;
}
%}

%exception {
    try {
        $action
        } catch (std::exception& e) {
            PyErr_SetString(PyExc_Exception, e.what());
            SWIG_fail;
        }
}

%typemap(out) CMutableTransaction (PyObject* obj)
%{
    obj = PyDict_New();

    {
        PyObject *name_txid = PyUnicode_FromString("txid");
        PyObject *txid = PyUnicode_FromString($1.GetHash().GetHex().c_str());
        PyDict_SetItem(obj, name_txid, txid);
        Py_XDECREF(name_txid);
        Py_XDECREF(txid);
    }

    {
        PyObject *inputs = PyList_New($1.vin.size());
        for (size_t i = 0;i < $1.vin.size();++i) {
            PyObject *in = PyDict_New();

            {
                PyObject *name_hash = PyUnicode_FromString("txid");
                PyObject *hash = PyUnicode_FromString($1.vin[i].prevout.hash.GetHex().c_str());
                PyDict_SetItem(in, name_hash, hash);
                Py_XDECREF(name_hash);
                Py_XDECREF(hash);
            }

            {
                PyObject *name_n = PyUnicode_FromString("vout");
                PyObject *n = PyInt_FromLong($1.vin[i].prevout.n);
                PyDict_SetItem(in, name_n, n);
                Py_XDECREF(name_n);
                Py_XDECREF(n);
            }

            PyList_SetItem(inputs, i, in);
            Py_XDECREF(in);
        }
        {
            PyObject *name_vin = PyUnicode_FromString("vin");
            PyDict_SetItem(obj, name_vin, inputs);
            Py_XDECREF(name_vin);
        }
        Py_XDECREF(inputs);
    }

    {
        PyObject* outputs = PyList_New($1.vout.size());
        for (size_t i = 0; i < $1.vout.size(); ++i) {
            PyObject* out = PyDict_New();

            {
                PyObject* name_val = PyUnicode_FromString("value");
                PyObject* val = PyLong_FromLongLong($1.vout[i].nValue);
                PyDict_SetItem(out, name_val, val);
                Py_XDECREF(name_val);
                Py_XDECREF(val);
            }

            {
                PyObject* name_n = PyUnicode_FromString("n");
                PyObject* n = PyInt_FromLong(i);
                PyDict_SetItem(out, name_n, n);
                Py_XDECREF(name_n);
                Py_XDECREF(n);
            }

            if (l15::core::IsTaproot($1.vout[i])) {
                PyObject *name_scriptpubkey = PyUnicode_FromString("pubKey");
                PyObject *scriptpubkey = PyUnicode_FromString(l15::core::GetTaprootPubKey($1.vout[i]).c_str());
                PyDict_SetItem(out, name_scriptpubkey, scriptpubkey);
                Py_XDECREF(name_scriptpubkey);
                Py_XDECREF(scriptpubkey);
            }

            PyList_SetItem(outputs, i, out);
            Py_XDECREF(out);
        }
        {
            PyObject* name_vout = PyUnicode_FromString("vout");
            PyDict_SetItem(obj, name_vout, outputs);
            Py_XDECREF(name_vout);
        }
        Py_XDECREF(outputs);
    }

    $result = SWIG_Python_AppendOutput($result, obj);
%}

%include "create_inscription.hpp"
%include "transaction.hpp"
%include "transaction.h"

%inline %{
    const std::string Version();
%}
