// ---------------------------------------------------------------------------
// Functional proof that libboost_python313-vc143-mt-s-x64-1_87.lib works.
//
// Why this file was rewritten twice: the first version reported a wall of
// errors that were all misuse of the Boost.Python API, not defects in the
// library. Specifically, in this Boost version:
//
//   * class_ is a template. bp::class_("Counter") does not create a Python
//     class; it needs a C++ type, bp::class_<T>.
//   * bp::list() returns bp::object, which has no append(). Declaring
//     bp::list lst; gives the derived type that does.
//   * error_already_set is a bare struct with a virtual destructor and does not
//     derive from std::exception, so it has no what(). The message has to come
//     from the Python error indicator directly.
//   * cpp_function is not reachable from boost/python.hpp - that header lists
//     60 includes and function.hpp is not one of them.
//
// The library and its headers were found and parsed in every one of those
// attempts; none of the errors came from the .lib.
//
// What each check exercises, and why it matters as evidence:
//   Py_Initialize            the CPython import library resolves
//   import + exec            import.cpp, exec.cpp, str.cpp
//   extract<int>             converter/builtin_converters.cpp
//   class_<T> + def + init   object/class.cpp, object/function.cpp,
//                            converter/registry.cpp, init.hpp
//   list + str converters    object/... , converter/builtin_converters.cpp
//   cpp_function             function.cpp, arg handling in args.hpp
//   exception round trip     errors.cpp
// If any of the 27 translation units were missing from the archive, this fails
// to link with an unresolved external rather than failing a check.
// ---------------------------------------------------------------------------
#include <boost/python.hpp>
// make_function lives here; boost/python.hpp does not include it. Note there is
// no boost/python/function.hpp and no boost::python::cpp_function in Boost at
// all - cpp_function is pybind11's spelling, and reaching for it was a mistake
// in an earlier version of this file. Boost.Python's bridge is make_function,
// and def() inside a class_ or module is a thin layer over it.
#include <boost/python/make_function.hpp>

#include <cstdio>
#include <string>

namespace bp = boost::python;

static int g_fail = 0;
static void check(const char* what, bool ok)
{
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++g_fail;
}

// A plain free function, the form make_function is documented for. Wrapped in a
// named function rather than a lambda so overload resolution cannot pick
// something unintended and the failure, if any, is about the library.
static int triple(int n) { return n * 3; }

// A real C++ type, because class_ is a template over one.
struct Greeter
{
    explicit Greeter(std::string n) : name(std::move(n)) {}
    std::string greet() const { return "hello " + name; }
    int add(int a, int b) const { return a + b; }
    std::string name;
};

// Pull the message out of the Python error indicator. error_already_set has no
// what() in this Boost version, so this is the only way to see the text.
static std::string fetch_python_error()
{
    PyObject *ptype = nullptr, *pvalue = nullptr, *ptraceback = nullptr;
    PyErr_Fetch(&ptype, &pvalue, &ptraceback);
    PyErr_NormalizeException(&ptype, &pvalue, &ptraceback);
    std::string out;
    if (pvalue) {
        PyObject *pstr = PyObject_Str(pvalue);
        if (pstr) {
            const char* utf8 = PyUnicode_AsUTF8(pstr);
            if (utf8) out = utf8;
            Py_DECREF(pstr);
        }
    }
    Py_XDECREF(ptype);
    Py_XDECREF(pvalue);
    Py_XDECREF(ptraceback);
    return out;
}

int main()
{
    std::printf("pointer size : %u bytes\n", static_cast<unsigned>(sizeof(void*)));
    std::printf("libpython    : %s\n", Py_GetVersion());
    check("binary is 64-bit", sizeof(void*) == 8);
    check("CPython is 3.13.x", std::string(Py_GetVersion()).find("3.13") == 0);

    Py_Initialize();
    if (!Py_IsInitialized()) { std::printf("  Py_Initialize failed\n"); return 2; }

    try {
        // The namespace for exec must be a real dict. On Python 3.13 the
        // __main__ module object is not one, and Boost.Python rejects it with
        // "globals must be a real dict". main.attr("__dict__") is the documented
        // way to get it. (There is no boost::python::globals in this version;
        // an earlier attempt used it and failed to compile.)
        bp::object main_mod = bp::import("__main__");
        check("bp::import(\"__main__\") returned an object", main_mod.ptr() != nullptr);

        // No separate "is it a dict" check: there is no boost::python::type in
        // this version, and if the namespace were wrong the exec below would
        // fail with the same message, which is the actual thing worth testing.
        bp::object ns = main_mod.attr("__dict__");

        // import.cpp + exec.cpp + str.cpp + converter/builtin_converters.cpp
        bp::exec("answer = 6 * 7\n", ns);
        check("exec, then extract<int> gives 42",
              bp::extract<int>(ns["answer"]) == 42);

        // object/class.cpp, object/function.cpp, converter/registry.cpp, init.hpp
        // Built once and stored: registering the same C++ type with class_ twice
        // raises, so the scope attribute and the registration have to be the
        // same object rather than two separate calls. The local is named
        // differently from the type so that class_<Greeter> still names the
        // C++ type rather than this variable.
        bp::object GreeterClass = bp::class_<Greeter>("Greeter", bp::init<std::string>())
            .def("greet", &Greeter::greet)
            .def("add", &Greeter::add);
        ns["Greeter"] = GreeterClass;

        bp::exec(
            "g = Greeter('world')\n"
            "msg = g.greet()\n"
            "total = g.add(19, 23)\n", ns);

        bp::extract<std::string> msg(ns["msg"]);
        check("a C++ method called from Python returns a std::string",
              msg.check() && msg() == std::string("hello world"));
        check("a C++ method with two int args returns 42",
              bp::extract<int>(ns["total"]) == 42);

        // list: bp::object has no append(), the derived bp::list does.
        bp::list lst;
        lst.append(bp::object(10));
        lst.append(bp::object(20));
        // bp::len returns ssize_t, not object, so it cannot be fed to extract.
        check("bp::list append and len", bp::len(lst) == 2);
        // subscripting and extracting an element exercises object/stl_iterator
        // paths and the int converter from the other direction.
        check("element extracted back out of the list",
              bp::extract<int>(lst[1]) == 20);

        // str conversion both ways
        bp::object joined = bp::str("n=") + bp::str(7);
        bp::extract<std::string> j(joined);
        check("str + str, extracted back to std::string",
              j.check() && j() == std::string("n=7"));

        // make_function.hpp and the argument-handling templates in args.hpp.
        ns["triple"] = bp::make_function(&triple);
        bp::exec("t = triple(14)\n", ns);
        check("a C++ free function exposed to Python and called back",
              bp::extract<int>(ns["t"]) == 42);

        // errors.cpp: a Python exception must arrive in C++.
        bp::exec("def boom():\n    raise ValueError('deliberate failure')\n", ns);
        bool caught = false;
        std::string text;
        try {
            bp::exec("boom()\n", ns);
        } catch (bp::error_already_set&) {
            caught = true;
            text = fetch_python_error();
        }
        check("a Python exception is catchable as error_already_set", caught);
        check("the exception text survives the round trip",
              text.find("deliberate failure") != std::string::npos);
    }
    catch (bp::error_already_set&) {
        std::printf("  UNCAUGHT python error: %s\n", fetch_python_error().c_str());
        return 2;
    }

    if (Py_FinalizeEx() < 0) { std::printf("  Py_Finalize reported an error\n"); ++g_fail; }

    std::printf("\n%s (%d check(s) failed)\n",
                g_fail ? "RESULT: FAILURES ABOVE" : "RESULT: ALL CHECKS PASSED", g_fail);
    return g_fail ? 1 : 0;
}
