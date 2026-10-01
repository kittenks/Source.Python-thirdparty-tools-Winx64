// ---------------------------------------------------------------------------
// Proof that the freshly built x86-64 Boost libraries are usable, not merely
// present. "cl.exe exited 0" and "the .lib exists" are not evidence; a program
// compiled the way Source.Python compiles - no /std: flag, so MSVC's default
// C++14, plus -DBOOST_ALL_NO_LIB as the project sets - that links against them
// and gets correct answers is.
//
// This deliberately exercises the private-header boundary that
// -DBOOST_FILESYSTEM_NO_CXX20_ATOMIC_REF sits behind: the library's own
// translation units use Boost's atomic_ref, while this consumer knows nothing
// about it. If the library and consumer disagreed about the C++ standard or the
// class layout, the calls below would misbehave rather than merely fail to link.
// ---------------------------------------------------------------------------
#include <boost/filesystem.hpp>
#include <boost/system/error_code.hpp>
#include <boost/version.hpp>

#include <cstdio>
#include <string>
#include <iostream>
#include <limits>

namespace fs = boost::filesystem;

static int g_fail = 0;

static void check(const char* what, bool ok)
{
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++g_fail;
}

int main()
{
    // --- the binary really is 64-bit, and LP64 not LLP64 --------------------
    // This matters: on Windows x64 an `unsigned long` is still 32 bits while a
    // pointer is 64. If this build were 32-bit the pointer check would fail.
    std::printf("pointer size      : %u bytes\n",
                static_cast<unsigned>(sizeof(void*)));
    std::printf("unsigned long     : %u bytes  <- 32 even on Win64 (LLP64)\n",
                static_cast<unsigned>(sizeof(unsigned long)));
    std::printf("BOOST_VERSION     : %d\n", BOOST_VERSION);

    check("binary is 64-bit (pointer == 8)", sizeof(void*) == 8);
    check("BOOST_VERSION is 1.87.0", BOOST_VERSION == 108700);

    // --- boost::system ------------------------------------------------------
    // error_code is the piece that has to interoperate with the library's own
    // copies of these symbols.
    boost::system::error_code ec;
    fs::path p = fs::path("C:/definitely/not/here/at/all");
    bool threw = false;
    try {
        fs::exists(p, ec);
    } catch (...) {
        threw = true;
    }
    std::printf("  exists() on a missing path: ec=%d (%s), threw=%d\n",
                ec.value(), ec.category().name(), static_cast<int>(threw));
    check("exists() reported failure through error_code", ec.value() != 0);
    check("exists() did not throw when given an error_code", !threw);

    // The value is printed as well as asserted, so a failure here says whether
    // the library is wrong or the expectation is. An earlier version of this
    // line asserted !exists() for a path that does exist, which is a check that
    // can never pass; printing removes the need to guess which kind of failure
    // a red line would have been.
    boost::system::error_code ok_ec;
    bool win_exists = fs::exists(fs::path("C:/Windows"), ok_ec);
    std::printf("  C:/Windows: exists=%d ec=%d (%s)\n",
                static_cast<int>(win_exists), ok_ec.value(), ok_ec.category().name());
    check("a path that does exist reports ec == 0",
          win_exists && ok_ec.value() == 0);

    // --- boost::filesystem: string handling ---------------------------------
    fs::path q("some/relative/path.txt");
    check("filename()", q.filename() == std::string("path.txt"));
    check("parent_path()", q.parent_path() == std::string("some/relative"));
    check("extension()", q.extension() == std::string(".txt"));
    check("is_absolute() is false for a relative path", !q.is_absolute());

    fs::path joined = fs::path("a") / "b" / "c.txt";
    check("operator/ composes", joined == fs::path("a/b/c.txt"));

    // --- boost::filesystem: the real filesystem, via a temp dir -------------
    // This is the part that actually touches the Win32 APIs, so it is the part
    // that would fail if the library were miscompiled.
    boost::system::error_code mk;
    fs::path dir = fs::temp_directory_path(mk) / "sp_boost_x64_check";
    if (mk) {
        std::printf("  could not locate a temp directory: %s\n", mk.message().c_str());
        return 2;
    }
    fs::remove_all(dir, mk);
    mk.clear();
    fs::create_directories(dir, mk);
    check("create_directories succeeded", !mk);

    fs::path f = dir / "probe.bin";
    {
        std::FILE* fp = std::fopen(f.string().c_str(), "wb");
        check("fopen for write", fp != nullptr);
        if (fp) { std::fputs("sourcepython", fp); std::fclose(fp); }
    }
    check("the file exists after writing", fs::exists(f));
    check("file_size is 12", fs::file_size(f) == 12);

    fs::rename(f, dir / "renamed.bin", mk);
    check("rename succeeded", !mk);
    check("the old name is gone", !fs::exists(f));
    check("the new name is there", fs::exists(dir / "renamed.bin"));

    // Must be a boost::system::error_code: the overloads take that, not
    // std::error_code. The compiler says so explicitly, so do not guess.
    boost::system::error_code rm_ec;
    fs::remove_all(dir, rm_ec);
    check("remove_all cleaned up", !fs::exists(dir) && !rm_ec);

    std::printf("\n%s (%d check(s) failed)\n",
                g_fail ? "RESULT: FAILURES ABOVE" : "RESULT: ALL CHECKS PASSED", g_fail);
    return g_fail ? 1 : 0;
}
