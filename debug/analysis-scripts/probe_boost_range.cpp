// Isolate group C: boost/range/detail/implementation_help.hpp fails to compile
// in the Source.Python x86-64 build with
//   error C2628: 'size_t' followed by 'unsigned' is illegal   (line 79, col 28)
//   error C2628: 'size_t' followed by 'int' is illegal
//   error C2988 / C2059 / C2143 / C2447
// and the same position reports two different following tokens, which is what a
// macro rewriting part of the declaration looks like.
//
// Line 79 is:
//     inline std::size_t str_size( const Char* const& s )
//
// Two hypotheses, and this file tests both:
//
//   H1: the vendored boost header is broken for this target. Then including it
//       on its own, with the project's flags, already fails.
//   H2: something Source.Python includes earlier defines a macro that lands in
//       that declaration. Then the header is fine alone and only fails once
//       SP's headers are in scope.
//
// The include alone is therefore the experiment. Run it via the accompanying
// .bat so the flags match the real build.
#include <boost/range/detail/implementation_help.hpp>

int main() { return 0; }
