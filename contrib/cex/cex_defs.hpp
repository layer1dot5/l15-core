#ifndef _CEX_DEFS_HPP
#define _CEX_DEFS_HPP

#ifndef CEXCXX20_CONSTEXPR
# if __cplusplus >= 202002L
#  define CEXCXX20_CONSTEXPR constexpr
# else
#  define CEXCXX20_CONSTEXPR
# endif
#endif

#ifndef CEXCXX_NOEXCEPT
# if __cplusplus >= 201103L
#  define CEXCXX_NOEXCEPT noexcept
# else
#  define CEXCXX_NOEXCEPT
# endif
#endif

#endif //L15_CORE_CEX_DEFS_HPP
