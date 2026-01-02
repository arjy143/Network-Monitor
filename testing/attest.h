#ifndef ATTEST_H
#define ATTEST_H

#include <stdio.h>
#include <stdarg.h>

#ifdef __cplusplus
    extern "C" {
#endif

/*  
    Attest - a minimal unit testing framework for C and C++.
*/

#define ATTEST_MAX_TESTS 1024

typedef void (*attest_func_t)(void);

//representation of a testcase
typedef struct attest_testcase
{
    const char* name;
    attest_func_t func;
    const char* file;
    int line;
    int passed;

} attest_testcase_t;

//helper to find float absolute value
static inline double float_abs(double x)
{
    if (x < 0)
    {
        return -x;
    }
    else
    {
        return x;
    }
}

//string.h replacement functions, because the original ones sound stupid

//strcmp
static int compare_strings(const char* a, const char* b)
{
    //iterate over the array pointers
    while (*a && (*a == *b))
    {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

//strncmp
static int compare_first_n_chars(const char* a, const char* b, size_t n)
{
    while (n-- && *a && (*a == *b))
    {
        a++;
        b++;
    }
    
    if (n == (size_t)-1)
    {
        return 0;
    }
    else
    {
        return (unsigned char)*a - (unsigned char)*b;
    }
}
//strstr - does a contain b, if yes then return pointer to first occurence in a
static const char* contains(const char* a, const char* b)
{
    if (!b)
    {
        return a;
    }
    for (; *a; a++)
    {
        const char* x = a;
        const char* y = b;
        while (*x && *y && *x == *y)
        {
            x++;
            y++;
        }

        if (!*y)
        {
            return a;
        }
    }
    return NULL;
}
//memcmp
static int compare_memory(const void* a, const void* b, size_t n)
{
    const unsigned char* x = (const unsigned char*)a;
    const unsigned char* y = (const unsigned char*)b;

    while (n--)
    {
        if (*x != *y)
        {
            return *x - *y;
        }
        x++;
        y++;
    }
    return 0;

}

//below is used for json output
static int attest_json_mode = 0;

static void attest_printf(const char* text, ...)
{
    if (!attest_json_mode)
    {
        va_list args;
        va_start(args, text);
        vfprintf(stdout, text, args);
        va_end(args);
    }
}

// C helper macros

#define __ATTEST_IS_ARITHMETIC_TYPE(t) ( \
    __builtin_types_compatible_p(t, signed char) || \
    __builtin_types_compatible_p(t, unsigned char) || \
    __builtin_types_compatible_p(t, short) || \
    __builtin_types_compatible_p(t, unsigned short) || \
    __builtin_types_compatible_p(t, int) || \
    __builtin_types_compatible_p(t, unsigned int) || \
    __builtin_types_compatible_p(t, long) || \
    __builtin_types_compatible_p(t, unsigned long) || \
    __builtin_types_compatible_p(t, long long) || \
    __builtin_types_compatible_p(t, unsigned long long) || \
    __builtin_types_compatible_p(t, float) || \
    __builtin_types_compatible_p(t, double) || \
    __builtin_types_compatible_p(t, long double) )

#define __ATTEST_IS_CSTRING_TYPE(t) ( \
    __builtin_types_compatible_p(t, char *) || \
    __builtin_types_compatible_p(t, const char *) || \
    __builtin_types_compatible_p(t, char[]) || \
    __builtin_types_compatible_p(t, const char[]) )

#define __ATTEST_IS_ARITHMETIC_EXPR(e) __ATTEST_IS_ARITHMETIC_TYPE(__typeof__(e))
#define __ATTEST_IS_CSTRING_EXPR(e) __ATTEST_IS_CSTRING_TYPE(__typeof__(e))


//  C assertion macros
#define REGISTER_TEST(name) \
        static void name(void); \
        static void __attribute__((constructor)) register_##name(void) \
        { \
            attest_register(#name, name, __FILE__, __LINE__); \
        } \
        static void name(void)

#define ATTEST_TRUE(condition) do \
        { \
            if (!(condition)) \
            { \
                attest_printf("\033[31m[FAIL]\033[0m %s:%d: ATTEST_TRUE(%s)\n", __FILE__, __LINE__, #condition); \
                attest_current_failed = 1; \
                return; \
            } \
        } while (0)

#define ATTEST_FALSE(condition) do \
        { \
            if ((condition)) \
            { \
                attest_printf("\033[31m[FAIL]\033[0m %s:%d: ATTEST_FALSE(%s)\n", __FILE__, __LINE__, #condition); \
                attest_current_failed = 1; \
                return; \
            } \
        } while (0)

//helper for C string comparison
static inline int __attest_cstring_equal(const char* a, const char* b)
{
    if (a && b) return compare_strings(a, b) == 0;
    return a == b;
}

//helper for memory comparison (takes void* to avoid type issues)
static inline int __attest_mem_equal(const void* a, const void* b, size_t size)
{
    return compare_memory(a, b, size) == 0;
}

//generic C implementation of equals check
//Note: uses GCC diagnostic pragmas to suppress warnings for branches that won't execute
#define ATTEST_EQUAL(x, y) do \
{ \
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wint-conversion\"") \
    _Pragma("GCC diagnostic ignored \"-Wint-to-pointer-cast\"") \
    __auto_type _a = (x); \
    __auto_type _b = (y); \
    int _is_equal = 0; \
    if (__ATTEST_IS_CSTRING_EXPR(_a) && __ATTEST_IS_CSTRING_EXPR(_b)) \
    { \
        _is_equal = __attest_cstring_equal((const char*)(_a), (const char*)(_b)); \
    } \
    else \
    { \
        _is_equal = __attest_mem_equal(&_a, &_b, sizeof(_a)); \
    } \
    _Pragma("GCC diagnostic pop") \
    if (!_is_equal) \
    { \
        attest_printf("\033[31m[FAIL]\033[0m %s:%d: ATTEST_EQUAL(%s, %s)\n", __FILE__, __LINE__, #x, #y); \
        attest_current_failed = 1; \
        return; \
    } \
} while (0)

//special equals macro for structs
#define ATTEST_STRUCT_EQUAL(a, b) do { \
    if (compare_memory(&(a), &(b), sizeof(a)) != 0) { \
        attest_printf("\033[31m[FAIL]\033[0m %s:%d: ATTEST_STRUCT_EQUAL(%s, %s) failed\n", \
            __FILE__, __LINE__, #a, #b); \
        attest_current_failed = 1; \
        return; \
    } \
} while(0)

//generic C implementation of not equals check
#define ATTEST_NOT_EQUAL(x, y) do \
{ \
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wint-conversion\"") \
    _Pragma("GCC diagnostic ignored \"-Wint-to-pointer-cast\"") \
    __auto_type _a = (x); \
    __auto_type _b = (y); \
    int _is_equal = 0; \
    if (__ATTEST_IS_CSTRING_EXPR(_a) && __ATTEST_IS_CSTRING_EXPR(_b)) \
    { \
        _is_equal = __attest_cstring_equal((const char*)(_a), (const char*)(_b)); \
    } \
    else \
    { \
        _is_equal = __attest_mem_equal(&_a, &_b, sizeof(_a)); \
    } \
    _Pragma("GCC diagnostic pop") \
    if (_is_equal) \
    { \
        attest_printf("\033[31m[FAIL]\033[0m %s:%d: ATTEST_NOT_EQUAL(%s, %s)\n", __FILE__, __LINE__, #x, #y); \
        attest_current_failed = 1; \
        return; \
    } \
} while (0)

#define ATTEST_LESS_THAN(x, y) do \
{ \
    __auto_type _a = (x); \
    __auto_type _b = (y); \
    if (!(__ATTEST_IS_ARITHMETIC_EXPR(_a) && __ATTEST_IS_ARITHMETIC_EXPR(_b))) \
    { \
        attest_printf("\033[31m[FAIL]\033[0m %s:%d: ATTEST_LESS_THAN(%s, %s) - non-arithmetic types\n", __FILE__, __LINE__, #x, #y); \
        attest_current_failed = 1; \
        return; \
    } \
    if (!((_a) < (_b))) \
    { \
        attest_printf("\033[31m[FAIL]\033[0m %s:%d: ATTEST_LESS_THAN(%s, %s) failed\n", __FILE__, __LINE__, #x, #y); \
        attest_current_failed = 1; \
        return; \
    } \
} while (0)

#define ATTEST_GREATER_THAN(x, y) do \
{ \
    __auto_type _a = (x); \
    __auto_type _b = (y); \
    if (!(__ATTEST_IS_ARITHMETIC_EXPR(_a) && __ATTEST_IS_ARITHMETIC_EXPR(_b))) \
    { \
        attest_printf("\033[31m[FAIL]\033[0m %s:%d: ATTEST_GREATER_THAN(%s, %s) - non-arithmetic types\n", __FILE__, __LINE__, #x, #y); \
        attest_current_failed = 1; \
        return; \
    } \
    if (!((_a) > (_b))) \
    { \
        attest_printf("\033[31m[FAIL]\033[0m %s:%d: ATTEST_GREATER_THAN(%s, %s) failed\n", __FILE__, __LINE__, #x, #y); \
        attest_current_failed = 1; \
        return; \
    } \
} while (0)


#define ATTEST_EQUAL_WITHIN_TOLERANCE(x, y, tolerance) do \
{ \
    __auto_type _a = (x); \
    __auto_type _b = (y); \
    if (!(__ATTEST_IS_ARITHMETIC_EXPR(_a) && __ATTEST_IS_ARITHMETIC_EXPR(_b))) \
    { \
        attest_printf("\033[31m[FAIL]\033[0m %s:%d: ATTEST_EQUAL_WITHIN_TOLERANCE(%s, %s) - non-arithmetic types\n", __FILE__, __LINE__, #x, #y); \
        attest_current_failed = 1; \
        return; \
    } \
    if (!(float_abs((double)(_a) - (double)(_b)) <= (double)(tolerance))) \
    { \
        attest_printf("\033[31m[FAIL]\033[0m %s:%d: ATTEST_EQUAL_WITHIN_TOLERANCE(%s, %s) failed (diff=%f)\n", __FILE__, __LINE__, #x, #y, float_abs((double)(_a) - (double)(_b))); \
        attest_current_failed = 1; \
        return; \
    } \
} while (0)



void attest_register(const char* name, attest_func_t func, const char* file, int line);
int run_all_tests(const char* filter, int quiet);

#ifdef ATTEST_IMPLEMENTATION

//below is a data structure to keep track of all tests
static attest_testcase_t attest_test_list[ATTEST_MAX_TESTS];
static size_t attest_test_index = 0;
//the below variable is used to keep track of if the current test failed
static int attest_current_failed = 0;

void attest_register(const char* name, attest_func_t func, const char* file, int line)
{
    if (attest_test_index < ATTEST_MAX_TESTS)
    {
        attest_test_list[attest_test_index].name = name;
        attest_test_list[attest_test_index].func = func;
        attest_test_list[attest_test_index].file = file;
        attest_test_list[attest_test_index].line = line;
        attest_test_list[attest_test_index].passed = 0;

        ++attest_test_index;
    }
    else
    {
        attest_printf("Test limit reached. Increase ATTEST_MAX_TESTS.");
    }
}

//run tests inside process itself instead of making a new one
int run_all_tests(const char* filter, int quiet)
{
    int passed = 0;
    int failed = 0;
    
    for (size_t i = 0; i < attest_test_index; ++i)
    {
        attest_testcase_t* t = &attest_test_list[i];

        if (filter && !contains(t->name, filter))
        {
            continue;     
        }
        if (!quiet)
        {
            attest_printf("\033[33m[RUN] %s\033[0m -> ", t->name);
        }

        fflush(stdout);

        t->func();

        if (attest_current_failed == 0)
        {
            if (!quiet)
            {
                attest_printf("\033[32m[PASS]\033[0m\n");
                
            }
            passed++;
            t->passed = 1;
        }
        else
        {
            attest_printf("\033[31m%s failed->\033\n", t->name);     
            failed++;
            attest_current_failed = 0;
            t->passed = 0;
        }
        
    }

    //if at least 1 test fails then the run will return 1, otherwise 0
    attest_printf("\033[34m\n=====Summary=====\033[0m\n\033[32m%d\033[0m passed and \033[31m%d\033[0m failed / \033[34m%d\033[0m total\n", passed, failed, passed+failed);
    return failed? 1 : 0;
}

//function to print json
static void attest_print_json(void) 
{
    int total = 0, passed = 0, failed = 0;
    printf("{\n  \"summary\": {\n");

    // Count
    for (size_t i = 0; i < attest_test_index; ++i)
    {
        attest_testcase_t* t = &attest_test_list[i];
        total++;
        if (t->passed)
        { 
            passed++;
        } 
        else
        {
            failed++;
        } 
    }

    printf("    \"total\": %d,\n    \"passed\": %d,\n    \"failed\": %d\n  },\n", total, passed, failed);
    printf("  \"tests\": [\n");

    for (size_t i = 0; i < attest_test_index; ++i)
    {
        attest_testcase_t* r = &attest_test_list[i];

        printf("    {\n");
        printf("      \"name\": \"%s\",\n", r->name);
        printf("      \"file\": \"%s\",\n", r->file);
        printf("      \"line\": %d,\n", r->line);
        printf("      \"status\": \"%s\"\n", r->passed ? "pass" : "fail");
        printf("    }%s\n", (i < attest_test_index - 1) ? "," : "");
    }

    printf("  ]\n}\n");
}

//default main if one is not provided
int main(int argc, char** argv)
{
    //no filter by default
    const char* filter = NULL;
    int quiet = 0;
    int list_only = 0;
    attest_json_mode = 0;

    for (int i = 1; i < argc; ++i)
    {
        if (compare_first_n_chars(argv[i], "--filter=", 9) == 0)
        {
            filter = argv[i] + 9;
        }
        else if (compare_first_n_chars(argv[i], "--quiet", 7) == 0)
        {
            quiet = 1;
        }
        else if (compare_first_n_chars(argv[i], "--list", 6) == 0)
        {
            list_only = 1;
        }
        else if (compare_first_n_chars(argv[i], "--json", 6) == 0)
        {
            attest_json_mode = 1;
        }
    }
    
    if (list_only)
    {
        attest_printf("List of registered tests:\n");
        for (size_t i = 0; i < attest_test_index; ++i)
        {
            attest_testcase_t* t = &attest_test_list[i];

            attest_printf("%s\n", t->name);
        }
        return 0;
    }
    int res = run_all_tests(filter, quiet);

    if (attest_json_mode)
    {
        attest_print_json();
    }
    return res;
}

#endif //ATTEST_IMPLEMENTATION

#ifdef __cplusplus
    }
#endif

//  C++ template based assertions
#ifdef __cplusplus

#include <type_traits>

//helper struct to check if == operator exists
template <typename T, typename U>
struct has_equal
{
    private:
        template <typename A, typename B>
        static auto test(int) -> decltype(std::declval<A>() == std::declval<B>(), std::true_type());
        
        template <typename, typename>
        static std::false_type test(...);
    
    public:
        static constexpr bool value = decltype(test<T, U>(0))::value;
};

//general equality check
template <typename T, typename U>
inline typename std::enable_if<has_equal<T,U>::value, bool>::type
attest_equal_implementation(const T& a, const U& b) 
{
    return a == b;
}

//for mem comparison
template <typename T, typename U>
inline typename std::enable_if<!has_equal<T,U>::value && std::is_trivially_copyable<T>::value && std::is_same<T,U>::value, bool>::type
attest_equal_implementation(const T& a, const U& b) 
{
    if (sizeof(T) != sizeof(U)) 
    {
        return false;
    }
    return compare_memory(&a, &b, sizeof(T)) == 0;
}

template <typename T>
inline typename std::enable_if<std::is_trivially_copyable<T>::value, bool>::type
attest_equal_implementation(const T& a, const T& b) 
{
    return compare_memory(&a, &b, sizeof(T)) == 0;
}

//for strings
inline bool attest_equal_implementation(const char* a, const char* b) 
{
    if (!a || !b) return a == b;
    return compare_strings(a, b) == 0;
}

//entry point - returns true if check failed (to support early return in macro)
template <typename T, typename U>
inline bool attest_equal(const T& a, const U& b,
                         const char* a_str, const char* b_str,
                         const char* file, int line)
{
    //should automatically deduce the types
    bool is_equal = attest_equal_implementation(a, b);

    if (!is_equal)
    {
        attest_printf("\033[31m[FAIL]\033[0m %s:%d: ATTEST_EQUAL(%s, %s) failed\n", file, line, a_str, b_str);
        attest_current_failed = 1;
        return true;
    }
    return false;
}

template <typename T, typename U>
inline bool attest_not_equal(const T& a, const U& b,
                         const char* a_str, const char* b_str,
                         const char* file, int line)
{
    //should automatically deduce the types
    bool is_equal = attest_equal_implementation(a, b);

    if (is_equal)
    {
        attest_printf("\033[31m[FAIL]\033[0m %s:%d: ATTEST_NOT_EQUAL(%s, %s) failed\n", file, line, a_str, b_str);
        attest_current_failed = 1;
        return true;
    }
    return false;
}

#undef ATTEST_EQUAL
#undef ATTEST_NOT_EQUAL
#define ATTEST_EQUAL(a, b) do { if (attest_equal(a, b, #a, #b, __FILE__, __LINE__)) return; } while(0)
#define ATTEST_NOT_EQUAL(a, b) do { if (attest_not_equal(a, b, #a, #b, __FILE__, __LINE__)) return; } while(0)

#endif

#endif //ATTEST_H