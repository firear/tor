/*
 * d_init_debug(LOGDIR, 0, 0, DEBUG_VERBOSE, DEBUG_VERBOSE, APPNAME);
 * d_destory_debug();
 *
*/

#ifndef _DEBUG_H_
#define _DEBUG_H_    1


#ifndef LOG_TAG
#define LOG_TAG ""
#endif

#ifndef DEBUG_SHOW_DEBUG
#define DEBUG_SHOW_DEBUG    1
#endif

#if DEBUG_SHOW_DEBUG
    #if defined(__ANDROID__)
        #define LOGINIT(d,s,c,lp,lf,n)
        #include <android/log.h>
        #define LOGF(fmt,...)  __android_log_print(ANDROID_LOG_FATAL,LOG_TAG,fmt,##__VA_ARGS__); printf(fmt"\n",##__VA_ARGS__);abort()
        #define LOGE(fmt,...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,fmt,##__VA_ARGS__); printf(fmt"\n",##__VA_ARGS__)
        #define LOGW(fmt,...)  __android_log_print(ANDROID_LOG_WARN,LOG_TAG,fmt,##__VA_ARGS__); printf(fmt"\n",##__VA_ARGS__)
        #define LOGI(fmt,...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,fmt,##__VA_ARGS__); printf(fmt"\n",##__VA_ARGS__)
        #define LOGD(fmt,...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,fmt,##__VA_ARGS__); printf(fmt"\n",##__VA_ARGS__)
        #define LOGV(fmt,...)  __android_log_print(ANDROID_LOG_VERBOSE,LOG_TAG,fmt,##__VA_ARGS__); printf(fmt"\n",##__VA_ARGS__)

    #else //!__ANDROID__

        #define DEBUG_NONE          0
        #define DEBUG_FATAL         1
        #define DEBUG_ERROR         2
        #define DEBUG_WARNING       3
        #define DEBUG_INFO          4
        #define DEBUG_DEBUG         5
        #define DEBUG_VERBOSE       6
        #define DEBUG_MIN           DEBUG_NONE
        #define DEBUG_MAX           DEBUG_VERBOSE

        #include <stdint.h>
        #include <stdlib.h>

        #if defined(WIN32)
        #include <windows.h>
        #else
        unsigned long GetCurrentThreadId();
        #endif

        /* Define used colors */
        extern const char *g_colortable[];
        enum COLOR{
            NONE,
            KGRN,
            KCYN,
            KRED,
            KYEL,
            KBLU,
            KCYN_L,
            KBRN,
            RESET
        };

        #define LOGINIT(d,s,c,lp,lf,n) d_init_debug(d,s,c,lp,lf,n)
        #define LOGF(format, ...)   __d_debug( DEBUG_FATAL,     LOG_TAG, GetCurrentThreadId(), KRED, format "\n", ##__VA_ARGS__ ); abort()
        #define LOGE(format, ...)   __d_debug( DEBUG_ERROR,     LOG_TAG, GetCurrentThreadId(), KRED, format "\n", ##__VA_ARGS__ )
        #define LOGW(format, ...)   __d_debug( DEBUG_WARNING,   LOG_TAG, GetCurrentThreadId(), KBRN, format "\n", ##__VA_ARGS__ )
        #define LOGI(format, ...)   __d_debug( DEBUG_INFO,      LOG_TAG, GetCurrentThreadId(), KGRN, format "\n", ##__VA_ARGS__ )
        #define LOGD(format, ...)   __d_debug( DEBUG_DEBUG,     LOG_TAG, GetCurrentThreadId(), KBLU, format "\n", ##__VA_ARGS__ )
        #define LOGV(format, ...)   __d_debug( DEBUG_VERBOSE,   LOG_TAG, GetCurrentThreadId(), KCYN, format "\n", ##__VA_ARGS__ )
        #define LOGBIN(data, len)   d_debug_bin_buffer(data, len)
        #define STOPHERE            {LOGD("STOP HERE"); while(true) sleep(1);}

        #if defined(__cplusplus)
        extern "C" {
        #endif
        /* debug.c */
        extern void d_debug_bin_buffer(const void*data, size_t len);
        /*
        logdir: path to logfile dir,must end with /
        logfilesize: max Kbyte size of a logfile default not limited
        maxlogfilenumber:max number of logfile default 10
        level: stdout log level
        log:    file log level
        binname:file prefix
        */
        extern void d_init_debug(const char *logdir, size_t logfilesize, size_t maxlogfilenumber, int level, int log, const char *binname);
        extern int  d_set_debug_level(int level);
        extern int  d_set_log_level(int level);
        extern void __d_debug(int level, const char* tag, const uint64_t pid, const enum COLOR color, const char* format,...);
        extern void d_destory_debug();

        #if defined(__cplusplus)
        }
        #endif
    #endif //__ANDROID
#else //DEBUG_SHOW_DEBUG
    #define LOGINIT
    #define LOGF(format, ...)   do {} while (0)
    #define LOGE(format, ...)   do {} while (0)
    #define LOGW(format, ...)   do {} while (0)
    #define LOGI(format, ...)   do {} while (0)
    #define LOGD(format, ...)   do {} while (0)
    #define LOGV(format, ...)   do {} while (0)
    #define LOGBIN(data, len)   do {} while (0)
    #define STOPHERE
#endif  //DEBUG_SHOW_DEBUG

#endif  // #ifndef _DEBUG_H_
