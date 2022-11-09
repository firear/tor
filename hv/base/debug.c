#if !__ANDROID__
#include "debug.h"
#include "hbase.h" //for mkdir -p
#include "thrqueue.h"
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#if defined _WIN32 || defined _WIN64
#include <process.h>
#include <windows.h>
typedef unsigned int(__stdcall* MYTHREADFUNROUTE)(void*);
#pragma warning(disable : 4996)
#elif defined __linux
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
unsigned long GetCurrentThreadId()
{
    return syscall(__NR_gettid);
}
#define __stdcall
typedef void* (*MYTHREADFUNROUTE)(void*);
#include <pthread.h>

const char* g_colortable[] = {
    "", // NONE
    "\033[0;32;32m", // KGRN
    "\033[0;36m", // KCYN
    "\033[0;32;31m", // KRED
    "\033[1;33m", // yellow
    "\033[0;32;34m", // KBLU
    "\033[1;36m", // KCYN_L
    "\033[0;33m", // KBRN
    "\033[0m" // RESET
};

#else
#error "not def"
#endif

#if _DEBUG
#define ASYNC 0
#else
#define ASYNC 1
#endif
#define DEFAULT_MAX_ROTATED_LOGS 10

typedef struct {
    size_t maxRotatedLogs;
    size_t logRotateSizeKBytes;
    size_t outByteCount;
    int level_stdout;
    int level_file;
    int level_cache; // min value of stdout and file log level
    FILE* fp;
    thrqueue_t* queue;
    char* outputFileName;
    char exit;
} Loger_s;

typedef struct LogBuf {
    int level;
    enum COLOR color;
    char* head;
    char* content;
    struct LogBuf* nxt;
} LogBuf_s;

static Loger_s g_logger = {
    DEFAULT_MAX_ROTATED_LOGS,
    0,
    0,
    DEBUG_NONE,
    DEBUG_NONE,
    -1,
    NULL,
    NULL,
    NULL,
    0
};

static int getbits(size_t n)
{
    int ret = 1;
    while (n /= 10)
        ret++;
    return ret;
}
static void rotateLogs(Loger_s* logger)
{
    int err;
    int i;
    int maxRotationCountDigits;

    fclose(logger->fp);
    // Compute the maximum number of digits needed to count up to logger->maxRotatedLogs in decimal.
    // eg: logger->maxRotatedLogs == 30 -> log10(30) == 1.477 -> maxRotationCountDigits == 2
    // maxRotationCountDigits = (logger->maxRotatedLogs > 0) ? (int)(floor(log10(logger->maxRotatedLogs) + 1)) : 0;
    maxRotationCountDigits = (logger->maxRotatedLogs > 0) ? getbits(logger->maxRotatedLogs) : 0;

    for (i = logger->maxRotatedLogs; i > 0; i--) {
        char *file0, *file1;
        asprintf(&file1, "%s.%.*d", logger->outputFileName, maxRotationCountDigits, i);
        if (i - 1 == 0) {
            asprintf(&file0, "%s", logger->outputFileName);
        } else {
            asprintf(&file0, "%s.%.*d", logger->outputFileName, maxRotationCountDigits, i - 1);
        }
        if (!file0 || !file1) {
            perror("while rotating log files");
            break;
        }
#ifdef _WIN32
        // no need on linux,rename will replace new path .
        if (access(file1, F_OK) == 0) {
            unlink(file1);
        }
#endif
        err = rename(file0, file1);
        if (err < 0 && errno != ENOENT) {
            perror("while rotating log files");
        }
        free(file1);
        free(file0);
    }
    logger->fp = fopen(logger->outputFileName, "wt");
    if (logger->fp == NULL) {
        fprintf(stderr, "couldn't open output file\n");
    }
    logger->outByteCount = 0;
}

static int writetofile(Loger_s* logger, LogBuf_s* bf)
{
    if (logger->logRotateSizeKBytes > 0
        && (logger->outByteCount / 1024) >= logger->logRotateSizeKBytes) {
        rotateLogs(logger);
    }

    logger->outByteCount += fprintf(logger->fp, "%s", bf->head);
    logger->outByteCount += fprintf(logger->fp, "%s", bf->content);

    fflush(logger->fp);
    return 0;
}

#if ASYNC
static
#if defined _WIN32
    unsigned int __stdcall logwriter_threadfun(void* lpParam)
#elif defined __linux
    void*
    logwriter_threadfun(void* lpParam)
#else
#error "error"
#endif
{
    Loger_s* logger = (Loger_s*)lpParam;
    LogBuf_s *bf, *temp;
    while (!logger->exit) {
        bf = (LogBuf_s*)thrqueue_dequeue(logger->queue);
        while (bf != NULL) {
            if (logger->level_stdout >= bf->level) {
#ifdef _WIN32
                fprintf(stderr, "%s%s", bf->head, bf->content);
                fflush(stderr);
#else
                fprintf(stderr, "%s%s%s%s", g_colortable[bf->color], bf->head, bf->content, g_colortable[RESET]);
#endif
            }
            if (logger->fp && logger->level_file >= bf->level) {
                writetofile(logger, bf);
            }
            free(bf->head);
            free(bf->content);
            temp = bf;
            bf = temp->nxt;
            free(temp);
        }
    }
#if defined _WIN32 || defined _WIN64
    _endthreadex(0);
#endif
    return 0;
}

static int mythread_create(MYTHREADFUNROUTE threadfun, void* info)
{
    int ret = 0;
#if defined _WIN32 || defined _WIN64
    HANDLE mThreadHandler = (HANDLE)_beginthreadex(NULL, 0, threadfun, info, 0, NULL);
    if (mThreadHandler) {
        CloseHandle(mThreadHandler);
    } else {
        ret = -1;
    }

#elif defined __linux
    pthread_t mThreadHandler;
    if (!(ret = pthread_create(&mThreadHandler, NULL, threadfun, info))) {
        pthread_detach(mThreadHandler);
    }
#else
#error "not def"
#endif
    return ret;
}

#endif // endif ASYNC
/***************************************************
  print binary buffer info
***************************************************/
void d_debug_bin_buffer(const void* temp, size_t len)
{
    size_t i = 0;
    const unsigned char* data = (const unsigned char*)temp;
    if (g_logger.level_stdout >= DEBUG_DEBUG) {
        fprintf(stderr, "\n");
        for (i = 0; i < len; i++) {
            fprintf(stderr, "0x%02hhx, ", (unsigned char)*(data + i));
            if (i % 17 == 16) { // match the xxd default output
                fprintf(stderr, "\n");
            }
        }
        fprintf(stderr, "\n");
    }

    if (g_logger.fp && g_logger.level_file > DEBUG_DEBUG) {
        fprintf(g_logger.fp, "\n");
        for (i = 0; i < len; i++) {
#if 0
            if(isprint(*(data+i)) || isspace(*(data+i))){
                fprintf(g_logger.log_fp, "%c",(unsigned char)*(data+i));
            }else
#endif
            {
                if (g_logger.level_file != DEBUG_VERBOSE && len > 30) {
                    if (i < 20 || (len - i) < 10) {
                        fprintf(g_logger.fp, "\\%02X", (unsigned char)*(data + i));
                    } else if (i == 20) {
                        fprintf(g_logger.fp, "\\......\\");
                    }
                } else {
                    fprintf(g_logger.fp, "\\%02hhX", (unsigned char)*(data + i));
                }
            }
        }
        fprintf(g_logger.fp, "\n");
    }
}

void d_destory_debug()
{
    time_t t = time(NULL);
    struct tm ptm;
    char buf[1024] = "";
    localtime_r(&t, &ptm);

    if (g_logger.fp) {
        sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d",
            ptm.tm_year + 1900, ptm.tm_mon + 1, ptm.tm_mday, ptm.tm_hour, ptm.tm_min, ptm.tm_sec);
        fprintf(g_logger.fp, "\n====== End logging at %s. ======\n", buf);
        fclose(g_logger.fp);
    }
    g_logger.fp = NULL;
    g_logger.level_stdout = DEBUG_INFO,
    g_logger.level_file = DEBUG_ERROR;
    g_logger.exit = 1;

#if 0
    //this should release when process exit.but it will auto release then, and may be crash if we release here.
    // so we do nothing.
    if(g_logger.queue){
        thrqueue_unblock_dequeue(g_logger.queue);
        thrqueue_unblock_enqueue(g_logger.queue);
        thrqueue_free(g_logger.queue);
    }
    if(g_logger.outputFileName){
        free(g_logger.outputFileName);
        g_logger.outputFileName = NULL;
    }
#endif
    fprintf(stderr, "destory debug\n");
}

void d_init_debug(const char* logdir, size_t logfilesize, size_t maxlogfilenumber, int level, int log, const char* binname)
{
    time_t t = time(NULL);
    struct tm ptm;
    char fn[1024] = "";
    localtime_r(&t, &ptm);

    if (g_logger.fp) {
        d_destory_debug();
    }
    if (logfilesize > 0) {
        g_logger.logRotateSizeKBytes = logfilesize;
    }
    if (maxlogfilenumber > 0) {
        g_logger.maxRotatedLogs = maxlogfilenumber;
    }
    g_logger.level_stdout = level;
    g_logger.level_file = log;
    g_logger.level_cache = level > log ? level : log;
    g_logger.exit = 0;
    g_logger.queue = thrqueue_new(1024);
    if (g_logger.queue == NULL) {
        printf("%s\n", "new queue failed");
        goto END;
    }

    if (g_logger.level_file <= DEBUG_NONE)
        goto END;

    if (binname == NULL) {
        binname = "";
    }
    if (logdir != NULL) {
        hv_mkdir_p(logdir);
        asprintf(&g_logger.outputFileName, "%s%s.log", logdir, binname);
    } else {
        asprintf(&g_logger.outputFileName, "%s.log", binname);
    }
    g_logger.fp = fopen(g_logger.outputFileName, "at");
    if (!g_logger.fp)
        goto END;
    sprintf(fn, "%04d-%02d-%02d %02d:%02d:%02d", ptm.tm_year + 1900, ptm.tm_mon + 1, ptm.tm_mday, ptm.tm_hour, ptm.tm_min, ptm.tm_sec);
    fprintf(g_logger.fp, "====== Start logging at %s. ======\n", fn);

END:

#if ASYNC
    mythread_create(logwriter_threadfun, &g_logger);
#endif
    return;
}

// set debug level
int d_set_debug_level(int level)
{
    if (level < DEBUG_MIN || level > DEBUG_MAX)
        return -1;

    g_logger.level_stdout = level;

    return 0;
}

// set log level
int d_set_log_level(int level)
{
    if (level < DEBUG_MIN || level > DEBUG_MAX)
        return -1;

    g_logger.level_file = level;

    return 0;
}

// get level string
static const char* d_level_string(int level)
{
    const char* ls[] = {
        "0",
        "F",
        "E",
        "W",
        "I",
        "D",
        "V",
        "UNK"
    };
    int ls_num = sizeof(ls) / sizeof(ls[0]);

    if (level < 0 || level >= ls_num)
        level = ls_num - 1;

    return ls[level];
}

// Return current time in string format
static char* strtime()
{
    static char buf[32];
#ifdef __linux
    // time_t t = 0;
    struct tm ptm;
    struct timeval tv = { 0, 0 };

    gettimeofday(&tv, NULL);
    // t=tv.tv_sec;
    localtime_r(&tv.tv_sec, &ptm);

    sprintf(buf, "%02d-%02d %02d:%02d:%02d.%03d",
        ptm.tm_mon + 1, ptm.tm_mday, ptm.tm_hour, ptm.tm_min, ptm.tm_sec, (int)(tv.tv_usec / 1000));
#elif defined(_WIN32) || defined(_WIN64)

    SYSTEMTIME wtm;
    GetLocalTime(&wtm);

    sprintf(buf, "%02d-%02d %02d:%02d:%02d.%03d",
        wtm.wMonth, wtm.wDay, wtm.wHour, wtm.wMinute, wtm.wSecond, wtm.wMilliseconds);
#endif
    return buf;
}

void __d_debug(int level, const char* tag, const uint64_t pid, const enum COLOR color, const char* format, ...)
{
    va_list ap;
    char* ts = strtime();
    const char* ls = d_level_string(level);
#if ASYNC
    LogBuf_s* head = NULL;
#endif
    va_start(ap, format);
    if (level <= g_logger.level_cache) {
#if ASYNC
        head = (LogBuf_s*)malloc(sizeof(LogBuf_s));
        head->head = head->content = NULL;
        head->level = level;
        head->color = color;
        asprintf(&head->head, "%s %s/%s(%8" PRIxLEAST64 "):", ts, ls, tag, pid);
        vasprintf(&head->content, format, ap);
        head->nxt = NULL;
        thrqueue_enqueue(g_logger.queue, head);
#else
        if (g_logger.level_stdout >= level) {
            va_list cp;
            va_copy(cp, ap);
            fprintf(stderr, "%s %s/%s(%8" PRIxLEAST64 "):", ts, ls, tag, pid);
            vfprintf(stderr, format, cp);
        }

        if (g_logger.fp && g_logger.level_file >= level) {
            fprintf(g_logger.fp, "%s %s/%s(%8" PRIxLEAST64 "):", ts, ls, tag, pid);
            vfprintf(g_logger.fp, format, ap);
            fflush(g_logger.fp);
        }
#endif
    } else if (g_logger.level_cache == -1) { // 未调用init
        fprintf(stderr, "%s %s/%s(%8" PRIxLEAST64 "):", ts, ls, tag, pid);
        vfprintf(stderr, format, ap);
    }
    va_end(ap);
}

#endif //!__ANDROID__
