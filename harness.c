#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <xls.h>

#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT();
#endif

#define MIN_FILE_SIZE 64
#define MAX_FILE_SIZE (1 << 20)

#define FORCE_READ(ptr)                                      \
    do {                                                     \
        if ((ptr) != NULL) {                                 \
            volatile unsigned char x =                       \
                *(volatile unsigned char *)(ptr);            \
            (void)x;                                         \
        }                                                    \
    } while (0)

/* ---------------- SST Stress ---------------- */

static void stress_sst(xlsWorkBook *wb) {
    if (!wb || wb->sst.count == 0 || !wb->sst.string)
        return;

    for (DWORD i = 0; i < wb->sst.count; i++) {
        char *s = wb->sst.string[i].str;
        if (!s)
            continue;

        FORCE_READ(s);

        size_t len = strlen(s);
        if (len > 0)
            FORCE_READ(s + len - 1);

        /* Boundary probe */
        FORCE_READ(s + len);
    }

    /* Index reuse stress */
    for (DWORD i = 0; i < wb->sst.count; i++) {
        DWORD idx = i % wb->sst.count;
        char *s = wb->sst.string[idx].str;
        if (s)
            FORCE_READ(s);
    }
}

/* ---------------- Fuzzer Entry ---------------- */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < MIN_FILE_SIZE || Size > MAX_FILE_SIZE)
        return 0;

    /* OLE header gate */
    if (!(Data[0] == 0xD0 && Data[1] == 0xCF))
        return 0;

    xls_error_t err = 0;
    xlsWorkBook *wb = xls_open_buffer(Data, Size, "UTF-8", &err);
    if (!wb)
        return 0;

    /* SST-first */
    stress_sst(wb);

    if (Data[Size / 2] & 1)
        stress_sst(wb);

    /* Worksheets */
    for (WORD si = 0; si < wb->sheets.count; si++) {
        xlsWorkSheet *ws = xls_getWorkSheet(wb, si);
        if (!ws)
            continue;

        xls_parseWorkSheet(ws);

        FORCE_READ(&ws->rows.lastrow);
        FORCE_READ(&ws->rows.lastcol);

        for (DWORD r = 0; r <= ws->rows.lastrow; r++) {
            for (DWORD c = 0; c <= ws->rows.lastcol; c++) {
                xlsCell *cell = xls_cell(ws, r, c);
                if (!cell)
                    continue;

                switch (cell->id) {
                    case XLS_RECORD_LABEL:
                    case XLS_RECORD_RSTRING:
                        if (cell->str) {
                            FORCE_READ(cell->str);
                            FORCE_READ(cell->str + strlen(cell->str));
                        }
                        break;

                    case XLS_RECORD_NUMBER:
                        FORCE_READ(&cell->d);
                        break;

                    case XLS_RECORD_FORMULA:
                        FORCE_READ(&cell->l);
                        if (cell->str)
                            FORCE_READ(cell->str);
                        break;

                    default:
                        break;
                }
            }
        }

        xls_close_WS(ws);
    }

    xls_close_WB(wb);
    return 0;
}

/* ---------------- AFL++ Persistent Loop ---------------- */

#ifdef __AFL_HAVE_MANUAL_CONTROL
int main(void) {
    __AFL_INIT();

    while (__AFL_LOOP(1000)) {
        unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, len);
    }

    return 0;
}
#endif

