#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* BIFF record IDs */
#define BIFF_SST        0x00FC
#define BIFF_CONTINUE   0x003C
#define BIFF_FORMULA    0x0006
#define BIFF_ROW        0x0208
#define BIFF_NUMBER     0x0203

typedef struct {
    uint8_t *buf;
    size_t   size;
} mut_state_t;

static mut_state_t ms;

/* Helpers */
static inline uint16_t rd16(const uint8_t *p) {
    return p[0] | (p[1] << 8);
}

static inline void wr16(uint8_t *p, uint16_t v) {
    p[0] = v & 0xFF;
    p[1] = v >> 8;
}

static inline uint32_t rd32(const uint8_t *p) {
    return rd16(p) | ((uint32_t)rd16(p + 2) << 16);
}

static inline void wr32(uint8_t *p, uint32_t v) {
    wr16(p, v & 0xFFFF);
    wr16(p + 2, v >> 16);
}

/* ---------------- AFL++ Custom Mutator API ---------------- */

void afl_custom_init(void *afl, unsigned int seed) {
    srand(seed);
    ms.buf = NULL;
    ms.size = 0;
}

void afl_custom_deinit(void *afl) {
    free(ms.buf);
}

size_t afl_custom_fuzz(
    void *afl,
    uint8_t *buf,
    size_t buf_size,
    uint8_t **out_buf,
    uint8_t *add_buf,
    size_t add_buf_size,
    size_t max_size
) {
    if (buf_size == 0) {
        *out_buf = buf;
        return 0;
    }

    /* Ensure internal buffer is large enough */
    if (ms.size < buf_size) {
        ms.buf = realloc(ms.buf, buf_size);
        ms.size = buf_size;
    }
    memcpy(ms.buf, buf, buf_size);

    size_t off = 0;

    while (off + 4 < buf_size) {
        uint16_t id  = rd16(ms.buf + off);
        uint16_t len = rd16(ms.buf + off + 2);
        size_t payload = off + 4;
        size_t next = payload + len;

        if (next > buf_size)
            break;

        /* Randomly mutate */
        if ((rand() & 0xFF) < 12) {
            switch (id) {
                /* 1) SST: count / unique desync + CONTINUE interaction */
                case BIFF_SST:
                    if (len >= 8) {
                        wr32(ms.buf + payload, rd32(ms.buf + payload) ^ (rand() & 0xFFFF));
                        wr32(ms.buf + payload + 4, rd32(ms.buf + payload + 4) + (rand() & 0xFF));

                        /* Clip length to avoid exceeding buffer */
                        uint16_t new_len = len + (rand() & 0x1F);
                        if (payload + new_len > buf_size) new_len = len;
                        wr16(ms.buf + off + 2, new_len);
                    }
                    break;

                /* 2) CONTINUE: break chaining */
                case BIFF_CONTINUE: {
                    uint16_t new_len = len ^ (1 << (rand() % 8));
                    if (payload + new_len > buf_size) new_len = len;
                    wr16(ms.buf + off + 2, new_len);
                    break;
                }

                /* 3) FORMULA: operand truncation vs length */
                case BIFF_FORMULA:
                    if (len > 6) {
                        uint16_t new_len = len - (rand() % 4);
                        if (payload + new_len > buf_size) new_len = len;
                        wr16(ms.buf + off + 2, new_len);
                    }
                    break;

                /* 4) ROW record: inflate row/col bounds */
                case BIFF_ROW:
                    if (len >= 16) {
                        uint16_t row = rd16(ms.buf + payload);
                        wr16(ms.buf + payload, row + (rand() & 0x3FFF));

                        uint16_t lastcol = rd16(ms.buf + payload + 6);
                        wr16(ms.buf + payload + 6, lastcol + (rand() & 0xFF));
                    }
                    break;

                /* 5) Generic length desync */
                default:
                    if ((rand() & 3) == 0) {
                        uint16_t new_len = len + (rand() & 0x1F);
                        if (payload + new_len > buf_size) new_len = len;
                        wr16(ms.buf + off + 2, new_len);
                    }
                    break;
            }
        }

        off = next;
    }

    /* Return valid size <= max_size */
    size_t ret_size = buf_size;
    if (ret_size > max_size) ret_size = max_size;

    *out_buf = ms.buf;
    return ret_size;
}

