#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "../const.h"
#include "../log.h"

typedef struct Buffer {
    uint8_t* const start;
    uint8_t* ptr;
    int32_t const len;
} Buffer;


static void inline write_raw_u8(Buffer* buf, uint8_t v)
{
    assert(buf->ptr < buf->start + buf->len);
    *buf->ptr++ = v;
}

static void write_leb_i32(Buffer* buf, int32_t v)
{
    // Super complex stuff. See the following:
    // https://en.wikipedia.org/wiki/LEB128#Encode_signed_integer
    // http://llvm.org/doxygen/LEB128_8h_source.html#l00048

    bool more = true;
    bool negative = v < 0;
    const uint32_t SIZE = 32;
    while (more)
    {
        uint8_t byte = v & 0b1111111; // get last 7 bits
        v >>= 7; // shift them away from the value
        if (negative)
        {
            v |= ((uint32_t)~0 << (SIZE - 7)); // extend sign
        }
        uint8_t sign_bit = byte & (1 << 6);
        if ((v == 0 && sign_bit == 0) || (v == -1 && sign_bit != 0))
        {
            more = false;
        }
        else
        {
            byte |= 0b10000000; // turn on MSB
        }
        write_raw_u8(buf, byte);
    }
}

static void write_leb_u32(Buffer* buf, uint32_t v)
{
    do {
        uint8_t byte = v & 0b1111111; // get last 7 bits
        v >>= 7; // shift them away from the value
        if (v != 0)
        {
            byte |= 0b10000000; // turn on MSB
        }
        write_raw_u8(buf, byte);
    } while (v != 0);
}

static void inline write_fixed_leb16_to_ptr(uint8_t* ptr, uint16_t x)
{
    dbg_assert(x < (1 << 14)); // we have 14 bits of available space in 2 bytes for leb
    *ptr = (x & 0b1111111) | 0b10000000;
    *(ptr + 1) = x >> 7;
}

static void append_buffer(Buffer *dest, Buffer *src)
{
    assert(dest->len - (dest->ptr - dest->start) >= (src->ptr - src->start));

    uint8_t* offset = src->start;
    while (offset < src->ptr)
    {
        write_raw_u8(dest, *offset++);
    }
}
