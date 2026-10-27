/* Register-only SSE experiment. Integer-only IEEE arithmetic, independent of
 * the host FPCR/MXCSR. All guest exceptions are masked. DAZ/FTZ are applied to
 * operand/result bits. SoftFloat's 8086-SSE specialization preserves SSE NaNs. */
#include <stdint.h>
#include "softfloat.h"

static unsigned mxcsr_flags(unsigned flags) {
    return ((flags & softfloat_flag_invalid) ? 1u : 0u) |
           ((flags & softfloat_flag_infinite) ? 4u : 0u) |
           ((flags & softfloat_flag_overflow) ? 8u : 0u) |
           ((flags & softfloat_flag_underflow) ? 16u : 0u) |
           ((flags & softfloat_flag_inexact) ? 32u : 0u);
}

typedef struct { uint_fast8_t rounding, tininess, flags; } SavedEnvironment;

static SavedEnvironment begin(uint32_t mxcsr) {
    SavedEnvironment saved = {softfloat_roundingMode, softfloat_detectTininess,
                              softfloat_exceptionFlags};
    static const uint_fast8_t modes[] = {softfloat_round_near_even, softfloat_round_min,
                                         softfloat_round_max, softfloat_round_minMag};
    softfloat_roundingMode = modes[(mxcsr >> 13) & 3];
    softfloat_detectTininess = softfloat_tininess_afterRounding;
    softfloat_exceptionFlags = 0;
    return saved;
}

static void end(SavedEnvironment saved, uint32_t *mxcsr, unsigned denormal) {
    /* Invalid and divide-by-zero are higher-priority pre-computation
     * exceptions; e.g. sqrt(negative subnormal) and subnormal/zero do not
     * additionally report a denormal-operand exception for that lane. */
    if (softfloat_exceptionFlags & (softfloat_flag_invalid | softfloat_flag_infinite))
        denormal = 0;
    *mxcsr |= mxcsr_flags(softfloat_exceptionFlags) | denormal;
    softfloat_roundingMode = saved.rounding;
    softfloat_detectTininess = saved.tininess;
    softfloat_exceptionFlags = saved.flags;
}

static float32_t calculate32(float32_t x, float32_t y, int operation) {
    switch (operation) {
    case 0: return f32_add(x, y);
    case 1: return f32_sub(x, y);
    case 2: return f32_mul(x, y);
    case 3: return f32_div(x, y);
    case 4: return f32_sqrt(y);
    default: __builtin_trap();
    }
}

static float64_t calculate64(float64_t x, float64_t y, int operation) {
    switch (operation) {
    case 0: return f64_add(x, y);
    case 1: return f64_sub(x, y);
    case 2: return f64_mul(x, y);
    case 3: return f64_div(x, y);
    case 4: return f64_sqrt(y);
    default: __builtin_trap();
    }
}

/* These exact power-of-two scalings are only used when the rounded result is
 * the smallest normal value. In that case the relevant finite operand ranges
 * cannot overflow when scaled by 2^32 (f32) or 2^64 (f64). Normalize subnormals
 * with integer shifts, without consuming host floating-point state. */
static uint32_t scale32(uint32_t bits) {
    uint32_t fraction = bits & 0x007fffff, exponent = (bits >> 23) & 255;
    int shift = 32;
    if (!exponent) {
        if (!fraction) return bits;
        exponent = 1;
        while (!(fraction & 0x00800000)) { fraction <<= 1; --shift; }
    }
    return (bits & 0x80000000) | ((exponent + shift) << 23) | (fraction & 0x007fffff);
}

static uint64_t scale64(uint64_t bits) {
    uint64_t fraction = bits & UINT64_C(0x000fffffffffffff);
    unsigned exponent = (unsigned)((bits >> 52) & 2047);
    int shift = 64;
    if (!exponent) {
        if (!fraction) return bits;
        exponent = 1;
        while (!(fraction & UINT64_C(0x0010000000000000))) { fraction <<= 1; --shift; }
    }
    return (bits & UINT64_C(0x8000000000000000)) |
           ((uint64_t)(exponent + shift) << 52) | (fraction & UINT64_C(0x000fffffffffffff));
}

/* FTZ tests tininess after rounding to the significand precision with an
 * unbounded exponent, before rounding to the subnormal lattice (Intel SDM
 * vol.1, appendix D). A tiny value can round up to the smallest normal in
 * gradual mode yet still require flushing. Re-evaluate this boundary in a
 * normal exponent range; do not change the original operation's flags. */
static int tiny_boundary32(float32_t x, float32_t y, int operation) {
    const uint_fast8_t flags = softfloat_exceptionFlags;
    if (operation == 4) return 0; /* sqrt of a finite f32 cannot be this tiny. */
    x.v = scale32(x.v);
    if (operation < 2) y.v = scale32(y.v);
    float32_t scaled = calculate32(x, y, operation);
    softfloat_exceptionFlags = flags;
    return (scaled.v & 0x7fffffff) < 0x10800000; /* smallest normal * 2^32 */
}

static int tiny_boundary64(float64_t x, float64_t y, int operation) {
    const uint_fast8_t flags = softfloat_exceptionFlags;
    if (operation == 4) return 0;
    x.v = scale64(x.v);
    if (operation < 2) y.v = scale64(y.v);
    float64_t scaled = calculate64(x, y, operation);
    softfloat_exceptionFlags = flags;
    return (scaled.v & UINT64_C(0x7fffffffffffffff)) < UINT64_C(0x0410000000000000);
}

uint32_t bb_fp32(uint32_t a, uint32_t b, int operation, uint32_t *mxcsr) {
    SavedEnvironment saved = begin(*mxcsr);
    if (*mxcsr & 0x40) { /* DAZ: preserve the sign of each flushed input. */
        if ((a & 0x7fffffff) < 0x00800000) a &= 0x80000000;
        if ((b & 0x7fffffff) < 0x00800000) b &= 0x80000000;
    }
    float32_t x = {a}, y = {b}, z = calculate32(x, y, operation);
    const uint32_t aa = a & 0x7fffffff, bb = b & 0x7fffffff;
    const unsigned nan = bb > 0x7f800000 || (operation != 4 && aa > 0x7f800000);
    const unsigned subnormal = (bb && bb < 0x00800000) ||
                               (operation != 4 && aa && aa < 0x00800000);
    const uint32_t absolute_result = z.v & 0x7fffffff;
    if ((*mxcsr & 0x8000) && ((absolute_result && absolute_result < 0x00800000) ||
        (absolute_result == 0x00800000 && (softfloat_exceptionFlags & softfloat_flag_inexact) &&
         tiny_boundary32(x, y, operation)))) {
        z.v &= 0x80000000;
        *mxcsr |= 0x30; /* FTZ reports underflow and precision, even for exact tiny results. */
    }
    end(saved, mxcsr, !nan && subnormal ? 2u : 0u);
    return z.v;
}

uint64_t bb_fp64(uint64_t a, uint64_t b, int operation, uint32_t *mxcsr) {
    SavedEnvironment saved = begin(*mxcsr);
    if (*mxcsr & 0x40) {
        if ((a & UINT64_C(0x7fffffffffffffff)) < UINT64_C(0x0010000000000000))
            a &= UINT64_C(0x8000000000000000);
        if ((b & UINT64_C(0x7fffffffffffffff)) < UINT64_C(0x0010000000000000))
            b &= UINT64_C(0x8000000000000000);
    }
    float64_t x = {a}, y = {b}, z = calculate64(x, y, operation);
    const uint64_t aa = a & UINT64_C(0x7fffffffffffffff);
    const uint64_t bb = b & UINT64_C(0x7fffffffffffffff);
    const unsigned nan = bb > UINT64_C(0x7ff0000000000000) ||
                          (operation != 4 && aa > UINT64_C(0x7ff0000000000000));
    const unsigned subnormal = (bb && bb < UINT64_C(0x0010000000000000)) ||
        (operation != 4 && aa && aa < UINT64_C(0x0010000000000000));
    const uint64_t absolute_result = z.v & UINT64_C(0x7fffffffffffffff);
    if ((*mxcsr & 0x8000) &&
        ((absolute_result && absolute_result < UINT64_C(0x0010000000000000)) ||
         (absolute_result == UINT64_C(0x0010000000000000) &&
          (softfloat_exceptionFlags & softfloat_flag_inexact) && tiny_boundary64(x, y, operation)))) {
        z.v &= UINT64_C(0x8000000000000000);
        *mxcsr |= 0x30;
    }
    end(saved, mxcsr, !nan && subnormal ? 2u : 0u);
    return z.v;
}
