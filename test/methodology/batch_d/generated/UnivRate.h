

#ifndef UnivRate_H
#define UnivRate_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "EverParse.h"

#define UNIVRATE____MAX_RATE (50U)

uint64_t
UnivRateValidateUnivRate(
  uint8_t *Ctxt,
  void
  (*ErrorHandlerFn)(
    EVERPARSE_STRING x0,
    EVERPARSE_STRING x1,
    EVERPARSE_STRING x2,
    uint64_t x3,
    uint8_t *x4,
    uint8_t *x5,
    uint64_t x6
  ),
  uint8_t *Input,
  uint64_t InputLength,
  uint64_t StartPosition
);

#if defined(__cplusplus)
}
#endif

#define UnivRate_H_DEFINED
#endif /* UnivRate_H */
