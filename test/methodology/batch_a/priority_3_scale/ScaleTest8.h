

#ifndef ScaleTest8_H
#define ScaleTest8_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "EverParse.h"

#define SCALETEST8____MAX_RATE (50U)

#define SCALETEST8____DEAD_HASH (0xDEADDEADU)

uint64_t
ScaleTest8ValidateScaleTest8(
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

#define ScaleTest8_H_DEFINED
#endif /* ScaleTest8_H */
