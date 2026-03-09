

#ifndef MealyAuth_H
#define MealyAuth_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "EverParse.h"

#define MEALYAUTH____AUTH_UNAUTH (0U)

#define MEALYAUTH____AUTH_OK (1U)

#define MEALYAUTH____METHOD_GET (1U)

#define MEALYAUTH____METHOD_POST (2U)

#define MEALYAUTH____PATH_LOGIN (0x11111111U)

#define MEALYAUTH____PATH_LOGOUT (0x22222222U)

#define MEALYAUTH____PATH_STATUS (0x33333333U)

#define MEALYAUTH____MAX_RATE (50U)

uint64_t
MealyAuthValidateLoginRequest(
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

uint64_t
MealyAuthValidateLogoutRequest(
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

uint64_t
MealyAuthValidateStatusRequest(
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

#define MealyAuth_H_DEFINED
#endif /* MealyAuth_H */
