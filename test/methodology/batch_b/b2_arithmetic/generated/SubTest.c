

#include "SubTest.h"

uint64_t
SubTestValidateSubTestU8(
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
)
{
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes0 = 1ULL <= (InputLength - StartPosition);
  uint64_t positionAfterSubTestU8;
  if (hasBytes0)
  {
    positionAfterSubTestU8 = StartPosition + 1ULL;
  }
  else
  {
    positionAfterSubTestU8 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAftera;
  if (EverParseIsSuccess(positionAfterSubTestU8))
  {
    positionAftera = positionAfterSubTestU8;
  }
  else
  {
    ErrorHandlerFn("_SubTestU8",
      "a",
      EverParseErrorReasonOfResult(positionAfterSubTestU8),
      EverParseGetValidatorErrorKind(positionAfterSubTestU8),
      Ctxt,
      Input,
      StartPosition);
    positionAftera = positionAfterSubTestU8;
  }
  if (EverParseIsError(positionAftera))
  {
    return positionAftera;
  }
  uint8_t a = Input[(uint32_t)StartPosition];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAftera);
  uint64_t positionAfterSubTestU80;
  if (hasBytes1)
  {
    positionAfterSubTestU80 = positionAftera + 1ULL;
  }
  else
  {
    positionAfterSubTestU80 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftera);
  }
  uint64_t positionAfterb;
  if (EverParseIsSuccess(positionAfterSubTestU80))
  {
    positionAfterb = positionAfterSubTestU80;
  }
  else
  {
    ErrorHandlerFn("_SubTestU8",
      "b",
      EverParseErrorReasonOfResult(positionAfterSubTestU80),
      EverParseGetValidatorErrorKind(positionAfterSubTestU80),
      Ctxt,
      Input,
      positionAftera);
    positionAfterb = positionAfterSubTestU80;
  }
  if (EverParseIsError(positionAfterb))
  {
    return positionAfterb;
  }
  uint8_t b = Input[(uint32_t)positionAftera];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes2 = 1ULL <= (InputLength - positionAfterb);
  uint64_t positionAfterSubTestU81;
  if (hasBytes2)
  {
    positionAfterSubTestU81 = positionAfterb + 1ULL;
  }
  else
  {
    positionAfterSubTestU81 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterb);
  }
  uint64_t positionAfterexpected;
  if (EverParseIsSuccess(positionAfterSubTestU81))
  {
    positionAfterexpected = positionAfterSubTestU81;
  }
  else
  {
    ErrorHandlerFn("_SubTestU8",
      "expected",
      EverParseErrorReasonOfResult(positionAfterSubTestU81),
      EverParseGetValidatorErrorKind(positionAfterSubTestU81),
      Ctxt,
      Input,
      positionAfterb);
    positionAfterexpected = positionAfterSubTestU81;
  }
  if (EverParseIsError(positionAfterexpected))
  {
    return positionAfterexpected;
  }
  uint8_t expected = Input[(uint32_t)positionAfterb];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes3 = 1ULL <= (InputLength - positionAfterexpected);
  uint64_t positionAfterGuard;
  if (hasBytes3)
  {
    positionAfterGuard = positionAfterexpected + 1ULL;
  }
  else
  {
    positionAfterGuard =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterexpected);
  }
  uint64_t positionAfterSubTestU82;
  if (EverParseIsError(positionAfterGuard))
  {
    positionAfterSubTestU82 = positionAfterGuard;
  }
  else
  {
    uint8_t guard = Input[(uint32_t)positionAfterexpected];
    KRML_MAYBE_UNUSED_VAR(guard);
    BOOLEAN guardConstraintIsOk = a >= b;
    uint64_t
    positionAfterGuard1 = EverParseCheckConstraintOk(guardConstraintIsOk, positionAfterGuard);
    if (EverParseIsError(positionAfterGuard1))
    {
      positionAfterSubTestU82 = positionAfterGuard1;
    }
    else
    {
      /* Validating field _check */
      /* Checking that we have enough space for a UINT8, i.e., 1 byte */
      BOOLEAN hasBytes = 1ULL <= (InputLength - positionAfterGuard1);
      uint64_t positionAfterCheck_refinement;
      if (hasBytes)
      {
        positionAfterCheck_refinement = positionAfterGuard1 + 1ULL;
      }
      else
      {
        positionAfterCheck_refinement =
          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterGuard1);
      }
      uint64_t positionAfterSubTestU83;
      if (EverParseIsError(positionAfterCheck_refinement))
      {
        positionAfterSubTestU83 = positionAfterCheck_refinement;
      }
      else
      {
        /* reading field_value */
        uint8_t check_refinement = Input[(uint32_t)positionAfterGuard1];
        KRML_MAYBE_UNUSED_VAR(check_refinement);
        /* start: checking constraint */
        BOOLEAN check_refinementConstraintIsOk = expected == (uint32_t)a - (uint32_t)b;
        /* end: checking constraint */
        positionAfterSubTestU83 =
          EverParseCheckConstraintOk(check_refinementConstraintIsOk,
            positionAfterCheck_refinement);
      }
      if (EverParseIsSuccess(positionAfterSubTestU83))
      {
        positionAfterSubTestU82 = positionAfterSubTestU83;
      }
      else
      {
        ErrorHandlerFn("_SubTestU8",
          "_check.refinement",
          EverParseErrorReasonOfResult(positionAfterSubTestU83),
          EverParseGetValidatorErrorKind(positionAfterSubTestU83),
          Ctxt,
          Input,
          positionAfterGuard1);
        positionAfterSubTestU82 = positionAfterSubTestU83;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterSubTestU82))
  {
    return positionAfterSubTestU82;
  }
  ErrorHandlerFn("_SubTestU8",
    "_guard",
    EverParseErrorReasonOfResult(positionAfterSubTestU82),
    EverParseGetValidatorErrorKind(positionAfterSubTestU82),
    Ctxt,
    Input,
    positionAfterexpected);
  return positionAfterSubTestU82;
}

