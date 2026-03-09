

#include "ArithAdd.h"

uint64_t
ArithAddValidateArithAdd(
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
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes0 = 2ULL <= (InputLength - StartPosition);
  uint64_t positionAfterArithAdd;
  if (hasBytes0)
  {
    positionAfterArithAdd = StartPosition + 2ULL;
  }
  else
  {
    positionAfterArithAdd =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAftera;
  if (EverParseIsSuccess(positionAfterArithAdd))
  {
    positionAftera = positionAfterArithAdd;
  }
  else
  {
    ErrorHandlerFn("_ArithAdd",
      "a",
      EverParseErrorReasonOfResult(positionAfterArithAdd),
      EverParseGetValidatorErrorKind(positionAfterArithAdd),
      Ctxt,
      Input,
      StartPosition);
    positionAftera = positionAfterArithAdd;
  }
  if (EverParseIsError(positionAftera))
  {
    return positionAftera;
  }
  uint16_t r0 = Load16Le(Input + (uint32_t)StartPosition);
  uint16_t a = (uint16_t)(uint32_t)r0;
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes1 = 2ULL <= (InputLength - positionAftera);
  uint64_t positionAfterArithAdd0;
  if (hasBytes1)
  {
    positionAfterArithAdd0 = positionAftera + 2ULL;
  }
  else
  {
    positionAfterArithAdd0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftera);
  }
  uint64_t positionAfterb;
  if (EverParseIsSuccess(positionAfterArithAdd0))
  {
    positionAfterb = positionAfterArithAdd0;
  }
  else
  {
    ErrorHandlerFn("_ArithAdd",
      "b",
      EverParseErrorReasonOfResult(positionAfterArithAdd0),
      EverParseGetValidatorErrorKind(positionAfterArithAdd0),
      Ctxt,
      Input,
      positionAftera);
    positionAfterb = positionAfterArithAdd0;
  }
  if (EverParseIsError(positionAfterb))
  {
    return positionAfterb;
  }
  uint16_t r1 = Load16Le(Input + (uint32_t)positionAftera);
  uint16_t b = (uint16_t)(uint32_t)r1;
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes2 = 2ULL <= (InputLength - positionAfterb);
  uint64_t positionAfterArithAdd1;
  if (hasBytes2)
  {
    positionAfterArithAdd1 = positionAfterb + 2ULL;
  }
  else
  {
    positionAfterArithAdd1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterb);
  }
  uint64_t positionAfterexpectedSum;
  if (EverParseIsSuccess(positionAfterArithAdd1))
  {
    positionAfterexpectedSum = positionAfterArithAdd1;
  }
  else
  {
    ErrorHandlerFn("_ArithAdd",
      "expected_sum",
      EverParseErrorReasonOfResult(positionAfterArithAdd1),
      EverParseGetValidatorErrorKind(positionAfterArithAdd1),
      Ctxt,
      Input,
      positionAfterb);
    positionAfterexpectedSum = positionAfterArithAdd1;
  }
  if (EverParseIsError(positionAfterexpectedSum))
  {
    return positionAfterexpectedSum;
  }
  uint16_t r = Load16Le(Input + (uint32_t)positionAfterb);
  uint16_t expectedSum = (uint16_t)(uint32_t)r;
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes3 = 1ULL <= (InputLength - positionAfterexpectedSum);
  uint64_t positionAfterGuard;
  if (hasBytes3)
  {
    positionAfterGuard = positionAfterexpectedSum + 1ULL;
  }
  else
  {
    positionAfterGuard =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterexpectedSum);
  }
  uint64_t positionAfterArithAdd2;
  if (EverParseIsError(positionAfterGuard))
  {
    positionAfterArithAdd2 = positionAfterGuard;
  }
  else
  {
    uint8_t guard = Input[(uint32_t)positionAfterexpectedSum];
    KRML_MAYBE_UNUSED_VAR(guard);
    BOOLEAN guardConstraintIsOk = a <= 30000U && b <= 30000U;
    uint64_t
    positionAfterGuard1 = EverParseCheckConstraintOk(guardConstraintIsOk, positionAfterGuard);
    if (EverParseIsError(positionAfterGuard1))
    {
      positionAfterArithAdd2 = positionAfterGuard1;
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
      uint64_t positionAfterArithAdd3;
      if (EverParseIsError(positionAfterCheck_refinement))
      {
        positionAfterArithAdd3 = positionAfterCheck_refinement;
      }
      else
      {
        /* reading field_value */
        uint8_t check_refinement = Input[(uint32_t)positionAfterGuard1];
        KRML_MAYBE_UNUSED_VAR(check_refinement);
        /* start: checking constraint */
        BOOLEAN check_refinementConstraintIsOk = expectedSum == (uint32_t)a + (uint32_t)b;
        /* end: checking constraint */
        positionAfterArithAdd3 =
          EverParseCheckConstraintOk(check_refinementConstraintIsOk,
            positionAfterCheck_refinement);
      }
      if (EverParseIsSuccess(positionAfterArithAdd3))
      {
        positionAfterArithAdd2 = positionAfterArithAdd3;
      }
      else
      {
        ErrorHandlerFn("_ArithAdd",
          "_check.refinement",
          EverParseErrorReasonOfResult(positionAfterArithAdd3),
          EverParseGetValidatorErrorKind(positionAfterArithAdd3),
          Ctxt,
          Input,
          positionAfterGuard1);
        positionAfterArithAdd2 = positionAfterArithAdd3;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterArithAdd2))
  {
    return positionAfterArithAdd2;
  }
  ErrorHandlerFn("_ArithAdd",
    "_guard",
    EverParseErrorReasonOfResult(positionAfterArithAdd2),
    EverParseGetValidatorErrorKind(positionAfterArithAdd2),
    Ctxt,
    Input,
    positionAfterexpectedSum);
  return positionAfterArithAdd2;
}

