

#include "ArithMul.h"

uint64_t
ArithMulValidateArithMul(
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
  uint64_t positionAfterArithMul;
  if (hasBytes0)
  {
    positionAfterArithMul = StartPosition + 2ULL;
  }
  else
  {
    positionAfterArithMul =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterquantity;
  if (EverParseIsSuccess(positionAfterArithMul))
  {
    positionAfterquantity = positionAfterArithMul;
  }
  else
  {
    ErrorHandlerFn("_ArithMul",
      "quantity",
      EverParseErrorReasonOfResult(positionAfterArithMul),
      EverParseGetValidatorErrorKind(positionAfterArithMul),
      Ctxt,
      Input,
      StartPosition);
    positionAfterquantity = positionAfterArithMul;
  }
  if (EverParseIsError(positionAfterquantity))
  {
    return positionAfterquantity;
  }
  uint16_t r = Load16Le(Input + (uint32_t)StartPosition);
  uint16_t quantity = (uint16_t)(uint32_t)r;
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAfterquantity);
  uint64_t positionAfterArithMul0;
  if (hasBytes1)
  {
    positionAfterArithMul0 = positionAfterquantity + 1ULL;
  }
  else
  {
    positionAfterArithMul0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterquantity);
  }
  uint64_t positionAfterbyteCount;
  if (EverParseIsSuccess(positionAfterArithMul0))
  {
    positionAfterbyteCount = positionAfterArithMul0;
  }
  else
  {
    ErrorHandlerFn("_ArithMul",
      "byte_count",
      EverParseErrorReasonOfResult(positionAfterArithMul0),
      EverParseGetValidatorErrorKind(positionAfterArithMul0),
      Ctxt,
      Input,
      positionAfterquantity);
    positionAfterbyteCount = positionAfterArithMul0;
  }
  if (EverParseIsError(positionAfterbyteCount))
  {
    return positionAfterbyteCount;
  }
  uint8_t byteCount = Input[(uint32_t)positionAfterquantity];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes2 = 1ULL <= (InputLength - positionAfterbyteCount);
  uint64_t positionAfterGuard;
  if (hasBytes2)
  {
    positionAfterGuard = positionAfterbyteCount + 1ULL;
  }
  else
  {
    positionAfterGuard =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterbyteCount);
  }
  uint64_t positionAfterArithMul1;
  if (EverParseIsError(positionAfterGuard))
  {
    positionAfterArithMul1 = positionAfterGuard;
  }
  else
  {
    uint8_t guard = Input[(uint32_t)positionAfterbyteCount];
    KRML_MAYBE_UNUSED_VAR(guard);
    BOOLEAN guardConstraintIsOk = quantity <= (uint16_t)127U;
    uint64_t
    positionAfterGuard1 = EverParseCheckConstraintOk(guardConstraintIsOk, positionAfterGuard);
    if (EverParseIsError(positionAfterGuard1))
    {
      positionAfterArithMul1 = positionAfterGuard1;
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
      uint64_t positionAfterArithMul2;
      if (EverParseIsError(positionAfterCheck_refinement))
      {
        positionAfterArithMul2 = positionAfterCheck_refinement;
      }
      else
      {
        /* reading field_value */
        uint8_t check_refinement = Input[(uint32_t)positionAfterGuard1];
        KRML_MAYBE_UNUSED_VAR(check_refinement);
        /* start: checking constraint */
        BOOLEAN
        check_refinementConstraintIsOk =
          (uint16_t)byteCount == (uint32_t)quantity * (uint32_t)(uint16_t)2U;
        /* end: checking constraint */
        positionAfterArithMul2 =
          EverParseCheckConstraintOk(check_refinementConstraintIsOk,
            positionAfterCheck_refinement);
      }
      if (EverParseIsSuccess(positionAfterArithMul2))
      {
        positionAfterArithMul1 = positionAfterArithMul2;
      }
      else
      {
        ErrorHandlerFn("_ArithMul",
          "_check.refinement",
          EverParseErrorReasonOfResult(positionAfterArithMul2),
          EverParseGetValidatorErrorKind(positionAfterArithMul2),
          Ctxt,
          Input,
          positionAfterGuard1);
        positionAfterArithMul1 = positionAfterArithMul2;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterArithMul1))
  {
    return positionAfterArithMul1;
  }
  ErrorHandlerFn("_ArithMul",
    "_guard",
    EverParseErrorReasonOfResult(positionAfterArithMul1),
    EverParseGetValidatorErrorKind(positionAfterArithMul1),
    Ctxt,
    Input,
    positionAfterbyteCount);
  return positionAfterArithMul1;
}

