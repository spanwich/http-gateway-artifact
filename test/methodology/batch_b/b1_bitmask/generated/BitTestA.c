

#include "BitTestA.h"

uint64_t
BitTestAValidateBitTestA(
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
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes0 = 4ULL <= (InputLength - StartPosition);
  uint64_t positionAfterBitTestA;
  if (hasBytes0)
  {
    positionAfterBitTestA = StartPosition + 4ULL;
  }
  else
  {
    positionAfterBitTestA =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterallowedMask;
  if (EverParseIsSuccess(positionAfterBitTestA))
  {
    positionAfterallowedMask = positionAfterBitTestA;
  }
  else
  {
    ErrorHandlerFn("_BitTestA",
      "allowed_mask",
      EverParseErrorReasonOfResult(positionAfterBitTestA),
      EverParseGetValidatorErrorKind(positionAfterBitTestA),
      Ctxt,
      Input,
      StartPosition);
    positionAfterallowedMask = positionAfterBitTestA;
  }
  if (EverParseIsError(positionAfterallowedMask))
  {
    return positionAfterallowedMask;
  }
  uint32_t allowedMask = Load32Le(Input + (uint32_t)StartPosition);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAfterallowedMask);
  uint64_t positionAfterBitTestA0;
  if (hasBytes1)
  {
    positionAfterBitTestA0 = positionAfterallowedMask + 1ULL;
  }
  else
  {
    positionAfterBitTestA0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterallowedMask);
  }
  uint64_t positionAfterfc;
  if (EverParseIsSuccess(positionAfterBitTestA0))
  {
    positionAfterfc = positionAfterBitTestA0;
  }
  else
  {
    ErrorHandlerFn("_BitTestA",
      "fc",
      EverParseErrorReasonOfResult(positionAfterBitTestA0),
      EverParseGetValidatorErrorKind(positionAfterBitTestA0),
      Ctxt,
      Input,
      positionAfterallowedMask);
    positionAfterfc = positionAfterBitTestA0;
  }
  if (EverParseIsError(positionAfterfc))
  {
    return positionAfterfc;
  }
  uint8_t fc = Input[(uint32_t)positionAfterallowedMask];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes2 = 1ULL <= (InputLength - positionAfterfc);
  uint64_t positionAfterGuard;
  if (hasBytes2)
  {
    positionAfterGuard = positionAfterfc + 1ULL;
  }
  else
  {
    positionAfterGuard =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterfc);
  }
  uint64_t positionAfterBitTestA1;
  if (EverParseIsError(positionAfterGuard))
  {
    positionAfterBitTestA1 = positionAfterGuard;
  }
  else
  {
    uint8_t guard = Input[(uint32_t)positionAfterfc];
    KRML_MAYBE_UNUSED_VAR(guard);
    BOOLEAN guardConstraintIsOk = fc < BITTESTA____FC_MAX;
    uint64_t
    positionAfterGuard1 = EverParseCheckConstraintOk(guardConstraintIsOk, positionAfterGuard);
    if (EverParseIsError(positionAfterGuard1))
    {
      positionAfterBitTestA1 = positionAfterGuard1;
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
      uint64_t positionAfterBitTestA2;
      if (EverParseIsError(positionAfterCheck_refinement))
      {
        positionAfterBitTestA2 = positionAfterCheck_refinement;
      }
      else
      {
        /* reading field_value */
        uint8_t check_refinement = Input[(uint32_t)positionAfterGuard1];
        KRML_MAYBE_UNUSED_VAR(check_refinement);
        /* start: checking constraint */
        BOOLEAN check_refinementConstraintIsOk = (allowedMask & 1U << (uint32_t)fc) != 0U;
        /* end: checking constraint */
        positionAfterBitTestA2 =
          EverParseCheckConstraintOk(check_refinementConstraintIsOk,
            positionAfterCheck_refinement);
      }
      if (EverParseIsSuccess(positionAfterBitTestA2))
      {
        positionAfterBitTestA1 = positionAfterBitTestA2;
      }
      else
      {
        ErrorHandlerFn("_BitTestA",
          "_check.refinement",
          EverParseErrorReasonOfResult(positionAfterBitTestA2),
          EverParseGetValidatorErrorKind(positionAfterBitTestA2),
          Ctxt,
          Input,
          positionAfterGuard1);
        positionAfterBitTestA1 = positionAfterBitTestA2;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterBitTestA1))
  {
    return positionAfterBitTestA1;
  }
  ErrorHandlerFn("_BitTestA",
    "_guard",
    EverParseErrorReasonOfResult(positionAfterBitTestA1),
    EverParseGetValidatorErrorKind(positionAfterBitTestA1),
    Ctxt,
    Input,
    positionAfterfc);
  return positionAfterBitTestA1;
}

