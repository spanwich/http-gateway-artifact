

#include "BitTestB.h"

uint64_t
BitTestBValidateBitTestB(
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
  uint64_t positionAfterBitTestB;
  if (hasBytes0)
  {
    positionAfterBitTestB = StartPosition + 4ULL;
  }
  else
  {
    positionAfterBitTestB =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterallowedMask;
  if (EverParseIsSuccess(positionAfterBitTestB))
  {
    positionAfterallowedMask = positionAfterBitTestB;
  }
  else
  {
    ErrorHandlerFn("_BitTestB",
      "allowed_mask",
      EverParseErrorReasonOfResult(positionAfterBitTestB),
      EverParseGetValidatorErrorKind(positionAfterBitTestB),
      Ctxt,
      Input,
      StartPosition);
    positionAfterallowedMask = positionAfterBitTestB;
  }
  if (EverParseIsError(positionAfterallowedMask))
  {
    return positionAfterallowedMask;
  }
  uint32_t allowedMask = Load32Le(Input + (uint32_t)StartPosition);
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes1 = 4ULL <= (InputLength - positionAfterallowedMask);
  uint64_t positionAfterBitTestB0;
  if (hasBytes1)
  {
    positionAfterBitTestB0 = positionAfterallowedMask + 4ULL;
  }
  else
  {
    positionAfterBitTestB0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterallowedMask);
  }
  uint64_t positionAfterfcBit;
  if (EverParseIsSuccess(positionAfterBitTestB0))
  {
    positionAfterfcBit = positionAfterBitTestB0;
  }
  else
  {
    ErrorHandlerFn("_BitTestB",
      "fc_bit",
      EverParseErrorReasonOfResult(positionAfterBitTestB0),
      EverParseGetValidatorErrorKind(positionAfterBitTestB0),
      Ctxt,
      Input,
      positionAfterallowedMask);
    positionAfterfcBit = positionAfterBitTestB0;
  }
  if (EverParseIsError(positionAfterfcBit))
  {
    return positionAfterfcBit;
  }
  uint32_t fcBit = Load32Le(Input + (uint32_t)positionAfterallowedMask);
  /* Validating field _check */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes = 1ULL <= (InputLength - positionAfterfcBit);
  uint64_t positionAfterCheck_refinement;
  if (hasBytes)
  {
    positionAfterCheck_refinement = positionAfterfcBit + 1ULL;
  }
  else
  {
    positionAfterCheck_refinement =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterfcBit);
  }
  uint64_t positionAfterBitTestB1;
  if (EverParseIsError(positionAfterCheck_refinement))
  {
    positionAfterBitTestB1 = positionAfterCheck_refinement;
  }
  else
  {
    /* reading field_value */
    uint8_t check_refinement = Input[(uint32_t)positionAfterfcBit];
    KRML_MAYBE_UNUSED_VAR(check_refinement);
    /* start: checking constraint */
    BOOLEAN check_refinementConstraintIsOk = (allowedMask & fcBit) != (uint32_t)0U;
    /* end: checking constraint */
    positionAfterBitTestB1 =
      EverParseCheckConstraintOk(check_refinementConstraintIsOk,
        positionAfterCheck_refinement);
  }
  if (EverParseIsSuccess(positionAfterBitTestB1))
  {
    return positionAfterBitTestB1;
  }
  ErrorHandlerFn("_BitTestB",
    "_check.refinement",
    EverParseErrorReasonOfResult(positionAfterBitTestB1),
    EverParseGetValidatorErrorKind(positionAfterBitTestB1),
    Ctxt,
    Input,
    positionAfterfcBit);
  return positionAfterBitTestB1;
}

