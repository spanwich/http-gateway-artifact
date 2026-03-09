

#include "BitTestC.h"

uint64_t
BitTestCValidateBitTestC(
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
  uint64_t positionAfterBitTestC;
  if (hasBytes0)
  {
    positionAfterBitTestC = StartPosition + 4ULL;
  }
  else
  {
    positionAfterBitTestC =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAftera;
  if (EverParseIsSuccess(positionAfterBitTestC))
  {
    positionAftera = positionAfterBitTestC;
  }
  else
  {
    ErrorHandlerFn("_BitTestC",
      "a",
      EverParseErrorReasonOfResult(positionAfterBitTestC),
      EverParseGetValidatorErrorKind(positionAfterBitTestC),
      Ctxt,
      Input,
      StartPosition);
    positionAftera = positionAfterBitTestC;
  }
  if (EverParseIsError(positionAftera))
  {
    return positionAftera;
  }
  uint32_t a = Load32Le(Input + (uint32_t)StartPosition);
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes1 = 4ULL <= (InputLength - positionAftera);
  uint64_t positionAfterBitTestC0;
  if (hasBytes1)
  {
    positionAfterBitTestC0 = positionAftera + 4ULL;
  }
  else
  {
    positionAfterBitTestC0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftera);
  }
  uint64_t positionAfterb;
  if (EverParseIsSuccess(positionAfterBitTestC0))
  {
    positionAfterb = positionAfterBitTestC0;
  }
  else
  {
    ErrorHandlerFn("_BitTestC",
      "b",
      EverParseErrorReasonOfResult(positionAfterBitTestC0),
      EverParseGetValidatorErrorKind(positionAfterBitTestC0),
      Ctxt,
      Input,
      positionAftera);
    positionAfterb = positionAfterBitTestC0;
  }
  if (EverParseIsError(positionAfterb))
  {
    return positionAfterb;
  }
  uint32_t b = Load32Le(Input + (uint32_t)positionAftera);
  /* Validating field _check */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes = 1ULL <= (InputLength - positionAfterb);
  uint64_t positionAfterCheck_refinement;
  if (hasBytes)
  {
    positionAfterCheck_refinement = positionAfterb + 1ULL;
  }
  else
  {
    positionAfterCheck_refinement =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterb);
  }
  uint64_t positionAfterBitTestC1;
  if (EverParseIsError(positionAfterCheck_refinement))
  {
    positionAfterBitTestC1 = positionAfterCheck_refinement;
  }
  else
  {
    /* reading field_value */
    uint8_t check_refinement = Input[(uint32_t)positionAfterb];
    KRML_MAYBE_UNUSED_VAR(check_refinement);
    /* start: checking constraint */
    BOOLEAN check_refinementConstraintIsOk = (a & b) != (uint32_t)0U;
    /* end: checking constraint */
    positionAfterBitTestC1 =
      EverParseCheckConstraintOk(check_refinementConstraintIsOk,
        positionAfterCheck_refinement);
  }
  if (EverParseIsSuccess(positionAfterBitTestC1))
  {
    return positionAfterBitTestC1;
  }
  ErrorHandlerFn("_BitTestC",
    "_check.refinement",
    EverParseErrorReasonOfResult(positionAfterBitTestC1),
    EverParseGetValidatorErrorKind(positionAfterBitTestC1),
    Ctxt,
    Input,
    positionAfterb);
  return positionAfterBitTestC1;
}

