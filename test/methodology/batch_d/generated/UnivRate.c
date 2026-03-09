

#include "UnivRate.h"

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
)
{
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes0 = 1ULL <= (InputLength - StartPosition);
  uint64_t positionAfterUnivRate;
  if (hasBytes0)
  {
    positionAfterUnivRate = StartPosition + 1ULL;
  }
  else
  {
    positionAfterUnivRate =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterrateCount;
  if (EverParseIsSuccess(positionAfterUnivRate))
  {
    positionAfterrateCount = positionAfterUnivRate;
  }
  else
  {
    ErrorHandlerFn("_UnivRate",
      "rate_count",
      EverParseErrorReasonOfResult(positionAfterUnivRate),
      EverParseGetValidatorErrorKind(positionAfterUnivRate),
      Ctxt,
      Input,
      StartPosition);
    positionAfterrateCount = positionAfterUnivRate;
  }
  if (EverParseIsError(positionAfterrateCount))
  {
    return positionAfterrateCount;
  }
  uint8_t rateCount = Input[(uint32_t)StartPosition];
  /* Validating field _rate_ok */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes = 1ULL <= (InputLength - positionAfterrateCount);
  uint64_t positionAfterRateOk_refinement;
  if (hasBytes)
  {
    positionAfterRateOk_refinement = positionAfterrateCount + 1ULL;
  }
  else
  {
    positionAfterRateOk_refinement =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrateCount);
  }
  uint64_t positionAfterUnivRate0;
  if (EverParseIsError(positionAfterRateOk_refinement))
  {
    positionAfterUnivRate0 = positionAfterRateOk_refinement;
  }
  else
  {
    /* reading field_value */
    uint8_t rateOk_refinement = Input[(uint32_t)positionAfterrateCount];
    KRML_MAYBE_UNUSED_VAR(rateOk_refinement);
    /* start: checking constraint */
    BOOLEAN rateOk_refinementConstraintIsOk = rateCount < UNIVRATE____MAX_RATE;
    /* end: checking constraint */
    positionAfterUnivRate0 =
      EverParseCheckConstraintOk(rateOk_refinementConstraintIsOk,
        positionAfterRateOk_refinement);
  }
  if (EverParseIsSuccess(positionAfterUnivRate0))
  {
    return positionAfterUnivRate0;
  }
  ErrorHandlerFn("_UnivRate",
    "_rate_ok.refinement",
    EverParseErrorReasonOfResult(positionAfterUnivRate0),
    EverParseGetValidatorErrorKind(positionAfterUnivRate0),
    Ctxt,
    Input,
    positionAfterrateCount);
  return positionAfterUnivRate0;
}

