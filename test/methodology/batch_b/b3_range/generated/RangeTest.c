

#include "RangeTest.h"

uint64_t
RangeTestValidateRangeCheck(
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
  uint64_t positionAfterRangeCheck;
  if (hasBytes0)
  {
    positionAfterRangeCheck = StartPosition + 2ULL;
  }
  else
  {
    positionAfterRangeCheck =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterallowedMin;
  if (EverParseIsSuccess(positionAfterRangeCheck))
  {
    positionAfterallowedMin = positionAfterRangeCheck;
  }
  else
  {
    ErrorHandlerFn("_RangeCheck",
      "allowed_min",
      EverParseErrorReasonOfResult(positionAfterRangeCheck),
      EverParseGetValidatorErrorKind(positionAfterRangeCheck),
      Ctxt,
      Input,
      StartPosition);
    positionAfterallowedMin = positionAfterRangeCheck;
  }
  if (EverParseIsError(positionAfterallowedMin))
  {
    return positionAfterallowedMin;
  }
  uint16_t r0 = Load16Le(Input + (uint32_t)StartPosition);
  uint16_t allowedMin = (uint16_t)(uint32_t)r0;
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes1 = 2ULL <= (InputLength - positionAfterallowedMin);
  uint64_t positionAfterRangeCheck0;
  if (hasBytes1)
  {
    positionAfterRangeCheck0 = positionAfterallowedMin + 2ULL;
  }
  else
  {
    positionAfterRangeCheck0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterallowedMin);
  }
  uint64_t positionAfterallowedMax;
  if (EverParseIsSuccess(positionAfterRangeCheck0))
  {
    positionAfterallowedMax = positionAfterRangeCheck0;
  }
  else
  {
    ErrorHandlerFn("_RangeCheck",
      "allowed_max",
      EverParseErrorReasonOfResult(positionAfterRangeCheck0),
      EverParseGetValidatorErrorKind(positionAfterRangeCheck0),
      Ctxt,
      Input,
      positionAfterallowedMin);
    positionAfterallowedMax = positionAfterRangeCheck0;
  }
  if (EverParseIsError(positionAfterallowedMax))
  {
    return positionAfterallowedMax;
  }
  uint16_t r1 = Load16Le(Input + (uint32_t)positionAfterallowedMin);
  uint16_t allowedMax = (uint16_t)(uint32_t)r1;
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes2 = 1ULL <= (InputLength - positionAfterallowedMax);
  uint64_t positionAfterRangeCheck1;
  if (hasBytes2)
  {
    positionAfterRangeCheck1 = positionAfterallowedMax + 1ULL;
  }
  else
  {
    positionAfterRangeCheck1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterallowedMax);
  }
  uint64_t positionAftermaxRate;
  if (EverParseIsSuccess(positionAfterRangeCheck1))
  {
    positionAftermaxRate = positionAfterRangeCheck1;
  }
  else
  {
    ErrorHandlerFn("_RangeCheck",
      "max_rate",
      EverParseErrorReasonOfResult(positionAfterRangeCheck1),
      EverParseGetValidatorErrorKind(positionAfterRangeCheck1),
      Ctxt,
      Input,
      positionAfterallowedMax);
    positionAftermaxRate = positionAfterRangeCheck1;
  }
  if (EverParseIsError(positionAftermaxRate))
  {
    return positionAftermaxRate;
  }
  uint8_t maxRate = Input[(uint32_t)positionAfterallowedMax];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes3 = 2ULL <= (InputLength - positionAftermaxRate);
  uint64_t positionAfterRangeCheck2;
  if (hasBytes3)
  {
    positionAfterRangeCheck2 = positionAftermaxRate + 2ULL;
  }
  else
  {
    positionAfterRangeCheck2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftermaxRate);
  }
  uint64_t positionAfteraddress;
  if (EverParseIsSuccess(positionAfterRangeCheck2))
  {
    positionAfteraddress = positionAfterRangeCheck2;
  }
  else
  {
    ErrorHandlerFn("_RangeCheck",
      "address",
      EverParseErrorReasonOfResult(positionAfterRangeCheck2),
      EverParseGetValidatorErrorKind(positionAfterRangeCheck2),
      Ctxt,
      Input,
      positionAftermaxRate);
    positionAfteraddress = positionAfterRangeCheck2;
  }
  if (EverParseIsError(positionAfteraddress))
  {
    return positionAfteraddress;
  }
  uint16_t r = Load16Le(Input + (uint32_t)positionAftermaxRate);
  uint16_t address = (uint16_t)(uint32_t)r;
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAfteraddress);
  uint64_t positionAfterRangeCheck3;
  if (hasBytes4)
  {
    positionAfterRangeCheck3 = positionAfteraddress + 1ULL;
  }
  else
  {
    positionAfterRangeCheck3 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfteraddress);
  }
  uint64_t positionAfterrateCount;
  if (EverParseIsSuccess(positionAfterRangeCheck3))
  {
    positionAfterrateCount = positionAfterRangeCheck3;
  }
  else
  {
    ErrorHandlerFn("_RangeCheck",
      "rate_count",
      EverParseErrorReasonOfResult(positionAfterRangeCheck3),
      EverParseGetValidatorErrorKind(positionAfterRangeCheck3),
      Ctxt,
      Input,
      positionAfteraddress);
    positionAfterrateCount = positionAfterRangeCheck3;
  }
  if (EverParseIsError(positionAfterrateCount))
  {
    return positionAfterrateCount;
  }
  uint8_t rateCount = Input[(uint32_t)positionAfteraddress];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes5 = 1ULL <= (InputLength - positionAfterrateCount);
  uint64_t positionAfterRangeOk;
  if (hasBytes5)
  {
    positionAfterRangeOk = positionAfterrateCount + 1ULL;
  }
  else
  {
    positionAfterRangeOk =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrateCount);
  }
  uint64_t positionAfterRangeCheck4;
  if (EverParseIsError(positionAfterRangeOk))
  {
    positionAfterRangeCheck4 = positionAfterRangeOk;
  }
  else
  {
    uint8_t rangeOk = Input[(uint32_t)positionAfterrateCount];
    KRML_MAYBE_UNUSED_VAR(rangeOk);
    BOOLEAN rangeOkConstraintIsOk = address >= allowedMin && address <= allowedMax;
    uint64_t
    positionAfterRangeOk1 = EverParseCheckConstraintOk(rangeOkConstraintIsOk, positionAfterRangeOk);
    if (EverParseIsError(positionAfterRangeOk1))
    {
      positionAfterRangeCheck4 = positionAfterRangeOk1;
    }
    else
    {
      /* Validating field _rate_ok */
      /* Checking that we have enough space for a UINT8, i.e., 1 byte */
      BOOLEAN hasBytes = 1ULL <= (InputLength - positionAfterRangeOk1);
      uint64_t positionAfterRateOk_refinement;
      if (hasBytes)
      {
        positionAfterRateOk_refinement = positionAfterRangeOk1 + 1ULL;
      }
      else
      {
        positionAfterRateOk_refinement =
          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterRangeOk1);
      }
      uint64_t positionAfterRangeCheck5;
      if (EverParseIsError(positionAfterRateOk_refinement))
      {
        positionAfterRangeCheck5 = positionAfterRateOk_refinement;
      }
      else
      {
        /* reading field_value */
        uint8_t rateOk_refinement = Input[(uint32_t)positionAfterRangeOk1];
        KRML_MAYBE_UNUSED_VAR(rateOk_refinement);
        /* start: checking constraint */
        BOOLEAN rateOk_refinementConstraintIsOk = rateCount < maxRate;
        /* end: checking constraint */
        positionAfterRangeCheck5 =
          EverParseCheckConstraintOk(rateOk_refinementConstraintIsOk,
            positionAfterRateOk_refinement);
      }
      if (EverParseIsSuccess(positionAfterRangeCheck5))
      {
        positionAfterRangeCheck4 = positionAfterRangeCheck5;
      }
      else
      {
        ErrorHandlerFn("_RangeCheck",
          "_rate_ok.refinement",
          EverParseErrorReasonOfResult(positionAfterRangeCheck5),
          EverParseGetValidatorErrorKind(positionAfterRangeCheck5),
          Ctxt,
          Input,
          positionAfterRangeOk1);
        positionAfterRangeCheck4 = positionAfterRangeCheck5;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterRangeCheck4))
  {
    return positionAfterRangeCheck4;
  }
  ErrorHandlerFn("_RangeCheck",
    "_range_ok",
    EverParseErrorReasonOfResult(positionAfterRangeCheck4),
    EverParseGetValidatorErrorKind(positionAfterRangeCheck4),
    Ctxt,
    Input,
    positionAfterrateCount);
  return positionAfterRangeCheck4;
}

