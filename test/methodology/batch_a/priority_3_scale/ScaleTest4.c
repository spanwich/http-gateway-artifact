

#include "ScaleTest4.h"

uint64_t
ScaleTest4ValidateScaleTest4(
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
  uint64_t positionAfterScaleTest4;
  if (hasBytes0)
  {
    positionAfterScaleTest4 = StartPosition + 4ULL;
  }
  else
  {
    positionAfterScaleTest4 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterr0PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest4))
  {
    positionAfterr0PathHash = positionAfterScaleTest4;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest4",
      "r0_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest4),
      EverParseGetValidatorErrorKind(positionAfterScaleTest4),
      Ctxt,
      Input,
      StartPosition);
    positionAfterr0PathHash = positionAfterScaleTest4;
  }
  if (EverParseIsError(positionAfterr0PathHash))
  {
    return positionAfterr0PathHash;
  }
  uint32_t r0PathHash = Load32Le(Input + (uint32_t)StartPosition);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAfterr0PathHash);
  uint64_t positionAfterScaleTest40;
  if (hasBytes1)
  {
    positionAfterScaleTest40 = positionAfterr0PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest40 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0PathHash);
  }
  uint64_t positionAfterr0Method;
  if (EverParseIsSuccess(positionAfterScaleTest40))
  {
    positionAfterr0Method = positionAfterScaleTest40;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest4",
      "r0_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest40),
      EverParseGetValidatorErrorKind(positionAfterScaleTest40),
      Ctxt,
      Input,
      positionAfterr0PathHash);
    positionAfterr0Method = positionAfterScaleTest40;
  }
  if (EverParseIsError(positionAfterr0Method))
  {
    return positionAfterr0Method;
  }
  uint8_t r0Method = Input[(uint32_t)positionAfterr0PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes2 = 1ULL <= (InputLength - positionAfterr0Method);
  uint64_t positionAfterScaleTest41;
  if (hasBytes2)
  {
    positionAfterScaleTest41 = positionAfterr0Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest41 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0Method);
  }
  uint64_t positionAfterr0MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest41))
  {
    positionAfterr0MinRole = positionAfterScaleTest41;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest4",
      "r0_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest41),
      EverParseGetValidatorErrorKind(positionAfterScaleTest41),
      Ctxt,
      Input,
      positionAfterr0Method);
    positionAfterr0MinRole = positionAfterScaleTest41;
  }
  if (EverParseIsError(positionAfterr0MinRole))
  {
    return positionAfterr0MinRole;
  }
  uint8_t r0MinRole = Input[(uint32_t)positionAfterr0Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes3 = 4ULL <= (InputLength - positionAfterr0MinRole);
  uint64_t positionAfterScaleTest42;
  if (hasBytes3)
  {
    positionAfterScaleTest42 = positionAfterr0MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest42 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0MinRole);
  }
  uint64_t positionAfterr1PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest42))
  {
    positionAfterr1PathHash = positionAfterScaleTest42;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest4",
      "r1_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest42),
      EverParseGetValidatorErrorKind(positionAfterScaleTest42),
      Ctxt,
      Input,
      positionAfterr0MinRole);
    positionAfterr1PathHash = positionAfterScaleTest42;
  }
  if (EverParseIsError(positionAfterr1PathHash))
  {
    return positionAfterr1PathHash;
  }
  uint32_t r1PathHash = Load32Le(Input + (uint32_t)positionAfterr0MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAfterr1PathHash);
  uint64_t positionAfterScaleTest43;
  if (hasBytes4)
  {
    positionAfterScaleTest43 = positionAfterr1PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest43 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1PathHash);
  }
  uint64_t positionAfterr1Method;
  if (EverParseIsSuccess(positionAfterScaleTest43))
  {
    positionAfterr1Method = positionAfterScaleTest43;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest4",
      "r1_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest43),
      EverParseGetValidatorErrorKind(positionAfterScaleTest43),
      Ctxt,
      Input,
      positionAfterr1PathHash);
    positionAfterr1Method = positionAfterScaleTest43;
  }
  if (EverParseIsError(positionAfterr1Method))
  {
    return positionAfterr1Method;
  }
  uint8_t r1Method = Input[(uint32_t)positionAfterr1PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes5 = 1ULL <= (InputLength - positionAfterr1Method);
  uint64_t positionAfterScaleTest44;
  if (hasBytes5)
  {
    positionAfterScaleTest44 = positionAfterr1Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest44 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1Method);
  }
  uint64_t positionAfterr1MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest44))
  {
    positionAfterr1MinRole = positionAfterScaleTest44;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest4",
      "r1_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest44),
      EverParseGetValidatorErrorKind(positionAfterScaleTest44),
      Ctxt,
      Input,
      positionAfterr1Method);
    positionAfterr1MinRole = positionAfterScaleTest44;
  }
  if (EverParseIsError(positionAfterr1MinRole))
  {
    return positionAfterr1MinRole;
  }
  uint8_t r1MinRole = Input[(uint32_t)positionAfterr1Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes6 = 4ULL <= (InputLength - positionAfterr1MinRole);
  uint64_t positionAfterScaleTest45;
  if (hasBytes6)
  {
    positionAfterScaleTest45 = positionAfterr1MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest45 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1MinRole);
  }
  uint64_t positionAfterr2PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest45))
  {
    positionAfterr2PathHash = positionAfterScaleTest45;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest4",
      "r2_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest45),
      EverParseGetValidatorErrorKind(positionAfterScaleTest45),
      Ctxt,
      Input,
      positionAfterr1MinRole);
    positionAfterr2PathHash = positionAfterScaleTest45;
  }
  if (EverParseIsError(positionAfterr2PathHash))
  {
    return positionAfterr2PathHash;
  }
  uint32_t r2PathHash = Load32Le(Input + (uint32_t)positionAfterr1MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes7 = 1ULL <= (InputLength - positionAfterr2PathHash);
  uint64_t positionAfterScaleTest46;
  if (hasBytes7)
  {
    positionAfterScaleTest46 = positionAfterr2PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest46 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2PathHash);
  }
  uint64_t positionAfterr2Method;
  if (EverParseIsSuccess(positionAfterScaleTest46))
  {
    positionAfterr2Method = positionAfterScaleTest46;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest4",
      "r2_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest46),
      EverParseGetValidatorErrorKind(positionAfterScaleTest46),
      Ctxt,
      Input,
      positionAfterr2PathHash);
    positionAfterr2Method = positionAfterScaleTest46;
  }
  if (EverParseIsError(positionAfterr2Method))
  {
    return positionAfterr2Method;
  }
  uint8_t r2Method = Input[(uint32_t)positionAfterr2PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes8 = 1ULL <= (InputLength - positionAfterr2Method);
  uint64_t positionAfterScaleTest47;
  if (hasBytes8)
  {
    positionAfterScaleTest47 = positionAfterr2Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest47 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2Method);
  }
  uint64_t positionAfterr2MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest47))
  {
    positionAfterr2MinRole = positionAfterScaleTest47;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest4",
      "r2_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest47),
      EverParseGetValidatorErrorKind(positionAfterScaleTest47),
      Ctxt,
      Input,
      positionAfterr2Method);
    positionAfterr2MinRole = positionAfterScaleTest47;
  }
  if (EverParseIsError(positionAfterr2MinRole))
  {
    return positionAfterr2MinRole;
  }
  uint8_t r2MinRole = Input[(uint32_t)positionAfterr2Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes9 = 4ULL <= (InputLength - positionAfterr2MinRole);
  uint64_t positionAfterScaleTest48;
  if (hasBytes9)
  {
    positionAfterScaleTest48 = positionAfterr2MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest48 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2MinRole);
  }
  uint64_t positionAfterr3PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest48))
  {
    positionAfterr3PathHash = positionAfterScaleTest48;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest4",
      "r3_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest48),
      EverParseGetValidatorErrorKind(positionAfterScaleTest48),
      Ctxt,
      Input,
      positionAfterr2MinRole);
    positionAfterr3PathHash = positionAfterScaleTest48;
  }
  if (EverParseIsError(positionAfterr3PathHash))
  {
    return positionAfterr3PathHash;
  }
  uint32_t r3PathHash = Load32Le(Input + (uint32_t)positionAfterr2MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes10 = 1ULL <= (InputLength - positionAfterr3PathHash);
  uint64_t positionAfterScaleTest49;
  if (hasBytes10)
  {
    positionAfterScaleTest49 = positionAfterr3PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest49 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3PathHash);
  }
  uint64_t positionAfterr3Method;
  if (EverParseIsSuccess(positionAfterScaleTest49))
  {
    positionAfterr3Method = positionAfterScaleTest49;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest4",
      "r3_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest49),
      EverParseGetValidatorErrorKind(positionAfterScaleTest49),
      Ctxt,
      Input,
      positionAfterr3PathHash);
    positionAfterr3Method = positionAfterScaleTest49;
  }
  if (EverParseIsError(positionAfterr3Method))
  {
    return positionAfterr3Method;
  }
  uint8_t r3Method = Input[(uint32_t)positionAfterr3PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes11 = 1ULL <= (InputLength - positionAfterr3Method);
  uint64_t positionAfterScaleTest410;
  if (hasBytes11)
  {
    positionAfterScaleTest410 = positionAfterr3Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest410 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3Method);
  }
  uint64_t positionAfterr3MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest410))
  {
    positionAfterr3MinRole = positionAfterScaleTest410;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest4",
      "r3_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest410),
      EverParseGetValidatorErrorKind(positionAfterScaleTest410),
      Ctxt,
      Input,
      positionAfterr3Method);
    positionAfterr3MinRole = positionAfterScaleTest410;
  }
  if (EverParseIsError(positionAfterr3MinRole))
  {
    return positionAfterr3MinRole;
  }
  uint8_t r3MinRole = Input[(uint32_t)positionAfterr3Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes12 = 4ULL <= (InputLength - positionAfterr3MinRole);
  uint64_t positionAfterScaleTest411;
  if (hasBytes12)
  {
    positionAfterScaleTest411 = positionAfterr3MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest411 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3MinRole);
  }
  uint64_t positionAfterreqPathHash;
  if (EverParseIsSuccess(positionAfterScaleTest411))
  {
    positionAfterreqPathHash = positionAfterScaleTest411;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest4",
      "req_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest411),
      EverParseGetValidatorErrorKind(positionAfterScaleTest411),
      Ctxt,
      Input,
      positionAfterr3MinRole);
    positionAfterreqPathHash = positionAfterScaleTest411;
  }
  if (EverParseIsError(positionAfterreqPathHash))
  {
    return positionAfterreqPathHash;
  }
  uint32_t reqPathHash = Load32Le(Input + (uint32_t)positionAfterr3MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes13 = 1ULL <= (InputLength - positionAfterreqPathHash);
  uint64_t positionAfterScaleTest412;
  if (hasBytes13)
  {
    positionAfterScaleTest412 = positionAfterreqPathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest412 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqPathHash);
  }
  uint64_t positionAfterreqMethod;
  if (EverParseIsSuccess(positionAfterScaleTest412))
  {
    positionAfterreqMethod = positionAfterScaleTest412;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest4",
      "req_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest412),
      EverParseGetValidatorErrorKind(positionAfterScaleTest412),
      Ctxt,
      Input,
      positionAfterreqPathHash);
    positionAfterreqMethod = positionAfterScaleTest412;
  }
  if (EverParseIsError(positionAfterreqMethod))
  {
    return positionAfterreqMethod;
  }
  uint8_t reqMethod = Input[(uint32_t)positionAfterreqPathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes14 = 1ULL <= (InputLength - positionAfterreqMethod);
  uint64_t positionAfterScaleTest413;
  if (hasBytes14)
  {
    positionAfterScaleTest413 = positionAfterreqMethod + 1ULL;
  }
  else
  {
    positionAfterScaleTest413 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqMethod);
  }
  uint64_t positionAfterauthState;
  if (EverParseIsSuccess(positionAfterScaleTest413))
  {
    positionAfterauthState = positionAfterScaleTest413;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest4",
      "auth_state",
      EverParseErrorReasonOfResult(positionAfterScaleTest413),
      EverParseGetValidatorErrorKind(positionAfterScaleTest413),
      Ctxt,
      Input,
      positionAfterreqMethod);
    positionAfterauthState = positionAfterScaleTest413;
  }
  if (EverParseIsError(positionAfterauthState))
  {
    return positionAfterauthState;
  }
  uint8_t authState = Input[(uint32_t)positionAfterreqMethod];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes15 = 1ULL <= (InputLength - positionAfterauthState);
  uint64_t positionAfterScaleTest414;
  if (hasBytes15)
  {
    positionAfterScaleTest414 = positionAfterauthState + 1ULL;
  }
  else
  {
    positionAfterScaleTest414 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterauthState);
  }
  uint64_t positionAfterrateCount;
  if (EverParseIsSuccess(positionAfterScaleTest414))
  {
    positionAfterrateCount = positionAfterScaleTest414;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest4",
      "rate_count",
      EverParseErrorReasonOfResult(positionAfterScaleTest414),
      EverParseGetValidatorErrorKind(positionAfterScaleTest414),
      Ctxt,
      Input,
      positionAfterauthState);
    positionAfterrateCount = positionAfterScaleTest414;
  }
  if (EverParseIsError(positionAfterrateCount))
  {
    return positionAfterrateCount;
  }
  uint8_t rateCount = Input[(uint32_t)positionAfterauthState];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes16 = 1ULL <= (InputLength - positionAfterrateCount);
  uint64_t positionAfterRateOk;
  if (hasBytes16)
  {
    positionAfterRateOk = positionAfterrateCount + 1ULL;
  }
  else
  {
    positionAfterRateOk =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrateCount);
  }
  uint64_t positionAfterScaleTest415;
  if (EverParseIsError(positionAfterRateOk))
  {
    positionAfterScaleTest415 = positionAfterRateOk;
  }
  else
  {
    uint8_t rateOk = Input[(uint32_t)positionAfterrateCount];
    KRML_MAYBE_UNUSED_VAR(rateOk);
    BOOLEAN rateOkConstraintIsOk = rateCount < SCALETEST4____MAX_RATE;
    uint64_t
    positionAfterRateOk1 = EverParseCheckConstraintOk(rateOkConstraintIsOk, positionAfterRateOk);
    if (EverParseIsError(positionAfterRateOk1))
    {
      positionAfterScaleTest415 = positionAfterRateOk1;
    }
    else
    {
      /* Validating field _access_ok */
      /* Checking that we have enough space for a UINT8, i.e., 1 byte */
      BOOLEAN hasBytes = 1ULL <= (InputLength - positionAfterRateOk1);
      uint64_t positionAfterAccessOk_refinement;
      if (hasBytes)
      {
        positionAfterAccessOk_refinement = positionAfterRateOk1 + 1ULL;
      }
      else
      {
        positionAfterAccessOk_refinement =
          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterRateOk1);
      }
      uint64_t positionAfterScaleTest416;
      if (EverParseIsError(positionAfterAccessOk_refinement))
      {
        positionAfterScaleTest416 = positionAfterAccessOk_refinement;
      }
      else
      {
        /* reading field_value */
        uint8_t accessOk_refinement = Input[(uint32_t)positionAfterRateOk1];
        KRML_MAYBE_UNUSED_VAR(accessOk_refinement);
        /* start: checking constraint */
        BOOLEAN
        accessOk_refinementConstraintIsOk =
          (r0PathHash == reqPathHash && r0Method == reqMethod && authState >= r0MinRole) ||
            (r1PathHash == reqPathHash && r1Method == reqMethod && authState >= r1MinRole)
          || (r2PathHash == reqPathHash && r2Method == reqMethod && authState >= r2MinRole)
          || (r3PathHash == reqPathHash && r3Method == reqMethod && authState >= r3MinRole);
        /* end: checking constraint */
        positionAfterScaleTest416 =
          EverParseCheckConstraintOk(accessOk_refinementConstraintIsOk,
            positionAfterAccessOk_refinement);
      }
      if (EverParseIsSuccess(positionAfterScaleTest416))
      {
        positionAfterScaleTest415 = positionAfterScaleTest416;
      }
      else
      {
        ErrorHandlerFn("_ScaleTest4",
          "_access_ok.refinement",
          EverParseErrorReasonOfResult(positionAfterScaleTest416),
          EverParseGetValidatorErrorKind(positionAfterScaleTest416),
          Ctxt,
          Input,
          positionAfterRateOk1);
        positionAfterScaleTest415 = positionAfterScaleTest416;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterScaleTest415))
  {
    return positionAfterScaleTest415;
  }
  ErrorHandlerFn("_ScaleTest4",
    "_rate_ok",
    EverParseErrorReasonOfResult(positionAfterScaleTest415),
    EverParseGetValidatorErrorKind(positionAfterScaleTest415),
    Ctxt,
    Input,
    positionAfterrateCount);
  return positionAfterScaleTest415;
}

