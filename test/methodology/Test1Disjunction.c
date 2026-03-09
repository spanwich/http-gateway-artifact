

#include "Test1Disjunction.h"

uint64_t
Test1disjunctionValidateTestAccess(
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
  uint64_t positionAfterTestAccess;
  if (hasBytes0)
  {
    positionAfterTestAccess = StartPosition + 4ULL;
  }
  else
  {
    positionAfterTestAccess =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterr0PathHash;
  if (EverParseIsSuccess(positionAfterTestAccess))
  {
    positionAfterr0PathHash = positionAfterTestAccess;
  }
  else
  {
    ErrorHandlerFn("_TestAccess",
      "r0_path_hash",
      EverParseErrorReasonOfResult(positionAfterTestAccess),
      EverParseGetValidatorErrorKind(positionAfterTestAccess),
      Ctxt,
      Input,
      StartPosition);
    positionAfterr0PathHash = positionAfterTestAccess;
  }
  if (EverParseIsError(positionAfterr0PathHash))
  {
    return positionAfterr0PathHash;
  }
  uint32_t r0PathHash = Load32Le(Input + (uint32_t)StartPosition);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAfterr0PathHash);
  uint64_t positionAfterTestAccess0;
  if (hasBytes1)
  {
    positionAfterTestAccess0 = positionAfterr0PathHash + 1ULL;
  }
  else
  {
    positionAfterTestAccess0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0PathHash);
  }
  uint64_t positionAfterr0Method;
  if (EverParseIsSuccess(positionAfterTestAccess0))
  {
    positionAfterr0Method = positionAfterTestAccess0;
  }
  else
  {
    ErrorHandlerFn("_TestAccess",
      "r0_method",
      EverParseErrorReasonOfResult(positionAfterTestAccess0),
      EverParseGetValidatorErrorKind(positionAfterTestAccess0),
      Ctxt,
      Input,
      positionAfterr0PathHash);
    positionAfterr0Method = positionAfterTestAccess0;
  }
  if (EverParseIsError(positionAfterr0Method))
  {
    return positionAfterr0Method;
  }
  uint8_t r0Method = Input[(uint32_t)positionAfterr0PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes2 = 1ULL <= (InputLength - positionAfterr0Method);
  uint64_t positionAfterTestAccess1;
  if (hasBytes2)
  {
    positionAfterTestAccess1 = positionAfterr0Method + 1ULL;
  }
  else
  {
    positionAfterTestAccess1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0Method);
  }
  uint64_t positionAfterr0MinRole;
  if (EverParseIsSuccess(positionAfterTestAccess1))
  {
    positionAfterr0MinRole = positionAfterTestAccess1;
  }
  else
  {
    ErrorHandlerFn("_TestAccess",
      "r0_min_role",
      EverParseErrorReasonOfResult(positionAfterTestAccess1),
      EverParseGetValidatorErrorKind(positionAfterTestAccess1),
      Ctxt,
      Input,
      positionAfterr0Method);
    positionAfterr0MinRole = positionAfterTestAccess1;
  }
  if (EverParseIsError(positionAfterr0MinRole))
  {
    return positionAfterr0MinRole;
  }
  uint8_t r0MinRole = Input[(uint32_t)positionAfterr0Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes3 = 4ULL <= (InputLength - positionAfterr0MinRole);
  uint64_t positionAfterTestAccess2;
  if (hasBytes3)
  {
    positionAfterTestAccess2 = positionAfterr0MinRole + 4ULL;
  }
  else
  {
    positionAfterTestAccess2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0MinRole);
  }
  uint64_t positionAfterr1PathHash;
  if (EverParseIsSuccess(positionAfterTestAccess2))
  {
    positionAfterr1PathHash = positionAfterTestAccess2;
  }
  else
  {
    ErrorHandlerFn("_TestAccess",
      "r1_path_hash",
      EverParseErrorReasonOfResult(positionAfterTestAccess2),
      EverParseGetValidatorErrorKind(positionAfterTestAccess2),
      Ctxt,
      Input,
      positionAfterr0MinRole);
    positionAfterr1PathHash = positionAfterTestAccess2;
  }
  if (EverParseIsError(positionAfterr1PathHash))
  {
    return positionAfterr1PathHash;
  }
  uint32_t r1PathHash = Load32Le(Input + (uint32_t)positionAfterr0MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAfterr1PathHash);
  uint64_t positionAfterTestAccess3;
  if (hasBytes4)
  {
    positionAfterTestAccess3 = positionAfterr1PathHash + 1ULL;
  }
  else
  {
    positionAfterTestAccess3 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1PathHash);
  }
  uint64_t positionAfterr1Method;
  if (EverParseIsSuccess(positionAfterTestAccess3))
  {
    positionAfterr1Method = positionAfterTestAccess3;
  }
  else
  {
    ErrorHandlerFn("_TestAccess",
      "r1_method",
      EverParseErrorReasonOfResult(positionAfterTestAccess3),
      EverParseGetValidatorErrorKind(positionAfterTestAccess3),
      Ctxt,
      Input,
      positionAfterr1PathHash);
    positionAfterr1Method = positionAfterTestAccess3;
  }
  if (EverParseIsError(positionAfterr1Method))
  {
    return positionAfterr1Method;
  }
  uint8_t r1Method = Input[(uint32_t)positionAfterr1PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes5 = 1ULL <= (InputLength - positionAfterr1Method);
  uint64_t positionAfterTestAccess4;
  if (hasBytes5)
  {
    positionAfterTestAccess4 = positionAfterr1Method + 1ULL;
  }
  else
  {
    positionAfterTestAccess4 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1Method);
  }
  uint64_t positionAfterr1MinRole;
  if (EverParseIsSuccess(positionAfterTestAccess4))
  {
    positionAfterr1MinRole = positionAfterTestAccess4;
  }
  else
  {
    ErrorHandlerFn("_TestAccess",
      "r1_min_role",
      EverParseErrorReasonOfResult(positionAfterTestAccess4),
      EverParseGetValidatorErrorKind(positionAfterTestAccess4),
      Ctxt,
      Input,
      positionAfterr1Method);
    positionAfterr1MinRole = positionAfterTestAccess4;
  }
  if (EverParseIsError(positionAfterr1MinRole))
  {
    return positionAfterr1MinRole;
  }
  uint8_t r1MinRole = Input[(uint32_t)positionAfterr1Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes6 = 4ULL <= (InputLength - positionAfterr1MinRole);
  uint64_t positionAfterTestAccess5;
  if (hasBytes6)
  {
    positionAfterTestAccess5 = positionAfterr1MinRole + 4ULL;
  }
  else
  {
    positionAfterTestAccess5 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1MinRole);
  }
  uint64_t positionAfterr2PathHash;
  if (EverParseIsSuccess(positionAfterTestAccess5))
  {
    positionAfterr2PathHash = positionAfterTestAccess5;
  }
  else
  {
    ErrorHandlerFn("_TestAccess",
      "r2_path_hash",
      EverParseErrorReasonOfResult(positionAfterTestAccess5),
      EverParseGetValidatorErrorKind(positionAfterTestAccess5),
      Ctxt,
      Input,
      positionAfterr1MinRole);
    positionAfterr2PathHash = positionAfterTestAccess5;
  }
  if (EverParseIsError(positionAfterr2PathHash))
  {
    return positionAfterr2PathHash;
  }
  uint32_t r2PathHash = Load32Le(Input + (uint32_t)positionAfterr1MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes7 = 1ULL <= (InputLength - positionAfterr2PathHash);
  uint64_t positionAfterTestAccess6;
  if (hasBytes7)
  {
    positionAfterTestAccess6 = positionAfterr2PathHash + 1ULL;
  }
  else
  {
    positionAfterTestAccess6 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2PathHash);
  }
  uint64_t positionAfterr2Method;
  if (EverParseIsSuccess(positionAfterTestAccess6))
  {
    positionAfterr2Method = positionAfterTestAccess6;
  }
  else
  {
    ErrorHandlerFn("_TestAccess",
      "r2_method",
      EverParseErrorReasonOfResult(positionAfterTestAccess6),
      EverParseGetValidatorErrorKind(positionAfterTestAccess6),
      Ctxt,
      Input,
      positionAfterr2PathHash);
    positionAfterr2Method = positionAfterTestAccess6;
  }
  if (EverParseIsError(positionAfterr2Method))
  {
    return positionAfterr2Method;
  }
  uint8_t r2Method = Input[(uint32_t)positionAfterr2PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes8 = 1ULL <= (InputLength - positionAfterr2Method);
  uint64_t positionAfterTestAccess7;
  if (hasBytes8)
  {
    positionAfterTestAccess7 = positionAfterr2Method + 1ULL;
  }
  else
  {
    positionAfterTestAccess7 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2Method);
  }
  uint64_t positionAfterr2MinRole;
  if (EverParseIsSuccess(positionAfterTestAccess7))
  {
    positionAfterr2MinRole = positionAfterTestAccess7;
  }
  else
  {
    ErrorHandlerFn("_TestAccess",
      "r2_min_role",
      EverParseErrorReasonOfResult(positionAfterTestAccess7),
      EverParseGetValidatorErrorKind(positionAfterTestAccess7),
      Ctxt,
      Input,
      positionAfterr2Method);
    positionAfterr2MinRole = positionAfterTestAccess7;
  }
  if (EverParseIsError(positionAfterr2MinRole))
  {
    return positionAfterr2MinRole;
  }
  uint8_t r2MinRole = Input[(uint32_t)positionAfterr2Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes9 = 4ULL <= (InputLength - positionAfterr2MinRole);
  uint64_t positionAfterTestAccess8;
  if (hasBytes9)
  {
    positionAfterTestAccess8 = positionAfterr2MinRole + 4ULL;
  }
  else
  {
    positionAfterTestAccess8 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2MinRole);
  }
  uint64_t positionAfterr3PathHash;
  if (EverParseIsSuccess(positionAfterTestAccess8))
  {
    positionAfterr3PathHash = positionAfterTestAccess8;
  }
  else
  {
    ErrorHandlerFn("_TestAccess",
      "r3_path_hash",
      EverParseErrorReasonOfResult(positionAfterTestAccess8),
      EverParseGetValidatorErrorKind(positionAfterTestAccess8),
      Ctxt,
      Input,
      positionAfterr2MinRole);
    positionAfterr3PathHash = positionAfterTestAccess8;
  }
  if (EverParseIsError(positionAfterr3PathHash))
  {
    return positionAfterr3PathHash;
  }
  uint32_t r3PathHash = Load32Le(Input + (uint32_t)positionAfterr2MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes10 = 1ULL <= (InputLength - positionAfterr3PathHash);
  uint64_t positionAfterTestAccess9;
  if (hasBytes10)
  {
    positionAfterTestAccess9 = positionAfterr3PathHash + 1ULL;
  }
  else
  {
    positionAfterTestAccess9 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3PathHash);
  }
  uint64_t positionAfterr3Method;
  if (EverParseIsSuccess(positionAfterTestAccess9))
  {
    positionAfterr3Method = positionAfterTestAccess9;
  }
  else
  {
    ErrorHandlerFn("_TestAccess",
      "r3_method",
      EverParseErrorReasonOfResult(positionAfterTestAccess9),
      EverParseGetValidatorErrorKind(positionAfterTestAccess9),
      Ctxt,
      Input,
      positionAfterr3PathHash);
    positionAfterr3Method = positionAfterTestAccess9;
  }
  if (EverParseIsError(positionAfterr3Method))
  {
    return positionAfterr3Method;
  }
  uint8_t r3Method = Input[(uint32_t)positionAfterr3PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes11 = 1ULL <= (InputLength - positionAfterr3Method);
  uint64_t positionAfterTestAccess10;
  if (hasBytes11)
  {
    positionAfterTestAccess10 = positionAfterr3Method + 1ULL;
  }
  else
  {
    positionAfterTestAccess10 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3Method);
  }
  uint64_t positionAfterr3MinRole;
  if (EverParseIsSuccess(positionAfterTestAccess10))
  {
    positionAfterr3MinRole = positionAfterTestAccess10;
  }
  else
  {
    ErrorHandlerFn("_TestAccess",
      "r3_min_role",
      EverParseErrorReasonOfResult(positionAfterTestAccess10),
      EverParseGetValidatorErrorKind(positionAfterTestAccess10),
      Ctxt,
      Input,
      positionAfterr3Method);
    positionAfterr3MinRole = positionAfterTestAccess10;
  }
  if (EverParseIsError(positionAfterr3MinRole))
  {
    return positionAfterr3MinRole;
  }
  uint8_t r3MinRole = Input[(uint32_t)positionAfterr3Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes12 = 4ULL <= (InputLength - positionAfterr3MinRole);
  uint64_t positionAfterTestAccess11;
  if (hasBytes12)
  {
    positionAfterTestAccess11 = positionAfterr3MinRole + 4ULL;
  }
  else
  {
    positionAfterTestAccess11 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3MinRole);
  }
  uint64_t positionAfterreqPathHash;
  if (EverParseIsSuccess(positionAfterTestAccess11))
  {
    positionAfterreqPathHash = positionAfterTestAccess11;
  }
  else
  {
    ErrorHandlerFn("_TestAccess",
      "req_path_hash",
      EverParseErrorReasonOfResult(positionAfterTestAccess11),
      EverParseGetValidatorErrorKind(positionAfterTestAccess11),
      Ctxt,
      Input,
      positionAfterr3MinRole);
    positionAfterreqPathHash = positionAfterTestAccess11;
  }
  if (EverParseIsError(positionAfterreqPathHash))
  {
    return positionAfterreqPathHash;
  }
  uint32_t reqPathHash = Load32Le(Input + (uint32_t)positionAfterr3MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes13 = 1ULL <= (InputLength - positionAfterreqPathHash);
  uint64_t positionAfterTestAccess12;
  if (hasBytes13)
  {
    positionAfterTestAccess12 = positionAfterreqPathHash + 1ULL;
  }
  else
  {
    positionAfterTestAccess12 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqPathHash);
  }
  uint64_t positionAfterreqMethod;
  if (EverParseIsSuccess(positionAfterTestAccess12))
  {
    positionAfterreqMethod = positionAfterTestAccess12;
  }
  else
  {
    ErrorHandlerFn("_TestAccess",
      "req_method",
      EverParseErrorReasonOfResult(positionAfterTestAccess12),
      EverParseGetValidatorErrorKind(positionAfterTestAccess12),
      Ctxt,
      Input,
      positionAfterreqPathHash);
    positionAfterreqMethod = positionAfterTestAccess12;
  }
  if (EverParseIsError(positionAfterreqMethod))
  {
    return positionAfterreqMethod;
  }
  uint8_t reqMethod = Input[(uint32_t)positionAfterreqPathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes14 = 1ULL <= (InputLength - positionAfterreqMethod);
  uint64_t positionAfterTestAccess13;
  if (hasBytes14)
  {
    positionAfterTestAccess13 = positionAfterreqMethod + 1ULL;
  }
  else
  {
    positionAfterTestAccess13 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqMethod);
  }
  uint64_t positionAfterreqAuthState;
  if (EverParseIsSuccess(positionAfterTestAccess13))
  {
    positionAfterreqAuthState = positionAfterTestAccess13;
  }
  else
  {
    ErrorHandlerFn("_TestAccess",
      "req_auth_state",
      EverParseErrorReasonOfResult(positionAfterTestAccess13),
      EverParseGetValidatorErrorKind(positionAfterTestAccess13),
      Ctxt,
      Input,
      positionAfterreqMethod);
    positionAfterreqAuthState = positionAfterTestAccess13;
  }
  if (EverParseIsError(positionAfterreqAuthState))
  {
    return positionAfterreqAuthState;
  }
  uint8_t reqAuthState = Input[(uint32_t)positionAfterreqMethod];
  /* Validating field _check */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes = 1ULL <= (InputLength - positionAfterreqAuthState);
  uint64_t positionAfterCheck_refinement;
  if (hasBytes)
  {
    positionAfterCheck_refinement = positionAfterreqAuthState + 1ULL;
  }
  else
  {
    positionAfterCheck_refinement =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqAuthState);
  }
  uint64_t positionAfterTestAccess14;
  if (EverParseIsError(positionAfterCheck_refinement))
  {
    positionAfterTestAccess14 = positionAfterCheck_refinement;
  }
  else
  {
    /* reading field_value */
    uint8_t check_refinement = Input[(uint32_t)positionAfterreqAuthState];
    KRML_MAYBE_UNUSED_VAR(check_refinement);
    /* start: checking constraint */
    BOOLEAN
    check_refinementConstraintIsOk =
      (r0PathHash == reqPathHash && r0Method == reqMethod && reqAuthState >= r0MinRole) ||
        (r1PathHash == reqPathHash && r1Method == reqMethod && reqAuthState >= r1MinRole)
      || (r2PathHash == reqPathHash && r2Method == reqMethod && reqAuthState >= r2MinRole)
      || (r3PathHash == reqPathHash && r3Method == reqMethod && reqAuthState >= r3MinRole);
    /* end: checking constraint */
    positionAfterTestAccess14 =
      EverParseCheckConstraintOk(check_refinementConstraintIsOk,
        positionAfterCheck_refinement);
  }
  if (EverParseIsSuccess(positionAfterTestAccess14))
  {
    return positionAfterTestAccess14;
  }
  ErrorHandlerFn("_TestAccess",
    "_check.refinement",
    EverParseErrorReasonOfResult(positionAfterTestAccess14),
    EverParseGetValidatorErrorKind(positionAfterTestAccess14),
    Ctxt,
    Input,
    positionAfterreqAuthState);
  return positionAfterTestAccess14;
}

