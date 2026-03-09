

#include "Test2Hybrid.h"

uint64_t
Test2hybridValidateTestHybrid(
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
  uint64_t positionAfterTestHybrid;
  if (hasBytes0)
  {
    positionAfterTestHybrid = StartPosition + 1ULL;
  }
  else
  {
    positionAfterTestHybrid =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAftermaxRate;
  if (EverParseIsSuccess(positionAfterTestHybrid))
  {
    positionAftermaxRate = positionAfterTestHybrid;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "max_rate",
      EverParseErrorReasonOfResult(positionAfterTestHybrid),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid),
      Ctxt,
      Input,
      StartPosition);
    positionAftermaxRate = positionAfterTestHybrid;
  }
  if (EverParseIsError(positionAftermaxRate))
  {
    return positionAftermaxRate;
  }
  uint8_t maxRate = Input[(uint32_t)StartPosition];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes1 = 4ULL <= (InputLength - positionAftermaxRate);
  uint64_t positionAfterTestHybrid0;
  if (hasBytes1)
  {
    positionAfterTestHybrid0 = positionAftermaxRate + 4ULL;
  }
  else
  {
    positionAfterTestHybrid0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftermaxRate);
  }
  uint64_t positionAftermaxBody;
  if (EverParseIsSuccess(positionAfterTestHybrid0))
  {
    positionAftermaxBody = positionAfterTestHybrid0;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "max_body",
      EverParseErrorReasonOfResult(positionAfterTestHybrid0),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid0),
      Ctxt,
      Input,
      positionAftermaxRate);
    positionAftermaxBody = positionAfterTestHybrid0;
  }
  if (EverParseIsError(positionAftermaxBody))
  {
    return positionAftermaxBody;
  }
  uint32_t maxBody = Load32Le(Input + (uint32_t)positionAftermaxRate);
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes2 = 4ULL <= (InputLength - positionAftermaxBody);
  uint64_t positionAfterTestHybrid1;
  if (hasBytes2)
  {
    positionAfterTestHybrid1 = positionAftermaxBody + 4ULL;
  }
  else
  {
    positionAfterTestHybrid1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftermaxBody);
  }
  uint64_t positionAfterr0PathHash;
  if (EverParseIsSuccess(positionAfterTestHybrid1))
  {
    positionAfterr0PathHash = positionAfterTestHybrid1;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "r0_path_hash",
      EverParseErrorReasonOfResult(positionAfterTestHybrid1),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid1),
      Ctxt,
      Input,
      positionAftermaxBody);
    positionAfterr0PathHash = positionAfterTestHybrid1;
  }
  if (EverParseIsError(positionAfterr0PathHash))
  {
    return positionAfterr0PathHash;
  }
  uint32_t r0PathHash = Load32Le(Input + (uint32_t)positionAftermaxBody);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes3 = 1ULL <= (InputLength - positionAfterr0PathHash);
  uint64_t positionAfterTestHybrid2;
  if (hasBytes3)
  {
    positionAfterTestHybrid2 = positionAfterr0PathHash + 1ULL;
  }
  else
  {
    positionAfterTestHybrid2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0PathHash);
  }
  uint64_t positionAfterr0Method;
  if (EverParseIsSuccess(positionAfterTestHybrid2))
  {
    positionAfterr0Method = positionAfterTestHybrid2;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "r0_method",
      EverParseErrorReasonOfResult(positionAfterTestHybrid2),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid2),
      Ctxt,
      Input,
      positionAfterr0PathHash);
    positionAfterr0Method = positionAfterTestHybrid2;
  }
  if (EverParseIsError(positionAfterr0Method))
  {
    return positionAfterr0Method;
  }
  uint8_t r0Method = Input[(uint32_t)positionAfterr0PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAfterr0Method);
  uint64_t positionAfterTestHybrid3;
  if (hasBytes4)
  {
    positionAfterTestHybrid3 = positionAfterr0Method + 1ULL;
  }
  else
  {
    positionAfterTestHybrid3 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0Method);
  }
  uint64_t positionAfterr0MinRole;
  if (EverParseIsSuccess(positionAfterTestHybrid3))
  {
    positionAfterr0MinRole = positionAfterTestHybrid3;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "r0_min_role",
      EverParseErrorReasonOfResult(positionAfterTestHybrid3),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid3),
      Ctxt,
      Input,
      positionAfterr0Method);
    positionAfterr0MinRole = positionAfterTestHybrid3;
  }
  if (EverParseIsError(positionAfterr0MinRole))
  {
    return positionAfterr0MinRole;
  }
  uint8_t r0MinRole = Input[(uint32_t)positionAfterr0Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes5 = 4ULL <= (InputLength - positionAfterr0MinRole);
  uint64_t positionAfterTestHybrid4;
  if (hasBytes5)
  {
    positionAfterTestHybrid4 = positionAfterr0MinRole + 4ULL;
  }
  else
  {
    positionAfterTestHybrid4 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0MinRole);
  }
  uint64_t positionAfterr1PathHash;
  if (EverParseIsSuccess(positionAfterTestHybrid4))
  {
    positionAfterr1PathHash = positionAfterTestHybrid4;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "r1_path_hash",
      EverParseErrorReasonOfResult(positionAfterTestHybrid4),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid4),
      Ctxt,
      Input,
      positionAfterr0MinRole);
    positionAfterr1PathHash = positionAfterTestHybrid4;
  }
  if (EverParseIsError(positionAfterr1PathHash))
  {
    return positionAfterr1PathHash;
  }
  uint32_t r1PathHash = Load32Le(Input + (uint32_t)positionAfterr0MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes6 = 1ULL <= (InputLength - positionAfterr1PathHash);
  uint64_t positionAfterTestHybrid5;
  if (hasBytes6)
  {
    positionAfterTestHybrid5 = positionAfterr1PathHash + 1ULL;
  }
  else
  {
    positionAfterTestHybrid5 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1PathHash);
  }
  uint64_t positionAfterr1Method;
  if (EverParseIsSuccess(positionAfterTestHybrid5))
  {
    positionAfterr1Method = positionAfterTestHybrid5;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "r1_method",
      EverParseErrorReasonOfResult(positionAfterTestHybrid5),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid5),
      Ctxt,
      Input,
      positionAfterr1PathHash);
    positionAfterr1Method = positionAfterTestHybrid5;
  }
  if (EverParseIsError(positionAfterr1Method))
  {
    return positionAfterr1Method;
  }
  uint8_t r1Method = Input[(uint32_t)positionAfterr1PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes7 = 1ULL <= (InputLength - positionAfterr1Method);
  uint64_t positionAfterTestHybrid6;
  if (hasBytes7)
  {
    positionAfterTestHybrid6 = positionAfterr1Method + 1ULL;
  }
  else
  {
    positionAfterTestHybrid6 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1Method);
  }
  uint64_t positionAfterr1MinRole;
  if (EverParseIsSuccess(positionAfterTestHybrid6))
  {
    positionAfterr1MinRole = positionAfterTestHybrid6;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "r1_min_role",
      EverParseErrorReasonOfResult(positionAfterTestHybrid6),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid6),
      Ctxt,
      Input,
      positionAfterr1Method);
    positionAfterr1MinRole = positionAfterTestHybrid6;
  }
  if (EverParseIsError(positionAfterr1MinRole))
  {
    return positionAfterr1MinRole;
  }
  uint8_t r1MinRole = Input[(uint32_t)positionAfterr1Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes8 = 4ULL <= (InputLength - positionAfterr1MinRole);
  uint64_t positionAfterTestHybrid7;
  if (hasBytes8)
  {
    positionAfterTestHybrid7 = positionAfterr1MinRole + 4ULL;
  }
  else
  {
    positionAfterTestHybrid7 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1MinRole);
  }
  uint64_t positionAfterr2PathHash;
  if (EverParseIsSuccess(positionAfterTestHybrid7))
  {
    positionAfterr2PathHash = positionAfterTestHybrid7;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "r2_path_hash",
      EverParseErrorReasonOfResult(positionAfterTestHybrid7),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid7),
      Ctxt,
      Input,
      positionAfterr1MinRole);
    positionAfterr2PathHash = positionAfterTestHybrid7;
  }
  if (EverParseIsError(positionAfterr2PathHash))
  {
    return positionAfterr2PathHash;
  }
  uint32_t r2PathHash = Load32Le(Input + (uint32_t)positionAfterr1MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes9 = 1ULL <= (InputLength - positionAfterr2PathHash);
  uint64_t positionAfterTestHybrid8;
  if (hasBytes9)
  {
    positionAfterTestHybrid8 = positionAfterr2PathHash + 1ULL;
  }
  else
  {
    positionAfterTestHybrid8 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2PathHash);
  }
  uint64_t positionAfterr2Method;
  if (EverParseIsSuccess(positionAfterTestHybrid8))
  {
    positionAfterr2Method = positionAfterTestHybrid8;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "r2_method",
      EverParseErrorReasonOfResult(positionAfterTestHybrid8),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid8),
      Ctxt,
      Input,
      positionAfterr2PathHash);
    positionAfterr2Method = positionAfterTestHybrid8;
  }
  if (EverParseIsError(positionAfterr2Method))
  {
    return positionAfterr2Method;
  }
  uint8_t r2Method = Input[(uint32_t)positionAfterr2PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes10 = 1ULL <= (InputLength - positionAfterr2Method);
  uint64_t positionAfterTestHybrid9;
  if (hasBytes10)
  {
    positionAfterTestHybrid9 = positionAfterr2Method + 1ULL;
  }
  else
  {
    positionAfterTestHybrid9 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2Method);
  }
  uint64_t positionAfterr2MinRole;
  if (EverParseIsSuccess(positionAfterTestHybrid9))
  {
    positionAfterr2MinRole = positionAfterTestHybrid9;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "r2_min_role",
      EverParseErrorReasonOfResult(positionAfterTestHybrid9),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid9),
      Ctxt,
      Input,
      positionAfterr2Method);
    positionAfterr2MinRole = positionAfterTestHybrid9;
  }
  if (EverParseIsError(positionAfterr2MinRole))
  {
    return positionAfterr2MinRole;
  }
  uint8_t r2MinRole = Input[(uint32_t)positionAfterr2Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes11 = 4ULL <= (InputLength - positionAfterr2MinRole);
  uint64_t positionAfterTestHybrid10;
  if (hasBytes11)
  {
    positionAfterTestHybrid10 = positionAfterr2MinRole + 4ULL;
  }
  else
  {
    positionAfterTestHybrid10 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2MinRole);
  }
  uint64_t positionAfterr3PathHash;
  if (EverParseIsSuccess(positionAfterTestHybrid10))
  {
    positionAfterr3PathHash = positionAfterTestHybrid10;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "r3_path_hash",
      EverParseErrorReasonOfResult(positionAfterTestHybrid10),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid10),
      Ctxt,
      Input,
      positionAfterr2MinRole);
    positionAfterr3PathHash = positionAfterTestHybrid10;
  }
  if (EverParseIsError(positionAfterr3PathHash))
  {
    return positionAfterr3PathHash;
  }
  uint32_t r3PathHash = Load32Le(Input + (uint32_t)positionAfterr2MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes12 = 1ULL <= (InputLength - positionAfterr3PathHash);
  uint64_t positionAfterTestHybrid11;
  if (hasBytes12)
  {
    positionAfterTestHybrid11 = positionAfterr3PathHash + 1ULL;
  }
  else
  {
    positionAfterTestHybrid11 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3PathHash);
  }
  uint64_t positionAfterr3Method;
  if (EverParseIsSuccess(positionAfterTestHybrid11))
  {
    positionAfterr3Method = positionAfterTestHybrid11;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "r3_method",
      EverParseErrorReasonOfResult(positionAfterTestHybrid11),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid11),
      Ctxt,
      Input,
      positionAfterr3PathHash);
    positionAfterr3Method = positionAfterTestHybrid11;
  }
  if (EverParseIsError(positionAfterr3Method))
  {
    return positionAfterr3Method;
  }
  uint8_t r3Method = Input[(uint32_t)positionAfterr3PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes13 = 1ULL <= (InputLength - positionAfterr3Method);
  uint64_t positionAfterTestHybrid12;
  if (hasBytes13)
  {
    positionAfterTestHybrid12 = positionAfterr3Method + 1ULL;
  }
  else
  {
    positionAfterTestHybrid12 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3Method);
  }
  uint64_t positionAfterr3MinRole;
  if (EverParseIsSuccess(positionAfterTestHybrid12))
  {
    positionAfterr3MinRole = positionAfterTestHybrid12;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "r3_min_role",
      EverParseErrorReasonOfResult(positionAfterTestHybrid12),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid12),
      Ctxt,
      Input,
      positionAfterr3Method);
    positionAfterr3MinRole = positionAfterTestHybrid12;
  }
  if (EverParseIsError(positionAfterr3MinRole))
  {
    return positionAfterr3MinRole;
  }
  uint8_t r3MinRole = Input[(uint32_t)positionAfterr3Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes14 = 4ULL <= (InputLength - positionAfterr3MinRole);
  uint64_t positionAfterTestHybrid13;
  if (hasBytes14)
  {
    positionAfterTestHybrid13 = positionAfterr3MinRole + 4ULL;
  }
  else
  {
    positionAfterTestHybrid13 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3MinRole);
  }
  uint64_t positionAfterreqPathHash;
  if (EverParseIsSuccess(positionAfterTestHybrid13))
  {
    positionAfterreqPathHash = positionAfterTestHybrid13;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "req_path_hash",
      EverParseErrorReasonOfResult(positionAfterTestHybrid13),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid13),
      Ctxt,
      Input,
      positionAfterr3MinRole);
    positionAfterreqPathHash = positionAfterTestHybrid13;
  }
  if (EverParseIsError(positionAfterreqPathHash))
  {
    return positionAfterreqPathHash;
  }
  uint32_t reqPathHash = Load32Le(Input + (uint32_t)positionAfterr3MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes15 = 1ULL <= (InputLength - positionAfterreqPathHash);
  uint64_t positionAfterTestHybrid14;
  if (hasBytes15)
  {
    positionAfterTestHybrid14 = positionAfterreqPathHash + 1ULL;
  }
  else
  {
    positionAfterTestHybrid14 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqPathHash);
  }
  uint64_t positionAfterreqMethod;
  if (EverParseIsSuccess(positionAfterTestHybrid14))
  {
    positionAfterreqMethod = positionAfterTestHybrid14;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "req_method",
      EverParseErrorReasonOfResult(positionAfterTestHybrid14),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid14),
      Ctxt,
      Input,
      positionAfterreqPathHash);
    positionAfterreqMethod = positionAfterTestHybrid14;
  }
  if (EverParseIsError(positionAfterreqMethod))
  {
    return positionAfterreqMethod;
  }
  uint8_t reqMethod = Input[(uint32_t)positionAfterreqPathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes16 = 1ULL <= (InputLength - positionAfterreqMethod);
  uint64_t positionAfterTestHybrid15;
  if (hasBytes16)
  {
    positionAfterTestHybrid15 = positionAfterreqMethod + 1ULL;
  }
  else
  {
    positionAfterTestHybrid15 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqMethod);
  }
  uint64_t positionAfterreqAuthState;
  if (EverParseIsSuccess(positionAfterTestHybrid15))
  {
    positionAfterreqAuthState = positionAfterTestHybrid15;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "req_auth_state",
      EverParseErrorReasonOfResult(positionAfterTestHybrid15),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid15),
      Ctxt,
      Input,
      positionAfterreqMethod);
    positionAfterreqAuthState = positionAfterTestHybrid15;
  }
  if (EverParseIsError(positionAfterreqAuthState))
  {
    return positionAfterreqAuthState;
  }
  uint8_t reqAuthState = Input[(uint32_t)positionAfterreqMethod];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes17 = 1ULL <= (InputLength - positionAfterreqAuthState);
  uint64_t positionAfterTestHybrid16;
  if (hasBytes17)
  {
    positionAfterTestHybrid16 = positionAfterreqAuthState + 1ULL;
  }
  else
  {
    positionAfterTestHybrid16 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqAuthState);
  }
  uint64_t positionAfterreqRateCount;
  if (EverParseIsSuccess(positionAfterTestHybrid16))
  {
    positionAfterreqRateCount = positionAfterTestHybrid16;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "req_rate_count",
      EverParseErrorReasonOfResult(positionAfterTestHybrid16),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid16),
      Ctxt,
      Input,
      positionAfterreqAuthState);
    positionAfterreqRateCount = positionAfterTestHybrid16;
  }
  if (EverParseIsError(positionAfterreqRateCount))
  {
    return positionAfterreqRateCount;
  }
  uint8_t reqRateCount = Input[(uint32_t)positionAfterreqAuthState];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes18 = 4ULL <= (InputLength - positionAfterreqRateCount);
  uint64_t positionAfterTestHybrid17;
  if (hasBytes18)
  {
    positionAfterTestHybrid17 = positionAfterreqRateCount + 4ULL;
  }
  else
  {
    positionAfterTestHybrid17 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqRateCount);
  }
  uint64_t positionAfterreqContentLength;
  if (EverParseIsSuccess(positionAfterTestHybrid17))
  {
    positionAfterreqContentLength = positionAfterTestHybrid17;
  }
  else
  {
    ErrorHandlerFn("_TestHybrid",
      "req_content_length",
      EverParseErrorReasonOfResult(positionAfterTestHybrid17),
      EverParseGetValidatorErrorKind(positionAfterTestHybrid17),
      Ctxt,
      Input,
      positionAfterreqRateCount);
    positionAfterreqContentLength = positionAfterTestHybrid17;
  }
  if (EverParseIsError(positionAfterreqContentLength))
  {
    return positionAfterreqContentLength;
  }
  uint32_t reqContentLength = Load32Le(Input + (uint32_t)positionAfterreqRateCount);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes19 = 1ULL <= (InputLength - positionAfterreqContentLength);
  uint64_t positionAfterRateOk;
  if (hasBytes19)
  {
    positionAfterRateOk = positionAfterreqContentLength + 1ULL;
  }
  else
  {
    positionAfterRateOk =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqContentLength);
  }
  uint64_t positionAfterTestHybrid18;
  if (EverParseIsError(positionAfterRateOk))
  {
    positionAfterTestHybrid18 = positionAfterRateOk;
  }
  else
  {
    uint8_t rateOk = Input[(uint32_t)positionAfterreqContentLength];
    KRML_MAYBE_UNUSED_VAR(rateOk);
    BOOLEAN rateOkConstraintIsOk = reqRateCount < maxRate;
    uint64_t
    positionAfterRateOk1 = EverParseCheckConstraintOk(rateOkConstraintIsOk, positionAfterRateOk);
    if (EverParseIsError(positionAfterRateOk1))
    {
      positionAfterTestHybrid18 = positionAfterRateOk1;
    }
    else
    {
      /* Checking that we have enough space for a UINT8, i.e., 1 byte */
      BOOLEAN hasBytes20 = 1ULL <= (InputLength - positionAfterRateOk1);
      uint64_t positionAfterSizeOk;
      if (hasBytes20)
      {
        positionAfterSizeOk = positionAfterRateOk1 + 1ULL;
      }
      else
      {
        positionAfterSizeOk =
          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterRateOk1);
      }
      uint64_t positionAfterTestHybrid19;
      if (EverParseIsError(positionAfterSizeOk))
      {
        positionAfterTestHybrid19 = positionAfterSizeOk;
      }
      else
      {
        uint8_t sizeOk = Input[(uint32_t)positionAfterRateOk1];
        KRML_MAYBE_UNUSED_VAR(sizeOk);
        BOOLEAN sizeOkConstraintIsOk = reqContentLength <= maxBody;
        uint64_t
        positionAfterSizeOk1 = EverParseCheckConstraintOk(sizeOkConstraintIsOk, positionAfterSizeOk);
        if (EverParseIsError(positionAfterSizeOk1))
        {
          positionAfterTestHybrid19 = positionAfterSizeOk1;
        }
        else
        {
          /* Validating field _access_ok */
          /* Checking that we have enough space for a UINT8, i.e., 1 byte */
          BOOLEAN hasBytes = 1ULL <= (InputLength - positionAfterSizeOk1);
          uint64_t positionAfterAccessOk_refinement;
          if (hasBytes)
          {
            positionAfterAccessOk_refinement = positionAfterSizeOk1 + 1ULL;
          }
          else
          {
            positionAfterAccessOk_refinement =
              EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                positionAfterSizeOk1);
          }
          uint64_t positionAfterTestHybrid20;
          if (EverParseIsError(positionAfterAccessOk_refinement))
          {
            positionAfterTestHybrid20 = positionAfterAccessOk_refinement;
          }
          else
          {
            /* reading field_value */
            uint8_t accessOk_refinement = Input[(uint32_t)positionAfterSizeOk1];
            KRML_MAYBE_UNUSED_VAR(accessOk_refinement);
            /* start: checking constraint */
            BOOLEAN
            accessOk_refinementConstraintIsOk =
              (r0PathHash == reqPathHash && r0Method == reqMethod && reqAuthState >= r0MinRole) ||
                (r1PathHash == reqPathHash && r1Method == reqMethod && reqAuthState >= r1MinRole)
              || (r2PathHash == reqPathHash && r2Method == reqMethod && reqAuthState >= r2MinRole)
              || (r3PathHash == reqPathHash && r3Method == reqMethod && reqAuthState >= r3MinRole);
            /* end: checking constraint */
            positionAfterTestHybrid20 =
              EverParseCheckConstraintOk(accessOk_refinementConstraintIsOk,
                positionAfterAccessOk_refinement);
          }
          if (EverParseIsSuccess(positionAfterTestHybrid20))
          {
            positionAfterTestHybrid19 = positionAfterTestHybrid20;
          }
          else
          {
            ErrorHandlerFn("_TestHybrid",
              "_access_ok.refinement",
              EverParseErrorReasonOfResult(positionAfterTestHybrid20),
              EverParseGetValidatorErrorKind(positionAfterTestHybrid20),
              Ctxt,
              Input,
              positionAfterSizeOk1);
            positionAfterTestHybrid19 = positionAfterTestHybrid20;
          }
        }
      }
      if (EverParseIsSuccess(positionAfterTestHybrid19))
      {
        positionAfterTestHybrid18 = positionAfterTestHybrid19;
      }
      else
      {
        ErrorHandlerFn("_TestHybrid",
          "_size_ok",
          EverParseErrorReasonOfResult(positionAfterTestHybrid19),
          EverParseGetValidatorErrorKind(positionAfterTestHybrid19),
          Ctxt,
          Input,
          positionAfterRateOk1);
        positionAfterTestHybrid18 = positionAfterTestHybrid19;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterTestHybrid18))
  {
    return positionAfterTestHybrid18;
  }
  ErrorHandlerFn("_TestHybrid",
    "_rate_ok",
    EverParseErrorReasonOfResult(positionAfterTestHybrid18),
    EverParseGetValidatorErrorKind(positionAfterTestHybrid18),
    Ctxt,
    Input,
    positionAfterreqContentLength);
  return positionAfterTestHybrid18;
}

