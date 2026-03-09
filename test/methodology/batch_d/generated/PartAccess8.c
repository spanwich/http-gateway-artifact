

#include "PartAccess8.h"

uint64_t
PartAccess8ValidatePartAccess8(
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
  uint64_t positionAfterPartAccess8;
  if (hasBytes0)
  {
    positionAfterPartAccess8 = StartPosition + 4ULL;
  }
  else
  {
    positionAfterPartAccess8 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterr0PathHash;
  if (EverParseIsSuccess(positionAfterPartAccess8))
  {
    positionAfterr0PathHash = positionAfterPartAccess8;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r0_path_hash",
      EverParseErrorReasonOfResult(positionAfterPartAccess8),
      EverParseGetValidatorErrorKind(positionAfterPartAccess8),
      Ctxt,
      Input,
      StartPosition);
    positionAfterr0PathHash = positionAfterPartAccess8;
  }
  if (EverParseIsError(positionAfterr0PathHash))
  {
    return positionAfterr0PathHash;
  }
  uint32_t r0PathHash = Load32Le(Input + (uint32_t)StartPosition);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAfterr0PathHash);
  uint64_t positionAfterPartAccess80;
  if (hasBytes1)
  {
    positionAfterPartAccess80 = positionAfterr0PathHash + 1ULL;
  }
  else
  {
    positionAfterPartAccess80 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0PathHash);
  }
  uint64_t positionAfterr0Method;
  if (EverParseIsSuccess(positionAfterPartAccess80))
  {
    positionAfterr0Method = positionAfterPartAccess80;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r0_method",
      EverParseErrorReasonOfResult(positionAfterPartAccess80),
      EverParseGetValidatorErrorKind(positionAfterPartAccess80),
      Ctxt,
      Input,
      positionAfterr0PathHash);
    positionAfterr0Method = positionAfterPartAccess80;
  }
  if (EverParseIsError(positionAfterr0Method))
  {
    return positionAfterr0Method;
  }
  uint8_t r0Method = Input[(uint32_t)positionAfterr0PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes2 = 1ULL <= (InputLength - positionAfterr0Method);
  uint64_t positionAfterPartAccess81;
  if (hasBytes2)
  {
    positionAfterPartAccess81 = positionAfterr0Method + 1ULL;
  }
  else
  {
    positionAfterPartAccess81 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0Method);
  }
  uint64_t positionAfterr0MinRole;
  if (EverParseIsSuccess(positionAfterPartAccess81))
  {
    positionAfterr0MinRole = positionAfterPartAccess81;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r0_min_role",
      EverParseErrorReasonOfResult(positionAfterPartAccess81),
      EverParseGetValidatorErrorKind(positionAfterPartAccess81),
      Ctxt,
      Input,
      positionAfterr0Method);
    positionAfterr0MinRole = positionAfterPartAccess81;
  }
  if (EverParseIsError(positionAfterr0MinRole))
  {
    return positionAfterr0MinRole;
  }
  uint8_t r0MinRole = Input[(uint32_t)positionAfterr0Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes3 = 4ULL <= (InputLength - positionAfterr0MinRole);
  uint64_t positionAfterPartAccess82;
  if (hasBytes3)
  {
    positionAfterPartAccess82 = positionAfterr0MinRole + 4ULL;
  }
  else
  {
    positionAfterPartAccess82 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0MinRole);
  }
  uint64_t positionAfterr1PathHash;
  if (EverParseIsSuccess(positionAfterPartAccess82))
  {
    positionAfterr1PathHash = positionAfterPartAccess82;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r1_path_hash",
      EverParseErrorReasonOfResult(positionAfterPartAccess82),
      EverParseGetValidatorErrorKind(positionAfterPartAccess82),
      Ctxt,
      Input,
      positionAfterr0MinRole);
    positionAfterr1PathHash = positionAfterPartAccess82;
  }
  if (EverParseIsError(positionAfterr1PathHash))
  {
    return positionAfterr1PathHash;
  }
  uint32_t r1PathHash = Load32Le(Input + (uint32_t)positionAfterr0MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAfterr1PathHash);
  uint64_t positionAfterPartAccess83;
  if (hasBytes4)
  {
    positionAfterPartAccess83 = positionAfterr1PathHash + 1ULL;
  }
  else
  {
    positionAfterPartAccess83 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1PathHash);
  }
  uint64_t positionAfterr1Method;
  if (EverParseIsSuccess(positionAfterPartAccess83))
  {
    positionAfterr1Method = positionAfterPartAccess83;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r1_method",
      EverParseErrorReasonOfResult(positionAfterPartAccess83),
      EverParseGetValidatorErrorKind(positionAfterPartAccess83),
      Ctxt,
      Input,
      positionAfterr1PathHash);
    positionAfterr1Method = positionAfterPartAccess83;
  }
  if (EverParseIsError(positionAfterr1Method))
  {
    return positionAfterr1Method;
  }
  uint8_t r1Method = Input[(uint32_t)positionAfterr1PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes5 = 1ULL <= (InputLength - positionAfterr1Method);
  uint64_t positionAfterPartAccess84;
  if (hasBytes5)
  {
    positionAfterPartAccess84 = positionAfterr1Method + 1ULL;
  }
  else
  {
    positionAfterPartAccess84 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1Method);
  }
  uint64_t positionAfterr1MinRole;
  if (EverParseIsSuccess(positionAfterPartAccess84))
  {
    positionAfterr1MinRole = positionAfterPartAccess84;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r1_min_role",
      EverParseErrorReasonOfResult(positionAfterPartAccess84),
      EverParseGetValidatorErrorKind(positionAfterPartAccess84),
      Ctxt,
      Input,
      positionAfterr1Method);
    positionAfterr1MinRole = positionAfterPartAccess84;
  }
  if (EverParseIsError(positionAfterr1MinRole))
  {
    return positionAfterr1MinRole;
  }
  uint8_t r1MinRole = Input[(uint32_t)positionAfterr1Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes6 = 4ULL <= (InputLength - positionAfterr1MinRole);
  uint64_t positionAfterPartAccess85;
  if (hasBytes6)
  {
    positionAfterPartAccess85 = positionAfterr1MinRole + 4ULL;
  }
  else
  {
    positionAfterPartAccess85 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1MinRole);
  }
  uint64_t positionAfterr2PathHash;
  if (EverParseIsSuccess(positionAfterPartAccess85))
  {
    positionAfterr2PathHash = positionAfterPartAccess85;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r2_path_hash",
      EverParseErrorReasonOfResult(positionAfterPartAccess85),
      EverParseGetValidatorErrorKind(positionAfterPartAccess85),
      Ctxt,
      Input,
      positionAfterr1MinRole);
    positionAfterr2PathHash = positionAfterPartAccess85;
  }
  if (EverParseIsError(positionAfterr2PathHash))
  {
    return positionAfterr2PathHash;
  }
  uint32_t r2PathHash = Load32Le(Input + (uint32_t)positionAfterr1MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes7 = 1ULL <= (InputLength - positionAfterr2PathHash);
  uint64_t positionAfterPartAccess86;
  if (hasBytes7)
  {
    positionAfterPartAccess86 = positionAfterr2PathHash + 1ULL;
  }
  else
  {
    positionAfterPartAccess86 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2PathHash);
  }
  uint64_t positionAfterr2Method;
  if (EverParseIsSuccess(positionAfterPartAccess86))
  {
    positionAfterr2Method = positionAfterPartAccess86;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r2_method",
      EverParseErrorReasonOfResult(positionAfterPartAccess86),
      EverParseGetValidatorErrorKind(positionAfterPartAccess86),
      Ctxt,
      Input,
      positionAfterr2PathHash);
    positionAfterr2Method = positionAfterPartAccess86;
  }
  if (EverParseIsError(positionAfterr2Method))
  {
    return positionAfterr2Method;
  }
  uint8_t r2Method = Input[(uint32_t)positionAfterr2PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes8 = 1ULL <= (InputLength - positionAfterr2Method);
  uint64_t positionAfterPartAccess87;
  if (hasBytes8)
  {
    positionAfterPartAccess87 = positionAfterr2Method + 1ULL;
  }
  else
  {
    positionAfterPartAccess87 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2Method);
  }
  uint64_t positionAfterr2MinRole;
  if (EverParseIsSuccess(positionAfterPartAccess87))
  {
    positionAfterr2MinRole = positionAfterPartAccess87;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r2_min_role",
      EverParseErrorReasonOfResult(positionAfterPartAccess87),
      EverParseGetValidatorErrorKind(positionAfterPartAccess87),
      Ctxt,
      Input,
      positionAfterr2Method);
    positionAfterr2MinRole = positionAfterPartAccess87;
  }
  if (EverParseIsError(positionAfterr2MinRole))
  {
    return positionAfterr2MinRole;
  }
  uint8_t r2MinRole = Input[(uint32_t)positionAfterr2Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes9 = 4ULL <= (InputLength - positionAfterr2MinRole);
  uint64_t positionAfterPartAccess88;
  if (hasBytes9)
  {
    positionAfterPartAccess88 = positionAfterr2MinRole + 4ULL;
  }
  else
  {
    positionAfterPartAccess88 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2MinRole);
  }
  uint64_t positionAfterr3PathHash;
  if (EverParseIsSuccess(positionAfterPartAccess88))
  {
    positionAfterr3PathHash = positionAfterPartAccess88;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r3_path_hash",
      EverParseErrorReasonOfResult(positionAfterPartAccess88),
      EverParseGetValidatorErrorKind(positionAfterPartAccess88),
      Ctxt,
      Input,
      positionAfterr2MinRole);
    positionAfterr3PathHash = positionAfterPartAccess88;
  }
  if (EverParseIsError(positionAfterr3PathHash))
  {
    return positionAfterr3PathHash;
  }
  uint32_t r3PathHash = Load32Le(Input + (uint32_t)positionAfterr2MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes10 = 1ULL <= (InputLength - positionAfterr3PathHash);
  uint64_t positionAfterPartAccess89;
  if (hasBytes10)
  {
    positionAfterPartAccess89 = positionAfterr3PathHash + 1ULL;
  }
  else
  {
    positionAfterPartAccess89 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3PathHash);
  }
  uint64_t positionAfterr3Method;
  if (EverParseIsSuccess(positionAfterPartAccess89))
  {
    positionAfterr3Method = positionAfterPartAccess89;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r3_method",
      EverParseErrorReasonOfResult(positionAfterPartAccess89),
      EverParseGetValidatorErrorKind(positionAfterPartAccess89),
      Ctxt,
      Input,
      positionAfterr3PathHash);
    positionAfterr3Method = positionAfterPartAccess89;
  }
  if (EverParseIsError(positionAfterr3Method))
  {
    return positionAfterr3Method;
  }
  uint8_t r3Method = Input[(uint32_t)positionAfterr3PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes11 = 1ULL <= (InputLength - positionAfterr3Method);
  uint64_t positionAfterPartAccess810;
  if (hasBytes11)
  {
    positionAfterPartAccess810 = positionAfterr3Method + 1ULL;
  }
  else
  {
    positionAfterPartAccess810 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3Method);
  }
  uint64_t positionAfterr3MinRole;
  if (EverParseIsSuccess(positionAfterPartAccess810))
  {
    positionAfterr3MinRole = positionAfterPartAccess810;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r3_min_role",
      EverParseErrorReasonOfResult(positionAfterPartAccess810),
      EverParseGetValidatorErrorKind(positionAfterPartAccess810),
      Ctxt,
      Input,
      positionAfterr3Method);
    positionAfterr3MinRole = positionAfterPartAccess810;
  }
  if (EverParseIsError(positionAfterr3MinRole))
  {
    return positionAfterr3MinRole;
  }
  uint8_t r3MinRole = Input[(uint32_t)positionAfterr3Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes12 = 4ULL <= (InputLength - positionAfterr3MinRole);
  uint64_t positionAfterPartAccess811;
  if (hasBytes12)
  {
    positionAfterPartAccess811 = positionAfterr3MinRole + 4ULL;
  }
  else
  {
    positionAfterPartAccess811 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3MinRole);
  }
  uint64_t positionAfterr4PathHash;
  if (EverParseIsSuccess(positionAfterPartAccess811))
  {
    positionAfterr4PathHash = positionAfterPartAccess811;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r4_path_hash",
      EverParseErrorReasonOfResult(positionAfterPartAccess811),
      EverParseGetValidatorErrorKind(positionAfterPartAccess811),
      Ctxt,
      Input,
      positionAfterr3MinRole);
    positionAfterr4PathHash = positionAfterPartAccess811;
  }
  if (EverParseIsError(positionAfterr4PathHash))
  {
    return positionAfterr4PathHash;
  }
  uint32_t r4PathHash = Load32Le(Input + (uint32_t)positionAfterr3MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes13 = 1ULL <= (InputLength - positionAfterr4PathHash);
  uint64_t positionAfterPartAccess812;
  if (hasBytes13)
  {
    positionAfterPartAccess812 = positionAfterr4PathHash + 1ULL;
  }
  else
  {
    positionAfterPartAccess812 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4PathHash);
  }
  uint64_t positionAfterr4Method;
  if (EverParseIsSuccess(positionAfterPartAccess812))
  {
    positionAfterr4Method = positionAfterPartAccess812;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r4_method",
      EverParseErrorReasonOfResult(positionAfterPartAccess812),
      EverParseGetValidatorErrorKind(positionAfterPartAccess812),
      Ctxt,
      Input,
      positionAfterr4PathHash);
    positionAfterr4Method = positionAfterPartAccess812;
  }
  if (EverParseIsError(positionAfterr4Method))
  {
    return positionAfterr4Method;
  }
  uint8_t r4Method = Input[(uint32_t)positionAfterr4PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes14 = 1ULL <= (InputLength - positionAfterr4Method);
  uint64_t positionAfterPartAccess813;
  if (hasBytes14)
  {
    positionAfterPartAccess813 = positionAfterr4Method + 1ULL;
  }
  else
  {
    positionAfterPartAccess813 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4Method);
  }
  uint64_t positionAfterr4MinRole;
  if (EverParseIsSuccess(positionAfterPartAccess813))
  {
    positionAfterr4MinRole = positionAfterPartAccess813;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r4_min_role",
      EverParseErrorReasonOfResult(positionAfterPartAccess813),
      EverParseGetValidatorErrorKind(positionAfterPartAccess813),
      Ctxt,
      Input,
      positionAfterr4Method);
    positionAfterr4MinRole = positionAfterPartAccess813;
  }
  if (EverParseIsError(positionAfterr4MinRole))
  {
    return positionAfterr4MinRole;
  }
  uint8_t r4MinRole = Input[(uint32_t)positionAfterr4Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes15 = 4ULL <= (InputLength - positionAfterr4MinRole);
  uint64_t positionAfterPartAccess814;
  if (hasBytes15)
  {
    positionAfterPartAccess814 = positionAfterr4MinRole + 4ULL;
  }
  else
  {
    positionAfterPartAccess814 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4MinRole);
  }
  uint64_t positionAfterr5PathHash;
  if (EverParseIsSuccess(positionAfterPartAccess814))
  {
    positionAfterr5PathHash = positionAfterPartAccess814;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r5_path_hash",
      EverParseErrorReasonOfResult(positionAfterPartAccess814),
      EverParseGetValidatorErrorKind(positionAfterPartAccess814),
      Ctxt,
      Input,
      positionAfterr4MinRole);
    positionAfterr5PathHash = positionAfterPartAccess814;
  }
  if (EverParseIsError(positionAfterr5PathHash))
  {
    return positionAfterr5PathHash;
  }
  uint32_t r5PathHash = Load32Le(Input + (uint32_t)positionAfterr4MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes16 = 1ULL <= (InputLength - positionAfterr5PathHash);
  uint64_t positionAfterPartAccess815;
  if (hasBytes16)
  {
    positionAfterPartAccess815 = positionAfterr5PathHash + 1ULL;
  }
  else
  {
    positionAfterPartAccess815 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5PathHash);
  }
  uint64_t positionAfterr5Method;
  if (EverParseIsSuccess(positionAfterPartAccess815))
  {
    positionAfterr5Method = positionAfterPartAccess815;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r5_method",
      EverParseErrorReasonOfResult(positionAfterPartAccess815),
      EverParseGetValidatorErrorKind(positionAfterPartAccess815),
      Ctxt,
      Input,
      positionAfterr5PathHash);
    positionAfterr5Method = positionAfterPartAccess815;
  }
  if (EverParseIsError(positionAfterr5Method))
  {
    return positionAfterr5Method;
  }
  uint8_t r5Method = Input[(uint32_t)positionAfterr5PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes17 = 1ULL <= (InputLength - positionAfterr5Method);
  uint64_t positionAfterPartAccess816;
  if (hasBytes17)
  {
    positionAfterPartAccess816 = positionAfterr5Method + 1ULL;
  }
  else
  {
    positionAfterPartAccess816 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5Method);
  }
  uint64_t positionAfterr5MinRole;
  if (EverParseIsSuccess(positionAfterPartAccess816))
  {
    positionAfterr5MinRole = positionAfterPartAccess816;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r5_min_role",
      EverParseErrorReasonOfResult(positionAfterPartAccess816),
      EverParseGetValidatorErrorKind(positionAfterPartAccess816),
      Ctxt,
      Input,
      positionAfterr5Method);
    positionAfterr5MinRole = positionAfterPartAccess816;
  }
  if (EverParseIsError(positionAfterr5MinRole))
  {
    return positionAfterr5MinRole;
  }
  uint8_t r5MinRole = Input[(uint32_t)positionAfterr5Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes18 = 4ULL <= (InputLength - positionAfterr5MinRole);
  uint64_t positionAfterPartAccess817;
  if (hasBytes18)
  {
    positionAfterPartAccess817 = positionAfterr5MinRole + 4ULL;
  }
  else
  {
    positionAfterPartAccess817 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5MinRole);
  }
  uint64_t positionAfterr6PathHash;
  if (EverParseIsSuccess(positionAfterPartAccess817))
  {
    positionAfterr6PathHash = positionAfterPartAccess817;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r6_path_hash",
      EverParseErrorReasonOfResult(positionAfterPartAccess817),
      EverParseGetValidatorErrorKind(positionAfterPartAccess817),
      Ctxt,
      Input,
      positionAfterr5MinRole);
    positionAfterr6PathHash = positionAfterPartAccess817;
  }
  if (EverParseIsError(positionAfterr6PathHash))
  {
    return positionAfterr6PathHash;
  }
  uint32_t r6PathHash = Load32Le(Input + (uint32_t)positionAfterr5MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes19 = 1ULL <= (InputLength - positionAfterr6PathHash);
  uint64_t positionAfterPartAccess818;
  if (hasBytes19)
  {
    positionAfterPartAccess818 = positionAfterr6PathHash + 1ULL;
  }
  else
  {
    positionAfterPartAccess818 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6PathHash);
  }
  uint64_t positionAfterr6Method;
  if (EverParseIsSuccess(positionAfterPartAccess818))
  {
    positionAfterr6Method = positionAfterPartAccess818;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r6_method",
      EverParseErrorReasonOfResult(positionAfterPartAccess818),
      EverParseGetValidatorErrorKind(positionAfterPartAccess818),
      Ctxt,
      Input,
      positionAfterr6PathHash);
    positionAfterr6Method = positionAfterPartAccess818;
  }
  if (EverParseIsError(positionAfterr6Method))
  {
    return positionAfterr6Method;
  }
  uint8_t r6Method = Input[(uint32_t)positionAfterr6PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes20 = 1ULL <= (InputLength - positionAfterr6Method);
  uint64_t positionAfterPartAccess819;
  if (hasBytes20)
  {
    positionAfterPartAccess819 = positionAfterr6Method + 1ULL;
  }
  else
  {
    positionAfterPartAccess819 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6Method);
  }
  uint64_t positionAfterr6MinRole;
  if (EverParseIsSuccess(positionAfterPartAccess819))
  {
    positionAfterr6MinRole = positionAfterPartAccess819;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r6_min_role",
      EverParseErrorReasonOfResult(positionAfterPartAccess819),
      EverParseGetValidatorErrorKind(positionAfterPartAccess819),
      Ctxt,
      Input,
      positionAfterr6Method);
    positionAfterr6MinRole = positionAfterPartAccess819;
  }
  if (EverParseIsError(positionAfterr6MinRole))
  {
    return positionAfterr6MinRole;
  }
  uint8_t r6MinRole = Input[(uint32_t)positionAfterr6Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes21 = 4ULL <= (InputLength - positionAfterr6MinRole);
  uint64_t positionAfterPartAccess820;
  if (hasBytes21)
  {
    positionAfterPartAccess820 = positionAfterr6MinRole + 4ULL;
  }
  else
  {
    positionAfterPartAccess820 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6MinRole);
  }
  uint64_t positionAfterr7PathHash;
  if (EverParseIsSuccess(positionAfterPartAccess820))
  {
    positionAfterr7PathHash = positionAfterPartAccess820;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r7_path_hash",
      EverParseErrorReasonOfResult(positionAfterPartAccess820),
      EverParseGetValidatorErrorKind(positionAfterPartAccess820),
      Ctxt,
      Input,
      positionAfterr6MinRole);
    positionAfterr7PathHash = positionAfterPartAccess820;
  }
  if (EverParseIsError(positionAfterr7PathHash))
  {
    return positionAfterr7PathHash;
  }
  uint32_t r7PathHash = Load32Le(Input + (uint32_t)positionAfterr6MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes22 = 1ULL <= (InputLength - positionAfterr7PathHash);
  uint64_t positionAfterPartAccess821;
  if (hasBytes22)
  {
    positionAfterPartAccess821 = positionAfterr7PathHash + 1ULL;
  }
  else
  {
    positionAfterPartAccess821 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7PathHash);
  }
  uint64_t positionAfterr7Method;
  if (EverParseIsSuccess(positionAfterPartAccess821))
  {
    positionAfterr7Method = positionAfterPartAccess821;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r7_method",
      EverParseErrorReasonOfResult(positionAfterPartAccess821),
      EverParseGetValidatorErrorKind(positionAfterPartAccess821),
      Ctxt,
      Input,
      positionAfterr7PathHash);
    positionAfterr7Method = positionAfterPartAccess821;
  }
  if (EverParseIsError(positionAfterr7Method))
  {
    return positionAfterr7Method;
  }
  uint8_t r7Method = Input[(uint32_t)positionAfterr7PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes23 = 1ULL <= (InputLength - positionAfterr7Method);
  uint64_t positionAfterPartAccess822;
  if (hasBytes23)
  {
    positionAfterPartAccess822 = positionAfterr7Method + 1ULL;
  }
  else
  {
    positionAfterPartAccess822 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7Method);
  }
  uint64_t positionAfterr7MinRole;
  if (EverParseIsSuccess(positionAfterPartAccess822))
  {
    positionAfterr7MinRole = positionAfterPartAccess822;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "r7_min_role",
      EverParseErrorReasonOfResult(positionAfterPartAccess822),
      EverParseGetValidatorErrorKind(positionAfterPartAccess822),
      Ctxt,
      Input,
      positionAfterr7Method);
    positionAfterr7MinRole = positionAfterPartAccess822;
  }
  if (EverParseIsError(positionAfterr7MinRole))
  {
    return positionAfterr7MinRole;
  }
  uint8_t r7MinRole = Input[(uint32_t)positionAfterr7Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes24 = 4ULL <= (InputLength - positionAfterr7MinRole);
  uint64_t positionAfterPartAccess823;
  if (hasBytes24)
  {
    positionAfterPartAccess823 = positionAfterr7MinRole + 4ULL;
  }
  else
  {
    positionAfterPartAccess823 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7MinRole);
  }
  uint64_t positionAfterreqPathHash;
  if (EverParseIsSuccess(positionAfterPartAccess823))
  {
    positionAfterreqPathHash = positionAfterPartAccess823;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "req_path_hash",
      EverParseErrorReasonOfResult(positionAfterPartAccess823),
      EverParseGetValidatorErrorKind(positionAfterPartAccess823),
      Ctxt,
      Input,
      positionAfterr7MinRole);
    positionAfterreqPathHash = positionAfterPartAccess823;
  }
  if (EverParseIsError(positionAfterreqPathHash))
  {
    return positionAfterreqPathHash;
  }
  uint32_t reqPathHash = Load32Le(Input + (uint32_t)positionAfterr7MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes25 = 1ULL <= (InputLength - positionAfterreqPathHash);
  uint64_t positionAfterPartAccess824;
  if (hasBytes25)
  {
    positionAfterPartAccess824 = positionAfterreqPathHash + 1ULL;
  }
  else
  {
    positionAfterPartAccess824 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqPathHash);
  }
  uint64_t positionAfterreqMethod;
  if (EverParseIsSuccess(positionAfterPartAccess824))
  {
    positionAfterreqMethod = positionAfterPartAccess824;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "req_method",
      EverParseErrorReasonOfResult(positionAfterPartAccess824),
      EverParseGetValidatorErrorKind(positionAfterPartAccess824),
      Ctxt,
      Input,
      positionAfterreqPathHash);
    positionAfterreqMethod = positionAfterPartAccess824;
  }
  if (EverParseIsError(positionAfterreqMethod))
  {
    return positionAfterreqMethod;
  }
  uint8_t reqMethod = Input[(uint32_t)positionAfterreqPathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes26 = 1ULL <= (InputLength - positionAfterreqMethod);
  uint64_t positionAfterPartAccess825;
  if (hasBytes26)
  {
    positionAfterPartAccess825 = positionAfterreqMethod + 1ULL;
  }
  else
  {
    positionAfterPartAccess825 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqMethod);
  }
  uint64_t positionAfterauthState;
  if (EverParseIsSuccess(positionAfterPartAccess825))
  {
    positionAfterauthState = positionAfterPartAccess825;
  }
  else
  {
    ErrorHandlerFn("_PartAccess8",
      "auth_state",
      EverParseErrorReasonOfResult(positionAfterPartAccess825),
      EverParseGetValidatorErrorKind(positionAfterPartAccess825),
      Ctxt,
      Input,
      positionAfterreqMethod);
    positionAfterauthState = positionAfterPartAccess825;
  }
  if (EverParseIsError(positionAfterauthState))
  {
    return positionAfterauthState;
  }
  uint8_t authState = Input[(uint32_t)positionAfterreqMethod];
  /* Validating field _access_ok */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes = 1ULL <= (InputLength - positionAfterauthState);
  uint64_t positionAfterAccessOk_refinement;
  if (hasBytes)
  {
    positionAfterAccessOk_refinement = positionAfterauthState + 1ULL;
  }
  else
  {
    positionAfterAccessOk_refinement =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterauthState);
  }
  uint64_t positionAfterPartAccess826;
  if (EverParseIsError(positionAfterAccessOk_refinement))
  {
    positionAfterPartAccess826 = positionAfterAccessOk_refinement;
  }
  else
  {
    /* reading field_value */
    uint8_t accessOk_refinement = Input[(uint32_t)positionAfterauthState];
    KRML_MAYBE_UNUSED_VAR(accessOk_refinement);
    /* start: checking constraint */
    BOOLEAN
    accessOk_refinementConstraintIsOk =
      (r0PathHash == reqPathHash && r0Method == reqMethod && authState >= r0MinRole) ||
        (r1PathHash == reqPathHash && r1Method == reqMethod && authState >= r1MinRole)
      || (r2PathHash == reqPathHash && r2Method == reqMethod && authState >= r2MinRole)
      || (r3PathHash == reqPathHash && r3Method == reqMethod && authState >= r3MinRole)
      || (r4PathHash == reqPathHash && r4Method == reqMethod && authState >= r4MinRole)
      || (r5PathHash == reqPathHash && r5Method == reqMethod && authState >= r5MinRole)
      || (r6PathHash == reqPathHash && r6Method == reqMethod && authState >= r6MinRole)
      || (r7PathHash == reqPathHash && r7Method == reqMethod && authState >= r7MinRole);
    /* end: checking constraint */
    positionAfterPartAccess826 =
      EverParseCheckConstraintOk(accessOk_refinementConstraintIsOk,
        positionAfterAccessOk_refinement);
  }
  if (EverParseIsSuccess(positionAfterPartAccess826))
  {
    return positionAfterPartAccess826;
  }
  ErrorHandlerFn("_PartAccess8",
    "_access_ok.refinement",
    EverParseErrorReasonOfResult(positionAfterPartAccess826),
    EverParseGetValidatorErrorKind(positionAfterPartAccess826),
    Ctxt,
    Input,
    positionAfterauthState);
  return positionAfterPartAccess826;
}

