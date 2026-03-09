

#include "ScaleTest8.h"

uint64_t
ScaleTest8ValidateScaleTest8(
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
  uint64_t positionAfterScaleTest8;
  if (hasBytes0)
  {
    positionAfterScaleTest8 = StartPosition + 4ULL;
  }
  else
  {
    positionAfterScaleTest8 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterr0PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest8))
  {
    positionAfterr0PathHash = positionAfterScaleTest8;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r0_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest8),
      EverParseGetValidatorErrorKind(positionAfterScaleTest8),
      Ctxt,
      Input,
      StartPosition);
    positionAfterr0PathHash = positionAfterScaleTest8;
  }
  if (EverParseIsError(positionAfterr0PathHash))
  {
    return positionAfterr0PathHash;
  }
  uint32_t r0PathHash = Load32Le(Input + (uint32_t)StartPosition);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAfterr0PathHash);
  uint64_t positionAfterScaleTest80;
  if (hasBytes1)
  {
    positionAfterScaleTest80 = positionAfterr0PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest80 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0PathHash);
  }
  uint64_t positionAfterr0Method;
  if (EverParseIsSuccess(positionAfterScaleTest80))
  {
    positionAfterr0Method = positionAfterScaleTest80;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r0_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest80),
      EverParseGetValidatorErrorKind(positionAfterScaleTest80),
      Ctxt,
      Input,
      positionAfterr0PathHash);
    positionAfterr0Method = positionAfterScaleTest80;
  }
  if (EverParseIsError(positionAfterr0Method))
  {
    return positionAfterr0Method;
  }
  uint8_t r0Method = Input[(uint32_t)positionAfterr0PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes2 = 1ULL <= (InputLength - positionAfterr0Method);
  uint64_t positionAfterScaleTest81;
  if (hasBytes2)
  {
    positionAfterScaleTest81 = positionAfterr0Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest81 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0Method);
  }
  uint64_t positionAfterr0MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest81))
  {
    positionAfterr0MinRole = positionAfterScaleTest81;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r0_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest81),
      EverParseGetValidatorErrorKind(positionAfterScaleTest81),
      Ctxt,
      Input,
      positionAfterr0Method);
    positionAfterr0MinRole = positionAfterScaleTest81;
  }
  if (EverParseIsError(positionAfterr0MinRole))
  {
    return positionAfterr0MinRole;
  }
  uint8_t r0MinRole = Input[(uint32_t)positionAfterr0Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes3 = 4ULL <= (InputLength - positionAfterr0MinRole);
  uint64_t positionAfterScaleTest82;
  if (hasBytes3)
  {
    positionAfterScaleTest82 = positionAfterr0MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest82 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0MinRole);
  }
  uint64_t positionAfterr1PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest82))
  {
    positionAfterr1PathHash = positionAfterScaleTest82;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r1_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest82),
      EverParseGetValidatorErrorKind(positionAfterScaleTest82),
      Ctxt,
      Input,
      positionAfterr0MinRole);
    positionAfterr1PathHash = positionAfterScaleTest82;
  }
  if (EverParseIsError(positionAfterr1PathHash))
  {
    return positionAfterr1PathHash;
  }
  uint32_t r1PathHash = Load32Le(Input + (uint32_t)positionAfterr0MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAfterr1PathHash);
  uint64_t positionAfterScaleTest83;
  if (hasBytes4)
  {
    positionAfterScaleTest83 = positionAfterr1PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest83 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1PathHash);
  }
  uint64_t positionAfterr1Method;
  if (EverParseIsSuccess(positionAfterScaleTest83))
  {
    positionAfterr1Method = positionAfterScaleTest83;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r1_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest83),
      EverParseGetValidatorErrorKind(positionAfterScaleTest83),
      Ctxt,
      Input,
      positionAfterr1PathHash);
    positionAfterr1Method = positionAfterScaleTest83;
  }
  if (EverParseIsError(positionAfterr1Method))
  {
    return positionAfterr1Method;
  }
  uint8_t r1Method = Input[(uint32_t)positionAfterr1PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes5 = 1ULL <= (InputLength - positionAfterr1Method);
  uint64_t positionAfterScaleTest84;
  if (hasBytes5)
  {
    positionAfterScaleTest84 = positionAfterr1Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest84 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1Method);
  }
  uint64_t positionAfterr1MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest84))
  {
    positionAfterr1MinRole = positionAfterScaleTest84;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r1_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest84),
      EverParseGetValidatorErrorKind(positionAfterScaleTest84),
      Ctxt,
      Input,
      positionAfterr1Method);
    positionAfterr1MinRole = positionAfterScaleTest84;
  }
  if (EverParseIsError(positionAfterr1MinRole))
  {
    return positionAfterr1MinRole;
  }
  uint8_t r1MinRole = Input[(uint32_t)positionAfterr1Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes6 = 4ULL <= (InputLength - positionAfterr1MinRole);
  uint64_t positionAfterScaleTest85;
  if (hasBytes6)
  {
    positionAfterScaleTest85 = positionAfterr1MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest85 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1MinRole);
  }
  uint64_t positionAfterr2PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest85))
  {
    positionAfterr2PathHash = positionAfterScaleTest85;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r2_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest85),
      EverParseGetValidatorErrorKind(positionAfterScaleTest85),
      Ctxt,
      Input,
      positionAfterr1MinRole);
    positionAfterr2PathHash = positionAfterScaleTest85;
  }
  if (EverParseIsError(positionAfterr2PathHash))
  {
    return positionAfterr2PathHash;
  }
  uint32_t r2PathHash = Load32Le(Input + (uint32_t)positionAfterr1MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes7 = 1ULL <= (InputLength - positionAfterr2PathHash);
  uint64_t positionAfterScaleTest86;
  if (hasBytes7)
  {
    positionAfterScaleTest86 = positionAfterr2PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest86 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2PathHash);
  }
  uint64_t positionAfterr2Method;
  if (EverParseIsSuccess(positionAfterScaleTest86))
  {
    positionAfterr2Method = positionAfterScaleTest86;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r2_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest86),
      EverParseGetValidatorErrorKind(positionAfterScaleTest86),
      Ctxt,
      Input,
      positionAfterr2PathHash);
    positionAfterr2Method = positionAfterScaleTest86;
  }
  if (EverParseIsError(positionAfterr2Method))
  {
    return positionAfterr2Method;
  }
  uint8_t r2Method = Input[(uint32_t)positionAfterr2PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes8 = 1ULL <= (InputLength - positionAfterr2Method);
  uint64_t positionAfterScaleTest87;
  if (hasBytes8)
  {
    positionAfterScaleTest87 = positionAfterr2Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest87 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2Method);
  }
  uint64_t positionAfterr2MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest87))
  {
    positionAfterr2MinRole = positionAfterScaleTest87;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r2_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest87),
      EverParseGetValidatorErrorKind(positionAfterScaleTest87),
      Ctxt,
      Input,
      positionAfterr2Method);
    positionAfterr2MinRole = positionAfterScaleTest87;
  }
  if (EverParseIsError(positionAfterr2MinRole))
  {
    return positionAfterr2MinRole;
  }
  uint8_t r2MinRole = Input[(uint32_t)positionAfterr2Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes9 = 4ULL <= (InputLength - positionAfterr2MinRole);
  uint64_t positionAfterScaleTest88;
  if (hasBytes9)
  {
    positionAfterScaleTest88 = positionAfterr2MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest88 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2MinRole);
  }
  uint64_t positionAfterr3PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest88))
  {
    positionAfterr3PathHash = positionAfterScaleTest88;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r3_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest88),
      EverParseGetValidatorErrorKind(positionAfterScaleTest88),
      Ctxt,
      Input,
      positionAfterr2MinRole);
    positionAfterr3PathHash = positionAfterScaleTest88;
  }
  if (EverParseIsError(positionAfterr3PathHash))
  {
    return positionAfterr3PathHash;
  }
  uint32_t r3PathHash = Load32Le(Input + (uint32_t)positionAfterr2MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes10 = 1ULL <= (InputLength - positionAfterr3PathHash);
  uint64_t positionAfterScaleTest89;
  if (hasBytes10)
  {
    positionAfterScaleTest89 = positionAfterr3PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest89 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3PathHash);
  }
  uint64_t positionAfterr3Method;
  if (EverParseIsSuccess(positionAfterScaleTest89))
  {
    positionAfterr3Method = positionAfterScaleTest89;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r3_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest89),
      EverParseGetValidatorErrorKind(positionAfterScaleTest89),
      Ctxt,
      Input,
      positionAfterr3PathHash);
    positionAfterr3Method = positionAfterScaleTest89;
  }
  if (EverParseIsError(positionAfterr3Method))
  {
    return positionAfterr3Method;
  }
  uint8_t r3Method = Input[(uint32_t)positionAfterr3PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes11 = 1ULL <= (InputLength - positionAfterr3Method);
  uint64_t positionAfterScaleTest810;
  if (hasBytes11)
  {
    positionAfterScaleTest810 = positionAfterr3Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest810 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3Method);
  }
  uint64_t positionAfterr3MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest810))
  {
    positionAfterr3MinRole = positionAfterScaleTest810;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r3_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest810),
      EverParseGetValidatorErrorKind(positionAfterScaleTest810),
      Ctxt,
      Input,
      positionAfterr3Method);
    positionAfterr3MinRole = positionAfterScaleTest810;
  }
  if (EverParseIsError(positionAfterr3MinRole))
  {
    return positionAfterr3MinRole;
  }
  uint8_t r3MinRole = Input[(uint32_t)positionAfterr3Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes12 = 4ULL <= (InputLength - positionAfterr3MinRole);
  uint64_t positionAfterScaleTest811;
  if (hasBytes12)
  {
    positionAfterScaleTest811 = positionAfterr3MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest811 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3MinRole);
  }
  uint64_t positionAfterr4PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest811))
  {
    positionAfterr4PathHash = positionAfterScaleTest811;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r4_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest811),
      EverParseGetValidatorErrorKind(positionAfterScaleTest811),
      Ctxt,
      Input,
      positionAfterr3MinRole);
    positionAfterr4PathHash = positionAfterScaleTest811;
  }
  if (EverParseIsError(positionAfterr4PathHash))
  {
    return positionAfterr4PathHash;
  }
  uint32_t r4PathHash = Load32Le(Input + (uint32_t)positionAfterr3MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes13 = 1ULL <= (InputLength - positionAfterr4PathHash);
  uint64_t positionAfterScaleTest812;
  if (hasBytes13)
  {
    positionAfterScaleTest812 = positionAfterr4PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest812 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4PathHash);
  }
  uint64_t positionAfterr4Method;
  if (EverParseIsSuccess(positionAfterScaleTest812))
  {
    positionAfterr4Method = positionAfterScaleTest812;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r4_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest812),
      EverParseGetValidatorErrorKind(positionAfterScaleTest812),
      Ctxt,
      Input,
      positionAfterr4PathHash);
    positionAfterr4Method = positionAfterScaleTest812;
  }
  if (EverParseIsError(positionAfterr4Method))
  {
    return positionAfterr4Method;
  }
  uint8_t r4Method = Input[(uint32_t)positionAfterr4PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes14 = 1ULL <= (InputLength - positionAfterr4Method);
  uint64_t positionAfterScaleTest813;
  if (hasBytes14)
  {
    positionAfterScaleTest813 = positionAfterr4Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest813 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4Method);
  }
  uint64_t positionAfterr4MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest813))
  {
    positionAfterr4MinRole = positionAfterScaleTest813;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r4_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest813),
      EverParseGetValidatorErrorKind(positionAfterScaleTest813),
      Ctxt,
      Input,
      positionAfterr4Method);
    positionAfterr4MinRole = positionAfterScaleTest813;
  }
  if (EverParseIsError(positionAfterr4MinRole))
  {
    return positionAfterr4MinRole;
  }
  uint8_t r4MinRole = Input[(uint32_t)positionAfterr4Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes15 = 4ULL <= (InputLength - positionAfterr4MinRole);
  uint64_t positionAfterScaleTest814;
  if (hasBytes15)
  {
    positionAfterScaleTest814 = positionAfterr4MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest814 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4MinRole);
  }
  uint64_t positionAfterr5PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest814))
  {
    positionAfterr5PathHash = positionAfterScaleTest814;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r5_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest814),
      EverParseGetValidatorErrorKind(positionAfterScaleTest814),
      Ctxt,
      Input,
      positionAfterr4MinRole);
    positionAfterr5PathHash = positionAfterScaleTest814;
  }
  if (EverParseIsError(positionAfterr5PathHash))
  {
    return positionAfterr5PathHash;
  }
  uint32_t r5PathHash = Load32Le(Input + (uint32_t)positionAfterr4MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes16 = 1ULL <= (InputLength - positionAfterr5PathHash);
  uint64_t positionAfterScaleTest815;
  if (hasBytes16)
  {
    positionAfterScaleTest815 = positionAfterr5PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest815 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5PathHash);
  }
  uint64_t positionAfterr5Method;
  if (EverParseIsSuccess(positionAfterScaleTest815))
  {
    positionAfterr5Method = positionAfterScaleTest815;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r5_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest815),
      EverParseGetValidatorErrorKind(positionAfterScaleTest815),
      Ctxt,
      Input,
      positionAfterr5PathHash);
    positionAfterr5Method = positionAfterScaleTest815;
  }
  if (EverParseIsError(positionAfterr5Method))
  {
    return positionAfterr5Method;
  }
  uint8_t r5Method = Input[(uint32_t)positionAfterr5PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes17 = 1ULL <= (InputLength - positionAfterr5Method);
  uint64_t positionAfterScaleTest816;
  if (hasBytes17)
  {
    positionAfterScaleTest816 = positionAfterr5Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest816 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5Method);
  }
  uint64_t positionAfterr5MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest816))
  {
    positionAfterr5MinRole = positionAfterScaleTest816;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r5_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest816),
      EverParseGetValidatorErrorKind(positionAfterScaleTest816),
      Ctxt,
      Input,
      positionAfterr5Method);
    positionAfterr5MinRole = positionAfterScaleTest816;
  }
  if (EverParseIsError(positionAfterr5MinRole))
  {
    return positionAfterr5MinRole;
  }
  uint8_t r5MinRole = Input[(uint32_t)positionAfterr5Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes18 = 4ULL <= (InputLength - positionAfterr5MinRole);
  uint64_t positionAfterScaleTest817;
  if (hasBytes18)
  {
    positionAfterScaleTest817 = positionAfterr5MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest817 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5MinRole);
  }
  uint64_t positionAfterr6PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest817))
  {
    positionAfterr6PathHash = positionAfterScaleTest817;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r6_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest817),
      EverParseGetValidatorErrorKind(positionAfterScaleTest817),
      Ctxt,
      Input,
      positionAfterr5MinRole);
    positionAfterr6PathHash = positionAfterScaleTest817;
  }
  if (EverParseIsError(positionAfterr6PathHash))
  {
    return positionAfterr6PathHash;
  }
  uint32_t r6PathHash = Load32Le(Input + (uint32_t)positionAfterr5MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes19 = 1ULL <= (InputLength - positionAfterr6PathHash);
  uint64_t positionAfterScaleTest818;
  if (hasBytes19)
  {
    positionAfterScaleTest818 = positionAfterr6PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest818 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6PathHash);
  }
  uint64_t positionAfterr6Method;
  if (EverParseIsSuccess(positionAfterScaleTest818))
  {
    positionAfterr6Method = positionAfterScaleTest818;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r6_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest818),
      EverParseGetValidatorErrorKind(positionAfterScaleTest818),
      Ctxt,
      Input,
      positionAfterr6PathHash);
    positionAfterr6Method = positionAfterScaleTest818;
  }
  if (EverParseIsError(positionAfterr6Method))
  {
    return positionAfterr6Method;
  }
  uint8_t r6Method = Input[(uint32_t)positionAfterr6PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes20 = 1ULL <= (InputLength - positionAfterr6Method);
  uint64_t positionAfterScaleTest819;
  if (hasBytes20)
  {
    positionAfterScaleTest819 = positionAfterr6Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest819 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6Method);
  }
  uint64_t positionAfterr6MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest819))
  {
    positionAfterr6MinRole = positionAfterScaleTest819;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r6_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest819),
      EverParseGetValidatorErrorKind(positionAfterScaleTest819),
      Ctxt,
      Input,
      positionAfterr6Method);
    positionAfterr6MinRole = positionAfterScaleTest819;
  }
  if (EverParseIsError(positionAfterr6MinRole))
  {
    return positionAfterr6MinRole;
  }
  uint8_t r6MinRole = Input[(uint32_t)positionAfterr6Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes21 = 4ULL <= (InputLength - positionAfterr6MinRole);
  uint64_t positionAfterScaleTest820;
  if (hasBytes21)
  {
    positionAfterScaleTest820 = positionAfterr6MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest820 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6MinRole);
  }
  uint64_t positionAfterr7PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest820))
  {
    positionAfterr7PathHash = positionAfterScaleTest820;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r7_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest820),
      EverParseGetValidatorErrorKind(positionAfterScaleTest820),
      Ctxt,
      Input,
      positionAfterr6MinRole);
    positionAfterr7PathHash = positionAfterScaleTest820;
  }
  if (EverParseIsError(positionAfterr7PathHash))
  {
    return positionAfterr7PathHash;
  }
  uint32_t r7PathHash = Load32Le(Input + (uint32_t)positionAfterr6MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes22 = 1ULL <= (InputLength - positionAfterr7PathHash);
  uint64_t positionAfterScaleTest821;
  if (hasBytes22)
  {
    positionAfterScaleTest821 = positionAfterr7PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest821 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7PathHash);
  }
  uint64_t positionAfterr7Method;
  if (EverParseIsSuccess(positionAfterScaleTest821))
  {
    positionAfterr7Method = positionAfterScaleTest821;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r7_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest821),
      EverParseGetValidatorErrorKind(positionAfterScaleTest821),
      Ctxt,
      Input,
      positionAfterr7PathHash);
    positionAfterr7Method = positionAfterScaleTest821;
  }
  if (EverParseIsError(positionAfterr7Method))
  {
    return positionAfterr7Method;
  }
  uint8_t r7Method = Input[(uint32_t)positionAfterr7PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes23 = 1ULL <= (InputLength - positionAfterr7Method);
  uint64_t positionAfterScaleTest822;
  if (hasBytes23)
  {
    positionAfterScaleTest822 = positionAfterr7Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest822 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7Method);
  }
  uint64_t positionAfterr7MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest822))
  {
    positionAfterr7MinRole = positionAfterScaleTest822;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "r7_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest822),
      EverParseGetValidatorErrorKind(positionAfterScaleTest822),
      Ctxt,
      Input,
      positionAfterr7Method);
    positionAfterr7MinRole = positionAfterScaleTest822;
  }
  if (EverParseIsError(positionAfterr7MinRole))
  {
    return positionAfterr7MinRole;
  }
  uint8_t r7MinRole = Input[(uint32_t)positionAfterr7Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes24 = 4ULL <= (InputLength - positionAfterr7MinRole);
  uint64_t positionAfterScaleTest823;
  if (hasBytes24)
  {
    positionAfterScaleTest823 = positionAfterr7MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest823 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7MinRole);
  }
  uint64_t positionAfterreqPathHash;
  if (EverParseIsSuccess(positionAfterScaleTest823))
  {
    positionAfterreqPathHash = positionAfterScaleTest823;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "req_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest823),
      EverParseGetValidatorErrorKind(positionAfterScaleTest823),
      Ctxt,
      Input,
      positionAfterr7MinRole);
    positionAfterreqPathHash = positionAfterScaleTest823;
  }
  if (EverParseIsError(positionAfterreqPathHash))
  {
    return positionAfterreqPathHash;
  }
  uint32_t reqPathHash = Load32Le(Input + (uint32_t)positionAfterr7MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes25 = 1ULL <= (InputLength - positionAfterreqPathHash);
  uint64_t positionAfterScaleTest824;
  if (hasBytes25)
  {
    positionAfterScaleTest824 = positionAfterreqPathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest824 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqPathHash);
  }
  uint64_t positionAfterreqMethod;
  if (EverParseIsSuccess(positionAfterScaleTest824))
  {
    positionAfterreqMethod = positionAfterScaleTest824;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "req_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest824),
      EverParseGetValidatorErrorKind(positionAfterScaleTest824),
      Ctxt,
      Input,
      positionAfterreqPathHash);
    positionAfterreqMethod = positionAfterScaleTest824;
  }
  if (EverParseIsError(positionAfterreqMethod))
  {
    return positionAfterreqMethod;
  }
  uint8_t reqMethod = Input[(uint32_t)positionAfterreqPathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes26 = 1ULL <= (InputLength - positionAfterreqMethod);
  uint64_t positionAfterScaleTest825;
  if (hasBytes26)
  {
    positionAfterScaleTest825 = positionAfterreqMethod + 1ULL;
  }
  else
  {
    positionAfterScaleTest825 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqMethod);
  }
  uint64_t positionAfterauthState;
  if (EverParseIsSuccess(positionAfterScaleTest825))
  {
    positionAfterauthState = positionAfterScaleTest825;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "auth_state",
      EverParseErrorReasonOfResult(positionAfterScaleTest825),
      EverParseGetValidatorErrorKind(positionAfterScaleTest825),
      Ctxt,
      Input,
      positionAfterreqMethod);
    positionAfterauthState = positionAfterScaleTest825;
  }
  if (EverParseIsError(positionAfterauthState))
  {
    return positionAfterauthState;
  }
  uint8_t authState = Input[(uint32_t)positionAfterreqMethod];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes27 = 1ULL <= (InputLength - positionAfterauthState);
  uint64_t positionAfterScaleTest826;
  if (hasBytes27)
  {
    positionAfterScaleTest826 = positionAfterauthState + 1ULL;
  }
  else
  {
    positionAfterScaleTest826 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterauthState);
  }
  uint64_t positionAfterrateCount;
  if (EverParseIsSuccess(positionAfterScaleTest826))
  {
    positionAfterrateCount = positionAfterScaleTest826;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest8",
      "rate_count",
      EverParseErrorReasonOfResult(positionAfterScaleTest826),
      EverParseGetValidatorErrorKind(positionAfterScaleTest826),
      Ctxt,
      Input,
      positionAfterauthState);
    positionAfterrateCount = positionAfterScaleTest826;
  }
  if (EverParseIsError(positionAfterrateCount))
  {
    return positionAfterrateCount;
  }
  uint8_t rateCount = Input[(uint32_t)positionAfterauthState];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes28 = 1ULL <= (InputLength - positionAfterrateCount);
  uint64_t positionAfterRateOk;
  if (hasBytes28)
  {
    positionAfterRateOk = positionAfterrateCount + 1ULL;
  }
  else
  {
    positionAfterRateOk =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrateCount);
  }
  uint64_t positionAfterScaleTest827;
  if (EverParseIsError(positionAfterRateOk))
  {
    positionAfterScaleTest827 = positionAfterRateOk;
  }
  else
  {
    uint8_t rateOk = Input[(uint32_t)positionAfterrateCount];
    KRML_MAYBE_UNUSED_VAR(rateOk);
    BOOLEAN rateOkConstraintIsOk = rateCount < SCALETEST8____MAX_RATE;
    uint64_t
    positionAfterRateOk1 = EverParseCheckConstraintOk(rateOkConstraintIsOk, positionAfterRateOk);
    if (EverParseIsError(positionAfterRateOk1))
    {
      positionAfterScaleTest827 = positionAfterRateOk1;
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
      uint64_t positionAfterScaleTest828;
      if (EverParseIsError(positionAfterAccessOk_refinement))
      {
        positionAfterScaleTest828 = positionAfterAccessOk_refinement;
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
          || (r3PathHash == reqPathHash && r3Method == reqMethod && authState >= r3MinRole)
          || (r4PathHash == reqPathHash && r4Method == reqMethod && authState >= r4MinRole)
          || (r5PathHash == reqPathHash && r5Method == reqMethod && authState >= r5MinRole)
          || (r6PathHash == reqPathHash && r6Method == reqMethod && authState >= r6MinRole)
          || (r7PathHash == reqPathHash && r7Method == reqMethod && authState >= r7MinRole);
        /* end: checking constraint */
        positionAfterScaleTest828 =
          EverParseCheckConstraintOk(accessOk_refinementConstraintIsOk,
            positionAfterAccessOk_refinement);
      }
      if (EverParseIsSuccess(positionAfterScaleTest828))
      {
        positionAfterScaleTest827 = positionAfterScaleTest828;
      }
      else
      {
        ErrorHandlerFn("_ScaleTest8",
          "_access_ok.refinement",
          EverParseErrorReasonOfResult(positionAfterScaleTest828),
          EverParseGetValidatorErrorKind(positionAfterScaleTest828),
          Ctxt,
          Input,
          positionAfterRateOk1);
        positionAfterScaleTest827 = positionAfterScaleTest828;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterScaleTest827))
  {
    return positionAfterScaleTest827;
  }
  ErrorHandlerFn("_ScaleTest8",
    "_rate_ok",
    EverParseErrorReasonOfResult(positionAfterScaleTest827),
    EverParseGetValidatorErrorKind(positionAfterScaleTest827),
    Ctxt,
    Input,
    positionAfterrateCount);
  return positionAfterScaleTest827;
}

