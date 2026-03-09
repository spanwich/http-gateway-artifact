

#include "ScaleTest16.h"

uint64_t
ScaleTest16ValidateScaleTest16(
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
  uint64_t positionAfterScaleTest16;
  if (hasBytes0)
  {
    positionAfterScaleTest16 = StartPosition + 4ULL;
  }
  else
  {
    positionAfterScaleTest16 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterr0PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest16))
  {
    positionAfterr0PathHash = positionAfterScaleTest16;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r0_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest16),
      EverParseGetValidatorErrorKind(positionAfterScaleTest16),
      Ctxt,
      Input,
      StartPosition);
    positionAfterr0PathHash = positionAfterScaleTest16;
  }
  if (EverParseIsError(positionAfterr0PathHash))
  {
    return positionAfterr0PathHash;
  }
  uint32_t r0PathHash = Load32Le(Input + (uint32_t)StartPosition);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAfterr0PathHash);
  uint64_t positionAfterScaleTest160;
  if (hasBytes1)
  {
    positionAfterScaleTest160 = positionAfterr0PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest160 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0PathHash);
  }
  uint64_t positionAfterr0Method;
  if (EverParseIsSuccess(positionAfterScaleTest160))
  {
    positionAfterr0Method = positionAfterScaleTest160;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r0_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest160),
      EverParseGetValidatorErrorKind(positionAfterScaleTest160),
      Ctxt,
      Input,
      positionAfterr0PathHash);
    positionAfterr0Method = positionAfterScaleTest160;
  }
  if (EverParseIsError(positionAfterr0Method))
  {
    return positionAfterr0Method;
  }
  uint8_t r0Method = Input[(uint32_t)positionAfterr0PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes2 = 1ULL <= (InputLength - positionAfterr0Method);
  uint64_t positionAfterScaleTest161;
  if (hasBytes2)
  {
    positionAfterScaleTest161 = positionAfterr0Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest161 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0Method);
  }
  uint64_t positionAfterr0MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest161))
  {
    positionAfterr0MinRole = positionAfterScaleTest161;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r0_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest161),
      EverParseGetValidatorErrorKind(positionAfterScaleTest161),
      Ctxt,
      Input,
      positionAfterr0Method);
    positionAfterr0MinRole = positionAfterScaleTest161;
  }
  if (EverParseIsError(positionAfterr0MinRole))
  {
    return positionAfterr0MinRole;
  }
  uint8_t r0MinRole = Input[(uint32_t)positionAfterr0Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes3 = 4ULL <= (InputLength - positionAfterr0MinRole);
  uint64_t positionAfterScaleTest162;
  if (hasBytes3)
  {
    positionAfterScaleTest162 = positionAfterr0MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest162 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0MinRole);
  }
  uint64_t positionAfterr1PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest162))
  {
    positionAfterr1PathHash = positionAfterScaleTest162;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r1_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest162),
      EverParseGetValidatorErrorKind(positionAfterScaleTest162),
      Ctxt,
      Input,
      positionAfterr0MinRole);
    positionAfterr1PathHash = positionAfterScaleTest162;
  }
  if (EverParseIsError(positionAfterr1PathHash))
  {
    return positionAfterr1PathHash;
  }
  uint32_t r1PathHash = Load32Le(Input + (uint32_t)positionAfterr0MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAfterr1PathHash);
  uint64_t positionAfterScaleTest163;
  if (hasBytes4)
  {
    positionAfterScaleTest163 = positionAfterr1PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest163 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1PathHash);
  }
  uint64_t positionAfterr1Method;
  if (EverParseIsSuccess(positionAfterScaleTest163))
  {
    positionAfterr1Method = positionAfterScaleTest163;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r1_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest163),
      EverParseGetValidatorErrorKind(positionAfterScaleTest163),
      Ctxt,
      Input,
      positionAfterr1PathHash);
    positionAfterr1Method = positionAfterScaleTest163;
  }
  if (EverParseIsError(positionAfterr1Method))
  {
    return positionAfterr1Method;
  }
  uint8_t r1Method = Input[(uint32_t)positionAfterr1PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes5 = 1ULL <= (InputLength - positionAfterr1Method);
  uint64_t positionAfterScaleTest164;
  if (hasBytes5)
  {
    positionAfterScaleTest164 = positionAfterr1Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest164 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1Method);
  }
  uint64_t positionAfterr1MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest164))
  {
    positionAfterr1MinRole = positionAfterScaleTest164;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r1_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest164),
      EverParseGetValidatorErrorKind(positionAfterScaleTest164),
      Ctxt,
      Input,
      positionAfterr1Method);
    positionAfterr1MinRole = positionAfterScaleTest164;
  }
  if (EverParseIsError(positionAfterr1MinRole))
  {
    return positionAfterr1MinRole;
  }
  uint8_t r1MinRole = Input[(uint32_t)positionAfterr1Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes6 = 4ULL <= (InputLength - positionAfterr1MinRole);
  uint64_t positionAfterScaleTest165;
  if (hasBytes6)
  {
    positionAfterScaleTest165 = positionAfterr1MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest165 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1MinRole);
  }
  uint64_t positionAfterr2PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest165))
  {
    positionAfterr2PathHash = positionAfterScaleTest165;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r2_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest165),
      EverParseGetValidatorErrorKind(positionAfterScaleTest165),
      Ctxt,
      Input,
      positionAfterr1MinRole);
    positionAfterr2PathHash = positionAfterScaleTest165;
  }
  if (EverParseIsError(positionAfterr2PathHash))
  {
    return positionAfterr2PathHash;
  }
  uint32_t r2PathHash = Load32Le(Input + (uint32_t)positionAfterr1MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes7 = 1ULL <= (InputLength - positionAfterr2PathHash);
  uint64_t positionAfterScaleTest166;
  if (hasBytes7)
  {
    positionAfterScaleTest166 = positionAfterr2PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest166 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2PathHash);
  }
  uint64_t positionAfterr2Method;
  if (EverParseIsSuccess(positionAfterScaleTest166))
  {
    positionAfterr2Method = positionAfterScaleTest166;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r2_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest166),
      EverParseGetValidatorErrorKind(positionAfterScaleTest166),
      Ctxt,
      Input,
      positionAfterr2PathHash);
    positionAfterr2Method = positionAfterScaleTest166;
  }
  if (EverParseIsError(positionAfterr2Method))
  {
    return positionAfterr2Method;
  }
  uint8_t r2Method = Input[(uint32_t)positionAfterr2PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes8 = 1ULL <= (InputLength - positionAfterr2Method);
  uint64_t positionAfterScaleTest167;
  if (hasBytes8)
  {
    positionAfterScaleTest167 = positionAfterr2Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest167 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2Method);
  }
  uint64_t positionAfterr2MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest167))
  {
    positionAfterr2MinRole = positionAfterScaleTest167;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r2_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest167),
      EverParseGetValidatorErrorKind(positionAfterScaleTest167),
      Ctxt,
      Input,
      positionAfterr2Method);
    positionAfterr2MinRole = positionAfterScaleTest167;
  }
  if (EverParseIsError(positionAfterr2MinRole))
  {
    return positionAfterr2MinRole;
  }
  uint8_t r2MinRole = Input[(uint32_t)positionAfterr2Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes9 = 4ULL <= (InputLength - positionAfterr2MinRole);
  uint64_t positionAfterScaleTest168;
  if (hasBytes9)
  {
    positionAfterScaleTest168 = positionAfterr2MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest168 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2MinRole);
  }
  uint64_t positionAfterr3PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest168))
  {
    positionAfterr3PathHash = positionAfterScaleTest168;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r3_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest168),
      EverParseGetValidatorErrorKind(positionAfterScaleTest168),
      Ctxt,
      Input,
      positionAfterr2MinRole);
    positionAfterr3PathHash = positionAfterScaleTest168;
  }
  if (EverParseIsError(positionAfterr3PathHash))
  {
    return positionAfterr3PathHash;
  }
  uint32_t r3PathHash = Load32Le(Input + (uint32_t)positionAfterr2MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes10 = 1ULL <= (InputLength - positionAfterr3PathHash);
  uint64_t positionAfterScaleTest169;
  if (hasBytes10)
  {
    positionAfterScaleTest169 = positionAfterr3PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest169 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3PathHash);
  }
  uint64_t positionAfterr3Method;
  if (EverParseIsSuccess(positionAfterScaleTest169))
  {
    positionAfterr3Method = positionAfterScaleTest169;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r3_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest169),
      EverParseGetValidatorErrorKind(positionAfterScaleTest169),
      Ctxt,
      Input,
      positionAfterr3PathHash);
    positionAfterr3Method = positionAfterScaleTest169;
  }
  if (EverParseIsError(positionAfterr3Method))
  {
    return positionAfterr3Method;
  }
  uint8_t r3Method = Input[(uint32_t)positionAfterr3PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes11 = 1ULL <= (InputLength - positionAfterr3Method);
  uint64_t positionAfterScaleTest1610;
  if (hasBytes11)
  {
    positionAfterScaleTest1610 = positionAfterr3Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest1610 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3Method);
  }
  uint64_t positionAfterr3MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest1610))
  {
    positionAfterr3MinRole = positionAfterScaleTest1610;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r3_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest1610),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1610),
      Ctxt,
      Input,
      positionAfterr3Method);
    positionAfterr3MinRole = positionAfterScaleTest1610;
  }
  if (EverParseIsError(positionAfterr3MinRole))
  {
    return positionAfterr3MinRole;
  }
  uint8_t r3MinRole = Input[(uint32_t)positionAfterr3Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes12 = 4ULL <= (InputLength - positionAfterr3MinRole);
  uint64_t positionAfterScaleTest1611;
  if (hasBytes12)
  {
    positionAfterScaleTest1611 = positionAfterr3MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest1611 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3MinRole);
  }
  uint64_t positionAfterr4PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest1611))
  {
    positionAfterr4PathHash = positionAfterScaleTest1611;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r4_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest1611),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1611),
      Ctxt,
      Input,
      positionAfterr3MinRole);
    positionAfterr4PathHash = positionAfterScaleTest1611;
  }
  if (EverParseIsError(positionAfterr4PathHash))
  {
    return positionAfterr4PathHash;
  }
  uint32_t r4PathHash = Load32Le(Input + (uint32_t)positionAfterr3MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes13 = 1ULL <= (InputLength - positionAfterr4PathHash);
  uint64_t positionAfterScaleTest1612;
  if (hasBytes13)
  {
    positionAfterScaleTest1612 = positionAfterr4PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest1612 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4PathHash);
  }
  uint64_t positionAfterr4Method;
  if (EverParseIsSuccess(positionAfterScaleTest1612))
  {
    positionAfterr4Method = positionAfterScaleTest1612;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r4_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest1612),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1612),
      Ctxt,
      Input,
      positionAfterr4PathHash);
    positionAfterr4Method = positionAfterScaleTest1612;
  }
  if (EverParseIsError(positionAfterr4Method))
  {
    return positionAfterr4Method;
  }
  uint8_t r4Method = Input[(uint32_t)positionAfterr4PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes14 = 1ULL <= (InputLength - positionAfterr4Method);
  uint64_t positionAfterScaleTest1613;
  if (hasBytes14)
  {
    positionAfterScaleTest1613 = positionAfterr4Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest1613 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4Method);
  }
  uint64_t positionAfterr4MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest1613))
  {
    positionAfterr4MinRole = positionAfterScaleTest1613;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r4_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest1613),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1613),
      Ctxt,
      Input,
      positionAfterr4Method);
    positionAfterr4MinRole = positionAfterScaleTest1613;
  }
  if (EverParseIsError(positionAfterr4MinRole))
  {
    return positionAfterr4MinRole;
  }
  uint8_t r4MinRole = Input[(uint32_t)positionAfterr4Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes15 = 4ULL <= (InputLength - positionAfterr4MinRole);
  uint64_t positionAfterScaleTest1614;
  if (hasBytes15)
  {
    positionAfterScaleTest1614 = positionAfterr4MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest1614 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4MinRole);
  }
  uint64_t positionAfterr5PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest1614))
  {
    positionAfterr5PathHash = positionAfterScaleTest1614;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r5_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest1614),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1614),
      Ctxt,
      Input,
      positionAfterr4MinRole);
    positionAfterr5PathHash = positionAfterScaleTest1614;
  }
  if (EverParseIsError(positionAfterr5PathHash))
  {
    return positionAfterr5PathHash;
  }
  uint32_t r5PathHash = Load32Le(Input + (uint32_t)positionAfterr4MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes16 = 1ULL <= (InputLength - positionAfterr5PathHash);
  uint64_t positionAfterScaleTest1615;
  if (hasBytes16)
  {
    positionAfterScaleTest1615 = positionAfterr5PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest1615 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5PathHash);
  }
  uint64_t positionAfterr5Method;
  if (EverParseIsSuccess(positionAfterScaleTest1615))
  {
    positionAfterr5Method = positionAfterScaleTest1615;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r5_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest1615),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1615),
      Ctxt,
      Input,
      positionAfterr5PathHash);
    positionAfterr5Method = positionAfterScaleTest1615;
  }
  if (EverParseIsError(positionAfterr5Method))
  {
    return positionAfterr5Method;
  }
  uint8_t r5Method = Input[(uint32_t)positionAfterr5PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes17 = 1ULL <= (InputLength - positionAfterr5Method);
  uint64_t positionAfterScaleTest1616;
  if (hasBytes17)
  {
    positionAfterScaleTest1616 = positionAfterr5Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest1616 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5Method);
  }
  uint64_t positionAfterr5MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest1616))
  {
    positionAfterr5MinRole = positionAfterScaleTest1616;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r5_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest1616),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1616),
      Ctxt,
      Input,
      positionAfterr5Method);
    positionAfterr5MinRole = positionAfterScaleTest1616;
  }
  if (EverParseIsError(positionAfterr5MinRole))
  {
    return positionAfterr5MinRole;
  }
  uint8_t r5MinRole = Input[(uint32_t)positionAfterr5Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes18 = 4ULL <= (InputLength - positionAfterr5MinRole);
  uint64_t positionAfterScaleTest1617;
  if (hasBytes18)
  {
    positionAfterScaleTest1617 = positionAfterr5MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest1617 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5MinRole);
  }
  uint64_t positionAfterr6PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest1617))
  {
    positionAfterr6PathHash = positionAfterScaleTest1617;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r6_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest1617),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1617),
      Ctxt,
      Input,
      positionAfterr5MinRole);
    positionAfterr6PathHash = positionAfterScaleTest1617;
  }
  if (EverParseIsError(positionAfterr6PathHash))
  {
    return positionAfterr6PathHash;
  }
  uint32_t r6PathHash = Load32Le(Input + (uint32_t)positionAfterr5MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes19 = 1ULL <= (InputLength - positionAfterr6PathHash);
  uint64_t positionAfterScaleTest1618;
  if (hasBytes19)
  {
    positionAfterScaleTest1618 = positionAfterr6PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest1618 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6PathHash);
  }
  uint64_t positionAfterr6Method;
  if (EverParseIsSuccess(positionAfterScaleTest1618))
  {
    positionAfterr6Method = positionAfterScaleTest1618;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r6_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest1618),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1618),
      Ctxt,
      Input,
      positionAfterr6PathHash);
    positionAfterr6Method = positionAfterScaleTest1618;
  }
  if (EverParseIsError(positionAfterr6Method))
  {
    return positionAfterr6Method;
  }
  uint8_t r6Method = Input[(uint32_t)positionAfterr6PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes20 = 1ULL <= (InputLength - positionAfterr6Method);
  uint64_t positionAfterScaleTest1619;
  if (hasBytes20)
  {
    positionAfterScaleTest1619 = positionAfterr6Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest1619 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6Method);
  }
  uint64_t positionAfterr6MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest1619))
  {
    positionAfterr6MinRole = positionAfterScaleTest1619;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r6_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest1619),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1619),
      Ctxt,
      Input,
      positionAfterr6Method);
    positionAfterr6MinRole = positionAfterScaleTest1619;
  }
  if (EverParseIsError(positionAfterr6MinRole))
  {
    return positionAfterr6MinRole;
  }
  uint8_t r6MinRole = Input[(uint32_t)positionAfterr6Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes21 = 4ULL <= (InputLength - positionAfterr6MinRole);
  uint64_t positionAfterScaleTest1620;
  if (hasBytes21)
  {
    positionAfterScaleTest1620 = positionAfterr6MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest1620 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6MinRole);
  }
  uint64_t positionAfterr7PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest1620))
  {
    positionAfterr7PathHash = positionAfterScaleTest1620;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r7_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest1620),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1620),
      Ctxt,
      Input,
      positionAfterr6MinRole);
    positionAfterr7PathHash = positionAfterScaleTest1620;
  }
  if (EverParseIsError(positionAfterr7PathHash))
  {
    return positionAfterr7PathHash;
  }
  uint32_t r7PathHash = Load32Le(Input + (uint32_t)positionAfterr6MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes22 = 1ULL <= (InputLength - positionAfterr7PathHash);
  uint64_t positionAfterScaleTest1621;
  if (hasBytes22)
  {
    positionAfterScaleTest1621 = positionAfterr7PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest1621 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7PathHash);
  }
  uint64_t positionAfterr7Method;
  if (EverParseIsSuccess(positionAfterScaleTest1621))
  {
    positionAfterr7Method = positionAfterScaleTest1621;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r7_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest1621),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1621),
      Ctxt,
      Input,
      positionAfterr7PathHash);
    positionAfterr7Method = positionAfterScaleTest1621;
  }
  if (EverParseIsError(positionAfterr7Method))
  {
    return positionAfterr7Method;
  }
  uint8_t r7Method = Input[(uint32_t)positionAfterr7PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes23 = 1ULL <= (InputLength - positionAfterr7Method);
  uint64_t positionAfterScaleTest1622;
  if (hasBytes23)
  {
    positionAfterScaleTest1622 = positionAfterr7Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest1622 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7Method);
  }
  uint64_t positionAfterr7MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest1622))
  {
    positionAfterr7MinRole = positionAfterScaleTest1622;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r7_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest1622),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1622),
      Ctxt,
      Input,
      positionAfterr7Method);
    positionAfterr7MinRole = positionAfterScaleTest1622;
  }
  if (EverParseIsError(positionAfterr7MinRole))
  {
    return positionAfterr7MinRole;
  }
  uint8_t r7MinRole = Input[(uint32_t)positionAfterr7Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes24 = 4ULL <= (InputLength - positionAfterr7MinRole);
  uint64_t positionAfterScaleTest1623;
  if (hasBytes24)
  {
    positionAfterScaleTest1623 = positionAfterr7MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest1623 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7MinRole);
  }
  uint64_t positionAfterr8PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest1623))
  {
    positionAfterr8PathHash = positionAfterScaleTest1623;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r8_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest1623),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1623),
      Ctxt,
      Input,
      positionAfterr7MinRole);
    positionAfterr8PathHash = positionAfterScaleTest1623;
  }
  if (EverParseIsError(positionAfterr8PathHash))
  {
    return positionAfterr8PathHash;
  }
  uint32_t r8PathHash = Load32Le(Input + (uint32_t)positionAfterr7MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes25 = 1ULL <= (InputLength - positionAfterr8PathHash);
  uint64_t positionAfterScaleTest1624;
  if (hasBytes25)
  {
    positionAfterScaleTest1624 = positionAfterr8PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest1624 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr8PathHash);
  }
  uint64_t positionAfterr8Method;
  if (EverParseIsSuccess(positionAfterScaleTest1624))
  {
    positionAfterr8Method = positionAfterScaleTest1624;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r8_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest1624),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1624),
      Ctxt,
      Input,
      positionAfterr8PathHash);
    positionAfterr8Method = positionAfterScaleTest1624;
  }
  if (EverParseIsError(positionAfterr8Method))
  {
    return positionAfterr8Method;
  }
  uint8_t r8Method = Input[(uint32_t)positionAfterr8PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes26 = 1ULL <= (InputLength - positionAfterr8Method);
  uint64_t positionAfterScaleTest1625;
  if (hasBytes26)
  {
    positionAfterScaleTest1625 = positionAfterr8Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest1625 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr8Method);
  }
  uint64_t positionAfterr8MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest1625))
  {
    positionAfterr8MinRole = positionAfterScaleTest1625;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r8_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest1625),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1625),
      Ctxt,
      Input,
      positionAfterr8Method);
    positionAfterr8MinRole = positionAfterScaleTest1625;
  }
  if (EverParseIsError(positionAfterr8MinRole))
  {
    return positionAfterr8MinRole;
  }
  uint8_t r8MinRole = Input[(uint32_t)positionAfterr8Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes27 = 4ULL <= (InputLength - positionAfterr8MinRole);
  uint64_t positionAfterScaleTest1626;
  if (hasBytes27)
  {
    positionAfterScaleTest1626 = positionAfterr8MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest1626 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr8MinRole);
  }
  uint64_t positionAfterr9PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest1626))
  {
    positionAfterr9PathHash = positionAfterScaleTest1626;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r9_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest1626),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1626),
      Ctxt,
      Input,
      positionAfterr8MinRole);
    positionAfterr9PathHash = positionAfterScaleTest1626;
  }
  if (EverParseIsError(positionAfterr9PathHash))
  {
    return positionAfterr9PathHash;
  }
  uint32_t r9PathHash = Load32Le(Input + (uint32_t)positionAfterr8MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes28 = 1ULL <= (InputLength - positionAfterr9PathHash);
  uint64_t positionAfterScaleTest1627;
  if (hasBytes28)
  {
    positionAfterScaleTest1627 = positionAfterr9PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest1627 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr9PathHash);
  }
  uint64_t positionAfterr9Method;
  if (EverParseIsSuccess(positionAfterScaleTest1627))
  {
    positionAfterr9Method = positionAfterScaleTest1627;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r9_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest1627),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1627),
      Ctxt,
      Input,
      positionAfterr9PathHash);
    positionAfterr9Method = positionAfterScaleTest1627;
  }
  if (EverParseIsError(positionAfterr9Method))
  {
    return positionAfterr9Method;
  }
  uint8_t r9Method = Input[(uint32_t)positionAfterr9PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes29 = 1ULL <= (InputLength - positionAfterr9Method);
  uint64_t positionAfterScaleTest1628;
  if (hasBytes29)
  {
    positionAfterScaleTest1628 = positionAfterr9Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest1628 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr9Method);
  }
  uint64_t positionAfterr9MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest1628))
  {
    positionAfterr9MinRole = positionAfterScaleTest1628;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r9_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest1628),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1628),
      Ctxt,
      Input,
      positionAfterr9Method);
    positionAfterr9MinRole = positionAfterScaleTest1628;
  }
  if (EverParseIsError(positionAfterr9MinRole))
  {
    return positionAfterr9MinRole;
  }
  uint8_t r9MinRole = Input[(uint32_t)positionAfterr9Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes30 = 4ULL <= (InputLength - positionAfterr9MinRole);
  uint64_t positionAfterScaleTest1629;
  if (hasBytes30)
  {
    positionAfterScaleTest1629 = positionAfterr9MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest1629 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr9MinRole);
  }
  uint64_t positionAfterr10PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest1629))
  {
    positionAfterr10PathHash = positionAfterScaleTest1629;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r10_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest1629),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1629),
      Ctxt,
      Input,
      positionAfterr9MinRole);
    positionAfterr10PathHash = positionAfterScaleTest1629;
  }
  if (EverParseIsError(positionAfterr10PathHash))
  {
    return positionAfterr10PathHash;
  }
  uint32_t r10PathHash = Load32Le(Input + (uint32_t)positionAfterr9MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes31 = 1ULL <= (InputLength - positionAfterr10PathHash);
  uint64_t positionAfterScaleTest1630;
  if (hasBytes31)
  {
    positionAfterScaleTest1630 = positionAfterr10PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest1630 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr10PathHash);
  }
  uint64_t positionAfterr10Method;
  if (EverParseIsSuccess(positionAfterScaleTest1630))
  {
    positionAfterr10Method = positionAfterScaleTest1630;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r10_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest1630),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1630),
      Ctxt,
      Input,
      positionAfterr10PathHash);
    positionAfterr10Method = positionAfterScaleTest1630;
  }
  if (EverParseIsError(positionAfterr10Method))
  {
    return positionAfterr10Method;
  }
  uint8_t r10Method = Input[(uint32_t)positionAfterr10PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes32 = 1ULL <= (InputLength - positionAfterr10Method);
  uint64_t positionAfterScaleTest1631;
  if (hasBytes32)
  {
    positionAfterScaleTest1631 = positionAfterr10Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest1631 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr10Method);
  }
  uint64_t positionAfterr10MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest1631))
  {
    positionAfterr10MinRole = positionAfterScaleTest1631;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r10_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest1631),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1631),
      Ctxt,
      Input,
      positionAfterr10Method);
    positionAfterr10MinRole = positionAfterScaleTest1631;
  }
  if (EverParseIsError(positionAfterr10MinRole))
  {
    return positionAfterr10MinRole;
  }
  uint8_t r10MinRole = Input[(uint32_t)positionAfterr10Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes33 = 4ULL <= (InputLength - positionAfterr10MinRole);
  uint64_t positionAfterScaleTest1632;
  if (hasBytes33)
  {
    positionAfterScaleTest1632 = positionAfterr10MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest1632 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr10MinRole);
  }
  uint64_t positionAfterr11PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest1632))
  {
    positionAfterr11PathHash = positionAfterScaleTest1632;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r11_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest1632),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1632),
      Ctxt,
      Input,
      positionAfterr10MinRole);
    positionAfterr11PathHash = positionAfterScaleTest1632;
  }
  if (EverParseIsError(positionAfterr11PathHash))
  {
    return positionAfterr11PathHash;
  }
  uint32_t r11PathHash = Load32Le(Input + (uint32_t)positionAfterr10MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes34 = 1ULL <= (InputLength - positionAfterr11PathHash);
  uint64_t positionAfterScaleTest1633;
  if (hasBytes34)
  {
    positionAfterScaleTest1633 = positionAfterr11PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest1633 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr11PathHash);
  }
  uint64_t positionAfterr11Method;
  if (EverParseIsSuccess(positionAfterScaleTest1633))
  {
    positionAfterr11Method = positionAfterScaleTest1633;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r11_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest1633),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1633),
      Ctxt,
      Input,
      positionAfterr11PathHash);
    positionAfterr11Method = positionAfterScaleTest1633;
  }
  if (EverParseIsError(positionAfterr11Method))
  {
    return positionAfterr11Method;
  }
  uint8_t r11Method = Input[(uint32_t)positionAfterr11PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes35 = 1ULL <= (InputLength - positionAfterr11Method);
  uint64_t positionAfterScaleTest1634;
  if (hasBytes35)
  {
    positionAfterScaleTest1634 = positionAfterr11Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest1634 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr11Method);
  }
  uint64_t positionAfterr11MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest1634))
  {
    positionAfterr11MinRole = positionAfterScaleTest1634;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r11_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest1634),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1634),
      Ctxt,
      Input,
      positionAfterr11Method);
    positionAfterr11MinRole = positionAfterScaleTest1634;
  }
  if (EverParseIsError(positionAfterr11MinRole))
  {
    return positionAfterr11MinRole;
  }
  uint8_t r11MinRole = Input[(uint32_t)positionAfterr11Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes36 = 4ULL <= (InputLength - positionAfterr11MinRole);
  uint64_t positionAfterScaleTest1635;
  if (hasBytes36)
  {
    positionAfterScaleTest1635 = positionAfterr11MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest1635 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr11MinRole);
  }
  uint64_t positionAfterr12PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest1635))
  {
    positionAfterr12PathHash = positionAfterScaleTest1635;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r12_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest1635),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1635),
      Ctxt,
      Input,
      positionAfterr11MinRole);
    positionAfterr12PathHash = positionAfterScaleTest1635;
  }
  if (EverParseIsError(positionAfterr12PathHash))
  {
    return positionAfterr12PathHash;
  }
  uint32_t r12PathHash = Load32Le(Input + (uint32_t)positionAfterr11MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes37 = 1ULL <= (InputLength - positionAfterr12PathHash);
  uint64_t positionAfterScaleTest1636;
  if (hasBytes37)
  {
    positionAfterScaleTest1636 = positionAfterr12PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest1636 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr12PathHash);
  }
  uint64_t positionAfterr12Method;
  if (EverParseIsSuccess(positionAfterScaleTest1636))
  {
    positionAfterr12Method = positionAfterScaleTest1636;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r12_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest1636),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1636),
      Ctxt,
      Input,
      positionAfterr12PathHash);
    positionAfterr12Method = positionAfterScaleTest1636;
  }
  if (EverParseIsError(positionAfterr12Method))
  {
    return positionAfterr12Method;
  }
  uint8_t r12Method = Input[(uint32_t)positionAfterr12PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes38 = 1ULL <= (InputLength - positionAfterr12Method);
  uint64_t positionAfterScaleTest1637;
  if (hasBytes38)
  {
    positionAfterScaleTest1637 = positionAfterr12Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest1637 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr12Method);
  }
  uint64_t positionAfterr12MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest1637))
  {
    positionAfterr12MinRole = positionAfterScaleTest1637;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r12_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest1637),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1637),
      Ctxt,
      Input,
      positionAfterr12Method);
    positionAfterr12MinRole = positionAfterScaleTest1637;
  }
  if (EverParseIsError(positionAfterr12MinRole))
  {
    return positionAfterr12MinRole;
  }
  uint8_t r12MinRole = Input[(uint32_t)positionAfterr12Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes39 = 4ULL <= (InputLength - positionAfterr12MinRole);
  uint64_t positionAfterScaleTest1638;
  if (hasBytes39)
  {
    positionAfterScaleTest1638 = positionAfterr12MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest1638 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr12MinRole);
  }
  uint64_t positionAfterr13PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest1638))
  {
    positionAfterr13PathHash = positionAfterScaleTest1638;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r13_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest1638),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1638),
      Ctxt,
      Input,
      positionAfterr12MinRole);
    positionAfterr13PathHash = positionAfterScaleTest1638;
  }
  if (EverParseIsError(positionAfterr13PathHash))
  {
    return positionAfterr13PathHash;
  }
  uint32_t r13PathHash = Load32Le(Input + (uint32_t)positionAfterr12MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes40 = 1ULL <= (InputLength - positionAfterr13PathHash);
  uint64_t positionAfterScaleTest1639;
  if (hasBytes40)
  {
    positionAfterScaleTest1639 = positionAfterr13PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest1639 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr13PathHash);
  }
  uint64_t positionAfterr13Method;
  if (EverParseIsSuccess(positionAfterScaleTest1639))
  {
    positionAfterr13Method = positionAfterScaleTest1639;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r13_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest1639),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1639),
      Ctxt,
      Input,
      positionAfterr13PathHash);
    positionAfterr13Method = positionAfterScaleTest1639;
  }
  if (EverParseIsError(positionAfterr13Method))
  {
    return positionAfterr13Method;
  }
  uint8_t r13Method = Input[(uint32_t)positionAfterr13PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes41 = 1ULL <= (InputLength - positionAfterr13Method);
  uint64_t positionAfterScaleTest1640;
  if (hasBytes41)
  {
    positionAfterScaleTest1640 = positionAfterr13Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest1640 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr13Method);
  }
  uint64_t positionAfterr13MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest1640))
  {
    positionAfterr13MinRole = positionAfterScaleTest1640;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r13_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest1640),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1640),
      Ctxt,
      Input,
      positionAfterr13Method);
    positionAfterr13MinRole = positionAfterScaleTest1640;
  }
  if (EverParseIsError(positionAfterr13MinRole))
  {
    return positionAfterr13MinRole;
  }
  uint8_t r13MinRole = Input[(uint32_t)positionAfterr13Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes42 = 4ULL <= (InputLength - positionAfterr13MinRole);
  uint64_t positionAfterScaleTest1641;
  if (hasBytes42)
  {
    positionAfterScaleTest1641 = positionAfterr13MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest1641 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr13MinRole);
  }
  uint64_t positionAfterr14PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest1641))
  {
    positionAfterr14PathHash = positionAfterScaleTest1641;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r14_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest1641),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1641),
      Ctxt,
      Input,
      positionAfterr13MinRole);
    positionAfterr14PathHash = positionAfterScaleTest1641;
  }
  if (EverParseIsError(positionAfterr14PathHash))
  {
    return positionAfterr14PathHash;
  }
  uint32_t r14PathHash = Load32Le(Input + (uint32_t)positionAfterr13MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes43 = 1ULL <= (InputLength - positionAfterr14PathHash);
  uint64_t positionAfterScaleTest1642;
  if (hasBytes43)
  {
    positionAfterScaleTest1642 = positionAfterr14PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest1642 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr14PathHash);
  }
  uint64_t positionAfterr14Method;
  if (EverParseIsSuccess(positionAfterScaleTest1642))
  {
    positionAfterr14Method = positionAfterScaleTest1642;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r14_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest1642),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1642),
      Ctxt,
      Input,
      positionAfterr14PathHash);
    positionAfterr14Method = positionAfterScaleTest1642;
  }
  if (EverParseIsError(positionAfterr14Method))
  {
    return positionAfterr14Method;
  }
  uint8_t r14Method = Input[(uint32_t)positionAfterr14PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes44 = 1ULL <= (InputLength - positionAfterr14Method);
  uint64_t positionAfterScaleTest1643;
  if (hasBytes44)
  {
    positionAfterScaleTest1643 = positionAfterr14Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest1643 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr14Method);
  }
  uint64_t positionAfterr14MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest1643))
  {
    positionAfterr14MinRole = positionAfterScaleTest1643;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r14_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest1643),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1643),
      Ctxt,
      Input,
      positionAfterr14Method);
    positionAfterr14MinRole = positionAfterScaleTest1643;
  }
  if (EverParseIsError(positionAfterr14MinRole))
  {
    return positionAfterr14MinRole;
  }
  uint8_t r14MinRole = Input[(uint32_t)positionAfterr14Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes45 = 4ULL <= (InputLength - positionAfterr14MinRole);
  uint64_t positionAfterScaleTest1644;
  if (hasBytes45)
  {
    positionAfterScaleTest1644 = positionAfterr14MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest1644 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr14MinRole);
  }
  uint64_t positionAfterr15PathHash;
  if (EverParseIsSuccess(positionAfterScaleTest1644))
  {
    positionAfterr15PathHash = positionAfterScaleTest1644;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r15_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest1644),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1644),
      Ctxt,
      Input,
      positionAfterr14MinRole);
    positionAfterr15PathHash = positionAfterScaleTest1644;
  }
  if (EverParseIsError(positionAfterr15PathHash))
  {
    return positionAfterr15PathHash;
  }
  uint32_t r15PathHash = Load32Le(Input + (uint32_t)positionAfterr14MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes46 = 1ULL <= (InputLength - positionAfterr15PathHash);
  uint64_t positionAfterScaleTest1645;
  if (hasBytes46)
  {
    positionAfterScaleTest1645 = positionAfterr15PathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest1645 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr15PathHash);
  }
  uint64_t positionAfterr15Method;
  if (EverParseIsSuccess(positionAfterScaleTest1645))
  {
    positionAfterr15Method = positionAfterScaleTest1645;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r15_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest1645),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1645),
      Ctxt,
      Input,
      positionAfterr15PathHash);
    positionAfterr15Method = positionAfterScaleTest1645;
  }
  if (EverParseIsError(positionAfterr15Method))
  {
    return positionAfterr15Method;
  }
  uint8_t r15Method = Input[(uint32_t)positionAfterr15PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes47 = 1ULL <= (InputLength - positionAfterr15Method);
  uint64_t positionAfterScaleTest1646;
  if (hasBytes47)
  {
    positionAfterScaleTest1646 = positionAfterr15Method + 1ULL;
  }
  else
  {
    positionAfterScaleTest1646 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr15Method);
  }
  uint64_t positionAfterr15MinRole;
  if (EverParseIsSuccess(positionAfterScaleTest1646))
  {
    positionAfterr15MinRole = positionAfterScaleTest1646;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "r15_min_role",
      EverParseErrorReasonOfResult(positionAfterScaleTest1646),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1646),
      Ctxt,
      Input,
      positionAfterr15Method);
    positionAfterr15MinRole = positionAfterScaleTest1646;
  }
  if (EverParseIsError(positionAfterr15MinRole))
  {
    return positionAfterr15MinRole;
  }
  uint8_t r15MinRole = Input[(uint32_t)positionAfterr15Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes48 = 4ULL <= (InputLength - positionAfterr15MinRole);
  uint64_t positionAfterScaleTest1647;
  if (hasBytes48)
  {
    positionAfterScaleTest1647 = positionAfterr15MinRole + 4ULL;
  }
  else
  {
    positionAfterScaleTest1647 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr15MinRole);
  }
  uint64_t positionAfterreqPathHash;
  if (EverParseIsSuccess(positionAfterScaleTest1647))
  {
    positionAfterreqPathHash = positionAfterScaleTest1647;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "req_path_hash",
      EverParseErrorReasonOfResult(positionAfterScaleTest1647),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1647),
      Ctxt,
      Input,
      positionAfterr15MinRole);
    positionAfterreqPathHash = positionAfterScaleTest1647;
  }
  if (EverParseIsError(positionAfterreqPathHash))
  {
    return positionAfterreqPathHash;
  }
  uint32_t reqPathHash = Load32Le(Input + (uint32_t)positionAfterr15MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes49 = 1ULL <= (InputLength - positionAfterreqPathHash);
  uint64_t positionAfterScaleTest1648;
  if (hasBytes49)
  {
    positionAfterScaleTest1648 = positionAfterreqPathHash + 1ULL;
  }
  else
  {
    positionAfterScaleTest1648 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqPathHash);
  }
  uint64_t positionAfterreqMethod;
  if (EverParseIsSuccess(positionAfterScaleTest1648))
  {
    positionAfterreqMethod = positionAfterScaleTest1648;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "req_method",
      EverParseErrorReasonOfResult(positionAfterScaleTest1648),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1648),
      Ctxt,
      Input,
      positionAfterreqPathHash);
    positionAfterreqMethod = positionAfterScaleTest1648;
  }
  if (EverParseIsError(positionAfterreqMethod))
  {
    return positionAfterreqMethod;
  }
  uint8_t reqMethod = Input[(uint32_t)positionAfterreqPathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes50 = 1ULL <= (InputLength - positionAfterreqMethod);
  uint64_t positionAfterScaleTest1649;
  if (hasBytes50)
  {
    positionAfterScaleTest1649 = positionAfterreqMethod + 1ULL;
  }
  else
  {
    positionAfterScaleTest1649 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqMethod);
  }
  uint64_t positionAfterauthState;
  if (EverParseIsSuccess(positionAfterScaleTest1649))
  {
    positionAfterauthState = positionAfterScaleTest1649;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "auth_state",
      EverParseErrorReasonOfResult(positionAfterScaleTest1649),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1649),
      Ctxt,
      Input,
      positionAfterreqMethod);
    positionAfterauthState = positionAfterScaleTest1649;
  }
  if (EverParseIsError(positionAfterauthState))
  {
    return positionAfterauthState;
  }
  uint8_t authState = Input[(uint32_t)positionAfterreqMethod];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes51 = 1ULL <= (InputLength - positionAfterauthState);
  uint64_t positionAfterScaleTest1650;
  if (hasBytes51)
  {
    positionAfterScaleTest1650 = positionAfterauthState + 1ULL;
  }
  else
  {
    positionAfterScaleTest1650 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterauthState);
  }
  uint64_t positionAfterrateCount;
  if (EverParseIsSuccess(positionAfterScaleTest1650))
  {
    positionAfterrateCount = positionAfterScaleTest1650;
  }
  else
  {
    ErrorHandlerFn("_ScaleTest16",
      "rate_count",
      EverParseErrorReasonOfResult(positionAfterScaleTest1650),
      EverParseGetValidatorErrorKind(positionAfterScaleTest1650),
      Ctxt,
      Input,
      positionAfterauthState);
    positionAfterrateCount = positionAfterScaleTest1650;
  }
  if (EverParseIsError(positionAfterrateCount))
  {
    return positionAfterrateCount;
  }
  uint8_t rateCount = Input[(uint32_t)positionAfterauthState];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes52 = 1ULL <= (InputLength - positionAfterrateCount);
  uint64_t positionAfterRateOk;
  if (hasBytes52)
  {
    positionAfterRateOk = positionAfterrateCount + 1ULL;
  }
  else
  {
    positionAfterRateOk =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrateCount);
  }
  uint64_t positionAfterScaleTest1651;
  if (EverParseIsError(positionAfterRateOk))
  {
    positionAfterScaleTest1651 = positionAfterRateOk;
  }
  else
  {
    uint8_t rateOk = Input[(uint32_t)positionAfterrateCount];
    KRML_MAYBE_UNUSED_VAR(rateOk);
    BOOLEAN rateOkConstraintIsOk = rateCount < SCALETEST16____MAX_RATE;
    uint64_t
    positionAfterRateOk1 = EverParseCheckConstraintOk(rateOkConstraintIsOk, positionAfterRateOk);
    if (EverParseIsError(positionAfterRateOk1))
    {
      positionAfterScaleTest1651 = positionAfterRateOk1;
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
      uint64_t positionAfterScaleTest1652;
      if (EverParseIsError(positionAfterAccessOk_refinement))
      {
        positionAfterScaleTest1652 = positionAfterAccessOk_refinement;
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
          || (r7PathHash == reqPathHash && r7Method == reqMethod && authState >= r7MinRole)
          || (r8PathHash == reqPathHash && r8Method == reqMethod && authState >= r8MinRole)
          || (r9PathHash == reqPathHash && r9Method == reqMethod && authState >= r9MinRole)
          || (r10PathHash == reqPathHash && r10Method == reqMethod && authState >= r10MinRole)
          || (r11PathHash == reqPathHash && r11Method == reqMethod && authState >= r11MinRole)
          || (r12PathHash == reqPathHash && r12Method == reqMethod && authState >= r12MinRole)
          || (r13PathHash == reqPathHash && r13Method == reqMethod && authState >= r13MinRole)
          || (r14PathHash == reqPathHash && r14Method == reqMethod && authState >= r14MinRole)
          || (r15PathHash == reqPathHash && r15Method == reqMethod && authState >= r15MinRole);
        /* end: checking constraint */
        positionAfterScaleTest1652 =
          EverParseCheckConstraintOk(accessOk_refinementConstraintIsOk,
            positionAfterAccessOk_refinement);
      }
      if (EverParseIsSuccess(positionAfterScaleTest1652))
      {
        positionAfterScaleTest1651 = positionAfterScaleTest1652;
      }
      else
      {
        ErrorHandlerFn("_ScaleTest16",
          "_access_ok.refinement",
          EverParseErrorReasonOfResult(positionAfterScaleTest1652),
          EverParseGetValidatorErrorKind(positionAfterScaleTest1652),
          Ctxt,
          Input,
          positionAfterRateOk1);
        positionAfterScaleTest1651 = positionAfterScaleTest1652;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterScaleTest1651))
  {
    return positionAfterScaleTest1651;
  }
  ErrorHandlerFn("_ScaleTest16",
    "_rate_ok",
    EverParseErrorReasonOfResult(positionAfterScaleTest1651),
    EverParseGetValidatorErrorKind(positionAfterScaleTest1651),
    Ctxt,
    Input,
    positionAfterrateCount);
  return positionAfterScaleTest1651;
}

