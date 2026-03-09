

#include "MonoAccess16.h"

uint64_t
MonoAccess16ValidateMonoAccess16(
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
  uint64_t positionAfterMonoAccess16;
  if (hasBytes0)
  {
    positionAfterMonoAccess16 = StartPosition + 4ULL;
  }
  else
  {
    positionAfterMonoAccess16 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterr0PathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess16))
  {
    positionAfterr0PathHash = positionAfterMonoAccess16;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r0_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess16),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess16),
      Ctxt,
      Input,
      StartPosition);
    positionAfterr0PathHash = positionAfterMonoAccess16;
  }
  if (EverParseIsError(positionAfterr0PathHash))
  {
    return positionAfterr0PathHash;
  }
  uint32_t r0PathHash = Load32Le(Input + (uint32_t)StartPosition);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAfterr0PathHash);
  uint64_t positionAfterMonoAccess160;
  if (hasBytes1)
  {
    positionAfterMonoAccess160 = positionAfterr0PathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess160 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0PathHash);
  }
  uint64_t positionAfterr0Method;
  if (EverParseIsSuccess(positionAfterMonoAccess160))
  {
    positionAfterr0Method = positionAfterMonoAccess160;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r0_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess160),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess160),
      Ctxt,
      Input,
      positionAfterr0PathHash);
    positionAfterr0Method = positionAfterMonoAccess160;
  }
  if (EverParseIsError(positionAfterr0Method))
  {
    return positionAfterr0Method;
  }
  uint8_t r0Method = Input[(uint32_t)positionAfterr0PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes2 = 1ULL <= (InputLength - positionAfterr0Method);
  uint64_t positionAfterMonoAccess161;
  if (hasBytes2)
  {
    positionAfterMonoAccess161 = positionAfterr0Method + 1ULL;
  }
  else
  {
    positionAfterMonoAccess161 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0Method);
  }
  uint64_t positionAfterr0MinRole;
  if (EverParseIsSuccess(positionAfterMonoAccess161))
  {
    positionAfterr0MinRole = positionAfterMonoAccess161;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r0_min_role",
      EverParseErrorReasonOfResult(positionAfterMonoAccess161),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess161),
      Ctxt,
      Input,
      positionAfterr0Method);
    positionAfterr0MinRole = positionAfterMonoAccess161;
  }
  if (EverParseIsError(positionAfterr0MinRole))
  {
    return positionAfterr0MinRole;
  }
  uint8_t r0MinRole = Input[(uint32_t)positionAfterr0Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes3 = 4ULL <= (InputLength - positionAfterr0MinRole);
  uint64_t positionAfterMonoAccess162;
  if (hasBytes3)
  {
    positionAfterMonoAccess162 = positionAfterr0MinRole + 4ULL;
  }
  else
  {
    positionAfterMonoAccess162 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0MinRole);
  }
  uint64_t positionAfterr1PathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess162))
  {
    positionAfterr1PathHash = positionAfterMonoAccess162;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r1_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess162),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess162),
      Ctxt,
      Input,
      positionAfterr0MinRole);
    positionAfterr1PathHash = positionAfterMonoAccess162;
  }
  if (EverParseIsError(positionAfterr1PathHash))
  {
    return positionAfterr1PathHash;
  }
  uint32_t r1PathHash = Load32Le(Input + (uint32_t)positionAfterr0MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAfterr1PathHash);
  uint64_t positionAfterMonoAccess163;
  if (hasBytes4)
  {
    positionAfterMonoAccess163 = positionAfterr1PathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess163 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1PathHash);
  }
  uint64_t positionAfterr1Method;
  if (EverParseIsSuccess(positionAfterMonoAccess163))
  {
    positionAfterr1Method = positionAfterMonoAccess163;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r1_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess163),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess163),
      Ctxt,
      Input,
      positionAfterr1PathHash);
    positionAfterr1Method = positionAfterMonoAccess163;
  }
  if (EverParseIsError(positionAfterr1Method))
  {
    return positionAfterr1Method;
  }
  uint8_t r1Method = Input[(uint32_t)positionAfterr1PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes5 = 1ULL <= (InputLength - positionAfterr1Method);
  uint64_t positionAfterMonoAccess164;
  if (hasBytes5)
  {
    positionAfterMonoAccess164 = positionAfterr1Method + 1ULL;
  }
  else
  {
    positionAfterMonoAccess164 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1Method);
  }
  uint64_t positionAfterr1MinRole;
  if (EverParseIsSuccess(positionAfterMonoAccess164))
  {
    positionAfterr1MinRole = positionAfterMonoAccess164;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r1_min_role",
      EverParseErrorReasonOfResult(positionAfterMonoAccess164),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess164),
      Ctxt,
      Input,
      positionAfterr1Method);
    positionAfterr1MinRole = positionAfterMonoAccess164;
  }
  if (EverParseIsError(positionAfterr1MinRole))
  {
    return positionAfterr1MinRole;
  }
  uint8_t r1MinRole = Input[(uint32_t)positionAfterr1Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes6 = 4ULL <= (InputLength - positionAfterr1MinRole);
  uint64_t positionAfterMonoAccess165;
  if (hasBytes6)
  {
    positionAfterMonoAccess165 = positionAfterr1MinRole + 4ULL;
  }
  else
  {
    positionAfterMonoAccess165 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1MinRole);
  }
  uint64_t positionAfterr2PathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess165))
  {
    positionAfterr2PathHash = positionAfterMonoAccess165;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r2_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess165),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess165),
      Ctxt,
      Input,
      positionAfterr1MinRole);
    positionAfterr2PathHash = positionAfterMonoAccess165;
  }
  if (EverParseIsError(positionAfterr2PathHash))
  {
    return positionAfterr2PathHash;
  }
  uint32_t r2PathHash = Load32Le(Input + (uint32_t)positionAfterr1MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes7 = 1ULL <= (InputLength - positionAfterr2PathHash);
  uint64_t positionAfterMonoAccess166;
  if (hasBytes7)
  {
    positionAfterMonoAccess166 = positionAfterr2PathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess166 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2PathHash);
  }
  uint64_t positionAfterr2Method;
  if (EverParseIsSuccess(positionAfterMonoAccess166))
  {
    positionAfterr2Method = positionAfterMonoAccess166;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r2_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess166),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess166),
      Ctxt,
      Input,
      positionAfterr2PathHash);
    positionAfterr2Method = positionAfterMonoAccess166;
  }
  if (EverParseIsError(positionAfterr2Method))
  {
    return positionAfterr2Method;
  }
  uint8_t r2Method = Input[(uint32_t)positionAfterr2PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes8 = 1ULL <= (InputLength - positionAfterr2Method);
  uint64_t positionAfterMonoAccess167;
  if (hasBytes8)
  {
    positionAfterMonoAccess167 = positionAfterr2Method + 1ULL;
  }
  else
  {
    positionAfterMonoAccess167 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2Method);
  }
  uint64_t positionAfterr2MinRole;
  if (EverParseIsSuccess(positionAfterMonoAccess167))
  {
    positionAfterr2MinRole = positionAfterMonoAccess167;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r2_min_role",
      EverParseErrorReasonOfResult(positionAfterMonoAccess167),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess167),
      Ctxt,
      Input,
      positionAfterr2Method);
    positionAfterr2MinRole = positionAfterMonoAccess167;
  }
  if (EverParseIsError(positionAfterr2MinRole))
  {
    return positionAfterr2MinRole;
  }
  uint8_t r2MinRole = Input[(uint32_t)positionAfterr2Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes9 = 4ULL <= (InputLength - positionAfterr2MinRole);
  uint64_t positionAfterMonoAccess168;
  if (hasBytes9)
  {
    positionAfterMonoAccess168 = positionAfterr2MinRole + 4ULL;
  }
  else
  {
    positionAfterMonoAccess168 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2MinRole);
  }
  uint64_t positionAfterr3PathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess168))
  {
    positionAfterr3PathHash = positionAfterMonoAccess168;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r3_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess168),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess168),
      Ctxt,
      Input,
      positionAfterr2MinRole);
    positionAfterr3PathHash = positionAfterMonoAccess168;
  }
  if (EverParseIsError(positionAfterr3PathHash))
  {
    return positionAfterr3PathHash;
  }
  uint32_t r3PathHash = Load32Le(Input + (uint32_t)positionAfterr2MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes10 = 1ULL <= (InputLength - positionAfterr3PathHash);
  uint64_t positionAfterMonoAccess169;
  if (hasBytes10)
  {
    positionAfterMonoAccess169 = positionAfterr3PathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess169 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3PathHash);
  }
  uint64_t positionAfterr3Method;
  if (EverParseIsSuccess(positionAfterMonoAccess169))
  {
    positionAfterr3Method = positionAfterMonoAccess169;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r3_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess169),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess169),
      Ctxt,
      Input,
      positionAfterr3PathHash);
    positionAfterr3Method = positionAfterMonoAccess169;
  }
  if (EverParseIsError(positionAfterr3Method))
  {
    return positionAfterr3Method;
  }
  uint8_t r3Method = Input[(uint32_t)positionAfterr3PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes11 = 1ULL <= (InputLength - positionAfterr3Method);
  uint64_t positionAfterMonoAccess1610;
  if (hasBytes11)
  {
    positionAfterMonoAccess1610 = positionAfterr3Method + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1610 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3Method);
  }
  uint64_t positionAfterr3MinRole;
  if (EverParseIsSuccess(positionAfterMonoAccess1610))
  {
    positionAfterr3MinRole = positionAfterMonoAccess1610;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r3_min_role",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1610),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1610),
      Ctxt,
      Input,
      positionAfterr3Method);
    positionAfterr3MinRole = positionAfterMonoAccess1610;
  }
  if (EverParseIsError(positionAfterr3MinRole))
  {
    return positionAfterr3MinRole;
  }
  uint8_t r3MinRole = Input[(uint32_t)positionAfterr3Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes12 = 4ULL <= (InputLength - positionAfterr3MinRole);
  uint64_t positionAfterMonoAccess1611;
  if (hasBytes12)
  {
    positionAfterMonoAccess1611 = positionAfterr3MinRole + 4ULL;
  }
  else
  {
    positionAfterMonoAccess1611 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3MinRole);
  }
  uint64_t positionAfterr4PathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess1611))
  {
    positionAfterr4PathHash = positionAfterMonoAccess1611;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r4_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1611),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1611),
      Ctxt,
      Input,
      positionAfterr3MinRole);
    positionAfterr4PathHash = positionAfterMonoAccess1611;
  }
  if (EverParseIsError(positionAfterr4PathHash))
  {
    return positionAfterr4PathHash;
  }
  uint32_t r4PathHash = Load32Le(Input + (uint32_t)positionAfterr3MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes13 = 1ULL <= (InputLength - positionAfterr4PathHash);
  uint64_t positionAfterMonoAccess1612;
  if (hasBytes13)
  {
    positionAfterMonoAccess1612 = positionAfterr4PathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1612 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4PathHash);
  }
  uint64_t positionAfterr4Method;
  if (EverParseIsSuccess(positionAfterMonoAccess1612))
  {
    positionAfterr4Method = positionAfterMonoAccess1612;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r4_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1612),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1612),
      Ctxt,
      Input,
      positionAfterr4PathHash);
    positionAfterr4Method = positionAfterMonoAccess1612;
  }
  if (EverParseIsError(positionAfterr4Method))
  {
    return positionAfterr4Method;
  }
  uint8_t r4Method = Input[(uint32_t)positionAfterr4PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes14 = 1ULL <= (InputLength - positionAfterr4Method);
  uint64_t positionAfterMonoAccess1613;
  if (hasBytes14)
  {
    positionAfterMonoAccess1613 = positionAfterr4Method + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1613 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4Method);
  }
  uint64_t positionAfterr4MinRole;
  if (EverParseIsSuccess(positionAfterMonoAccess1613))
  {
    positionAfterr4MinRole = positionAfterMonoAccess1613;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r4_min_role",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1613),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1613),
      Ctxt,
      Input,
      positionAfterr4Method);
    positionAfterr4MinRole = positionAfterMonoAccess1613;
  }
  if (EverParseIsError(positionAfterr4MinRole))
  {
    return positionAfterr4MinRole;
  }
  uint8_t r4MinRole = Input[(uint32_t)positionAfterr4Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes15 = 4ULL <= (InputLength - positionAfterr4MinRole);
  uint64_t positionAfterMonoAccess1614;
  if (hasBytes15)
  {
    positionAfterMonoAccess1614 = positionAfterr4MinRole + 4ULL;
  }
  else
  {
    positionAfterMonoAccess1614 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4MinRole);
  }
  uint64_t positionAfterr5PathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess1614))
  {
    positionAfterr5PathHash = positionAfterMonoAccess1614;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r5_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1614),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1614),
      Ctxt,
      Input,
      positionAfterr4MinRole);
    positionAfterr5PathHash = positionAfterMonoAccess1614;
  }
  if (EverParseIsError(positionAfterr5PathHash))
  {
    return positionAfterr5PathHash;
  }
  uint32_t r5PathHash = Load32Le(Input + (uint32_t)positionAfterr4MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes16 = 1ULL <= (InputLength - positionAfterr5PathHash);
  uint64_t positionAfterMonoAccess1615;
  if (hasBytes16)
  {
    positionAfterMonoAccess1615 = positionAfterr5PathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1615 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5PathHash);
  }
  uint64_t positionAfterr5Method;
  if (EverParseIsSuccess(positionAfterMonoAccess1615))
  {
    positionAfterr5Method = positionAfterMonoAccess1615;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r5_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1615),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1615),
      Ctxt,
      Input,
      positionAfterr5PathHash);
    positionAfterr5Method = positionAfterMonoAccess1615;
  }
  if (EverParseIsError(positionAfterr5Method))
  {
    return positionAfterr5Method;
  }
  uint8_t r5Method = Input[(uint32_t)positionAfterr5PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes17 = 1ULL <= (InputLength - positionAfterr5Method);
  uint64_t positionAfterMonoAccess1616;
  if (hasBytes17)
  {
    positionAfterMonoAccess1616 = positionAfterr5Method + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1616 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5Method);
  }
  uint64_t positionAfterr5MinRole;
  if (EverParseIsSuccess(positionAfterMonoAccess1616))
  {
    positionAfterr5MinRole = positionAfterMonoAccess1616;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r5_min_role",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1616),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1616),
      Ctxt,
      Input,
      positionAfterr5Method);
    positionAfterr5MinRole = positionAfterMonoAccess1616;
  }
  if (EverParseIsError(positionAfterr5MinRole))
  {
    return positionAfterr5MinRole;
  }
  uint8_t r5MinRole = Input[(uint32_t)positionAfterr5Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes18 = 4ULL <= (InputLength - positionAfterr5MinRole);
  uint64_t positionAfterMonoAccess1617;
  if (hasBytes18)
  {
    positionAfterMonoAccess1617 = positionAfterr5MinRole + 4ULL;
  }
  else
  {
    positionAfterMonoAccess1617 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5MinRole);
  }
  uint64_t positionAfterr6PathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess1617))
  {
    positionAfterr6PathHash = positionAfterMonoAccess1617;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r6_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1617),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1617),
      Ctxt,
      Input,
      positionAfterr5MinRole);
    positionAfterr6PathHash = positionAfterMonoAccess1617;
  }
  if (EverParseIsError(positionAfterr6PathHash))
  {
    return positionAfterr6PathHash;
  }
  uint32_t r6PathHash = Load32Le(Input + (uint32_t)positionAfterr5MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes19 = 1ULL <= (InputLength - positionAfterr6PathHash);
  uint64_t positionAfterMonoAccess1618;
  if (hasBytes19)
  {
    positionAfterMonoAccess1618 = positionAfterr6PathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1618 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6PathHash);
  }
  uint64_t positionAfterr6Method;
  if (EverParseIsSuccess(positionAfterMonoAccess1618))
  {
    positionAfterr6Method = positionAfterMonoAccess1618;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r6_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1618),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1618),
      Ctxt,
      Input,
      positionAfterr6PathHash);
    positionAfterr6Method = positionAfterMonoAccess1618;
  }
  if (EverParseIsError(positionAfterr6Method))
  {
    return positionAfterr6Method;
  }
  uint8_t r6Method = Input[(uint32_t)positionAfterr6PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes20 = 1ULL <= (InputLength - positionAfterr6Method);
  uint64_t positionAfterMonoAccess1619;
  if (hasBytes20)
  {
    positionAfterMonoAccess1619 = positionAfterr6Method + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1619 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6Method);
  }
  uint64_t positionAfterr6MinRole;
  if (EverParseIsSuccess(positionAfterMonoAccess1619))
  {
    positionAfterr6MinRole = positionAfterMonoAccess1619;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r6_min_role",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1619),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1619),
      Ctxt,
      Input,
      positionAfterr6Method);
    positionAfterr6MinRole = positionAfterMonoAccess1619;
  }
  if (EverParseIsError(positionAfterr6MinRole))
  {
    return positionAfterr6MinRole;
  }
  uint8_t r6MinRole = Input[(uint32_t)positionAfterr6Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes21 = 4ULL <= (InputLength - positionAfterr6MinRole);
  uint64_t positionAfterMonoAccess1620;
  if (hasBytes21)
  {
    positionAfterMonoAccess1620 = positionAfterr6MinRole + 4ULL;
  }
  else
  {
    positionAfterMonoAccess1620 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6MinRole);
  }
  uint64_t positionAfterr7PathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess1620))
  {
    positionAfterr7PathHash = positionAfterMonoAccess1620;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r7_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1620),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1620),
      Ctxt,
      Input,
      positionAfterr6MinRole);
    positionAfterr7PathHash = positionAfterMonoAccess1620;
  }
  if (EverParseIsError(positionAfterr7PathHash))
  {
    return positionAfterr7PathHash;
  }
  uint32_t r7PathHash = Load32Le(Input + (uint32_t)positionAfterr6MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes22 = 1ULL <= (InputLength - positionAfterr7PathHash);
  uint64_t positionAfterMonoAccess1621;
  if (hasBytes22)
  {
    positionAfterMonoAccess1621 = positionAfterr7PathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1621 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7PathHash);
  }
  uint64_t positionAfterr7Method;
  if (EverParseIsSuccess(positionAfterMonoAccess1621))
  {
    positionAfterr7Method = positionAfterMonoAccess1621;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r7_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1621),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1621),
      Ctxt,
      Input,
      positionAfterr7PathHash);
    positionAfterr7Method = positionAfterMonoAccess1621;
  }
  if (EverParseIsError(positionAfterr7Method))
  {
    return positionAfterr7Method;
  }
  uint8_t r7Method = Input[(uint32_t)positionAfterr7PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes23 = 1ULL <= (InputLength - positionAfterr7Method);
  uint64_t positionAfterMonoAccess1622;
  if (hasBytes23)
  {
    positionAfterMonoAccess1622 = positionAfterr7Method + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1622 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7Method);
  }
  uint64_t positionAfterr7MinRole;
  if (EverParseIsSuccess(positionAfterMonoAccess1622))
  {
    positionAfterr7MinRole = positionAfterMonoAccess1622;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r7_min_role",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1622),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1622),
      Ctxt,
      Input,
      positionAfterr7Method);
    positionAfterr7MinRole = positionAfterMonoAccess1622;
  }
  if (EverParseIsError(positionAfterr7MinRole))
  {
    return positionAfterr7MinRole;
  }
  uint8_t r7MinRole = Input[(uint32_t)positionAfterr7Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes24 = 4ULL <= (InputLength - positionAfterr7MinRole);
  uint64_t positionAfterMonoAccess1623;
  if (hasBytes24)
  {
    positionAfterMonoAccess1623 = positionAfterr7MinRole + 4ULL;
  }
  else
  {
    positionAfterMonoAccess1623 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7MinRole);
  }
  uint64_t positionAfterr8PathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess1623))
  {
    positionAfterr8PathHash = positionAfterMonoAccess1623;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r8_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1623),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1623),
      Ctxt,
      Input,
      positionAfterr7MinRole);
    positionAfterr8PathHash = positionAfterMonoAccess1623;
  }
  if (EverParseIsError(positionAfterr8PathHash))
  {
    return positionAfterr8PathHash;
  }
  uint32_t r8PathHash = Load32Le(Input + (uint32_t)positionAfterr7MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes25 = 1ULL <= (InputLength - positionAfterr8PathHash);
  uint64_t positionAfterMonoAccess1624;
  if (hasBytes25)
  {
    positionAfterMonoAccess1624 = positionAfterr8PathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1624 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr8PathHash);
  }
  uint64_t positionAfterr8Method;
  if (EverParseIsSuccess(positionAfterMonoAccess1624))
  {
    positionAfterr8Method = positionAfterMonoAccess1624;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r8_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1624),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1624),
      Ctxt,
      Input,
      positionAfterr8PathHash);
    positionAfterr8Method = positionAfterMonoAccess1624;
  }
  if (EverParseIsError(positionAfterr8Method))
  {
    return positionAfterr8Method;
  }
  uint8_t r8Method = Input[(uint32_t)positionAfterr8PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes26 = 1ULL <= (InputLength - positionAfterr8Method);
  uint64_t positionAfterMonoAccess1625;
  if (hasBytes26)
  {
    positionAfterMonoAccess1625 = positionAfterr8Method + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1625 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr8Method);
  }
  uint64_t positionAfterr8MinRole;
  if (EverParseIsSuccess(positionAfterMonoAccess1625))
  {
    positionAfterr8MinRole = positionAfterMonoAccess1625;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r8_min_role",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1625),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1625),
      Ctxt,
      Input,
      positionAfterr8Method);
    positionAfterr8MinRole = positionAfterMonoAccess1625;
  }
  if (EverParseIsError(positionAfterr8MinRole))
  {
    return positionAfterr8MinRole;
  }
  uint8_t r8MinRole = Input[(uint32_t)positionAfterr8Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes27 = 4ULL <= (InputLength - positionAfterr8MinRole);
  uint64_t positionAfterMonoAccess1626;
  if (hasBytes27)
  {
    positionAfterMonoAccess1626 = positionAfterr8MinRole + 4ULL;
  }
  else
  {
    positionAfterMonoAccess1626 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr8MinRole);
  }
  uint64_t positionAfterr9PathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess1626))
  {
    positionAfterr9PathHash = positionAfterMonoAccess1626;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r9_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1626),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1626),
      Ctxt,
      Input,
      positionAfterr8MinRole);
    positionAfterr9PathHash = positionAfterMonoAccess1626;
  }
  if (EverParseIsError(positionAfterr9PathHash))
  {
    return positionAfterr9PathHash;
  }
  uint32_t r9PathHash = Load32Le(Input + (uint32_t)positionAfterr8MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes28 = 1ULL <= (InputLength - positionAfterr9PathHash);
  uint64_t positionAfterMonoAccess1627;
  if (hasBytes28)
  {
    positionAfterMonoAccess1627 = positionAfterr9PathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1627 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr9PathHash);
  }
  uint64_t positionAfterr9Method;
  if (EverParseIsSuccess(positionAfterMonoAccess1627))
  {
    positionAfterr9Method = positionAfterMonoAccess1627;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r9_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1627),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1627),
      Ctxt,
      Input,
      positionAfterr9PathHash);
    positionAfterr9Method = positionAfterMonoAccess1627;
  }
  if (EverParseIsError(positionAfterr9Method))
  {
    return positionAfterr9Method;
  }
  uint8_t r9Method = Input[(uint32_t)positionAfterr9PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes29 = 1ULL <= (InputLength - positionAfterr9Method);
  uint64_t positionAfterMonoAccess1628;
  if (hasBytes29)
  {
    positionAfterMonoAccess1628 = positionAfterr9Method + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1628 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr9Method);
  }
  uint64_t positionAfterr9MinRole;
  if (EverParseIsSuccess(positionAfterMonoAccess1628))
  {
    positionAfterr9MinRole = positionAfterMonoAccess1628;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r9_min_role",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1628),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1628),
      Ctxt,
      Input,
      positionAfterr9Method);
    positionAfterr9MinRole = positionAfterMonoAccess1628;
  }
  if (EverParseIsError(positionAfterr9MinRole))
  {
    return positionAfterr9MinRole;
  }
  uint8_t r9MinRole = Input[(uint32_t)positionAfterr9Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes30 = 4ULL <= (InputLength - positionAfterr9MinRole);
  uint64_t positionAfterMonoAccess1629;
  if (hasBytes30)
  {
    positionAfterMonoAccess1629 = positionAfterr9MinRole + 4ULL;
  }
  else
  {
    positionAfterMonoAccess1629 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr9MinRole);
  }
  uint64_t positionAfterr10PathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess1629))
  {
    positionAfterr10PathHash = positionAfterMonoAccess1629;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r10_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1629),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1629),
      Ctxt,
      Input,
      positionAfterr9MinRole);
    positionAfterr10PathHash = positionAfterMonoAccess1629;
  }
  if (EverParseIsError(positionAfterr10PathHash))
  {
    return positionAfterr10PathHash;
  }
  uint32_t r10PathHash = Load32Le(Input + (uint32_t)positionAfterr9MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes31 = 1ULL <= (InputLength - positionAfterr10PathHash);
  uint64_t positionAfterMonoAccess1630;
  if (hasBytes31)
  {
    positionAfterMonoAccess1630 = positionAfterr10PathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1630 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr10PathHash);
  }
  uint64_t positionAfterr10Method;
  if (EverParseIsSuccess(positionAfterMonoAccess1630))
  {
    positionAfterr10Method = positionAfterMonoAccess1630;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r10_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1630),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1630),
      Ctxt,
      Input,
      positionAfterr10PathHash);
    positionAfterr10Method = positionAfterMonoAccess1630;
  }
  if (EverParseIsError(positionAfterr10Method))
  {
    return positionAfterr10Method;
  }
  uint8_t r10Method = Input[(uint32_t)positionAfterr10PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes32 = 1ULL <= (InputLength - positionAfterr10Method);
  uint64_t positionAfterMonoAccess1631;
  if (hasBytes32)
  {
    positionAfterMonoAccess1631 = positionAfterr10Method + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1631 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr10Method);
  }
  uint64_t positionAfterr10MinRole;
  if (EverParseIsSuccess(positionAfterMonoAccess1631))
  {
    positionAfterr10MinRole = positionAfterMonoAccess1631;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r10_min_role",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1631),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1631),
      Ctxt,
      Input,
      positionAfterr10Method);
    positionAfterr10MinRole = positionAfterMonoAccess1631;
  }
  if (EverParseIsError(positionAfterr10MinRole))
  {
    return positionAfterr10MinRole;
  }
  uint8_t r10MinRole = Input[(uint32_t)positionAfterr10Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes33 = 4ULL <= (InputLength - positionAfterr10MinRole);
  uint64_t positionAfterMonoAccess1632;
  if (hasBytes33)
  {
    positionAfterMonoAccess1632 = positionAfterr10MinRole + 4ULL;
  }
  else
  {
    positionAfterMonoAccess1632 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr10MinRole);
  }
  uint64_t positionAfterr11PathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess1632))
  {
    positionAfterr11PathHash = positionAfterMonoAccess1632;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r11_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1632),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1632),
      Ctxt,
      Input,
      positionAfterr10MinRole);
    positionAfterr11PathHash = positionAfterMonoAccess1632;
  }
  if (EverParseIsError(positionAfterr11PathHash))
  {
    return positionAfterr11PathHash;
  }
  uint32_t r11PathHash = Load32Le(Input + (uint32_t)positionAfterr10MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes34 = 1ULL <= (InputLength - positionAfterr11PathHash);
  uint64_t positionAfterMonoAccess1633;
  if (hasBytes34)
  {
    positionAfterMonoAccess1633 = positionAfterr11PathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1633 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr11PathHash);
  }
  uint64_t positionAfterr11Method;
  if (EverParseIsSuccess(positionAfterMonoAccess1633))
  {
    positionAfterr11Method = positionAfterMonoAccess1633;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r11_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1633),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1633),
      Ctxt,
      Input,
      positionAfterr11PathHash);
    positionAfterr11Method = positionAfterMonoAccess1633;
  }
  if (EverParseIsError(positionAfterr11Method))
  {
    return positionAfterr11Method;
  }
  uint8_t r11Method = Input[(uint32_t)positionAfterr11PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes35 = 1ULL <= (InputLength - positionAfterr11Method);
  uint64_t positionAfterMonoAccess1634;
  if (hasBytes35)
  {
    positionAfterMonoAccess1634 = positionAfterr11Method + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1634 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr11Method);
  }
  uint64_t positionAfterr11MinRole;
  if (EverParseIsSuccess(positionAfterMonoAccess1634))
  {
    positionAfterr11MinRole = positionAfterMonoAccess1634;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r11_min_role",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1634),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1634),
      Ctxt,
      Input,
      positionAfterr11Method);
    positionAfterr11MinRole = positionAfterMonoAccess1634;
  }
  if (EverParseIsError(positionAfterr11MinRole))
  {
    return positionAfterr11MinRole;
  }
  uint8_t r11MinRole = Input[(uint32_t)positionAfterr11Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes36 = 4ULL <= (InputLength - positionAfterr11MinRole);
  uint64_t positionAfterMonoAccess1635;
  if (hasBytes36)
  {
    positionAfterMonoAccess1635 = positionAfterr11MinRole + 4ULL;
  }
  else
  {
    positionAfterMonoAccess1635 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr11MinRole);
  }
  uint64_t positionAfterr12PathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess1635))
  {
    positionAfterr12PathHash = positionAfterMonoAccess1635;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r12_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1635),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1635),
      Ctxt,
      Input,
      positionAfterr11MinRole);
    positionAfterr12PathHash = positionAfterMonoAccess1635;
  }
  if (EverParseIsError(positionAfterr12PathHash))
  {
    return positionAfterr12PathHash;
  }
  uint32_t r12PathHash = Load32Le(Input + (uint32_t)positionAfterr11MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes37 = 1ULL <= (InputLength - positionAfterr12PathHash);
  uint64_t positionAfterMonoAccess1636;
  if (hasBytes37)
  {
    positionAfterMonoAccess1636 = positionAfterr12PathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1636 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr12PathHash);
  }
  uint64_t positionAfterr12Method;
  if (EverParseIsSuccess(positionAfterMonoAccess1636))
  {
    positionAfterr12Method = positionAfterMonoAccess1636;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r12_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1636),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1636),
      Ctxt,
      Input,
      positionAfterr12PathHash);
    positionAfterr12Method = positionAfterMonoAccess1636;
  }
  if (EverParseIsError(positionAfterr12Method))
  {
    return positionAfterr12Method;
  }
  uint8_t r12Method = Input[(uint32_t)positionAfterr12PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes38 = 1ULL <= (InputLength - positionAfterr12Method);
  uint64_t positionAfterMonoAccess1637;
  if (hasBytes38)
  {
    positionAfterMonoAccess1637 = positionAfterr12Method + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1637 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr12Method);
  }
  uint64_t positionAfterr12MinRole;
  if (EverParseIsSuccess(positionAfterMonoAccess1637))
  {
    positionAfterr12MinRole = positionAfterMonoAccess1637;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r12_min_role",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1637),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1637),
      Ctxt,
      Input,
      positionAfterr12Method);
    positionAfterr12MinRole = positionAfterMonoAccess1637;
  }
  if (EverParseIsError(positionAfterr12MinRole))
  {
    return positionAfterr12MinRole;
  }
  uint8_t r12MinRole = Input[(uint32_t)positionAfterr12Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes39 = 4ULL <= (InputLength - positionAfterr12MinRole);
  uint64_t positionAfterMonoAccess1638;
  if (hasBytes39)
  {
    positionAfterMonoAccess1638 = positionAfterr12MinRole + 4ULL;
  }
  else
  {
    positionAfterMonoAccess1638 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr12MinRole);
  }
  uint64_t positionAfterr13PathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess1638))
  {
    positionAfterr13PathHash = positionAfterMonoAccess1638;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r13_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1638),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1638),
      Ctxt,
      Input,
      positionAfterr12MinRole);
    positionAfterr13PathHash = positionAfterMonoAccess1638;
  }
  if (EverParseIsError(positionAfterr13PathHash))
  {
    return positionAfterr13PathHash;
  }
  uint32_t r13PathHash = Load32Le(Input + (uint32_t)positionAfterr12MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes40 = 1ULL <= (InputLength - positionAfterr13PathHash);
  uint64_t positionAfterMonoAccess1639;
  if (hasBytes40)
  {
    positionAfterMonoAccess1639 = positionAfterr13PathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1639 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr13PathHash);
  }
  uint64_t positionAfterr13Method;
  if (EverParseIsSuccess(positionAfterMonoAccess1639))
  {
    positionAfterr13Method = positionAfterMonoAccess1639;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r13_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1639),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1639),
      Ctxt,
      Input,
      positionAfterr13PathHash);
    positionAfterr13Method = positionAfterMonoAccess1639;
  }
  if (EverParseIsError(positionAfterr13Method))
  {
    return positionAfterr13Method;
  }
  uint8_t r13Method = Input[(uint32_t)positionAfterr13PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes41 = 1ULL <= (InputLength - positionAfterr13Method);
  uint64_t positionAfterMonoAccess1640;
  if (hasBytes41)
  {
    positionAfterMonoAccess1640 = positionAfterr13Method + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1640 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr13Method);
  }
  uint64_t positionAfterr13MinRole;
  if (EverParseIsSuccess(positionAfterMonoAccess1640))
  {
    positionAfterr13MinRole = positionAfterMonoAccess1640;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r13_min_role",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1640),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1640),
      Ctxt,
      Input,
      positionAfterr13Method);
    positionAfterr13MinRole = positionAfterMonoAccess1640;
  }
  if (EverParseIsError(positionAfterr13MinRole))
  {
    return positionAfterr13MinRole;
  }
  uint8_t r13MinRole = Input[(uint32_t)positionAfterr13Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes42 = 4ULL <= (InputLength - positionAfterr13MinRole);
  uint64_t positionAfterMonoAccess1641;
  if (hasBytes42)
  {
    positionAfterMonoAccess1641 = positionAfterr13MinRole + 4ULL;
  }
  else
  {
    positionAfterMonoAccess1641 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr13MinRole);
  }
  uint64_t positionAfterr14PathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess1641))
  {
    positionAfterr14PathHash = positionAfterMonoAccess1641;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r14_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1641),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1641),
      Ctxt,
      Input,
      positionAfterr13MinRole);
    positionAfterr14PathHash = positionAfterMonoAccess1641;
  }
  if (EverParseIsError(positionAfterr14PathHash))
  {
    return positionAfterr14PathHash;
  }
  uint32_t r14PathHash = Load32Le(Input + (uint32_t)positionAfterr13MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes43 = 1ULL <= (InputLength - positionAfterr14PathHash);
  uint64_t positionAfterMonoAccess1642;
  if (hasBytes43)
  {
    positionAfterMonoAccess1642 = positionAfterr14PathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1642 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr14PathHash);
  }
  uint64_t positionAfterr14Method;
  if (EverParseIsSuccess(positionAfterMonoAccess1642))
  {
    positionAfterr14Method = positionAfterMonoAccess1642;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r14_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1642),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1642),
      Ctxt,
      Input,
      positionAfterr14PathHash);
    positionAfterr14Method = positionAfterMonoAccess1642;
  }
  if (EverParseIsError(positionAfterr14Method))
  {
    return positionAfterr14Method;
  }
  uint8_t r14Method = Input[(uint32_t)positionAfterr14PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes44 = 1ULL <= (InputLength - positionAfterr14Method);
  uint64_t positionAfterMonoAccess1643;
  if (hasBytes44)
  {
    positionAfterMonoAccess1643 = positionAfterr14Method + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1643 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr14Method);
  }
  uint64_t positionAfterr14MinRole;
  if (EverParseIsSuccess(positionAfterMonoAccess1643))
  {
    positionAfterr14MinRole = positionAfterMonoAccess1643;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r14_min_role",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1643),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1643),
      Ctxt,
      Input,
      positionAfterr14Method);
    positionAfterr14MinRole = positionAfterMonoAccess1643;
  }
  if (EverParseIsError(positionAfterr14MinRole))
  {
    return positionAfterr14MinRole;
  }
  uint8_t r14MinRole = Input[(uint32_t)positionAfterr14Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes45 = 4ULL <= (InputLength - positionAfterr14MinRole);
  uint64_t positionAfterMonoAccess1644;
  if (hasBytes45)
  {
    positionAfterMonoAccess1644 = positionAfterr14MinRole + 4ULL;
  }
  else
  {
    positionAfterMonoAccess1644 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr14MinRole);
  }
  uint64_t positionAfterr15PathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess1644))
  {
    positionAfterr15PathHash = positionAfterMonoAccess1644;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r15_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1644),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1644),
      Ctxt,
      Input,
      positionAfterr14MinRole);
    positionAfterr15PathHash = positionAfterMonoAccess1644;
  }
  if (EverParseIsError(positionAfterr15PathHash))
  {
    return positionAfterr15PathHash;
  }
  uint32_t r15PathHash = Load32Le(Input + (uint32_t)positionAfterr14MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes46 = 1ULL <= (InputLength - positionAfterr15PathHash);
  uint64_t positionAfterMonoAccess1645;
  if (hasBytes46)
  {
    positionAfterMonoAccess1645 = positionAfterr15PathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1645 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr15PathHash);
  }
  uint64_t positionAfterr15Method;
  if (EverParseIsSuccess(positionAfterMonoAccess1645))
  {
    positionAfterr15Method = positionAfterMonoAccess1645;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r15_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1645),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1645),
      Ctxt,
      Input,
      positionAfterr15PathHash);
    positionAfterr15Method = positionAfterMonoAccess1645;
  }
  if (EverParseIsError(positionAfterr15Method))
  {
    return positionAfterr15Method;
  }
  uint8_t r15Method = Input[(uint32_t)positionAfterr15PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes47 = 1ULL <= (InputLength - positionAfterr15Method);
  uint64_t positionAfterMonoAccess1646;
  if (hasBytes47)
  {
    positionAfterMonoAccess1646 = positionAfterr15Method + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1646 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr15Method);
  }
  uint64_t positionAfterr15MinRole;
  if (EverParseIsSuccess(positionAfterMonoAccess1646))
  {
    positionAfterr15MinRole = positionAfterMonoAccess1646;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "r15_min_role",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1646),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1646),
      Ctxt,
      Input,
      positionAfterr15Method);
    positionAfterr15MinRole = positionAfterMonoAccess1646;
  }
  if (EverParseIsError(positionAfterr15MinRole))
  {
    return positionAfterr15MinRole;
  }
  uint8_t r15MinRole = Input[(uint32_t)positionAfterr15Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes48 = 4ULL <= (InputLength - positionAfterr15MinRole);
  uint64_t positionAfterMonoAccess1647;
  if (hasBytes48)
  {
    positionAfterMonoAccess1647 = positionAfterr15MinRole + 4ULL;
  }
  else
  {
    positionAfterMonoAccess1647 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr15MinRole);
  }
  uint64_t positionAfterreqPathHash;
  if (EverParseIsSuccess(positionAfterMonoAccess1647))
  {
    positionAfterreqPathHash = positionAfterMonoAccess1647;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "req_path_hash",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1647),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1647),
      Ctxt,
      Input,
      positionAfterr15MinRole);
    positionAfterreqPathHash = positionAfterMonoAccess1647;
  }
  if (EverParseIsError(positionAfterreqPathHash))
  {
    return positionAfterreqPathHash;
  }
  uint32_t reqPathHash = Load32Le(Input + (uint32_t)positionAfterr15MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes49 = 1ULL <= (InputLength - positionAfterreqPathHash);
  uint64_t positionAfterMonoAccess1648;
  if (hasBytes49)
  {
    positionAfterMonoAccess1648 = positionAfterreqPathHash + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1648 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqPathHash);
  }
  uint64_t positionAfterreqMethod;
  if (EverParseIsSuccess(positionAfterMonoAccess1648))
  {
    positionAfterreqMethod = positionAfterMonoAccess1648;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "req_method",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1648),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1648),
      Ctxt,
      Input,
      positionAfterreqPathHash);
    positionAfterreqMethod = positionAfterMonoAccess1648;
  }
  if (EverParseIsError(positionAfterreqMethod))
  {
    return positionAfterreqMethod;
  }
  uint8_t reqMethod = Input[(uint32_t)positionAfterreqPathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes50 = 1ULL <= (InputLength - positionAfterreqMethod);
  uint64_t positionAfterMonoAccess1649;
  if (hasBytes50)
  {
    positionAfterMonoAccess1649 = positionAfterreqMethod + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1649 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqMethod);
  }
  uint64_t positionAfterauthState;
  if (EverParseIsSuccess(positionAfterMonoAccess1649))
  {
    positionAfterauthState = positionAfterMonoAccess1649;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "auth_state",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1649),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1649),
      Ctxt,
      Input,
      positionAfterreqMethod);
    positionAfterauthState = positionAfterMonoAccess1649;
  }
  if (EverParseIsError(positionAfterauthState))
  {
    return positionAfterauthState;
  }
  uint8_t authState = Input[(uint32_t)positionAfterreqMethod];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes51 = 1ULL <= (InputLength - positionAfterauthState);
  uint64_t positionAfterMonoAccess1650;
  if (hasBytes51)
  {
    positionAfterMonoAccess1650 = positionAfterauthState + 1ULL;
  }
  else
  {
    positionAfterMonoAccess1650 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterauthState);
  }
  uint64_t positionAfterrateCount;
  if (EverParseIsSuccess(positionAfterMonoAccess1650))
  {
    positionAfterrateCount = positionAfterMonoAccess1650;
  }
  else
  {
    ErrorHandlerFn("_MonoAccess16",
      "rate_count",
      EverParseErrorReasonOfResult(positionAfterMonoAccess1650),
      EverParseGetValidatorErrorKind(positionAfterMonoAccess1650),
      Ctxt,
      Input,
      positionAfterauthState);
    positionAfterrateCount = positionAfterMonoAccess1650;
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
  uint64_t positionAfterMonoAccess1651;
  if (EverParseIsError(positionAfterRateOk))
  {
    positionAfterMonoAccess1651 = positionAfterRateOk;
  }
  else
  {
    uint8_t rateOk = Input[(uint32_t)positionAfterrateCount];
    KRML_MAYBE_UNUSED_VAR(rateOk);
    BOOLEAN rateOkConstraintIsOk = rateCount < MONOACCESS16____MAX_RATE;
    uint64_t
    positionAfterRateOk1 = EverParseCheckConstraintOk(rateOkConstraintIsOk, positionAfterRateOk);
    if (EverParseIsError(positionAfterRateOk1))
    {
      positionAfterMonoAccess1651 = positionAfterRateOk1;
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
      uint64_t positionAfterMonoAccess1652;
      if (EverParseIsError(positionAfterAccessOk_refinement))
      {
        positionAfterMonoAccess1652 = positionAfterAccessOk_refinement;
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
        positionAfterMonoAccess1652 =
          EverParseCheckConstraintOk(accessOk_refinementConstraintIsOk,
            positionAfterAccessOk_refinement);
      }
      if (EverParseIsSuccess(positionAfterMonoAccess1652))
      {
        positionAfterMonoAccess1651 = positionAfterMonoAccess1652;
      }
      else
      {
        ErrorHandlerFn("_MonoAccess16",
          "_access_ok.refinement",
          EverParseErrorReasonOfResult(positionAfterMonoAccess1652),
          EverParseGetValidatorErrorKind(positionAfterMonoAccess1652),
          Ctxt,
          Input,
          positionAfterRateOk1);
        positionAfterMonoAccess1651 = positionAfterMonoAccess1652;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterMonoAccess1651))
  {
    return positionAfterMonoAccess1651;
  }
  ErrorHandlerFn("_MonoAccess16",
    "_rate_ok",
    EverParseErrorReasonOfResult(positionAfterMonoAccess1651),
    EverParseGetValidatorErrorKind(positionAfterMonoAccess1651),
    Ctxt,
    Input,
    positionAfterrateCount);
  return positionAfterMonoAccess1651;
}

