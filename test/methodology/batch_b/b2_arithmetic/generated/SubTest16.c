

#include "SubTest16.h"

uint64_t
SubTest16ValidateSubTest16(
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
  uint64_t positionAfterSubTest16;
  if (hasBytes0)
  {
    positionAfterSubTest16 = StartPosition + 2ULL;
  }
  else
  {
    positionAfterSubTest16 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAftermsgTotal;
  if (EverParseIsSuccess(positionAfterSubTest16))
  {
    positionAftermsgTotal = positionAfterSubTest16;
  }
  else
  {
    ErrorHandlerFn("_SubTest16",
      "msg_total",
      EverParseErrorReasonOfResult(positionAfterSubTest16),
      EverParseGetValidatorErrorKind(positionAfterSubTest16),
      Ctxt,
      Input,
      StartPosition);
    positionAftermsgTotal = positionAfterSubTest16;
  }
  if (EverParseIsError(positionAftermsgTotal))
  {
    return positionAftermsgTotal;
  }
  uint16_t r0 = Load16Le(Input + (uint32_t)StartPosition);
  uint16_t msgTotal = (uint16_t)(uint32_t)r0;
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes1 = 2ULL <= (InputLength - positionAftermsgTotal);
  uint64_t positionAfterSubTest160;
  if (hasBytes1)
  {
    positionAfterSubTest160 = positionAftermsgTotal + 2ULL;
  }
  else
  {
    positionAfterSubTest160 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftermsgTotal);
  }
  uint64_t positionAftermsgHeader;
  if (EverParseIsSuccess(positionAfterSubTest160))
  {
    positionAftermsgHeader = positionAfterSubTest160;
  }
  else
  {
    ErrorHandlerFn("_SubTest16",
      "msg_header",
      EverParseErrorReasonOfResult(positionAfterSubTest160),
      EverParseGetValidatorErrorKind(positionAfterSubTest160),
      Ctxt,
      Input,
      positionAftermsgTotal);
    positionAftermsgHeader = positionAfterSubTest160;
  }
  if (EverParseIsError(positionAftermsgHeader))
  {
    return positionAftermsgHeader;
  }
  uint16_t r1 = Load16Le(Input + (uint32_t)positionAftermsgTotal);
  uint16_t msgHeader = (uint16_t)(uint32_t)r1;
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes2 = 2ULL <= (InputLength - positionAftermsgHeader);
  uint64_t positionAfterSubTest161;
  if (hasBytes2)
  {
    positionAfterSubTest161 = positionAftermsgHeader + 2ULL;
  }
  else
  {
    positionAfterSubTest161 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftermsgHeader);
  }
  uint64_t positionAfterexpectedBody;
  if (EverParseIsSuccess(positionAfterSubTest161))
  {
    positionAfterexpectedBody = positionAfterSubTest161;
  }
  else
  {
    ErrorHandlerFn("_SubTest16",
      "expected_body",
      EverParseErrorReasonOfResult(positionAfterSubTest161),
      EverParseGetValidatorErrorKind(positionAfterSubTest161),
      Ctxt,
      Input,
      positionAftermsgHeader);
    positionAfterexpectedBody = positionAfterSubTest161;
  }
  if (EverParseIsError(positionAfterexpectedBody))
  {
    return positionAfterexpectedBody;
  }
  uint16_t r = Load16Le(Input + (uint32_t)positionAftermsgHeader);
  uint16_t expectedBody = (uint16_t)(uint32_t)r;
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes3 = 1ULL <= (InputLength - positionAfterexpectedBody);
  uint64_t positionAfterGuard;
  if (hasBytes3)
  {
    positionAfterGuard = positionAfterexpectedBody + 1ULL;
  }
  else
  {
    positionAfterGuard =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterexpectedBody);
  }
  uint64_t positionAfterSubTest162;
  if (EverParseIsError(positionAfterGuard))
  {
    positionAfterSubTest162 = positionAfterGuard;
  }
  else
  {
    uint8_t guard = Input[(uint32_t)positionAfterexpectedBody];
    KRML_MAYBE_UNUSED_VAR(guard);
    BOOLEAN guardConstraintIsOk = msgTotal >= msgHeader;
    uint64_t
    positionAfterGuard1 = EverParseCheckConstraintOk(guardConstraintIsOk, positionAfterGuard);
    if (EverParseIsError(positionAfterGuard1))
    {
      positionAfterSubTest162 = positionAfterGuard1;
    }
    else
    {
      /* Validating field _check */
      /* Checking that we have enough space for a UINT8, i.e., 1 byte */
      BOOLEAN hasBytes = 1ULL <= (InputLength - positionAfterGuard1);
      uint64_t positionAfterCheck_refinement;
      if (hasBytes)
      {
        positionAfterCheck_refinement = positionAfterGuard1 + 1ULL;
      }
      else
      {
        positionAfterCheck_refinement =
          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterGuard1);
      }
      uint64_t positionAfterSubTest163;
      if (EverParseIsError(positionAfterCheck_refinement))
      {
        positionAfterSubTest163 = positionAfterCheck_refinement;
      }
      else
      {
        /* reading field_value */
        uint8_t check_refinement = Input[(uint32_t)positionAfterGuard1];
        KRML_MAYBE_UNUSED_VAR(check_refinement);
        /* start: checking constraint */
        BOOLEAN
        check_refinementConstraintIsOk = expectedBody == (uint32_t)msgTotal - (uint32_t)msgHeader;
        /* end: checking constraint */
        positionAfterSubTest163 =
          EverParseCheckConstraintOk(check_refinementConstraintIsOk,
            positionAfterCheck_refinement);
      }
      if (EverParseIsSuccess(positionAfterSubTest163))
      {
        positionAfterSubTest162 = positionAfterSubTest163;
      }
      else
      {
        ErrorHandlerFn("_SubTest16",
          "_check.refinement",
          EverParseErrorReasonOfResult(positionAfterSubTest163),
          EverParseGetValidatorErrorKind(positionAfterSubTest163),
          Ctxt,
          Input,
          positionAfterGuard1);
        positionAfterSubTest162 = positionAfterSubTest163;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterSubTest162))
  {
    return positionAfterSubTest162;
  }
  ErrorHandlerFn("_SubTest16",
    "_guard",
    EverParseErrorReasonOfResult(positionAfterSubTest162),
    EverParseGetValidatorErrorKind(positionAfterSubTest162),
    Ctxt,
    Input,
    positionAfterexpectedBody);
  return positionAfterSubTest162;
}

