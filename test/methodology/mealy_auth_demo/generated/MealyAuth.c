

#include "MealyAuth.h"

uint64_t
MealyAuthValidateLoginRequest(
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
  /* Validating field auth_state */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes0 = 1ULL <= (InputLength - StartPosition);
  uint64_t positionAfterLoginRequest;
  if (hasBytes0)
  {
    positionAfterLoginRequest = StartPosition + 1ULL;
  }
  else
  {
    positionAfterLoginRequest =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t res0;
  if (EverParseIsSuccess(positionAfterLoginRequest))
  {
    res0 = positionAfterLoginRequest;
  }
  else
  {
    ErrorHandlerFn("_LoginRequest",
      "auth_state",
      EverParseErrorReasonOfResult(positionAfterLoginRequest),
      EverParseGetValidatorErrorKind(positionAfterLoginRequest),
      Ctxt,
      Input,
      StartPosition);
    res0 = positionAfterLoginRequest;
  }
  uint64_t positionAfterauthState = res0;
  if (EverParseIsError(positionAfterauthState))
  {
    return positionAfterauthState;
  }
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAfterauthState);
  uint64_t positionAfterLoginRequest0;
  if (hasBytes1)
  {
    positionAfterLoginRequest0 = positionAfterauthState + 1ULL;
  }
  else
  {
    positionAfterLoginRequest0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterauthState);
  }
  uint64_t positionAfterrateCount;
  if (EverParseIsSuccess(positionAfterLoginRequest0))
  {
    positionAfterrateCount = positionAfterLoginRequest0;
  }
  else
  {
    ErrorHandlerFn("_LoginRequest",
      "rate_count",
      EverParseErrorReasonOfResult(positionAfterLoginRequest0),
      EverParseGetValidatorErrorKind(positionAfterLoginRequest0),
      Ctxt,
      Input,
      positionAfterauthState);
    positionAfterrateCount = positionAfterLoginRequest0;
  }
  if (EverParseIsError(positionAfterrateCount))
  {
    return positionAfterrateCount;
  }
  uint8_t rateCount = Input[(uint32_t)positionAfterauthState];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes2 = 4ULL <= (InputLength - positionAfterrateCount);
  uint64_t positionAfterLoginRequest1;
  if (hasBytes2)
  {
    positionAfterLoginRequest1 = positionAfterrateCount + 4ULL;
  }
  else
  {
    positionAfterLoginRequest1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrateCount);
  }
  uint64_t positionAfterpathHash;
  if (EverParseIsSuccess(positionAfterLoginRequest1))
  {
    positionAfterpathHash = positionAfterLoginRequest1;
  }
  else
  {
    ErrorHandlerFn("_LoginRequest",
      "path_hash",
      EverParseErrorReasonOfResult(positionAfterLoginRequest1),
      EverParseGetValidatorErrorKind(positionAfterLoginRequest1),
      Ctxt,
      Input,
      positionAfterrateCount);
    positionAfterpathHash = positionAfterLoginRequest1;
  }
  if (EverParseIsError(positionAfterpathHash))
  {
    return positionAfterpathHash;
  }
  uint32_t pathHash = Load32Le(Input + (uint32_t)positionAfterrateCount);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes3 = 1ULL <= (InputLength - positionAfterpathHash);
  uint64_t positionAfterLoginRequest2;
  if (hasBytes3)
  {
    positionAfterLoginRequest2 = positionAfterpathHash + 1ULL;
  }
  else
  {
    positionAfterLoginRequest2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterpathHash);
  }
  uint64_t positionAftermethod;
  if (EverParseIsSuccess(positionAfterLoginRequest2))
  {
    positionAftermethod = positionAfterLoginRequest2;
  }
  else
  {
    ErrorHandlerFn("_LoginRequest",
      "method",
      EverParseErrorReasonOfResult(positionAfterLoginRequest2),
      EverParseGetValidatorErrorKind(positionAfterLoginRequest2),
      Ctxt,
      Input,
      positionAfterpathHash);
    positionAftermethod = positionAfterLoginRequest2;
  }
  if (EverParseIsError(positionAftermethod))
  {
    return positionAftermethod;
  }
  uint8_t method = Input[(uint32_t)positionAfterpathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAftermethod);
  uint64_t positionAfterCheck;
  if (hasBytes4)
  {
    positionAfterCheck = positionAftermethod + 1ULL;
  }
  else
  {
    positionAfterCheck =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftermethod);
  }
  uint64_t positionAfterLoginRequest3;
  if (EverParseIsError(positionAfterCheck))
  {
    positionAfterLoginRequest3 = positionAfterCheck;
  }
  else
  {
    uint8_t check = Input[(uint32_t)positionAftermethod];
    KRML_MAYBE_UNUSED_VAR(check);
    BOOLEAN
    checkConstraintIsOk =
      pathHash == MEALYAUTH____PATH_LOGIN && method == MEALYAUTH____METHOD_POST &&
        rateCount < MEALYAUTH____MAX_RATE;
    uint64_t
    positionAfterCheck1 = EverParseCheckConstraintOk(checkConstraintIsOk, positionAfterCheck);
    if (EverParseIsError(positionAfterCheck1))
    {
      positionAfterLoginRequest3 = positionAfterCheck1;
    }
    else
    {
      /* Checking that we have enough space for a UINT8, i.e., 1 byte */
      BOOLEAN hasBytes5 = 1ULL <= (InputLength - positionAfterCheck1);
      uint64_t positionAfterusernameLen;
      if (hasBytes5)
      {
        positionAfterusernameLen = positionAfterCheck1 + 1ULL;
      }
      else
      {
        positionAfterusernameLen =
          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterCheck1);
      }
      uint64_t positionAfterLoginRequest4;
      if (EverParseIsError(positionAfterusernameLen))
      {
        positionAfterLoginRequest4 = positionAfterusernameLen;
      }
      else
      {
        uint8_t usernameLen = Input[(uint32_t)positionAfterCheck1];
        BOOLEAN usernameLenConstraintIsOk = usernameLen >= 1U && usernameLen <= 32U;
        uint64_t
        positionAfterusernameLen1 =
          EverParseCheckConstraintOk(usernameLenConstraintIsOk,
            positionAfterusernameLen);
        if (EverParseIsError(positionAfterusernameLen1))
        {
          positionAfterLoginRequest4 = positionAfterusernameLen1;
        }
        else
        {
          /* Validating field username */
          BOOLEAN
          hasBytes6 = (uint64_t)(uint32_t)usernameLen <= (InputLength - positionAfterusernameLen1);
          uint64_t res1;
          if (hasBytes6)
          {
            res1 = positionAfterusernameLen1 + (uint64_t)(uint32_t)usernameLen;
          }
          else
          {
            res1 =
              EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                positionAfterusernameLen1);
          }
          uint64_t positionAfterLoginRequest5 = res1;
          uint64_t positionAfterusername;
          if (EverParseIsSuccess(positionAfterLoginRequest5))
          {
            positionAfterusername = positionAfterLoginRequest5;
          }
          else
          {
            ErrorHandlerFn("_LoginRequest",
              "username",
              EverParseErrorReasonOfResult(positionAfterLoginRequest5),
              EverParseGetValidatorErrorKind(positionAfterLoginRequest5),
              Ctxt,
              Input,
              positionAfterusernameLen1);
            positionAfterusername = positionAfterLoginRequest5;
          }
          if (EverParseIsError(positionAfterusername))
          {
            positionAfterLoginRequest4 = positionAfterusername;
          }
          else
          {
            /* Checking that we have enough space for a UINT8, i.e., 1 byte */
            BOOLEAN hasBytes7 = 1ULL <= (InputLength - positionAfterusername);
            uint64_t positionAfterpasswordLen;
            if (hasBytes7)
            {
              positionAfterpasswordLen = positionAfterusername + 1ULL;
            }
            else
            {
              positionAfterpasswordLen =
                EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                  positionAfterusername);
            }
            uint64_t positionAfterLoginRequest6;
            if (EverParseIsError(positionAfterpasswordLen))
            {
              positionAfterLoginRequest6 = positionAfterpasswordLen;
            }
            else
            {
              uint8_t passwordLen = Input[(uint32_t)positionAfterusername];
              BOOLEAN passwordLenConstraintIsOk = passwordLen >= 1U && passwordLen <= 64U;
              uint64_t
              positionAfterpasswordLen1 =
                EverParseCheckConstraintOk(passwordLenConstraintIsOk,
                  positionAfterpasswordLen);
              if (EverParseIsError(positionAfterpasswordLen1))
              {
                positionAfterLoginRequest6 = positionAfterpasswordLen1;
              }
              else
              {
                /* Validating field password */
                BOOLEAN
                hasBytes =
                  (uint64_t)(uint32_t)passwordLen <= (InputLength - positionAfterpasswordLen1);
                uint64_t res;
                if (hasBytes)
                {
                  res = positionAfterpasswordLen1 + (uint64_t)(uint32_t)passwordLen;
                }
                else
                {
                  res =
                    EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                      positionAfterpasswordLen1);
                }
                uint64_t positionAfterLoginRequest7 = res;
                if (EverParseIsSuccess(positionAfterLoginRequest7))
                {
                  positionAfterLoginRequest6 = positionAfterLoginRequest7;
                }
                else
                {
                  ErrorHandlerFn("_LoginRequest",
                    "password",
                    EverParseErrorReasonOfResult(positionAfterLoginRequest7),
                    EverParseGetValidatorErrorKind(positionAfterLoginRequest7),
                    Ctxt,
                    Input,
                    positionAfterpasswordLen1);
                  positionAfterLoginRequest6 = positionAfterLoginRequest7;
                }
              }
            }
            if (EverParseIsSuccess(positionAfterLoginRequest6))
            {
              positionAfterLoginRequest4 = positionAfterLoginRequest6;
            }
            else
            {
              ErrorHandlerFn("_LoginRequest",
                "password_len",
                EverParseErrorReasonOfResult(positionAfterLoginRequest6),
                EverParseGetValidatorErrorKind(positionAfterLoginRequest6),
                Ctxt,
                Input,
                positionAfterusername);
              positionAfterLoginRequest4 = positionAfterLoginRequest6;
            }
          }
        }
      }
      if (EverParseIsSuccess(positionAfterLoginRequest4))
      {
        positionAfterLoginRequest3 = positionAfterLoginRequest4;
      }
      else
      {
        ErrorHandlerFn("_LoginRequest",
          "username_len",
          EverParseErrorReasonOfResult(positionAfterLoginRequest4),
          EverParseGetValidatorErrorKind(positionAfterLoginRequest4),
          Ctxt,
          Input,
          positionAfterCheck1);
        positionAfterLoginRequest3 = positionAfterLoginRequest4;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterLoginRequest3))
  {
    return positionAfterLoginRequest3;
  }
  ErrorHandlerFn("_LoginRequest",
    "_check",
    EverParseErrorReasonOfResult(positionAfterLoginRequest3),
    EverParseGetValidatorErrorKind(positionAfterLoginRequest3),
    Ctxt,
    Input,
    positionAftermethod);
  return positionAfterLoginRequest3;
}

uint64_t
MealyAuthValidateLogoutRequest(
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
  uint64_t positionAfterLogoutRequest;
  if (hasBytes0)
  {
    positionAfterLogoutRequest = StartPosition + 1ULL;
  }
  else
  {
    positionAfterLogoutRequest =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterauthState;
  if (EverParseIsSuccess(positionAfterLogoutRequest))
  {
    positionAfterauthState = positionAfterLogoutRequest;
  }
  else
  {
    ErrorHandlerFn("_LogoutRequest",
      "auth_state",
      EverParseErrorReasonOfResult(positionAfterLogoutRequest),
      EverParseGetValidatorErrorKind(positionAfterLogoutRequest),
      Ctxt,
      Input,
      StartPosition);
    positionAfterauthState = positionAfterLogoutRequest;
  }
  if (EverParseIsError(positionAfterauthState))
  {
    return positionAfterauthState;
  }
  uint8_t authState = Input[(uint32_t)StartPosition];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAfterauthState);
  uint64_t positionAfterLogoutRequest0;
  if (hasBytes1)
  {
    positionAfterLogoutRequest0 = positionAfterauthState + 1ULL;
  }
  else
  {
    positionAfterLogoutRequest0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterauthState);
  }
  uint64_t positionAfterrateCount;
  if (EverParseIsSuccess(positionAfterLogoutRequest0))
  {
    positionAfterrateCount = positionAfterLogoutRequest0;
  }
  else
  {
    ErrorHandlerFn("_LogoutRequest",
      "rate_count",
      EverParseErrorReasonOfResult(positionAfterLogoutRequest0),
      EverParseGetValidatorErrorKind(positionAfterLogoutRequest0),
      Ctxt,
      Input,
      positionAfterauthState);
    positionAfterrateCount = positionAfterLogoutRequest0;
  }
  if (EverParseIsError(positionAfterrateCount))
  {
    return positionAfterrateCount;
  }
  uint8_t rateCount = Input[(uint32_t)positionAfterauthState];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes2 = 4ULL <= (InputLength - positionAfterrateCount);
  uint64_t positionAfterLogoutRequest1;
  if (hasBytes2)
  {
    positionAfterLogoutRequest1 = positionAfterrateCount + 4ULL;
  }
  else
  {
    positionAfterLogoutRequest1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrateCount);
  }
  uint64_t positionAfterpathHash;
  if (EverParseIsSuccess(positionAfterLogoutRequest1))
  {
    positionAfterpathHash = positionAfterLogoutRequest1;
  }
  else
  {
    ErrorHandlerFn("_LogoutRequest",
      "path_hash",
      EverParseErrorReasonOfResult(positionAfterLogoutRequest1),
      EverParseGetValidatorErrorKind(positionAfterLogoutRequest1),
      Ctxt,
      Input,
      positionAfterrateCount);
    positionAfterpathHash = positionAfterLogoutRequest1;
  }
  if (EverParseIsError(positionAfterpathHash))
  {
    return positionAfterpathHash;
  }
  uint32_t pathHash = Load32Le(Input + (uint32_t)positionAfterrateCount);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes3 = 1ULL <= (InputLength - positionAfterpathHash);
  uint64_t positionAfterLogoutRequest2;
  if (hasBytes3)
  {
    positionAfterLogoutRequest2 = positionAfterpathHash + 1ULL;
  }
  else
  {
    positionAfterLogoutRequest2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterpathHash);
  }
  uint64_t positionAftermethod;
  if (EverParseIsSuccess(positionAfterLogoutRequest2))
  {
    positionAftermethod = positionAfterLogoutRequest2;
  }
  else
  {
    ErrorHandlerFn("_LogoutRequest",
      "method",
      EverParseErrorReasonOfResult(positionAfterLogoutRequest2),
      EverParseGetValidatorErrorKind(positionAfterLogoutRequest2),
      Ctxt,
      Input,
      positionAfterpathHash);
    positionAftermethod = positionAfterLogoutRequest2;
  }
  if (EverParseIsError(positionAftermethod))
  {
    return positionAftermethod;
  }
  uint8_t method = Input[(uint32_t)positionAfterpathHash];
  /* Validating field _check */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes = 1ULL <= (InputLength - positionAftermethod);
  uint64_t positionAfterCheck_refinement;
  if (hasBytes)
  {
    positionAfterCheck_refinement = positionAftermethod + 1ULL;
  }
  else
  {
    positionAfterCheck_refinement =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftermethod);
  }
  uint64_t positionAfterLogoutRequest3;
  if (EverParseIsError(positionAfterCheck_refinement))
  {
    positionAfterLogoutRequest3 = positionAfterCheck_refinement;
  }
  else
  {
    /* reading field_value */
    uint8_t check_refinement = Input[(uint32_t)positionAftermethod];
    KRML_MAYBE_UNUSED_VAR(check_refinement);
    /* start: checking constraint */
    BOOLEAN
    check_refinementConstraintIsOk =
      pathHash == MEALYAUTH____PATH_LOGOUT && method == MEALYAUTH____METHOD_POST &&
        authState == MEALYAUTH____AUTH_OK
      && rateCount < MEALYAUTH____MAX_RATE;
    /* end: checking constraint */
    positionAfterLogoutRequest3 =
      EverParseCheckConstraintOk(check_refinementConstraintIsOk,
        positionAfterCheck_refinement);
  }
  if (EverParseIsSuccess(positionAfterLogoutRequest3))
  {
    return positionAfterLogoutRequest3;
  }
  ErrorHandlerFn("_LogoutRequest",
    "_check.refinement",
    EverParseErrorReasonOfResult(positionAfterLogoutRequest3),
    EverParseGetValidatorErrorKind(positionAfterLogoutRequest3),
    Ctxt,
    Input,
    positionAftermethod);
  return positionAfterLogoutRequest3;
}

uint64_t
MealyAuthValidateStatusRequest(
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
  uint64_t positionAfterStatusRequest;
  if (hasBytes0)
  {
    positionAfterStatusRequest = StartPosition + 1ULL;
  }
  else
  {
    positionAfterStatusRequest =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterauthState;
  if (EverParseIsSuccess(positionAfterStatusRequest))
  {
    positionAfterauthState = positionAfterStatusRequest;
  }
  else
  {
    ErrorHandlerFn("_StatusRequest",
      "auth_state",
      EverParseErrorReasonOfResult(positionAfterStatusRequest),
      EverParseGetValidatorErrorKind(positionAfterStatusRequest),
      Ctxt,
      Input,
      StartPosition);
    positionAfterauthState = positionAfterStatusRequest;
  }
  if (EverParseIsError(positionAfterauthState))
  {
    return positionAfterauthState;
  }
  uint8_t authState = Input[(uint32_t)StartPosition];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAfterauthState);
  uint64_t positionAfterStatusRequest0;
  if (hasBytes1)
  {
    positionAfterStatusRequest0 = positionAfterauthState + 1ULL;
  }
  else
  {
    positionAfterStatusRequest0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterauthState);
  }
  uint64_t positionAfterrateCount;
  if (EverParseIsSuccess(positionAfterStatusRequest0))
  {
    positionAfterrateCount = positionAfterStatusRequest0;
  }
  else
  {
    ErrorHandlerFn("_StatusRequest",
      "rate_count",
      EverParseErrorReasonOfResult(positionAfterStatusRequest0),
      EverParseGetValidatorErrorKind(positionAfterStatusRequest0),
      Ctxt,
      Input,
      positionAfterauthState);
    positionAfterrateCount = positionAfterStatusRequest0;
  }
  if (EverParseIsError(positionAfterrateCount))
  {
    return positionAfterrateCount;
  }
  uint8_t rateCount = Input[(uint32_t)positionAfterauthState];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes2 = 4ULL <= (InputLength - positionAfterrateCount);
  uint64_t positionAfterStatusRequest1;
  if (hasBytes2)
  {
    positionAfterStatusRequest1 = positionAfterrateCount + 4ULL;
  }
  else
  {
    positionAfterStatusRequest1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrateCount);
  }
  uint64_t positionAfterpathHash;
  if (EverParseIsSuccess(positionAfterStatusRequest1))
  {
    positionAfterpathHash = positionAfterStatusRequest1;
  }
  else
  {
    ErrorHandlerFn("_StatusRequest",
      "path_hash",
      EverParseErrorReasonOfResult(positionAfterStatusRequest1),
      EverParseGetValidatorErrorKind(positionAfterStatusRequest1),
      Ctxt,
      Input,
      positionAfterrateCount);
    positionAfterpathHash = positionAfterStatusRequest1;
  }
  if (EverParseIsError(positionAfterpathHash))
  {
    return positionAfterpathHash;
  }
  uint32_t pathHash = Load32Le(Input + (uint32_t)positionAfterrateCount);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes3 = 1ULL <= (InputLength - positionAfterpathHash);
  uint64_t positionAfterStatusRequest2;
  if (hasBytes3)
  {
    positionAfterStatusRequest2 = positionAfterpathHash + 1ULL;
  }
  else
  {
    positionAfterStatusRequest2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterpathHash);
  }
  uint64_t positionAftermethod;
  if (EverParseIsSuccess(positionAfterStatusRequest2))
  {
    positionAftermethod = positionAfterStatusRequest2;
  }
  else
  {
    ErrorHandlerFn("_StatusRequest",
      "method",
      EverParseErrorReasonOfResult(positionAfterStatusRequest2),
      EverParseGetValidatorErrorKind(positionAfterStatusRequest2),
      Ctxt,
      Input,
      positionAfterpathHash);
    positionAftermethod = positionAfterStatusRequest2;
  }
  if (EverParseIsError(positionAftermethod))
  {
    return positionAftermethod;
  }
  uint8_t method = Input[(uint32_t)positionAfterpathHash];
  /* Validating field _check */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes = 1ULL <= (InputLength - positionAftermethod);
  uint64_t positionAfterCheck_refinement;
  if (hasBytes)
  {
    positionAfterCheck_refinement = positionAftermethod + 1ULL;
  }
  else
  {
    positionAfterCheck_refinement =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftermethod);
  }
  uint64_t positionAfterStatusRequest3;
  if (EverParseIsError(positionAfterCheck_refinement))
  {
    positionAfterStatusRequest3 = positionAfterCheck_refinement;
  }
  else
  {
    /* reading field_value */
    uint8_t check_refinement = Input[(uint32_t)positionAftermethod];
    KRML_MAYBE_UNUSED_VAR(check_refinement);
    /* start: checking constraint */
    BOOLEAN
    check_refinementConstraintIsOk =
      pathHash == MEALYAUTH____PATH_STATUS && method == MEALYAUTH____METHOD_GET &&
        authState == MEALYAUTH____AUTH_OK
      && rateCount < MEALYAUTH____MAX_RATE;
    /* end: checking constraint */
    positionAfterStatusRequest3 =
      EverParseCheckConstraintOk(check_refinementConstraintIsOk,
        positionAfterCheck_refinement);
  }
  if (EverParseIsSuccess(positionAfterStatusRequest3))
  {
    return positionAfterStatusRequest3;
  }
  ErrorHandlerFn("_StatusRequest",
    "_check.refinement",
    EverParseErrorReasonOfResult(positionAfterStatusRequest3),
    EverParseGetValidatorErrorKind(positionAfterStatusRequest3),
    Ctxt,
    Input,
    positionAftermethod);
  return positionAfterStatusRequest3;
}

