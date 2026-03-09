

#include "RbacPolicy.h"

uint64_t
RbacPolicyValidateLoginRequest(
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
      pathHash == RBACPOLICY____PATH_LOGIN && method == RBACPOLICY____METHOD_POST &&
        rateCount < RBACPOLICY____MAX_RATE;
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
RbacPolicyValidatePolicyBlob(
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
  uint64_t positionAfterPolicyBlob;
  if (hasBytes0)
  {
    positionAfterPolicyBlob = StartPosition + 1ULL;
  }
  else
  {
    positionAfterPolicyBlob =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterauthState;
  if (EverParseIsSuccess(positionAfterPolicyBlob))
  {
    positionAfterauthState = positionAfterPolicyBlob;
  }
  else
  {
    ErrorHandlerFn("_PolicyBlob",
      "auth_state",
      EverParseErrorReasonOfResult(positionAfterPolicyBlob),
      EverParseGetValidatorErrorKind(positionAfterPolicyBlob),
      Ctxt,
      Input,
      StartPosition);
    positionAfterauthState = positionAfterPolicyBlob;
  }
  if (EverParseIsError(positionAfterauthState))
  {
    return positionAfterauthState;
  }
  uint8_t authState = Input[(uint32_t)StartPosition];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAfterauthState);
  uint64_t positionAfterPolicyBlob0;
  if (hasBytes1)
  {
    positionAfterPolicyBlob0 = positionAfterauthState + 1ULL;
  }
  else
  {
    positionAfterPolicyBlob0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterauthState);
  }
  uint64_t positionAfterrateCount;
  if (EverParseIsSuccess(positionAfterPolicyBlob0))
  {
    positionAfterrateCount = positionAfterPolicyBlob0;
  }
  else
  {
    ErrorHandlerFn("_PolicyBlob",
      "rate_count",
      EverParseErrorReasonOfResult(positionAfterPolicyBlob0),
      EverParseGetValidatorErrorKind(positionAfterPolicyBlob0),
      Ctxt,
      Input,
      positionAfterauthState);
    positionAfterrateCount = positionAfterPolicyBlob0;
  }
  if (EverParseIsError(positionAfterrateCount))
  {
    return positionAfterrateCount;
  }
  uint8_t rateCount = Input[(uint32_t)positionAfterauthState];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes2 = 1ULL <= (InputLength - positionAfterrateCount);
  uint64_t positionAfterPolicyBlob1;
  if (hasBytes2)
  {
    positionAfterPolicyBlob1 = positionAfterrateCount + 1ULL;
  }
  else
  {
    positionAfterPolicyBlob1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrateCount);
  }
  uint64_t positionAfternumRules;
  if (EverParseIsSuccess(positionAfterPolicyBlob1))
  {
    positionAfternumRules = positionAfterPolicyBlob1;
  }
  else
  {
    ErrorHandlerFn("_PolicyBlob",
      "num_rules",
      EverParseErrorReasonOfResult(positionAfterPolicyBlob1),
      EverParseGetValidatorErrorKind(positionAfterPolicyBlob1),
      Ctxt,
      Input,
      positionAfterrateCount);
    positionAfternumRules = positionAfterPolicyBlob1;
  }
  if (EverParseIsError(positionAfternumRules))
  {
    return positionAfternumRules;
  }
  uint8_t numRules = Input[(uint32_t)positionAfterrateCount];
  /* Validating field r0_path_hash */
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes3 = 4ULL <= (InputLength - positionAfternumRules);
  uint64_t positionAfterPolicyBlob2;
  if (hasBytes3)
  {
    positionAfterPolicyBlob2 = positionAfternumRules + 4ULL;
  }
  else
  {
    positionAfterPolicyBlob2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfternumRules);
  }
  uint64_t res0;
  if (EverParseIsSuccess(positionAfterPolicyBlob2))
  {
    res0 = positionAfterPolicyBlob2;
  }
  else
  {
    ErrorHandlerFn("_PolicyBlob",
      "r0_path_hash",
      EverParseErrorReasonOfResult(positionAfterPolicyBlob2),
      EverParseGetValidatorErrorKind(positionAfterPolicyBlob2),
      Ctxt,
      Input,
      positionAfternumRules);
    res0 = positionAfterPolicyBlob2;
  }
  uint64_t positionAfterr0PathHash = res0;
  if (EverParseIsError(positionAfterr0PathHash))
  {
    return positionAfterr0PathHash;
  }
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAfterr0PathHash);
  uint64_t positionAfterr0Method;
  if (hasBytes4)
  {
    positionAfterr0Method = positionAfterr0PathHash + 1ULL;
  }
  else
  {
    positionAfterr0Method =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0PathHash);
  }
  uint64_t positionAfterPolicyBlob3;
  if (EverParseIsError(positionAfterr0Method))
  {
    positionAfterPolicyBlob3 = positionAfterr0Method;
  }
  else
  {
    uint8_t r0Method = Input[(uint32_t)positionAfterr0PathHash];
    BOOLEAN r0MethodConstraintIsOk = r0Method <= 3U;
    uint64_t
    positionAfterr0Method1 =
      EverParseCheckConstraintOk(r0MethodConstraintIsOk,
        positionAfterr0Method);
    if (EverParseIsError(positionAfterr0Method1))
    {
      positionAfterPolicyBlob3 = positionAfterr0Method1;
    }
    else
    {
      /* Checking that we have enough space for a UINT8, i.e., 1 byte */
      BOOLEAN hasBytes5 = 1ULL <= (InputLength - positionAfterr0Method1);
      uint64_t positionAfterr0MinRole;
      if (hasBytes5)
      {
        positionAfterr0MinRole = positionAfterr0Method1 + 1ULL;
      }
      else
      {
        positionAfterr0MinRole =
          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterr0Method1);
      }
      uint64_t positionAfterPolicyBlob4;
      if (EverParseIsError(positionAfterr0MinRole))
      {
        positionAfterPolicyBlob4 = positionAfterr0MinRole;
      }
      else
      {
        uint8_t r0MinRole = Input[(uint32_t)positionAfterr0Method1];
        BOOLEAN r0MinRoleConstraintIsOk = r0MinRole <= 2U;
        uint64_t
        positionAfterr0MinRole1 =
          EverParseCheckConstraintOk(r0MinRoleConstraintIsOk,
            positionAfterr0MinRole);
        if (EverParseIsError(positionAfterr0MinRole1))
        {
          positionAfterPolicyBlob4 = positionAfterr0MinRole1;
        }
        else
        {
          /* Validating field r1_path_hash */
          /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
          BOOLEAN hasBytes6 = 4ULL <= (InputLength - positionAfterr0MinRole1);
          uint64_t positionAfterPolicyBlob5;
          if (hasBytes6)
          {
            positionAfterPolicyBlob5 = positionAfterr0MinRole1 + 4ULL;
          }
          else
          {
            positionAfterPolicyBlob5 =
              EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                positionAfterr0MinRole1);
          }
          uint64_t res1;
          if (EverParseIsSuccess(positionAfterPolicyBlob5))
          {
            res1 = positionAfterPolicyBlob5;
          }
          else
          {
            ErrorHandlerFn("_PolicyBlob",
              "r1_path_hash",
              EverParseErrorReasonOfResult(positionAfterPolicyBlob5),
              EverParseGetValidatorErrorKind(positionAfterPolicyBlob5),
              Ctxt,
              Input,
              positionAfterr0MinRole1);
            res1 = positionAfterPolicyBlob5;
          }
          uint64_t positionAfterr1PathHash = res1;
          if (EverParseIsError(positionAfterr1PathHash))
          {
            positionAfterPolicyBlob4 = positionAfterr1PathHash;
          }
          else
          {
            /* Checking that we have enough space for a UINT8, i.e., 1 byte */
            BOOLEAN hasBytes7 = 1ULL <= (InputLength - positionAfterr1PathHash);
            uint64_t positionAfterr1Method;
            if (hasBytes7)
            {
              positionAfterr1Method = positionAfterr1PathHash + 1ULL;
            }
            else
            {
              positionAfterr1Method =
                EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                  positionAfterr1PathHash);
            }
            uint64_t positionAfterPolicyBlob6;
            if (EverParseIsError(positionAfterr1Method))
            {
              positionAfterPolicyBlob6 = positionAfterr1Method;
            }
            else
            {
              uint8_t r1Method = Input[(uint32_t)positionAfterr1PathHash];
              BOOLEAN r1MethodConstraintIsOk = r1Method <= 3U;
              uint64_t
              positionAfterr1Method1 =
                EverParseCheckConstraintOk(r1MethodConstraintIsOk,
                  positionAfterr1Method);
              if (EverParseIsError(positionAfterr1Method1))
              {
                positionAfterPolicyBlob6 = positionAfterr1Method1;
              }
              else
              {
                /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                BOOLEAN hasBytes8 = 1ULL <= (InputLength - positionAfterr1Method1);
                uint64_t positionAfterr1MinRole;
                if (hasBytes8)
                {
                  positionAfterr1MinRole = positionAfterr1Method1 + 1ULL;
                }
                else
                {
                  positionAfterr1MinRole =
                    EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                      positionAfterr1Method1);
                }
                uint64_t positionAfterPolicyBlob7;
                if (EverParseIsError(positionAfterr1MinRole))
                {
                  positionAfterPolicyBlob7 = positionAfterr1MinRole;
                }
                else
                {
                  uint8_t r1MinRole = Input[(uint32_t)positionAfterr1Method1];
                  BOOLEAN r1MinRoleConstraintIsOk = r1MinRole <= 2U;
                  uint64_t
                  positionAfterr1MinRole1 =
                    EverParseCheckConstraintOk(r1MinRoleConstraintIsOk,
                      positionAfterr1MinRole);
                  if (EverParseIsError(positionAfterr1MinRole1))
                  {
                    positionAfterPolicyBlob7 = positionAfterr1MinRole1;
                  }
                  else
                  {
                    /* Validating field r2_path_hash */
                    /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
                    BOOLEAN hasBytes9 = 4ULL <= (InputLength - positionAfterr1MinRole1);
                    uint64_t positionAfterPolicyBlob8;
                    if (hasBytes9)
                    {
                      positionAfterPolicyBlob8 = positionAfterr1MinRole1 + 4ULL;
                    }
                    else
                    {
                      positionAfterPolicyBlob8 =
                        EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                          positionAfterr1MinRole1);
                    }
                    uint64_t res2;
                    if (EverParseIsSuccess(positionAfterPolicyBlob8))
                    {
                      res2 = positionAfterPolicyBlob8;
                    }
                    else
                    {
                      ErrorHandlerFn("_PolicyBlob",
                        "r2_path_hash",
                        EverParseErrorReasonOfResult(positionAfterPolicyBlob8),
                        EverParseGetValidatorErrorKind(positionAfterPolicyBlob8),
                        Ctxt,
                        Input,
                        positionAfterr1MinRole1);
                      res2 = positionAfterPolicyBlob8;
                    }
                    uint64_t positionAfterr2PathHash = res2;
                    if (EverParseIsError(positionAfterr2PathHash))
                    {
                      positionAfterPolicyBlob7 = positionAfterr2PathHash;
                    }
                    else
                    {
                      /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                      BOOLEAN hasBytes10 = 1ULL <= (InputLength - positionAfterr2PathHash);
                      uint64_t positionAfterr2Method;
                      if (hasBytes10)
                      {
                        positionAfterr2Method = positionAfterr2PathHash + 1ULL;
                      }
                      else
                      {
                        positionAfterr2Method =
                          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterr2PathHash);
                      }
                      uint64_t positionAfterPolicyBlob9;
                      if (EverParseIsError(positionAfterr2Method))
                      {
                        positionAfterPolicyBlob9 = positionAfterr2Method;
                      }
                      else
                      {
                        uint8_t r2Method = Input[(uint32_t)positionAfterr2PathHash];
                        BOOLEAN r2MethodConstraintIsOk = r2Method <= 3U;
                        uint64_t
                        positionAfterr2Method1 =
                          EverParseCheckConstraintOk(r2MethodConstraintIsOk,
                            positionAfterr2Method);
                        if (EverParseIsError(positionAfterr2Method1))
                        {
                          positionAfterPolicyBlob9 = positionAfterr2Method1;
                        }
                        else
                        {
                          /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                          BOOLEAN hasBytes11 = 1ULL <= (InputLength - positionAfterr2Method1);
                          uint64_t positionAfterr2MinRole;
                          if (hasBytes11)
                          {
                            positionAfterr2MinRole = positionAfterr2Method1 + 1ULL;
                          }
                          else
                          {
                            positionAfterr2MinRole =
                              EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                positionAfterr2Method1);
                          }
                          uint64_t positionAfterPolicyBlob10;
                          if (EverParseIsError(positionAfterr2MinRole))
                          {
                            positionAfterPolicyBlob10 = positionAfterr2MinRole;
                          }
                          else
                          {
                            uint8_t r2MinRole = Input[(uint32_t)positionAfterr2Method1];
                            BOOLEAN r2MinRoleConstraintIsOk = r2MinRole <= 2U;
                            uint64_t
                            positionAfterr2MinRole1 =
                              EverParseCheckConstraintOk(r2MinRoleConstraintIsOk,
                                positionAfterr2MinRole);
                            if (EverParseIsError(positionAfterr2MinRole1))
                            {
                              positionAfterPolicyBlob10 = positionAfterr2MinRole1;
                            }
                            else
                            {
                              /* Validating field r3_path_hash */
                              /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
                              BOOLEAN hasBytes12 = 4ULL <= (InputLength - positionAfterr2MinRole1);
                              uint64_t positionAfterPolicyBlob11;
                              if (hasBytes12)
                              {
                                positionAfterPolicyBlob11 = positionAfterr2MinRole1 + 4ULL;
                              }
                              else
                              {
                                positionAfterPolicyBlob11 =
                                  EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    positionAfterr2MinRole1);
                              }
                              uint64_t res3;
                              if (EverParseIsSuccess(positionAfterPolicyBlob11))
                              {
                                res3 = positionAfterPolicyBlob11;
                              }
                              else
                              {
                                ErrorHandlerFn("_PolicyBlob",
                                  "r3_path_hash",
                                  EverParseErrorReasonOfResult(positionAfterPolicyBlob11),
                                  EverParseGetValidatorErrorKind(positionAfterPolicyBlob11),
                                  Ctxt,
                                  Input,
                                  positionAfterr2MinRole1);
                                res3 = positionAfterPolicyBlob11;
                              }
                              uint64_t positionAfterr3PathHash = res3;
                              if (EverParseIsError(positionAfterr3PathHash))
                              {
                                positionAfterPolicyBlob10 = positionAfterr3PathHash;
                              }
                              else
                              {
                                /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                BOOLEAN
                                hasBytes13 = 1ULL <= (InputLength - positionAfterr3PathHash);
                                uint64_t positionAfterr3Method;
                                if (hasBytes13)
                                {
                                  positionAfterr3Method = positionAfterr3PathHash + 1ULL;
                                }
                                else
                                {
                                  positionAfterr3Method =
                                    EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                      positionAfterr3PathHash);
                                }
                                uint64_t positionAfterPolicyBlob12;
                                if (EverParseIsError(positionAfterr3Method))
                                {
                                  positionAfterPolicyBlob12 = positionAfterr3Method;
                                }
                                else
                                {
                                  uint8_t r3Method = Input[(uint32_t)positionAfterr3PathHash];
                                  BOOLEAN r3MethodConstraintIsOk = r3Method <= 3U;
                                  uint64_t
                                  positionAfterr3Method1 =
                                    EverParseCheckConstraintOk(r3MethodConstraintIsOk,
                                      positionAfterr3Method);
                                  if (EverParseIsError(positionAfterr3Method1))
                                  {
                                    positionAfterPolicyBlob12 = positionAfterr3Method1;
                                  }
                                  else
                                  {
                                    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                    BOOLEAN
                                    hasBytes14 = 1ULL <= (InputLength - positionAfterr3Method1);
                                    uint64_t positionAfterr3MinRole;
                                    if (hasBytes14)
                                    {
                                      positionAfterr3MinRole = positionAfterr3Method1 + 1ULL;
                                    }
                                    else
                                    {
                                      positionAfterr3MinRole =
                                        EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                          positionAfterr3Method1);
                                    }
                                    uint64_t positionAfterPolicyBlob13;
                                    if (EverParseIsError(positionAfterr3MinRole))
                                    {
                                      positionAfterPolicyBlob13 = positionAfterr3MinRole;
                                    }
                                    else
                                    {
                                      uint8_t r3MinRole = Input[(uint32_t)positionAfterr3Method1];
                                      BOOLEAN r3MinRoleConstraintIsOk = r3MinRole <= 2U;
                                      uint64_t
                                      positionAfterr3MinRole1 =
                                        EverParseCheckConstraintOk(r3MinRoleConstraintIsOk,
                                          positionAfterr3MinRole);
                                      if (EverParseIsError(positionAfterr3MinRole1))
                                      {
                                        positionAfterPolicyBlob13 = positionAfterr3MinRole1;
                                      }
                                      else
                                      {
                                        /* Validating field r4_path_hash */
                                        /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
                                        BOOLEAN
                                        hasBytes15 = 4ULL <= (InputLength - positionAfterr3MinRole1);
                                        uint64_t positionAfterPolicyBlob14;
                                        if (hasBytes15)
                                        {
                                          positionAfterPolicyBlob14 = positionAfterr3MinRole1 + 4ULL;
                                        }
                                        else
                                        {
                                          positionAfterPolicyBlob14 =
                                            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                              positionAfterr3MinRole1);
                                        }
                                        uint64_t res4;
                                        if (EverParseIsSuccess(positionAfterPolicyBlob14))
                                        {
                                          res4 = positionAfterPolicyBlob14;
                                        }
                                        else
                                        {
                                          ErrorHandlerFn("_PolicyBlob",
                                            "r4_path_hash",
                                            EverParseErrorReasonOfResult(positionAfterPolicyBlob14),
                                            EverParseGetValidatorErrorKind(positionAfterPolicyBlob14),
                                            Ctxt,
                                            Input,
                                            positionAfterr3MinRole1);
                                          res4 = positionAfterPolicyBlob14;
                                        }
                                        uint64_t positionAfterr4PathHash = res4;
                                        if (EverParseIsError(positionAfterr4PathHash))
                                        {
                                          positionAfterPolicyBlob13 = positionAfterr4PathHash;
                                        }
                                        else
                                        {
                                          /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                          BOOLEAN
                                          hasBytes16 =
                                            1ULL <= (InputLength - positionAfterr4PathHash);
                                          uint64_t positionAfterr4Method;
                                          if (hasBytes16)
                                          {
                                            positionAfterr4Method = positionAfterr4PathHash + 1ULL;
                                          }
                                          else
                                          {
                                            positionAfterr4Method =
                                              EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                positionAfterr4PathHash);
                                          }
                                          uint64_t positionAfterPolicyBlob15;
                                          if (EverParseIsError(positionAfterr4Method))
                                          {
                                            positionAfterPolicyBlob15 = positionAfterr4Method;
                                          }
                                          else
                                          {
                                            uint8_t
                                            r4Method = Input[(uint32_t)positionAfterr4PathHash];
                                            BOOLEAN r4MethodConstraintIsOk = r4Method <= 3U;
                                            uint64_t
                                            positionAfterr4Method1 =
                                              EverParseCheckConstraintOk(r4MethodConstraintIsOk,
                                                positionAfterr4Method);
                                            if (EverParseIsError(positionAfterr4Method1))
                                            {
                                              positionAfterPolicyBlob15 = positionAfterr4Method1;
                                            }
                                            else
                                            {
                                              /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                              BOOLEAN
                                              hasBytes17 =
                                                1ULL <= (InputLength - positionAfterr4Method1);
                                              uint64_t positionAfterr4MinRole;
                                              if (hasBytes17)
                                              {
                                                positionAfterr4MinRole =
                                                  positionAfterr4Method1 + 1ULL;
                                              }
                                              else
                                              {
                                                positionAfterr4MinRole =
                                                  EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                    positionAfterr4Method1);
                                              }
                                              uint64_t positionAfterPolicyBlob16;
                                              if (EverParseIsError(positionAfterr4MinRole))
                                              {
                                                positionAfterPolicyBlob16 = positionAfterr4MinRole;
                                              }
                                              else
                                              {
                                                uint8_t
                                                r4MinRole = Input[(uint32_t)positionAfterr4Method1];
                                                BOOLEAN r4MinRoleConstraintIsOk = r4MinRole <= 2U;
                                                uint64_t
                                                positionAfterr4MinRole1 =
                                                  EverParseCheckConstraintOk(r4MinRoleConstraintIsOk,
                                                    positionAfterr4MinRole);
                                                if (EverParseIsError(positionAfterr4MinRole1))
                                                {
                                                  positionAfterPolicyBlob16 =
                                                    positionAfterr4MinRole1;
                                                }
                                                else
                                                {
                                                  /* Validating field r5_path_hash */
                                                  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
                                                  BOOLEAN
                                                  hasBytes18 =
                                                    4ULL <= (InputLength - positionAfterr4MinRole1);
                                                  uint64_t positionAfterPolicyBlob17;
                                                  if (hasBytes18)
                                                  {
                                                    positionAfterPolicyBlob17 =
                                                      positionAfterr4MinRole1 + 4ULL;
                                                  }
                                                  else
                                                  {
                                                    positionAfterPolicyBlob17 =
                                                      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                        positionAfterr4MinRole1);
                                                  }
                                                  uint64_t res5;
                                                  if (EverParseIsSuccess(positionAfterPolicyBlob17))
                                                  {
                                                    res5 = positionAfterPolicyBlob17;
                                                  }
                                                  else
                                                  {
                                                    ErrorHandlerFn("_PolicyBlob",
                                                      "r5_path_hash",
                                                      EverParseErrorReasonOfResult(positionAfterPolicyBlob17),
                                                      EverParseGetValidatorErrorKind(positionAfterPolicyBlob17),
                                                      Ctxt,
                                                      Input,
                                                      positionAfterr4MinRole1);
                                                    res5 = positionAfterPolicyBlob17;
                                                  }
                                                  uint64_t positionAfterr5PathHash = res5;
                                                  if (EverParseIsError(positionAfterr5PathHash))
                                                  {
                                                    positionAfterPolicyBlob16 =
                                                      positionAfterr5PathHash;
                                                  }
                                                  else
                                                  {
                                                    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                    BOOLEAN
                                                    hasBytes19 =
                                                      1ULL <=
                                                        (InputLength - positionAfterr5PathHash);
                                                    uint64_t positionAfterr5Method;
                                                    if (hasBytes19)
                                                    {
                                                      positionAfterr5Method =
                                                        positionAfterr5PathHash + 1ULL;
                                                    }
                                                    else
                                                    {
                                                      positionAfterr5Method =
                                                        EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                          positionAfterr5PathHash);
                                                    }
                                                    uint64_t positionAfterPolicyBlob18;
                                                    if (EverParseIsError(positionAfterr5Method))
                                                    {
                                                      positionAfterPolicyBlob18 =
                                                        positionAfterr5Method;
                                                    }
                                                    else
                                                    {
                                                      uint8_t
                                                      r5Method =
                                                        Input[(uint32_t)positionAfterr5PathHash];
                                                      BOOLEAN
                                                      r5MethodConstraintIsOk = r5Method <= 3U;
                                                      uint64_t
                                                      positionAfterr5Method1 =
                                                        EverParseCheckConstraintOk(r5MethodConstraintIsOk,
                                                          positionAfterr5Method);
                                                      if (EverParseIsError(positionAfterr5Method1))
                                                      {
                                                        positionAfterPolicyBlob18 =
                                                          positionAfterr5Method1;
                                                      }
                                                      else
                                                      {
                                                        /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                        BOOLEAN
                                                        hasBytes20 =
                                                          1ULL <=
                                                            (InputLength - positionAfterr5Method1);
                                                        uint64_t positionAfterr5MinRole;
                                                        if (hasBytes20)
                                                        {
                                                          positionAfterr5MinRole =
                                                            positionAfterr5Method1 + 1ULL;
                                                        }
                                                        else
                                                        {
                                                          positionAfterr5MinRole =
                                                            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                              positionAfterr5Method1);
                                                        }
                                                        uint64_t positionAfterPolicyBlob19;
                                                        if
                                                        (EverParseIsError(positionAfterr5MinRole))
                                                        {
                                                          positionAfterPolicyBlob19 =
                                                            positionAfterr5MinRole;
                                                        }
                                                        else
                                                        {
                                                          uint8_t
                                                          r5MinRole =
                                                            Input[(uint32_t)positionAfterr5Method1];
                                                          BOOLEAN
                                                          r5MinRoleConstraintIsOk = r5MinRole <= 2U;
                                                          uint64_t
                                                          positionAfterr5MinRole1 =
                                                            EverParseCheckConstraintOk(r5MinRoleConstraintIsOk,
                                                              positionAfterr5MinRole);
                                                          if
                                                          (
                                                            EverParseIsError(positionAfterr5MinRole1)
                                                          )
                                                          {
                                                            positionAfterPolicyBlob19 =
                                                              positionAfterr5MinRole1;
                                                          }
                                                          else
                                                          {
                                                            /* Validating field r6_path_hash */
                                                            /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
                                                            BOOLEAN
                                                            hasBytes21 =
                                                              4ULL <=
                                                                (InputLength -
                                                                  positionAfterr5MinRole1);
                                                            uint64_t positionAfterPolicyBlob20;
                                                            if (hasBytes21)
                                                            {
                                                              positionAfterPolicyBlob20 =
                                                                positionAfterr5MinRole1 + 4ULL;
                                                            }
                                                            else
                                                            {
                                                              positionAfterPolicyBlob20 =
                                                                EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                  positionAfterr5MinRole1);
                                                            }
                                                            uint64_t res6;
                                                            if
                                                            (
                                                              EverParseIsSuccess(positionAfterPolicyBlob20)
                                                            )
                                                            {
                                                              res6 = positionAfterPolicyBlob20;
                                                            }
                                                            else
                                                            {
                                                              ErrorHandlerFn("_PolicyBlob",
                                                                "r6_path_hash",
                                                                EverParseErrorReasonOfResult(positionAfterPolicyBlob20),
                                                                EverParseGetValidatorErrorKind(positionAfterPolicyBlob20),
                                                                Ctxt,
                                                                Input,
                                                                positionAfterr5MinRole1);
                                                              res6 = positionAfterPolicyBlob20;
                                                            }
                                                            uint64_t positionAfterr6PathHash = res6;
                                                            if
                                                            (
                                                              EverParseIsError(positionAfterr6PathHash)
                                                            )
                                                            {
                                                              positionAfterPolicyBlob19 =
                                                                positionAfterr6PathHash;
                                                            }
                                                            else
                                                            {
                                                              /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                              BOOLEAN
                                                              hasBytes22 =
                                                                1ULL <=
                                                                  (InputLength -
                                                                    positionAfterr6PathHash);
                                                              uint64_t positionAfterr6Method;
                                                              if (hasBytes22)
                                                              {
                                                                positionAfterr6Method =
                                                                  positionAfterr6PathHash + 1ULL;
                                                              }
                                                              else
                                                              {
                                                                positionAfterr6Method =
                                                                  EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                    positionAfterr6PathHash);
                                                              }
                                                              uint64_t positionAfterPolicyBlob21;
                                                              if
                                                              (
                                                                EverParseIsError(positionAfterr6Method)
                                                              )
                                                              {
                                                                positionAfterPolicyBlob21 =
                                                                  positionAfterr6Method;
                                                              }
                                                              else
                                                              {
                                                                uint8_t
                                                                r6Method =
                                                                  Input[(uint32_t)positionAfterr6PathHash];
                                                                BOOLEAN
                                                                r6MethodConstraintIsOk =
                                                                  r6Method <= 3U;
                                                                uint64_t
                                                                positionAfterr6Method1 =
                                                                  EverParseCheckConstraintOk(r6MethodConstraintIsOk,
                                                                    positionAfterr6Method);
                                                                if
                                                                (
                                                                  EverParseIsError(positionAfterr6Method1)
                                                                )
                                                                {
                                                                  positionAfterPolicyBlob21 =
                                                                    positionAfterr6Method1;
                                                                }
                                                                else
                                                                {
                                                                  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                                  BOOLEAN
                                                                  hasBytes23 =
                                                                    1ULL <=
                                                                      (InputLength -
                                                                        positionAfterr6Method1);
                                                                  uint64_t positionAfterr6MinRole;
                                                                  if (hasBytes23)
                                                                  {
                                                                    positionAfterr6MinRole =
                                                                      positionAfterr6Method1 + 1ULL;
                                                                  }
                                                                  else
                                                                  {
                                                                    positionAfterr6MinRole =
                                                                      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                        positionAfterr6Method1);
                                                                  }
                                                                  uint64_t
                                                                  positionAfterPolicyBlob22;
                                                                  if
                                                                  (
                                                                    EverParseIsError(positionAfterr6MinRole)
                                                                  )
                                                                  {
                                                                    positionAfterPolicyBlob22 =
                                                                      positionAfterr6MinRole;
                                                                  }
                                                                  else
                                                                  {
                                                                    uint8_t
                                                                    r6MinRole =
                                                                      Input[(uint32_t)positionAfterr6Method1];
                                                                    BOOLEAN
                                                                    r6MinRoleConstraintIsOk =
                                                                      r6MinRole <= 2U;
                                                                    uint64_t
                                                                    positionAfterr6MinRole1 =
                                                                      EverParseCheckConstraintOk(r6MinRoleConstraintIsOk,
                                                                        positionAfterr6MinRole);
                                                                    if
                                                                    (
                                                                      EverParseIsError(positionAfterr6MinRole1)
                                                                    )
                                                                    {
                                                                      positionAfterPolicyBlob22 =
                                                                        positionAfterr6MinRole1;
                                                                    }
                                                                    else
                                                                    {
                                                                      /* Validating field r7_path_hash */
                                                                      /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
                                                                      BOOLEAN
                                                                      hasBytes24 =
                                                                        4ULL <=
                                                                          (InputLength -
                                                                            positionAfterr6MinRole1);
                                                                      uint64_t
                                                                      positionAfterPolicyBlob23;
                                                                      if (hasBytes24)
                                                                      {
                                                                        positionAfterPolicyBlob23 =
                                                                          positionAfterr6MinRole1 +
                                                                            4ULL;
                                                                      }
                                                                      else
                                                                      {
                                                                        positionAfterPolicyBlob23 =
                                                                          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                            positionAfterr6MinRole1);
                                                                      }
                                                                      uint64_t res;
                                                                      if
                                                                      (
                                                                        EverParseIsSuccess(positionAfterPolicyBlob23)
                                                                      )
                                                                      {
                                                                        res =
                                                                          positionAfterPolicyBlob23;
                                                                      }
                                                                      else
                                                                      {
                                                                        ErrorHandlerFn("_PolicyBlob",
                                                                          "r7_path_hash",
                                                                          EverParseErrorReasonOfResult(positionAfterPolicyBlob23),
                                                                          EverParseGetValidatorErrorKind(positionAfterPolicyBlob23),
                                                                          Ctxt,
                                                                          Input,
                                                                          positionAfterr6MinRole1);
                                                                        res =
                                                                          positionAfterPolicyBlob23;
                                                                      }
                                                                      uint64_t
                                                                      positionAfterr7PathHash = res;
                                                                      if
                                                                      (
                                                                        EverParseIsError(positionAfterr7PathHash)
                                                                      )
                                                                      {
                                                                        positionAfterPolicyBlob22 =
                                                                          positionAfterr7PathHash;
                                                                      }
                                                                      else
                                                                      {
                                                                        /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                                        BOOLEAN
                                                                        hasBytes25 =
                                                                          1ULL <=
                                                                            (InputLength -
                                                                              positionAfterr7PathHash);
                                                                        uint64_t
                                                                        positionAfterr7Method;
                                                                        if (hasBytes25)
                                                                        {
                                                                          positionAfterr7Method =
                                                                            positionAfterr7PathHash
                                                                            + 1ULL;
                                                                        }
                                                                        else
                                                                        {
                                                                          positionAfterr7Method =
                                                                            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                              positionAfterr7PathHash);
                                                                        }
                                                                        uint64_t
                                                                        positionAfterPolicyBlob24;
                                                                        if
                                                                        (
                                                                          EverParseIsError(positionAfterr7Method)
                                                                        )
                                                                        {
                                                                          positionAfterPolicyBlob24
                                                                          = positionAfterr7Method;
                                                                        }
                                                                        else
                                                                        {
                                                                          uint8_t
                                                                          r7Method =
                                                                            Input[(uint32_t)positionAfterr7PathHash];
                                                                          BOOLEAN
                                                                          r7MethodConstraintIsOk =
                                                                            r7Method <= 3U;
                                                                          uint64_t
                                                                          positionAfterr7Method1 =
                                                                            EverParseCheckConstraintOk(r7MethodConstraintIsOk,
                                                                              positionAfterr7Method);
                                                                          if
                                                                          (
                                                                            EverParseIsError(positionAfterr7Method1)
                                                                          )
                                                                          {
                                                                            positionAfterPolicyBlob24
                                                                            = positionAfterr7Method1;
                                                                          }
                                                                          else
                                                                          {
                                                                            /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                                            BOOLEAN
                                                                            hasBytes26 =
                                                                              1ULL <=
                                                                                (InputLength -
                                                                                  positionAfterr7Method1);
                                                                            uint64_t
                                                                            positionAfterr7MinRole;
                                                                            if (hasBytes26)
                                                                            {
                                                                              positionAfterr7MinRole
                                                                              =
                                                                                positionAfterr7Method1
                                                                                + 1ULL;
                                                                            }
                                                                            else
                                                                            {
                                                                              positionAfterr7MinRole
                                                                              =
                                                                                EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                  positionAfterr7Method1);
                                                                            }
                                                                            uint64_t
                                                                            positionAfterPolicyBlob25;
                                                                            if
                                                                            (
                                                                              EverParseIsError(positionAfterr7MinRole)
                                                                            )
                                                                            {
                                                                              positionAfterPolicyBlob25
                                                                              =
                                                                                positionAfterr7MinRole;
                                                                            }
                                                                            else
                                                                            {
                                                                              uint8_t
                                                                              r7MinRole =
                                                                                Input[(uint32_t)positionAfterr7Method1];
                                                                              BOOLEAN
                                                                              r7MinRoleConstraintIsOk =
                                                                                r7MinRole <= 2U;
                                                                              uint64_t
                                                                              positionAfterr7MinRole1 =
                                                                                EverParseCheckConstraintOk(r7MinRoleConstraintIsOk,
                                                                                  positionAfterr7MinRole);
                                                                              if
                                                                              (
                                                                                EverParseIsError(positionAfterr7MinRole1)
                                                                              )
                                                                              {
                                                                                positionAfterPolicyBlob25
                                                                                =
                                                                                  positionAfterr7MinRole1;
                                                                              }
                                                                              else
                                                                              {
                                                                                /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                                                BOOLEAN
                                                                                hasBytes27 =
                                                                                  1ULL <=
                                                                                    (InputLength -
                                                                                      positionAfterr7MinRole1);
                                                                                uint64_t
                                                                                positionAfterAuthOk;
                                                                                if (hasBytes27)
                                                                                {
                                                                                  positionAfterAuthOk
                                                                                  =
                                                                                    positionAfterr7MinRole1
                                                                                    + 1ULL;
                                                                                }
                                                                                else
                                                                                {
                                                                                  positionAfterAuthOk
                                                                                  =
                                                                                    EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                      positionAfterr7MinRole1);
                                                                                }
                                                                                uint64_t
                                                                                positionAfterPolicyBlob26;
                                                                                if
                                                                                (
                                                                                  EverParseIsError(positionAfterAuthOk)
                                                                                )
                                                                                {
                                                                                  positionAfterPolicyBlob26
                                                                                  =
                                                                                    positionAfterAuthOk;
                                                                                }
                                                                                else
                                                                                {
                                                                                  uint8_t
                                                                                  authOk =
                                                                                    Input[(uint32_t)positionAfterr7MinRole1];
                                                                                  KRML_MAYBE_UNUSED_VAR(authOk);
                                                                                  BOOLEAN
                                                                                  authOkConstraintIsOk =
                                                                                    authState >=
                                                                                      RBACPOLICY____ROLE_ADMIN;
                                                                                  uint64_t
                                                                                  positionAfterAuthOk1 =
                                                                                    EverParseCheckConstraintOk(authOkConstraintIsOk,
                                                                                      positionAfterAuthOk);
                                                                                  if
                                                                                  (
                                                                                    EverParseIsError(positionAfterAuthOk1)
                                                                                  )
                                                                                  {
                                                                                    positionAfterPolicyBlob26
                                                                                    =
                                                                                      positionAfterAuthOk1;
                                                                                  }
                                                                                  else
                                                                                  {
                                                                                    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                                                    BOOLEAN
                                                                                    hasBytes28 =
                                                                                      1ULL <=
                                                                                        (InputLength
                                                                                        -
                                                                                          positionAfterAuthOk1);
                                                                                    uint64_t
                                                                                    positionAfterRateOk;
                                                                                    if (hasBytes28)
                                                                                    {
                                                                                      positionAfterRateOk
                                                                                      =
                                                                                        positionAfterAuthOk1
                                                                                        + 1ULL;
                                                                                    }
                                                                                    else
                                                                                    {
                                                                                      positionAfterRateOk
                                                                                      =
                                                                                        EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                          positionAfterAuthOk1);
                                                                                    }
                                                                                    uint64_t
                                                                                    positionAfterPolicyBlob27;
                                                                                    if
                                                                                    (
                                                                                      EverParseIsError(positionAfterRateOk)
                                                                                    )
                                                                                    {
                                                                                      positionAfterPolicyBlob27
                                                                                      =
                                                                                        positionAfterRateOk;
                                                                                    }
                                                                                    else
                                                                                    {
                                                                                      uint8_t
                                                                                      rateOk =
                                                                                        Input[(uint32_t)positionAfterAuthOk1];
                                                                                      KRML_MAYBE_UNUSED_VAR(rateOk);
                                                                                      BOOLEAN
                                                                                      rateOkConstraintIsOk =
                                                                                        rateCount <
                                                                                          RBACPOLICY____MAX_RATE;
                                                                                      uint64_t
                                                                                      positionAfterRateOk1 =
                                                                                        EverParseCheckConstraintOk(rateOkConstraintIsOk,
                                                                                          positionAfterRateOk);
                                                                                      if
                                                                                      (
                                                                                        EverParseIsError(positionAfterRateOk1)
                                                                                      )
                                                                                      {
                                                                                        positionAfterPolicyBlob27
                                                                                        =
                                                                                          positionAfterRateOk1;
                                                                                      }
                                                                                      else
                                                                                      {
                                                                                        /* Validating field _rules_ok */
                                                                                        /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                                                        BOOLEAN
                                                                                        hasBytes =
                                                                                          1ULL <=
                                                                                            (InputLength
                                                                                            -
                                                                                              positionAfterRateOk1);
                                                                                        uint64_t
                                                                                        positionAfterRulesOk_refinement;
                                                                                        if
                                                                                        (hasBytes)
                                                                                        {
                                                                                          positionAfterRulesOk_refinement
                                                                                          =
                                                                                            positionAfterRateOk1
                                                                                            + 1ULL;
                                                                                        }
                                                                                        else
                                                                                        {
                                                                                          positionAfterRulesOk_refinement
                                                                                          =
                                                                                            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                              positionAfterRateOk1);
                                                                                        }
                                                                                        uint64_t
                                                                                        positionAfterPolicyBlob28;
                                                                                        if
                                                                                        (
                                                                                          EverParseIsError(positionAfterRulesOk_refinement)
                                                                                        )
                                                                                        {
                                                                                          positionAfterPolicyBlob28
                                                                                          =
                                                                                            positionAfterRulesOk_refinement;
                                                                                        }
                                                                                        else
                                                                                        {
                                                                                          /* reading field_value */
                                                                                          uint8_t
                                                                                          rulesOk_refinement =
                                                                                            Input[(uint32_t)positionAfterRateOk1];
                                                                                          KRML_MAYBE_UNUSED_VAR(rulesOk_refinement);
                                                                                          /* start: checking constraint */
                                                                                          BOOLEAN
                                                                                          rulesOk_refinementConstraintIsOk =
                                                                                            numRules
                                                                                            >= 1U
                                                                                            &&
                                                                                              numRules
                                                                                              <=
                                                                                                RBACPOLICY____MAX_RULES;
                                                                                          /* end: checking constraint */
                                                                                          positionAfterPolicyBlob28
                                                                                          =
                                                                                            EverParseCheckConstraintOk(rulesOk_refinementConstraintIsOk,
                                                                                              positionAfterRulesOk_refinement);
                                                                                        }
                                                                                        if
                                                                                        (
                                                                                          EverParseIsSuccess(positionAfterPolicyBlob28)
                                                                                        )
                                                                                        {
                                                                                          positionAfterPolicyBlob27
                                                                                          =
                                                                                            positionAfterPolicyBlob28;
                                                                                        }
                                                                                        else
                                                                                        {
                                                                                          ErrorHandlerFn("_PolicyBlob",
                                                                                            "_rules_ok.refinement",
                                                                                            EverParseErrorReasonOfResult(positionAfterPolicyBlob28),
                                                                                            EverParseGetValidatorErrorKind(positionAfterPolicyBlob28),
                                                                                            Ctxt,
                                                                                            Input,
                                                                                            positionAfterRateOk1);
                                                                                          positionAfterPolicyBlob27
                                                                                          =
                                                                                            positionAfterPolicyBlob28;
                                                                                        }
                                                                                      }
                                                                                    }
                                                                                    if
                                                                                    (
                                                                                      EverParseIsSuccess(positionAfterPolicyBlob27)
                                                                                    )
                                                                                    {
                                                                                      positionAfterPolicyBlob26
                                                                                      =
                                                                                        positionAfterPolicyBlob27;
                                                                                    }
                                                                                    else
                                                                                    {
                                                                                      ErrorHandlerFn("_PolicyBlob",
                                                                                        "_rate_ok",
                                                                                        EverParseErrorReasonOfResult(positionAfterPolicyBlob27),
                                                                                        EverParseGetValidatorErrorKind(positionAfterPolicyBlob27),
                                                                                        Ctxt,
                                                                                        Input,
                                                                                        positionAfterAuthOk1);
                                                                                      positionAfterPolicyBlob26
                                                                                      =
                                                                                        positionAfterPolicyBlob27;
                                                                                    }
                                                                                  }
                                                                                }
                                                                                if
                                                                                (
                                                                                  EverParseIsSuccess(positionAfterPolicyBlob26)
                                                                                )
                                                                                {
                                                                                  positionAfterPolicyBlob25
                                                                                  =
                                                                                    positionAfterPolicyBlob26;
                                                                                }
                                                                                else
                                                                                {
                                                                                  ErrorHandlerFn("_PolicyBlob",
                                                                                    "_auth_ok",
                                                                                    EverParseErrorReasonOfResult(positionAfterPolicyBlob26),
                                                                                    EverParseGetValidatorErrorKind(positionAfterPolicyBlob26),
                                                                                    Ctxt,
                                                                                    Input,
                                                                                    positionAfterr7MinRole1);
                                                                                  positionAfterPolicyBlob25
                                                                                  =
                                                                                    positionAfterPolicyBlob26;
                                                                                }
                                                                              }
                                                                            }
                                                                            if
                                                                            (
                                                                              EverParseIsSuccess(positionAfterPolicyBlob25)
                                                                            )
                                                                            {
                                                                              positionAfterPolicyBlob24
                                                                              =
                                                                                positionAfterPolicyBlob25;
                                                                            }
                                                                            else
                                                                            {
                                                                              ErrorHandlerFn("_PolicyBlob",
                                                                                "r7_min_role",
                                                                                EverParseErrorReasonOfResult(positionAfterPolicyBlob25),
                                                                                EverParseGetValidatorErrorKind(positionAfterPolicyBlob25),
                                                                                Ctxt,
                                                                                Input,
                                                                                positionAfterr7Method1);
                                                                              positionAfterPolicyBlob24
                                                                              =
                                                                                positionAfterPolicyBlob25;
                                                                            }
                                                                          }
                                                                        }
                                                                        if
                                                                        (
                                                                          EverParseIsSuccess(positionAfterPolicyBlob24)
                                                                        )
                                                                        {
                                                                          positionAfterPolicyBlob22
                                                                          =
                                                                            positionAfterPolicyBlob24;
                                                                        }
                                                                        else
                                                                        {
                                                                          ErrorHandlerFn("_PolicyBlob",
                                                                            "r7_method",
                                                                            EverParseErrorReasonOfResult(positionAfterPolicyBlob24),
                                                                            EverParseGetValidatorErrorKind(positionAfterPolicyBlob24),
                                                                            Ctxt,
                                                                            Input,
                                                                            positionAfterr7PathHash);
                                                                          positionAfterPolicyBlob22
                                                                          =
                                                                            positionAfterPolicyBlob24;
                                                                        }
                                                                      }
                                                                    }
                                                                  }
                                                                  if
                                                                  (
                                                                    EverParseIsSuccess(positionAfterPolicyBlob22)
                                                                  )
                                                                  {
                                                                    positionAfterPolicyBlob21 =
                                                                      positionAfterPolicyBlob22;
                                                                  }
                                                                  else
                                                                  {
                                                                    ErrorHandlerFn("_PolicyBlob",
                                                                      "r6_min_role",
                                                                      EverParseErrorReasonOfResult(positionAfterPolicyBlob22),
                                                                      EverParseGetValidatorErrorKind(positionAfterPolicyBlob22),
                                                                      Ctxt,
                                                                      Input,
                                                                      positionAfterr6Method1);
                                                                    positionAfterPolicyBlob21 =
                                                                      positionAfterPolicyBlob22;
                                                                  }
                                                                }
                                                              }
                                                              if
                                                              (
                                                                EverParseIsSuccess(positionAfterPolicyBlob21)
                                                              )
                                                              {
                                                                positionAfterPolicyBlob19 =
                                                                  positionAfterPolicyBlob21;
                                                              }
                                                              else
                                                              {
                                                                ErrorHandlerFn("_PolicyBlob",
                                                                  "r6_method",
                                                                  EverParseErrorReasonOfResult(positionAfterPolicyBlob21),
                                                                  EverParseGetValidatorErrorKind(positionAfterPolicyBlob21),
                                                                  Ctxt,
                                                                  Input,
                                                                  positionAfterr6PathHash);
                                                                positionAfterPolicyBlob19 =
                                                                  positionAfterPolicyBlob21;
                                                              }
                                                            }
                                                          }
                                                        }
                                                        if
                                                        (
                                                          EverParseIsSuccess(positionAfterPolicyBlob19)
                                                        )
                                                        {
                                                          positionAfterPolicyBlob18 =
                                                            positionAfterPolicyBlob19;
                                                        }
                                                        else
                                                        {
                                                          ErrorHandlerFn("_PolicyBlob",
                                                            "r5_min_role",
                                                            EverParseErrorReasonOfResult(positionAfterPolicyBlob19),
                                                            EverParseGetValidatorErrorKind(positionAfterPolicyBlob19),
                                                            Ctxt,
                                                            Input,
                                                            positionAfterr5Method1);
                                                          positionAfterPolicyBlob18 =
                                                            positionAfterPolicyBlob19;
                                                        }
                                                      }
                                                    }
                                                    if
                                                    (EverParseIsSuccess(positionAfterPolicyBlob18))
                                                    {
                                                      positionAfterPolicyBlob16 =
                                                        positionAfterPolicyBlob18;
                                                    }
                                                    else
                                                    {
                                                      ErrorHandlerFn("_PolicyBlob",
                                                        "r5_method",
                                                        EverParseErrorReasonOfResult(positionAfterPolicyBlob18),
                                                        EverParseGetValidatorErrorKind(positionAfterPolicyBlob18),
                                                        Ctxt,
                                                        Input,
                                                        positionAfterr5PathHash);
                                                      positionAfterPolicyBlob16 =
                                                        positionAfterPolicyBlob18;
                                                    }
                                                  }
                                                }
                                              }
                                              if (EverParseIsSuccess(positionAfterPolicyBlob16))
                                              {
                                                positionAfterPolicyBlob15 =
                                                  positionAfterPolicyBlob16;
                                              }
                                              else
                                              {
                                                ErrorHandlerFn("_PolicyBlob",
                                                  "r4_min_role",
                                                  EverParseErrorReasonOfResult(positionAfterPolicyBlob16),
                                                  EverParseGetValidatorErrorKind(positionAfterPolicyBlob16),
                                                  Ctxt,
                                                  Input,
                                                  positionAfterr4Method1);
                                                positionAfterPolicyBlob15 =
                                                  positionAfterPolicyBlob16;
                                              }
                                            }
                                          }
                                          if (EverParseIsSuccess(positionAfterPolicyBlob15))
                                          {
                                            positionAfterPolicyBlob13 = positionAfterPolicyBlob15;
                                          }
                                          else
                                          {
                                            ErrorHandlerFn("_PolicyBlob",
                                              "r4_method",
                                              EverParseErrorReasonOfResult(positionAfterPolicyBlob15),
                                              EverParseGetValidatorErrorKind(positionAfterPolicyBlob15),
                                              Ctxt,
                                              Input,
                                              positionAfterr4PathHash);
                                            positionAfterPolicyBlob13 = positionAfterPolicyBlob15;
                                          }
                                        }
                                      }
                                    }
                                    if (EverParseIsSuccess(positionAfterPolicyBlob13))
                                    {
                                      positionAfterPolicyBlob12 = positionAfterPolicyBlob13;
                                    }
                                    else
                                    {
                                      ErrorHandlerFn("_PolicyBlob",
                                        "r3_min_role",
                                        EverParseErrorReasonOfResult(positionAfterPolicyBlob13),
                                        EverParseGetValidatorErrorKind(positionAfterPolicyBlob13),
                                        Ctxt,
                                        Input,
                                        positionAfterr3Method1);
                                      positionAfterPolicyBlob12 = positionAfterPolicyBlob13;
                                    }
                                  }
                                }
                                if (EverParseIsSuccess(positionAfterPolicyBlob12))
                                {
                                  positionAfterPolicyBlob10 = positionAfterPolicyBlob12;
                                }
                                else
                                {
                                  ErrorHandlerFn("_PolicyBlob",
                                    "r3_method",
                                    EverParseErrorReasonOfResult(positionAfterPolicyBlob12),
                                    EverParseGetValidatorErrorKind(positionAfterPolicyBlob12),
                                    Ctxt,
                                    Input,
                                    positionAfterr3PathHash);
                                  positionAfterPolicyBlob10 = positionAfterPolicyBlob12;
                                }
                              }
                            }
                          }
                          if (EverParseIsSuccess(positionAfterPolicyBlob10))
                          {
                            positionAfterPolicyBlob9 = positionAfterPolicyBlob10;
                          }
                          else
                          {
                            ErrorHandlerFn("_PolicyBlob",
                              "r2_min_role",
                              EverParseErrorReasonOfResult(positionAfterPolicyBlob10),
                              EverParseGetValidatorErrorKind(positionAfterPolicyBlob10),
                              Ctxt,
                              Input,
                              positionAfterr2Method1);
                            positionAfterPolicyBlob9 = positionAfterPolicyBlob10;
                          }
                        }
                      }
                      if (EverParseIsSuccess(positionAfterPolicyBlob9))
                      {
                        positionAfterPolicyBlob7 = positionAfterPolicyBlob9;
                      }
                      else
                      {
                        ErrorHandlerFn("_PolicyBlob",
                          "r2_method",
                          EverParseErrorReasonOfResult(positionAfterPolicyBlob9),
                          EverParseGetValidatorErrorKind(positionAfterPolicyBlob9),
                          Ctxt,
                          Input,
                          positionAfterr2PathHash);
                        positionAfterPolicyBlob7 = positionAfterPolicyBlob9;
                      }
                    }
                  }
                }
                if (EverParseIsSuccess(positionAfterPolicyBlob7))
                {
                  positionAfterPolicyBlob6 = positionAfterPolicyBlob7;
                }
                else
                {
                  ErrorHandlerFn("_PolicyBlob",
                    "r1_min_role",
                    EverParseErrorReasonOfResult(positionAfterPolicyBlob7),
                    EverParseGetValidatorErrorKind(positionAfterPolicyBlob7),
                    Ctxt,
                    Input,
                    positionAfterr1Method1);
                  positionAfterPolicyBlob6 = positionAfterPolicyBlob7;
                }
              }
            }
            if (EverParseIsSuccess(positionAfterPolicyBlob6))
            {
              positionAfterPolicyBlob4 = positionAfterPolicyBlob6;
            }
            else
            {
              ErrorHandlerFn("_PolicyBlob",
                "r1_method",
                EverParseErrorReasonOfResult(positionAfterPolicyBlob6),
                EverParseGetValidatorErrorKind(positionAfterPolicyBlob6),
                Ctxt,
                Input,
                positionAfterr1PathHash);
              positionAfterPolicyBlob4 = positionAfterPolicyBlob6;
            }
          }
        }
      }
      if (EverParseIsSuccess(positionAfterPolicyBlob4))
      {
        positionAfterPolicyBlob3 = positionAfterPolicyBlob4;
      }
      else
      {
        ErrorHandlerFn("_PolicyBlob",
          "r0_min_role",
          EverParseErrorReasonOfResult(positionAfterPolicyBlob4),
          EverParseGetValidatorErrorKind(positionAfterPolicyBlob4),
          Ctxt,
          Input,
          positionAfterr0Method1);
        positionAfterPolicyBlob3 = positionAfterPolicyBlob4;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterPolicyBlob3))
  {
    return positionAfterPolicyBlob3;
  }
  ErrorHandlerFn("_PolicyBlob",
    "r0_method",
    EverParseErrorReasonOfResult(positionAfterPolicyBlob3),
    EverParseGetValidatorErrorKind(positionAfterPolicyBlob3),
    Ctxt,
    Input,
    positionAfterr0PathHash);
  return positionAfterPolicyBlob3;
}

uint64_t
RbacPolicyValidateAccessRequest(
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
  uint64_t positionAfterAccessRequest;
  if (hasBytes0)
  {
    positionAfterAccessRequest = StartPosition + 1ULL;
  }
  else
  {
    positionAfterAccessRequest =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterauthState;
  if (EverParseIsSuccess(positionAfterAccessRequest))
  {
    positionAfterauthState = positionAfterAccessRequest;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "auth_state",
      EverParseErrorReasonOfResult(positionAfterAccessRequest),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest),
      Ctxt,
      Input,
      StartPosition);
    positionAfterauthState = positionAfterAccessRequest;
  }
  if (EverParseIsError(positionAfterauthState))
  {
    return positionAfterauthState;
  }
  uint8_t authState = Input[(uint32_t)StartPosition];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAfterauthState);
  uint64_t positionAfterAccessRequest0;
  if (hasBytes1)
  {
    positionAfterAccessRequest0 = positionAfterauthState + 1ULL;
  }
  else
  {
    positionAfterAccessRequest0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterauthState);
  }
  uint64_t positionAfterrateCount;
  if (EverParseIsSuccess(positionAfterAccessRequest0))
  {
    positionAfterrateCount = positionAfterAccessRequest0;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "rate_count",
      EverParseErrorReasonOfResult(positionAfterAccessRequest0),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest0),
      Ctxt,
      Input,
      positionAfterauthState);
    positionAfterrateCount = positionAfterAccessRequest0;
  }
  if (EverParseIsError(positionAfterrateCount))
  {
    return positionAfterrateCount;
  }
  uint8_t rateCount = Input[(uint32_t)positionAfterauthState];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes2 = 4ULL <= (InputLength - positionAfterrateCount);
  uint64_t positionAfterAccessRequest1;
  if (hasBytes2)
  {
    positionAfterAccessRequest1 = positionAfterrateCount + 4ULL;
  }
  else
  {
    positionAfterAccessRequest1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrateCount);
  }
  uint64_t positionAfterr0PathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest1))
  {
    positionAfterr0PathHash = positionAfterAccessRequest1;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r0_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest1),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest1),
      Ctxt,
      Input,
      positionAfterrateCount);
    positionAfterr0PathHash = positionAfterAccessRequest1;
  }
  if (EverParseIsError(positionAfterr0PathHash))
  {
    return positionAfterr0PathHash;
  }
  uint32_t r0PathHash = Load32Le(Input + (uint32_t)positionAfterrateCount);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes3 = 1ULL <= (InputLength - positionAfterr0PathHash);
  uint64_t positionAfterAccessRequest2;
  if (hasBytes3)
  {
    positionAfterAccessRequest2 = positionAfterr0PathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0PathHash);
  }
  uint64_t positionAfterr0Method;
  if (EverParseIsSuccess(positionAfterAccessRequest2))
  {
    positionAfterr0Method = positionAfterAccessRequest2;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r0_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest2),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest2),
      Ctxt,
      Input,
      positionAfterr0PathHash);
    positionAfterr0Method = positionAfterAccessRequest2;
  }
  if (EverParseIsError(positionAfterr0Method))
  {
    return positionAfterr0Method;
  }
  uint8_t r0Method = Input[(uint32_t)positionAfterr0PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAfterr0Method);
  uint64_t positionAfterAccessRequest3;
  if (hasBytes4)
  {
    positionAfterAccessRequest3 = positionAfterr0Method + 1ULL;
  }
  else
  {
    positionAfterAccessRequest3 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0Method);
  }
  uint64_t positionAfterr0MinRole;
  if (EverParseIsSuccess(positionAfterAccessRequest3))
  {
    positionAfterr0MinRole = positionAfterAccessRequest3;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r0_min_role",
      EverParseErrorReasonOfResult(positionAfterAccessRequest3),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest3),
      Ctxt,
      Input,
      positionAfterr0Method);
    positionAfterr0MinRole = positionAfterAccessRequest3;
  }
  if (EverParseIsError(positionAfterr0MinRole))
  {
    return positionAfterr0MinRole;
  }
  uint8_t r0MinRole = Input[(uint32_t)positionAfterr0Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes5 = 4ULL <= (InputLength - positionAfterr0MinRole);
  uint64_t positionAfterAccessRequest4;
  if (hasBytes5)
  {
    positionAfterAccessRequest4 = positionAfterr0MinRole + 4ULL;
  }
  else
  {
    positionAfterAccessRequest4 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0MinRole);
  }
  uint64_t positionAfterr1PathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest4))
  {
    positionAfterr1PathHash = positionAfterAccessRequest4;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r1_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest4),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest4),
      Ctxt,
      Input,
      positionAfterr0MinRole);
    positionAfterr1PathHash = positionAfterAccessRequest4;
  }
  if (EverParseIsError(positionAfterr1PathHash))
  {
    return positionAfterr1PathHash;
  }
  uint32_t r1PathHash = Load32Le(Input + (uint32_t)positionAfterr0MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes6 = 1ULL <= (InputLength - positionAfterr1PathHash);
  uint64_t positionAfterAccessRequest5;
  if (hasBytes6)
  {
    positionAfterAccessRequest5 = positionAfterr1PathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest5 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1PathHash);
  }
  uint64_t positionAfterr1Method;
  if (EverParseIsSuccess(positionAfterAccessRequest5))
  {
    positionAfterr1Method = positionAfterAccessRequest5;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r1_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest5),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest5),
      Ctxt,
      Input,
      positionAfterr1PathHash);
    positionAfterr1Method = positionAfterAccessRequest5;
  }
  if (EverParseIsError(positionAfterr1Method))
  {
    return positionAfterr1Method;
  }
  uint8_t r1Method = Input[(uint32_t)positionAfterr1PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes7 = 1ULL <= (InputLength - positionAfterr1Method);
  uint64_t positionAfterAccessRequest6;
  if (hasBytes7)
  {
    positionAfterAccessRequest6 = positionAfterr1Method + 1ULL;
  }
  else
  {
    positionAfterAccessRequest6 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1Method);
  }
  uint64_t positionAfterr1MinRole;
  if (EverParseIsSuccess(positionAfterAccessRequest6))
  {
    positionAfterr1MinRole = positionAfterAccessRequest6;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r1_min_role",
      EverParseErrorReasonOfResult(positionAfterAccessRequest6),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest6),
      Ctxt,
      Input,
      positionAfterr1Method);
    positionAfterr1MinRole = positionAfterAccessRequest6;
  }
  if (EverParseIsError(positionAfterr1MinRole))
  {
    return positionAfterr1MinRole;
  }
  uint8_t r1MinRole = Input[(uint32_t)positionAfterr1Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes8 = 4ULL <= (InputLength - positionAfterr1MinRole);
  uint64_t positionAfterAccessRequest7;
  if (hasBytes8)
  {
    positionAfterAccessRequest7 = positionAfterr1MinRole + 4ULL;
  }
  else
  {
    positionAfterAccessRequest7 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1MinRole);
  }
  uint64_t positionAfterr2PathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest7))
  {
    positionAfterr2PathHash = positionAfterAccessRequest7;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r2_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest7),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest7),
      Ctxt,
      Input,
      positionAfterr1MinRole);
    positionAfterr2PathHash = positionAfterAccessRequest7;
  }
  if (EverParseIsError(positionAfterr2PathHash))
  {
    return positionAfterr2PathHash;
  }
  uint32_t r2PathHash = Load32Le(Input + (uint32_t)positionAfterr1MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes9 = 1ULL <= (InputLength - positionAfterr2PathHash);
  uint64_t positionAfterAccessRequest8;
  if (hasBytes9)
  {
    positionAfterAccessRequest8 = positionAfterr2PathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest8 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2PathHash);
  }
  uint64_t positionAfterr2Method;
  if (EverParseIsSuccess(positionAfterAccessRequest8))
  {
    positionAfterr2Method = positionAfterAccessRequest8;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r2_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest8),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest8),
      Ctxt,
      Input,
      positionAfterr2PathHash);
    positionAfterr2Method = positionAfterAccessRequest8;
  }
  if (EverParseIsError(positionAfterr2Method))
  {
    return positionAfterr2Method;
  }
  uint8_t r2Method = Input[(uint32_t)positionAfterr2PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes10 = 1ULL <= (InputLength - positionAfterr2Method);
  uint64_t positionAfterAccessRequest9;
  if (hasBytes10)
  {
    positionAfterAccessRequest9 = positionAfterr2Method + 1ULL;
  }
  else
  {
    positionAfterAccessRequest9 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2Method);
  }
  uint64_t positionAfterr2MinRole;
  if (EverParseIsSuccess(positionAfterAccessRequest9))
  {
    positionAfterr2MinRole = positionAfterAccessRequest9;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r2_min_role",
      EverParseErrorReasonOfResult(positionAfterAccessRequest9),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest9),
      Ctxt,
      Input,
      positionAfterr2Method);
    positionAfterr2MinRole = positionAfterAccessRequest9;
  }
  if (EverParseIsError(positionAfterr2MinRole))
  {
    return positionAfterr2MinRole;
  }
  uint8_t r2MinRole = Input[(uint32_t)positionAfterr2Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes11 = 4ULL <= (InputLength - positionAfterr2MinRole);
  uint64_t positionAfterAccessRequest10;
  if (hasBytes11)
  {
    positionAfterAccessRequest10 = positionAfterr2MinRole + 4ULL;
  }
  else
  {
    positionAfterAccessRequest10 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2MinRole);
  }
  uint64_t positionAfterr3PathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest10))
  {
    positionAfterr3PathHash = positionAfterAccessRequest10;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r3_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest10),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest10),
      Ctxt,
      Input,
      positionAfterr2MinRole);
    positionAfterr3PathHash = positionAfterAccessRequest10;
  }
  if (EverParseIsError(positionAfterr3PathHash))
  {
    return positionAfterr3PathHash;
  }
  uint32_t r3PathHash = Load32Le(Input + (uint32_t)positionAfterr2MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes12 = 1ULL <= (InputLength - positionAfterr3PathHash);
  uint64_t positionAfterAccessRequest11;
  if (hasBytes12)
  {
    positionAfterAccessRequest11 = positionAfterr3PathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest11 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3PathHash);
  }
  uint64_t positionAfterr3Method;
  if (EverParseIsSuccess(positionAfterAccessRequest11))
  {
    positionAfterr3Method = positionAfterAccessRequest11;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r3_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest11),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest11),
      Ctxt,
      Input,
      positionAfterr3PathHash);
    positionAfterr3Method = positionAfterAccessRequest11;
  }
  if (EverParseIsError(positionAfterr3Method))
  {
    return positionAfterr3Method;
  }
  uint8_t r3Method = Input[(uint32_t)positionAfterr3PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes13 = 1ULL <= (InputLength - positionAfterr3Method);
  uint64_t positionAfterAccessRequest12;
  if (hasBytes13)
  {
    positionAfterAccessRequest12 = positionAfterr3Method + 1ULL;
  }
  else
  {
    positionAfterAccessRequest12 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3Method);
  }
  uint64_t positionAfterr3MinRole;
  if (EverParseIsSuccess(positionAfterAccessRequest12))
  {
    positionAfterr3MinRole = positionAfterAccessRequest12;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r3_min_role",
      EverParseErrorReasonOfResult(positionAfterAccessRequest12),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest12),
      Ctxt,
      Input,
      positionAfterr3Method);
    positionAfterr3MinRole = positionAfterAccessRequest12;
  }
  if (EverParseIsError(positionAfterr3MinRole))
  {
    return positionAfterr3MinRole;
  }
  uint8_t r3MinRole = Input[(uint32_t)positionAfterr3Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes14 = 4ULL <= (InputLength - positionAfterr3MinRole);
  uint64_t positionAfterAccessRequest13;
  if (hasBytes14)
  {
    positionAfterAccessRequest13 = positionAfterr3MinRole + 4ULL;
  }
  else
  {
    positionAfterAccessRequest13 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3MinRole);
  }
  uint64_t positionAfterr4PathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest13))
  {
    positionAfterr4PathHash = positionAfterAccessRequest13;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r4_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest13),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest13),
      Ctxt,
      Input,
      positionAfterr3MinRole);
    positionAfterr4PathHash = positionAfterAccessRequest13;
  }
  if (EverParseIsError(positionAfterr4PathHash))
  {
    return positionAfterr4PathHash;
  }
  uint32_t r4PathHash = Load32Le(Input + (uint32_t)positionAfterr3MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes15 = 1ULL <= (InputLength - positionAfterr4PathHash);
  uint64_t positionAfterAccessRequest14;
  if (hasBytes15)
  {
    positionAfterAccessRequest14 = positionAfterr4PathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest14 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4PathHash);
  }
  uint64_t positionAfterr4Method;
  if (EverParseIsSuccess(positionAfterAccessRequest14))
  {
    positionAfterr4Method = positionAfterAccessRequest14;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r4_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest14),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest14),
      Ctxt,
      Input,
      positionAfterr4PathHash);
    positionAfterr4Method = positionAfterAccessRequest14;
  }
  if (EverParseIsError(positionAfterr4Method))
  {
    return positionAfterr4Method;
  }
  uint8_t r4Method = Input[(uint32_t)positionAfterr4PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes16 = 1ULL <= (InputLength - positionAfterr4Method);
  uint64_t positionAfterAccessRequest15;
  if (hasBytes16)
  {
    positionAfterAccessRequest15 = positionAfterr4Method + 1ULL;
  }
  else
  {
    positionAfterAccessRequest15 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4Method);
  }
  uint64_t positionAfterr4MinRole;
  if (EverParseIsSuccess(positionAfterAccessRequest15))
  {
    positionAfterr4MinRole = positionAfterAccessRequest15;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r4_min_role",
      EverParseErrorReasonOfResult(positionAfterAccessRequest15),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest15),
      Ctxt,
      Input,
      positionAfterr4Method);
    positionAfterr4MinRole = positionAfterAccessRequest15;
  }
  if (EverParseIsError(positionAfterr4MinRole))
  {
    return positionAfterr4MinRole;
  }
  uint8_t r4MinRole = Input[(uint32_t)positionAfterr4Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes17 = 4ULL <= (InputLength - positionAfterr4MinRole);
  uint64_t positionAfterAccessRequest16;
  if (hasBytes17)
  {
    positionAfterAccessRequest16 = positionAfterr4MinRole + 4ULL;
  }
  else
  {
    positionAfterAccessRequest16 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4MinRole);
  }
  uint64_t positionAfterr5PathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest16))
  {
    positionAfterr5PathHash = positionAfterAccessRequest16;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r5_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest16),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest16),
      Ctxt,
      Input,
      positionAfterr4MinRole);
    positionAfterr5PathHash = positionAfterAccessRequest16;
  }
  if (EverParseIsError(positionAfterr5PathHash))
  {
    return positionAfterr5PathHash;
  }
  uint32_t r5PathHash = Load32Le(Input + (uint32_t)positionAfterr4MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes18 = 1ULL <= (InputLength - positionAfterr5PathHash);
  uint64_t positionAfterAccessRequest17;
  if (hasBytes18)
  {
    positionAfterAccessRequest17 = positionAfterr5PathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest17 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5PathHash);
  }
  uint64_t positionAfterr5Method;
  if (EverParseIsSuccess(positionAfterAccessRequest17))
  {
    positionAfterr5Method = positionAfterAccessRequest17;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r5_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest17),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest17),
      Ctxt,
      Input,
      positionAfterr5PathHash);
    positionAfterr5Method = positionAfterAccessRequest17;
  }
  if (EverParseIsError(positionAfterr5Method))
  {
    return positionAfterr5Method;
  }
  uint8_t r5Method = Input[(uint32_t)positionAfterr5PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes19 = 1ULL <= (InputLength - positionAfterr5Method);
  uint64_t positionAfterAccessRequest18;
  if (hasBytes19)
  {
    positionAfterAccessRequest18 = positionAfterr5Method + 1ULL;
  }
  else
  {
    positionAfterAccessRequest18 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5Method);
  }
  uint64_t positionAfterr5MinRole;
  if (EverParseIsSuccess(positionAfterAccessRequest18))
  {
    positionAfterr5MinRole = positionAfterAccessRequest18;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r5_min_role",
      EverParseErrorReasonOfResult(positionAfterAccessRequest18),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest18),
      Ctxt,
      Input,
      positionAfterr5Method);
    positionAfterr5MinRole = positionAfterAccessRequest18;
  }
  if (EverParseIsError(positionAfterr5MinRole))
  {
    return positionAfterr5MinRole;
  }
  uint8_t r5MinRole = Input[(uint32_t)positionAfterr5Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes20 = 4ULL <= (InputLength - positionAfterr5MinRole);
  uint64_t positionAfterAccessRequest19;
  if (hasBytes20)
  {
    positionAfterAccessRequest19 = positionAfterr5MinRole + 4ULL;
  }
  else
  {
    positionAfterAccessRequest19 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5MinRole);
  }
  uint64_t positionAfterr6PathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest19))
  {
    positionAfterr6PathHash = positionAfterAccessRequest19;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r6_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest19),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest19),
      Ctxt,
      Input,
      positionAfterr5MinRole);
    positionAfterr6PathHash = positionAfterAccessRequest19;
  }
  if (EverParseIsError(positionAfterr6PathHash))
  {
    return positionAfterr6PathHash;
  }
  uint32_t r6PathHash = Load32Le(Input + (uint32_t)positionAfterr5MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes21 = 1ULL <= (InputLength - positionAfterr6PathHash);
  uint64_t positionAfterAccessRequest20;
  if (hasBytes21)
  {
    positionAfterAccessRequest20 = positionAfterr6PathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest20 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6PathHash);
  }
  uint64_t positionAfterr6Method;
  if (EverParseIsSuccess(positionAfterAccessRequest20))
  {
    positionAfterr6Method = positionAfterAccessRequest20;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r6_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest20),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest20),
      Ctxt,
      Input,
      positionAfterr6PathHash);
    positionAfterr6Method = positionAfterAccessRequest20;
  }
  if (EverParseIsError(positionAfterr6Method))
  {
    return positionAfterr6Method;
  }
  uint8_t r6Method = Input[(uint32_t)positionAfterr6PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes22 = 1ULL <= (InputLength - positionAfterr6Method);
  uint64_t positionAfterAccessRequest21;
  if (hasBytes22)
  {
    positionAfterAccessRequest21 = positionAfterr6Method + 1ULL;
  }
  else
  {
    positionAfterAccessRequest21 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6Method);
  }
  uint64_t positionAfterr6MinRole;
  if (EverParseIsSuccess(positionAfterAccessRequest21))
  {
    positionAfterr6MinRole = positionAfterAccessRequest21;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r6_min_role",
      EverParseErrorReasonOfResult(positionAfterAccessRequest21),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest21),
      Ctxt,
      Input,
      positionAfterr6Method);
    positionAfterr6MinRole = positionAfterAccessRequest21;
  }
  if (EverParseIsError(positionAfterr6MinRole))
  {
    return positionAfterr6MinRole;
  }
  uint8_t r6MinRole = Input[(uint32_t)positionAfterr6Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes23 = 4ULL <= (InputLength - positionAfterr6MinRole);
  uint64_t positionAfterAccessRequest22;
  if (hasBytes23)
  {
    positionAfterAccessRequest22 = positionAfterr6MinRole + 4ULL;
  }
  else
  {
    positionAfterAccessRequest22 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6MinRole);
  }
  uint64_t positionAfterr7PathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest22))
  {
    positionAfterr7PathHash = positionAfterAccessRequest22;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r7_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest22),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest22),
      Ctxt,
      Input,
      positionAfterr6MinRole);
    positionAfterr7PathHash = positionAfterAccessRequest22;
  }
  if (EverParseIsError(positionAfterr7PathHash))
  {
    return positionAfterr7PathHash;
  }
  uint32_t r7PathHash = Load32Le(Input + (uint32_t)positionAfterr6MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes24 = 1ULL <= (InputLength - positionAfterr7PathHash);
  uint64_t positionAfterAccessRequest23;
  if (hasBytes24)
  {
    positionAfterAccessRequest23 = positionAfterr7PathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest23 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7PathHash);
  }
  uint64_t positionAfterr7Method;
  if (EverParseIsSuccess(positionAfterAccessRequest23))
  {
    positionAfterr7Method = positionAfterAccessRequest23;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r7_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest23),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest23),
      Ctxt,
      Input,
      positionAfterr7PathHash);
    positionAfterr7Method = positionAfterAccessRequest23;
  }
  if (EverParseIsError(positionAfterr7Method))
  {
    return positionAfterr7Method;
  }
  uint8_t r7Method = Input[(uint32_t)positionAfterr7PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes25 = 1ULL <= (InputLength - positionAfterr7Method);
  uint64_t positionAfterAccessRequest24;
  if (hasBytes25)
  {
    positionAfterAccessRequest24 = positionAfterr7Method + 1ULL;
  }
  else
  {
    positionAfterAccessRequest24 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7Method);
  }
  uint64_t positionAfterr7MinRole;
  if (EverParseIsSuccess(positionAfterAccessRequest24))
  {
    positionAfterr7MinRole = positionAfterAccessRequest24;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r7_min_role",
      EverParseErrorReasonOfResult(positionAfterAccessRequest24),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest24),
      Ctxt,
      Input,
      positionAfterr7Method);
    positionAfterr7MinRole = positionAfterAccessRequest24;
  }
  if (EverParseIsError(positionAfterr7MinRole))
  {
    return positionAfterr7MinRole;
  }
  uint8_t r7MinRole = Input[(uint32_t)positionAfterr7Method];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes26 = 4ULL <= (InputLength - positionAfterr7MinRole);
  uint64_t positionAfterAccessRequest25;
  if (hasBytes26)
  {
    positionAfterAccessRequest25 = positionAfterr7MinRole + 4ULL;
  }
  else
  {
    positionAfterAccessRequest25 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7MinRole);
  }
  uint64_t positionAfterreqPathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest25))
  {
    positionAfterreqPathHash = positionAfterAccessRequest25;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "req_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest25),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest25),
      Ctxt,
      Input,
      positionAfterr7MinRole);
    positionAfterreqPathHash = positionAfterAccessRequest25;
  }
  if (EverParseIsError(positionAfterreqPathHash))
  {
    return positionAfterreqPathHash;
  }
  uint32_t reqPathHash = Load32Le(Input + (uint32_t)positionAfterr7MinRole);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes27 = 1ULL <= (InputLength - positionAfterreqPathHash);
  uint64_t positionAfterAccessRequest26;
  if (hasBytes27)
  {
    positionAfterAccessRequest26 = positionAfterreqPathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest26 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqPathHash);
  }
  uint64_t positionAfterreqMethod;
  if (EverParseIsSuccess(positionAfterAccessRequest26))
  {
    positionAfterreqMethod = positionAfterAccessRequest26;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "req_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest26),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest26),
      Ctxt,
      Input,
      positionAfterreqPathHash);
    positionAfterreqMethod = positionAfterAccessRequest26;
  }
  if (EverParseIsError(positionAfterreqMethod))
  {
    return positionAfterreqMethod;
  }
  uint8_t reqMethod = Input[(uint32_t)positionAfterreqPathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes28 = 1ULL <= (InputLength - positionAfterreqMethod);
  uint64_t positionAfterRateOk;
  if (hasBytes28)
  {
    positionAfterRateOk = positionAfterreqMethod + 1ULL;
  }
  else
  {
    positionAfterRateOk =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqMethod);
  }
  uint64_t positionAfterAccessRequest27;
  if (EverParseIsError(positionAfterRateOk))
  {
    positionAfterAccessRequest27 = positionAfterRateOk;
  }
  else
  {
    uint8_t rateOk = Input[(uint32_t)positionAfterreqMethod];
    KRML_MAYBE_UNUSED_VAR(rateOk);
    BOOLEAN rateOkConstraintIsOk = rateCount < RBACPOLICY____MAX_RATE;
    uint64_t
    positionAfterRateOk1 = EverParseCheckConstraintOk(rateOkConstraintIsOk, positionAfterRateOk);
    if (EverParseIsError(positionAfterRateOk1))
    {
      positionAfterAccessRequest27 = positionAfterRateOk1;
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
      uint64_t positionAfterAccessRequest28;
      if (EverParseIsError(positionAfterAccessOk_refinement))
      {
        positionAfterAccessRequest28 = positionAfterAccessOk_refinement;
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
        positionAfterAccessRequest28 =
          EverParseCheckConstraintOk(accessOk_refinementConstraintIsOk,
            positionAfterAccessOk_refinement);
      }
      if (EverParseIsSuccess(positionAfterAccessRequest28))
      {
        positionAfterAccessRequest27 = positionAfterAccessRequest28;
      }
      else
      {
        ErrorHandlerFn("_AccessRequest",
          "_access_ok.refinement",
          EverParseErrorReasonOfResult(positionAfterAccessRequest28),
          EverParseGetValidatorErrorKind(positionAfterAccessRequest28),
          Ctxt,
          Input,
          positionAfterRateOk1);
        positionAfterAccessRequest27 = positionAfterAccessRequest28;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterAccessRequest27))
  {
    return positionAfterAccessRequest27;
  }
  ErrorHandlerFn("_AccessRequest",
    "_rate_ok",
    EverParseErrorReasonOfResult(positionAfterAccessRequest27),
    EverParseGetValidatorErrorKind(positionAfterAccessRequest27),
    Ctxt,
    Input,
    positionAfterreqMethod);
  return positionAfterAccessRequest27;
}

