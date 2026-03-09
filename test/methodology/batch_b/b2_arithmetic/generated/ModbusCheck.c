

#include "ModbusCheck.h"

uint64_t
ModbusCheckValidateModbusCheck(
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
  uint64_t positionAfterModbusCheck;
  if (hasBytes0)
  {
    positionAfterModbusCheck = StartPosition + 1ULL;
  }
  else
  {
    positionAfterModbusCheck =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterfc;
  if (EverParseIsSuccess(positionAfterModbusCheck))
  {
    positionAfterfc = positionAfterModbusCheck;
  }
  else
  {
    ErrorHandlerFn("_ModbusCheck",
      "fc",
      EverParseErrorReasonOfResult(positionAfterModbusCheck),
      EverParseGetValidatorErrorKind(positionAfterModbusCheck),
      Ctxt,
      Input,
      StartPosition);
    positionAfterfc = positionAfterModbusCheck;
  }
  if (EverParseIsError(positionAfterfc))
  {
    return positionAfterfc;
  }
  uint8_t fc = Input[(uint32_t)StartPosition];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes1 = 2ULL <= (InputLength - positionAfterfc);
  uint64_t positionAfterModbusCheck0;
  if (hasBytes1)
  {
    positionAfterModbusCheck0 = positionAfterfc + 2ULL;
  }
  else
  {
    positionAfterModbusCheck0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterfc);
  }
  uint64_t positionAfterstartAddress;
  if (EverParseIsSuccess(positionAfterModbusCheck0))
  {
    positionAfterstartAddress = positionAfterModbusCheck0;
  }
  else
  {
    ErrorHandlerFn("_ModbusCheck",
      "start_address",
      EverParseErrorReasonOfResult(positionAfterModbusCheck0),
      EverParseGetValidatorErrorKind(positionAfterModbusCheck0),
      Ctxt,
      Input,
      positionAfterfc);
    positionAfterstartAddress = positionAfterModbusCheck0;
  }
  if (EverParseIsError(positionAfterstartAddress))
  {
    return positionAfterstartAddress;
  }
  uint16_t r0 = Load16Le(Input + (uint32_t)positionAfterfc);
  uint16_t startAddress = (uint16_t)(uint32_t)r0;
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes2 = 2ULL <= (InputLength - positionAfterstartAddress);
  uint64_t positionAfterModbusCheck1;
  if (hasBytes2)
  {
    positionAfterModbusCheck1 = positionAfterstartAddress + 2ULL;
  }
  else
  {
    positionAfterModbusCheck1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterstartAddress);
  }
  uint64_t positionAfterquantity;
  if (EverParseIsSuccess(positionAfterModbusCheck1))
  {
    positionAfterquantity = positionAfterModbusCheck1;
  }
  else
  {
    ErrorHandlerFn("_ModbusCheck",
      "quantity",
      EverParseErrorReasonOfResult(positionAfterModbusCheck1),
      EverParseGetValidatorErrorKind(positionAfterModbusCheck1),
      Ctxt,
      Input,
      positionAfterstartAddress);
    positionAfterquantity = positionAfterModbusCheck1;
  }
  if (EverParseIsError(positionAfterquantity))
  {
    return positionAfterquantity;
  }
  uint16_t r = Load16Le(Input + (uint32_t)positionAfterstartAddress);
  uint16_t quantity = (uint16_t)(uint32_t)r;
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes3 = 1ULL <= (InputLength - positionAfterquantity);
  uint64_t positionAfterModbusCheck2;
  if (hasBytes3)
  {
    positionAfterModbusCheck2 = positionAfterquantity + 1ULL;
  }
  else
  {
    positionAfterModbusCheck2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterquantity);
  }
  uint64_t positionAfterbyteCount;
  if (EverParseIsSuccess(positionAfterModbusCheck2))
  {
    positionAfterbyteCount = positionAfterModbusCheck2;
  }
  else
  {
    ErrorHandlerFn("_ModbusCheck",
      "byte_count",
      EverParseErrorReasonOfResult(positionAfterModbusCheck2),
      EverParseGetValidatorErrorKind(positionAfterModbusCheck2),
      Ctxt,
      Input,
      positionAfterquantity);
    positionAfterbyteCount = positionAfterModbusCheck2;
  }
  if (EverParseIsError(positionAfterbyteCount))
  {
    return positionAfterbyteCount;
  }
  uint8_t byteCount = Input[(uint32_t)positionAfterquantity];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAfterbyteCount);
  uint64_t positionAfterBounds;
  if (hasBytes4)
  {
    positionAfterBounds = positionAfterbyteCount + 1ULL;
  }
  else
  {
    positionAfterBounds =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterbyteCount);
  }
  uint64_t positionAfterModbusCheck3;
  if (EverParseIsError(positionAfterBounds))
  {
    positionAfterModbusCheck3 = positionAfterBounds;
  }
  else
  {
    uint8_t bounds = Input[(uint32_t)positionAfterbyteCount];
    KRML_MAYBE_UNUSED_VAR(bounds);
    BOOLEAN
    boundsConstraintIsOk =
      quantity >= (uint16_t)1U && quantity <= (uint16_t)125U && startAddress <= 65410U;
    uint64_t
    positionAfterBounds1 = EverParseCheckConstraintOk(boundsConstraintIsOk, positionAfterBounds);
    if (EverParseIsError(positionAfterBounds1))
    {
      positionAfterModbusCheck3 = positionAfterBounds1;
    }
    else
    {
      /* Validating field _check */
      /* Checking that we have enough space for a UINT8, i.e., 1 byte */
      BOOLEAN hasBytes = 1ULL <= (InputLength - positionAfterBounds1);
      uint64_t positionAfterCheck_refinement;
      if (hasBytes)
      {
        positionAfterCheck_refinement = positionAfterBounds1 + 1ULL;
      }
      else
      {
        positionAfterCheck_refinement =
          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterBounds1);
      }
      uint64_t positionAfterModbusCheck4;
      if (EverParseIsError(positionAfterCheck_refinement))
      {
        positionAfterModbusCheck4 = positionAfterCheck_refinement;
      }
      else
      {
        /* reading field_value */
        uint8_t check_refinement = Input[(uint32_t)positionAfterBounds1];
        KRML_MAYBE_UNUSED_VAR(check_refinement);
        /* start: checking constraint */
        BOOLEAN
        check_refinementConstraintIsOk =
          fc == 3U && (uint16_t)byteCount == (uint32_t)quantity * (uint32_t)(uint16_t)2U &&
            ((uint32_t)startAddress + (uint32_t)quantity) <= 65535U;
        /* end: checking constraint */
        positionAfterModbusCheck4 =
          EverParseCheckConstraintOk(check_refinementConstraintIsOk,
            positionAfterCheck_refinement);
      }
      if (EverParseIsSuccess(positionAfterModbusCheck4))
      {
        positionAfterModbusCheck3 = positionAfterModbusCheck4;
      }
      else
      {
        ErrorHandlerFn("_ModbusCheck",
          "_check.refinement",
          EverParseErrorReasonOfResult(positionAfterModbusCheck4),
          EverParseGetValidatorErrorKind(positionAfterModbusCheck4),
          Ctxt,
          Input,
          positionAfterBounds1);
        positionAfterModbusCheck3 = positionAfterModbusCheck4;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterModbusCheck3))
  {
    return positionAfterModbusCheck3;
  }
  ErrorHandlerFn("_ModbusCheck",
    "_bounds",
    EverParseErrorReasonOfResult(positionAfterModbusCheck3),
    EverParseGetValidatorErrorKind(positionAfterModbusCheck3),
    Ctxt,
    Input,
    positionAfterbyteCount);
  return positionAfterModbusCheck3;
}

