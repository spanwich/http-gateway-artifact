#include "Test1DisjunctionWrapper.h"
#include "EverParse.h"
#include "Test1Disjunction.h"
void Test1DisjunctionEverParseError(const char *StructName, const char *FieldName, const char *Reason);

static
void DefaultErrorHandler(
	const char *typename_s,
	const char *fieldname,
	const char *reason,
	uint64_t error_code,
	uint8_t *context,
	EVERPARSE_INPUT_BUFFER input,
	uint64_t start_pos)
{
	EVERPARSE_ERROR_FRAME *frame = (EVERPARSE_ERROR_FRAME*)context;
	EverParseDefaultErrorHandler(
		typename_s,
		fieldname,
		reason,
		error_code,
		frame,
		input,
		start_pos
	);
}

BOOLEAN Test1disjunctionCheckTestAccess(uint8_t *base, uint32_t len) {
	EVERPARSE_ERROR_FRAME frame;
	frame.filled = FALSE;
	uint64_t result = Test1disjunctionValidateTestAccess( (uint8_t*)&frame, &DefaultErrorHandler, base, len, 0);
	if (EverParseIsError(result))
	{
		if (frame.filled)
		{
			Test1DisjunctionEverParseError(frame.typename_s, frame.fieldname, frame.reason);
		}
		return FALSE;
	}
	return TRUE;
}
