'use strict';

// API error code registry (SPEC.md §8.4).
const ERR = {
	MALFORMED_REQUEST: 1000,
	UNAUTHORIZED: 1001,
	UNKNOWN_OPERATION: 1002,
	METHOD_NOT_ALLOWED: 1003,
	UNKNOWN_ENDPOINT: 1004,
	INVALID_REQUEST_DATA: 1100,
	KEY_NOT_FOUND: 1101,
	INCOMPATIBLE_KEY_TYPE: 1102,
	INVALID_INPUT_TOKEN: 1103,
	OPERATION_DISABLED: 1104,
	INVALID_ACL: 1105,
	KEY_NOT_AVAILABLE: 1106,
	INTERNAL_ERROR: 1900
};

const ERR_MESSAGE = {
	[ERR.MALFORMED_REQUEST]: 'Malformed request',
	[ERR.UNAUTHORIZED]: 'Unauthorized',
	[ERR.UNKNOWN_OPERATION]: 'Unknown operation',
	[ERR.METHOD_NOT_ALLOWED]: 'Method not allowed',
	[ERR.UNKNOWN_ENDPOINT]: 'Unknown endpoint',
	[ERR.INVALID_REQUEST_DATA]: 'Invalid request data',
	[ERR.KEY_NOT_FOUND]: 'Key not found',
	[ERR.INCOMPATIBLE_KEY_TYPE]: 'Incompatible key type',
	[ERR.INVALID_INPUT_TOKEN]: 'Invalid input token',
	[ERR.OPERATION_DISABLED]: 'Operation disabled',
	[ERR.INVALID_ACL]: 'Invalid ACL',
	[ERR.KEY_NOT_AVAILABLE]: 'Key not available',
	[ERR.INTERNAL_ERROR]: 'Internal error'
};

// Operation-level API error. `message` defaults to the registry
// message for the code; messages are short fixed strings and must
// never include key material, tokens, or internals.
class ApiError extends Error {
	constructor(errorCode, message) {
		super(message || ERR_MESSAGE[errorCode] || 'Error');
		this.name = 'ApiError';
		this.errorCode = errorCode;
	}
}

// Internal marker: the wrapping KEK of a key row is not configured.
// Mapped to ERR.KEY_NOT_AVAILABLE only for otherwise-authorized
// callers (SPEC.md §5).
class KekUnavailableError extends Error {
	constructor(embeddingKeyId) {
		super('Embedding key not available');
		this.name = 'KekUnavailableError';
		this.embeddingKeyId = embeddingKeyId;
	}
}

module.exports = { ERR, ERR_MESSAGE, ApiError, KekUnavailableError };
