class ResponseTypes:
    SUCCESS = "Success"  # the process ended correctly
    DUPLICATE = "Duplicate"  # already delivered: acknowledged, not stored again
    PARAMETERS_ERROR = "ParametersError"  # missing or invalid parameters
    UNSUPPORTED_VERSION = "UnsupportedVersion"  # unknown wire protocol version
    UNKNOWN_MAILBOX = "UnknownMailbox"  # no such user on this node
    TOO_LARGE = "TooLarge"  # message exceeds the receiver's size cap
    VERIFICATION_ERROR = "VerificationError"  # signature or id check failed
    PAYMENT_REQUIRED = "PaymentRequired"  # first contact needs a postage stamp
    KEYS_UNREACHABLE = "KeysUnreachable"  # sender's discovery document unreachable
    REJECTED = "Rejected"  # the receiver refused permanently (4xx)
    RESOURCE_ERROR = "ResourceError"  # a needed resource is missing
    SYSTEM_ERROR = "SystemError"  # unexpected error, never a raw exception


def success(**data) -> dict:
    return {"type": ResponseTypes.SUCCESS, "errors": [], "data": data}


def failure(response_type: str, field: str, message: str, **data) -> dict:
    return {
        "type": response_type,
        "errors": [{"field": field, "message": message}],
        "data": data,
    }
