VERSION = 1  # wire protocol version, see SPEC.md
MAX_SIZE = 64_000  # per message JSON, in bytes
MAX_ATTACHMENT = 10_000_000  # per encrypted blob, in bytes
MAX_ATTACHMENTS = 4  # per message
MAX_BACKOFF = 86_400  # retry at most once a day
RETRY_BASE = 300  # first retry after 5 minutes, doubling per attempt
