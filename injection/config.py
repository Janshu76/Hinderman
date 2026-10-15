"""Central settings for the injection module. Nothing here is a shared contract."""
import os

# Score >= LABEL_THRESHOLD -> label "injection". Matches the INJ-002 policy tier.
LABEL_THRESHOLD = 0.5
# Documented here, enforced by M1's policy file (INJ-001 -> block).
BLOCK_THRESHOLD = 0.8
# Findings below this confidence are not sent to the policy engine.
MIN_FINDING_CONFIDENCE = 0.5

# Document-only signal: this many invisible characters in one chunk is suspicious.
HIDDEN_CHARS_THRESHOLD = 5

# The contract has no "generic injection" type, so a model-only detection
# (no rule fired) is reported under DEFAULT_USER_TYPE.
DEFAULT_USER_TYPE = "INSTRUCTION_OVERRIDE"
DOCUMENT_TYPE = "INDIRECT_INJECTION"

# Layer 2 (classifier)
MODEL_NAME = os.getenv("INJECTION_MODEL", "protectai/deberta-v3-base-prompt-injection-v2")
MAX_TOKENS = 512        # model limit
STRIDE_TOKENS = 128     # overlap between windows
MAX_WINDOWS = 16        # latency cap: about 8k tokens scanned by the model


def get_mode() -> str:
    """rules | model | combined. Read at call time so tests and eval can change it."""
    mode = os.getenv("INJECTION_MODE", "combined").strip().lower()
    return mode if mode in {"rules", "model", "combined"} else "combined"