"""Track 4 Adapter v1 entry point. One JSON request per process."""

import json
import sys
from pqguard.service import dispatch


def main() -> int:
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            raise ValueError("Request must be a JSON object")
        response = dispatch(request)
        if not isinstance(response, dict):
            raise ValueError("Response must be a JSON object")
        encoded = json.dumps(response, allow_nan=False)
    except Exception:
        # Never print request data, keys, or secrets to stderr.
        print("Request failed; inspect application state locally.", file=sys.stderr)
        return 1
    sys.stdout.write(encoded + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
