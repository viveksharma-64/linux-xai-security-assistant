import os

import uvicorn

from observability import configure_logging


def main() -> None:
    configure_logging()
    host = os.getenv("SECURITY_API_HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "localhost", "::1"} and os.getenv("ALLOW_NON_LOOPBACK_API") != "1":
        raise SystemExit("Refusing non-loopback API host; set ALLOW_NON_LOOPBACK_API=1 explicitly.")
    uvicorn.run("api.app:app", host=host, port=int(os.getenv("SECURITY_API_PORT", "8000")))


if __name__ == "__main__":
    main()
