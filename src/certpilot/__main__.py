"""Allow ``python -m certpilot``."""

from certpilot.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
