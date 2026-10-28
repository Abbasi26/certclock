"""Allow ``python -m certclock``."""

from certclock.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
