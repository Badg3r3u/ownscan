"""Allow `python -m ownscan`."""

from ownscan.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
