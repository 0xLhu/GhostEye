#!/usr/bin/env python3
"""GhostEye entry point.  python main.py            → graphical interface
                           python main.py --help     → all commands"""

import sys

if sys.version_info < (3, 8):
    sys.exit("GhostEye needs Python 3.8+")

from ghosteye.cli import main

if __name__ == "__main__":
    main()
