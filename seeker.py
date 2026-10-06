#!/usr/bin/env python3
"""Seeker — authorized awareness simulations and deceptive-location audits.

v2 entry point.  The v1 tool (flat files + PHP) is preserved under ``legacy/``
and can still be run with ``python3 legacy/seeker_v1.py``.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.cli import main  # noqa: E402

if __name__ == '__main__':
    sys.exit(main())
