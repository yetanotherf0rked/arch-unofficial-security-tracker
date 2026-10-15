#!/usr/bin/env python3
"""
Refresh the tracker: build the feed into _site/ (see archsec/build.py).

  python update.py                      fetch everything, write _site/
  python update.py --out DIR            write elsewhere
  python update.py --packages snap.json --osv-dir zips/   offline rebuild
"""

import sys

from archsec.build import main

if __name__ == "__main__":
    sys.exit(main())
