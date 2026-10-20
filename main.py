"""TracertMap — запуск: python main.py  (или двойной щелчок по run.bat в Windows)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tracemap.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
