"""`python -m sectestgen ...` - same as the `sectestgen` console script.

Useful where the generated `sectestgen.exe` launcher can't run (e.g. it is
blocked by Windows Application Control) or another `sectestgen` is first
on PATH.
"""

from sectestgen.cli import main

raise SystemExit(main())
