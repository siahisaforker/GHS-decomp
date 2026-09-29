# Local setup

The current harness expects a local compiler tree at:

```text
ghs5.3.22/bin/cxppc.exe
ghs5.3.22/bin/ecomppc.exe
ghs5.3.22/bin/asppc.exe
```

That directory is intentionally ignored by git.

On Linux, install either Wine or Wibo. The harness prefers Wibo when available and otherwise uses Wine where supported.

Typical first checks:

```bash
wine ghs5.3.22/bin/cxppc.exe -help
python3 analysis/oracle/probe_ghs.py --help
python3 analysis/oracle/run_blackbox.py --help
```

For reverse engineering, Ghidra 12.x headless mode is sufficient; the Ghidra installation itself should remain outside the repository.
