"""DOLOS — the exploit crafter. A dynamic EVM attack harness for the UNI bubble.

Named for the Greek spirit of trickery and guile: DOLOS attacks the bubble's own contracts on a
throwaway fork, proving which flaws are real and which are static-analysis noise, and — on the
sandbox chain only — driving a fix through to a re-tested redeploy. It risks nothing because it
never touches a chain it cannot throw away.
"""

__version__ = "0.1.0"
