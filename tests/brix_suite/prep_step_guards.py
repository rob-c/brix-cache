"""Small failure guards shared by fleet-preparation steps."""


def require_success(tolerate, proc, argv):
    """Raise for a failed preparation command unless failure is tolerated."""
    if proc.returncode != 0 and not tolerate:
        raise RuntimeError(
            f"{' '.join(map(str, argv))} exited {proc.returncode}\n{proc.stderr}"
        )
