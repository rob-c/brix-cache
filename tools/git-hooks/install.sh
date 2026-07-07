#!/usr/bin/env bash
#
# install.sh — point this repo's git at the tracked hooks in tools/git-hooks/.
# One-time, per-clone.  Undo with:  git config --unset core.hooksPath
#
set -eu
REPO="$(git rev-parse --show-toplevel)"
cd "$REPO"
git config core.hooksPath tools/git-hooks
chmod +x tools/git-hooks/pre-push
echo "Installed: core.hooksPath → tools/git-hooks"
echo "  pre-push now runs 'tests/run_suite.sh --fast' (~4min). Bypass: git push --no-verify"
