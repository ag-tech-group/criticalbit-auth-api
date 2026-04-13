"""Consistency checks for CURRENT_POLICY_VERSION.

The privacy policy version lives in two places:

- `app/consent/constants.py` in this repo (the authoritative constant
  used when stamping consent rows and computing the `is_stale` flag)
- `criticalbit-web/src/pages/privacy/privacy-page.tsx` in the sibling
  frontend repo (the user-visible "Last updated" string)

If those two drift apart, the re-prompt flow silently misbehaves:
either users are re-prompted against a policy they already saw, or
they keep acknowledging a stale version without realizing the text
changed. The tests below guard against both:

1. Format check — catches typos and non-ISO dates that would break
   lexicographic ordering. Runs everywhere, including CI.
2. Cross-repo string check — runs only when the sibling repo is
   checked out next to this one on disk (typical local dev layout).
   In CI the auth-api workflow only checks out this repo, so the
   test skips cleanly rather than failing. Local dev runs still
   catch drift before commit.
"""

from datetime import date
from pathlib import Path

import pytest

from app.consent import CURRENT_POLICY_VERSION


def test_current_policy_version_parses_as_iso_8601_date():
    # Must be a valid YYYY-MM-DD string so string ordering matches
    # chronological ordering — the re-prompt logic treats a stored
    # consent as stale when its version string does not equal
    # CURRENT_POLICY_VERSION, and future bumps need to be comparable.
    parsed = date.fromisoformat(CURRENT_POLICY_VERSION)
    assert parsed.isoformat() == CURRENT_POLICY_VERSION


def test_current_policy_version_matches_privacy_page_when_sibling_checked_out():
    privacy_page = (
        Path(__file__).parents[2]
        / "criticalbit-web"
        / "src"
        / "pages"
        / "privacy"
        / "privacy-page.tsx"
    )
    if not privacy_page.exists():
        pytest.skip(
            f"Sibling criticalbit-web repo not present at {privacy_page}; "
            "cross-repo consistency check skipped. CI environments that "
            "only check out criticalbit-auth-api hit this path."
        )
    content = privacy_page.read_text(encoding="utf-8")
    assert CURRENT_POLICY_VERSION in content, (
        f"CURRENT_POLICY_VERSION={CURRENT_POLICY_VERSION!r} not found in "
        f"{privacy_page}. The auth-api constant and the privacy policy "
        "page have drifted — bump both in lockstep when updating the "
        "policy."
    )
