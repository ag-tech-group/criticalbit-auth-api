# Must stay in sync with the "Last updated" date in the privacy policy at
# criticalbit-web/src/pages/privacy/privacy-page.tsx. Bumping this string
# re-prompts every user on their next authenticated page load.
CURRENT_POLICY_VERSION = "2026-04-12"

CONSENT_TYPES: frozenset[str] = frozenset({"analytics", "session_replay"})
