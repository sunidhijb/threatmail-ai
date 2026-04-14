import anthropic
import json
import re
import logging

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 PROMPT — Asset extraction ONLY.
# Separate call. Returns a plain JSON array. Nothing else.
# ─────────────────────────────────────────────────────────────────────────────
ASSET_EXTRACTION_PROMPT = """You are a CTI asset parser. Your ONLY job is to extract every asset mentioned in the text.

EXTRACT:
- URLs and domains (defang: [.] → ., [:] → :, https[:]// → https://)
- Subdomains
- Telegram handles (e.g. @HandleName)
- Social media accounts / pages (e.g. Facebook page "BrandName Support")
- Mobile app names (prefix with "Mobile App — ")
- Dark web references (prefix with "Dark Web Post — ")
- Any other infrastructure indicators

OUTPUT FORMAT — return ONLY a raw JSON array. No markdown. No explanation. No wrapper object.
Example:
["domain1.com","https://subdomain.domain2.net","@TelegramHandle","Mobile App — FakeBankApp","Dark Web Post — credential dump dated 5 days ago","Facebook page — Brand Customer Care","Instagram — @brand.support.official"]

RULES:
- If in doubt, include it. Never skip an asset.
- Defang ALL URLs before including.
- Return [] only if the text contains zero assets (very rare).
- Return the raw array and nothing else."""


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 PROMPT — Escalation understanding. Assets are injected, not re-extracted.
# ─────────────────────────────────────────────────────────────────────────────
UNDERSTANDING_PROMPT = """You are a senior CTI analyst analyzing escalation emails.
You will be given the email text AND a pre-extracted asset list. Do NOT re-extract assets.

LANGUAGE RULES:
- Use neutral factual language only
- No failure words, no emotional language
- Generic — applies to any industry
- Do NOT include client_sentiment field

Return ONLY valid JSON. No markdown. No preamble.

{
  "escalation_type": "missed_detection",
  "platform_affected": "Domain/Web, Telegram, Dark Web",
  "pillar_affected": "Brand Intelligence – Domain Impersonation",
  "severity": "Critical",
  "brand_targeted": "Brand Name",
  "escalation_summary": "2-3 sentence factual neutral summary.",
  "detection_issue": "Neutral technical description of what was not surfaced.",
  "client_impact": "Measured factual description of impact.",
  "ticket_reference": "TICKET-001",
  "escalation_date": "2026-04-01"
}

ticket_reference and escalation_date can be null if not mentioned."""


def _strip_json_fences(raw: str) -> str:
    raw = raw.strip()
    raw = re.sub(r'^```json\s*', '', raw)
    raw = re.sub(r'^```\s*', '', raw)
    raw = re.sub(r'\s*```$', '', raw)
    return raw.strip()


class EscalationUnderstandingAgent:
    def __init__(self, api_key: str):
        self.client = anthropic.Anthropic(api_key=api_key)

    # ── STEP 1: Dedicated asset extraction with retry ─────────────────────────
    def _extract_assets(self, email_text: str, max_retries: int = 3) -> list:
        for attempt in range(1, max_retries + 1):
            try:
                log.info(f"Asset extraction attempt {attempt}/{max_retries}")
                msg = self.client.messages.create(
                    model="claude-sonnet-4-6",
                    max_tokens=800,
                    system=ASSET_EXTRACTION_PROMPT,
                    messages=[{
                        "role": "user",
                        "content": f"Extract every asset from this text. Return a raw JSON array only:\n\n{email_text}"
                    }]
                )
                raw = _strip_json_fences(msg.content[0].text)
                assets = json.loads(raw)

                if not isinstance(assets, list):
                    log.warning(f"Attempt {attempt}: extraction returned non-list type: {type(assets)}")
                    continue

                if len(assets) == 0:
                    log.warning(f"Attempt {attempt}: extraction returned empty list — retrying")
                    continue

                log.info(f"Asset extraction succeeded on attempt {attempt}: {len(assets)} assets found")
                return assets

            except json.JSONDecodeError as e:
                log.warning(f"Attempt {attempt}: JSON parse error in asset extraction: {e}")
            except Exception as e:
                log.warning(f"Attempt {attempt}: Unexpected error in asset extraction: {e}")

        # All retries exhausted
        log.error(
            "ASSET EXTRACTION FAILED after all retries. "
            "Downstream analysis will proceed with empty asset list. "
            "Manual review required."
        )
        return []

    # ── STEP 2: Escalation understanding (assets injected, not re-extracted) ──
    def _understand_escalation(self, email_text: str, assets: list) -> dict:
        asset_block = json.dumps(assets, indent=2)
        msg = self.client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1200,
            system=UNDERSTANDING_PROMPT,
            messages=[{
                "role": "user",
                "content": (
                    f"PRE-EXTRACTED ASSETS (do not re-extract):\n{asset_block}\n\n"
                    f"ESCALATION EMAIL:\n{email_text}\n\n"
                    "Analyze the escalation and return JSON only."
                )
            }]
        )
        raw = _strip_json_fences(msg.content[0].text)
        return json.loads(raw)

    # ── Main entry point ──────────────────────────────────────────────────────
    def analyze(self, email_text: str) -> dict:
        # STEP 1: Extract assets in a dedicated call with retry enforcement
        assets = self._extract_assets(email_text)

        if not assets:
            log.error(
                "Proceeding with ZERO extracted assets. "
                "All downstream asset-dependent logic (VT enrichment, takedowns) will be empty. "
                "Manual asset review required."
            )

        # STEP 2: Understand escalation context (assets are injected, not re-extracted)
        try:
            understanding = self._understand_escalation(email_text, assets)
        except (json.JSONDecodeError, Exception) as e:
            log.error(f"Escalation understanding parse error: {e}")
            understanding = {
                "escalation_type": "other",
                "platform_affected": "Multiple",
                "pillar_affected": "Brand Intelligence",
                "severity": "High",
                "brand_targeted": "Unknown",
                "escalation_summary": "Escalation received — manual review required.",
                "detection_issue": "Unable to automatically parse escalation details.",
                "client_impact": "Impact assessment pending review.",
                "ticket_reference": None,
                "escalation_date": None,
            }

        # STEP 3: Merge — assets always from the dedicated extraction step
        result = {**understanding, "assets_extracted": assets}

        log.info(
            f"Escalation analysis complete — type: {result.get('escalation_type')}, "
            f"assets extracted: {len(assets)}"
        )
        return result
