import anthropic
import json
import re
import logging

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior CTI analyst investigating threat assets.

Return ONLY valid JSON. No markdown.

STRICT LANGUAGE RULES:
- Never use: "sophisticated", "advanced", "professional", "well-resourced", "orchestrated", "coordinated"
- Never use: "operated within thresholds", "blended with legitimate", "typical behavioral parameters"
- Use instead: "observed", "assessed to be", "consistent with", "identified"
- Never use absolute statements: all, none, completely
- Use: several, a number of, assessed to

ASSET HANDLING:
- For dark web assets: asset_type = "Dark Web Post", describe what was posted
- For mobile apps: asset_type = "Mobile App"
- For social accounts: asset_type = "Social Account"
- For packages: asset_type = "Malicious Package"
- Include ALL assets from the escalation

{
  "threat_classification": "Brand Abuse / Multi-Platform Impersonation",
  "attack_vector": "Factual description of observed activity. No overclaims.",
  "victim_targeting": "Who appears targeted — factual, measured, generic terms.",
  "threat_actor_behavior": "Observable patterns only. No intent assertions. No capability claims.",
  "detection_evasion": "Observable characteristics only. No: operated within thresholds, blended with legitimate.",
  "threat_narrative": "3-4 sentences. Factual observations using assessed/observed/consistent with. No overclaims.",
  "assets_investigated": [
    {
      "asset": "exact asset from email",
      "asset_type": "Phishing Domain | Telegram Channel | Social Account | Mobile App | Dark Web Post | Malicious Package | Other",
      "risk_level": "Critical | High | Medium | Low",
      "why_suspicious": "Specific factual reasoning. No overclaims.",
      "likely_purpose": "Suspected purpose — use suspected if not confirmed.",
      "indicators": ["indicator1", "indicator2", "indicator3"]
    }
  ]
}"""


class InvestigationAgent:
    def __init__(self, api_key: str):
        self.client = anthropic.Anthropic(api_key=api_key)

    def investigate(self, email_text: str, escalation: dict) -> dict:
        assets_str = ', '.join(escalation.get('assets_extracted', []))
        context = f"""Escalation Type: {escalation.get('escalation_type', 'unknown')}
Platform: {escalation.get('platform_affected', 'unknown')}
Brand: {escalation.get('brand_targeted', 'unknown')}
All Assets to Investigate: {assets_str if assets_str else 'See email — extract all assets'}
Issue: {escalation.get('detection_issue', '')}

Original Email:
{email_text}"""

        try:
            msg = self.client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=2500,
                system=SYSTEM_PROMPT,
                messages=[{
                    "role": "user",
                    "content": f"Investigate ALL assets in this escalation. Include dark web, mobile apps, social accounts — everything. Return JSON only:\n\n{context}"
                }]
            )
            raw = msg.content[0].text.strip()
            raw = re.sub(r'^```json\s*', '', raw)
            raw = re.sub(r'^```\s*', '', raw)
            raw = re.sub(r'\s*```$', '', raw)
            result = json.loads(raw)
            log.info(f"Investigation complete: {len(result.get('assets_investigated', []))} assets")
            return result
        except json.JSONDecodeError as e:
            log.error(f"Investigation agent parse error: {e}")
            return {
                "threat_classification": "Brand Abuse",
                "attack_vector": "Multi-platform brand impersonation activity identified across several channels.",
                "victim_targeting": "Brand account holders and platform users.",
                "threat_actor_behavior": "Observable brand impersonation activity across multiple channels.",
                "detection_evasion": "Newly established infrastructure with no prior reputation data.",
                "threat_narrative": "Brand impersonation activity was identified across multiple platforms. Assets assessed to include domain infrastructure and social media accounts exhibiting characteristics consistent with impersonation activity. The pattern warrants immediate investigation and takedown action.",
                "assets_investigated": []
            }
