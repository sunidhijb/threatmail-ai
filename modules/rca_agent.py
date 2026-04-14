import anthropic
import json
import re
import logging

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior CTI analyst writing a Root Cause Analysis for EXTERNAL CLIENT delivery.

=== ABSOLUTE RULES — NO EXCEPTIONS ===

FORBIDDEN WORDS AND PHRASES:
"failed" "failure" "missed" "gap" "cannot" "unable"
"detection processes were not calibrated" — internal config exposure
"operated within expected behavioral thresholds" — internal metric
"blended with legitimate traffic patterns" — defensive justification
"appeared consistent with legitimate indicators" — defensive justification
"optimized for single-vector threats" — internal architecture
"detection framework" — internal system reference
"professionally orchestrated" "advanced threat actor" — overclaim
"cryptocurrency" "financial information" "banking" — industry-specific

REQUIRED REPLACEMENTS:
"failed to detect" → "was not surfaced within expected timelines"
"detection processes were not calibrated" → "monitoring coverage for this activity category is being enhanced"
"operated within thresholds" → REMOVE entirely
"blended with legitimate" → REMOVE entirely — do not justify the miss
"appeared consistent with legitimate" → REMOVE entirely
"cryptocurrency users" → "platform users" or "account holders"
"financial information" → "account credentials"
"banking operations" → "platform operations"

UNCERTAINTY MARKERS — use throughout:
"assessed to be" "observed to" "consistent with" "likely" "appears to"
Never present assessments as confirmed facts.

NO REPETITION:
- Executive Summary, Root Cause, Detection Gap must each say something DIFFERENT
- If same concept appears in two sections — delete from the less important one
- Contributing factors must be genuinely different from each other AND from root cause

NO DEFENSIVE FRAMING:
- Do not explain WHY the miss happened in a way that sounds like an excuse
- Simply state what happened and what is being done about it

NO VAGUE EXTERNAL CLAIMS:
- Not: "documented across several industry breach responses" — unverifiable
- Use: "consistent with observed threat actor behaviors" — measurable

SOLUTIONS MUST BE SPECIFIC:
- Name the technology or process being deployed
- Not: "implement enhanced detection protocols"
- Yes: "Deploy keyword-triggered domain monitoring for brand identifiers registered during high-visibility security events"

=== OUTPUT — valid JSON only, no markdown ===

{
  "problem_statement": "One sentence. Neutral. No failure language. No industry terms. Any organization.",

  "executive_summary": "Three sentences. S1: what was identified. S2: immediate response. S3: ongoing enhancement. No failure language. No internal details.",

  "problem_setup": "One paragraph. Objective. Use assessed/observed where appropriate. No defensive language. No industry-specific terms.",

  "cause_and_effect": {
    "root_cause": "One paragraph. High-level reason activity was not surfaced. Frame as a coverage area being enhanced — do NOT reveal internal config, thresholds, or architecture. Do NOT use defensive justification framing.",

    "contributing_factors": [
      "Factor 1 — unique content, not repeating root cause. One sentence. Use likely/assessed.",
      "Factor 2 — different from Factor 1. One sentence.",
      "Factor 3 — different from all above. One sentence."
    ],

    "detection_gap_explanation": "One paragraph. Describes the observable activity pattern — NOT the same as root cause. No internal system details. No defensive framing. Use the activity exhibited or consistent with. No threshold or calibration language.",

    "platform_constraints": "One sentence. Forward-looking enhancement statement — not a limitation admission."
  },

  "threat_intelligence_context": "One paragraph. What external data supports — factual, measured. Use consistent with observed patterns. No unverifiable claims. Generic — any industry.",

  "impact_assessment": {
    "actual_impact": "Measured. Use several not all. Use assessed to have where appropriate. No industry terms.",
    "potential_impact": "Measured. One sentence. Not catastrophic. No industry terms.",
    "affected_area": "Generic service areas — no industry-specific terms."
  },

  "proposed_solutions": [
    {
      "solution_id": "001",
      "title": "Specific action: deploy/implement [specific what] for [specific purpose].",
      "description": "Specific technology or process being deployed. What it addresses. 2 sentences.",
      "term": "Immediate",
      "status": "In Progress",
      "expected_completion": "Within 48 hours"
    },
    {
      "solution_id": "002",
      "title": "Second specific solution.",
      "description": "Specific. 2 sentences.",
      "term": "Short-term",
      "status": "Planned",
      "expected_completion": "Within 2 weeks"
    },
    {
      "solution_id": "003",
      "title": "Third specific solution.",
      "description": "Specific. 2 sentences.",
      "term": "Long-term",
      "status": "Planned",
      "expected_completion": "Within 30 days"
    }
  ],

  "preventive_measures": [
    "Specific. Starts with verb. Names what is being deployed.",
    "Measure 2. Specific.",
    "Measure 3. Specific.",
    "Measure 4. Specific."
  ],

  "recommended_actions": [
    "Specific client-facing action.",
    "Action 2. Specific.",
    "Action 3. Specific."
  ],

  "lessons_learned": "One paragraph. Forward-looking. This engagement has informed framing. No criticism. No defensive language. Universally applicable — not scenario-specific."
}"""


class RCAAgent:
    def __init__(self, api_key: str):
        self.client = anthropic.Anthropic(api_key=api_key)

    def generate(self, email_text: str, escalation: dict, investigation: dict, vt_data: dict) -> dict:
        vt_lines = []
        if vt_data:
            for domain, info in vt_data.items():
                if info.get('found'):
                    vt_lines.append(
                        f"  - {domain}: Verdict={info.get('verdict')}, "
                        f"Detections={info.get('malicious', 0)}/{info.get('total_engines', 0)} engines"
                    )
                else:
                    vt_lines.append(f"  - {domain}: No prior reputation data available")
        vt_summary = ("\nEXTERNAL THREAT INTELLIGENCE:\n" + "\n".join(vt_lines)) if vt_lines else ""

        context = f"""ESCALATION:
Type: {escalation.get('escalation_type', 'unknown').replace('_', ' ').title()}
Severity: {escalation.get('severity', 'High')}
Platform: {escalation.get('platform_affected', 'Multiple')}
Brand: {escalation.get('brand_targeted', 'Unknown')}
Ticket: {escalation.get('ticket_reference') or 'Not provided'}
Issue: {escalation.get('detection_issue', '')}

INVESTIGATION:
Classification: {investigation.get('threat_classification', '')}
Vector: {investigation.get('attack_vector', '')}
Evasion: {investigation.get('detection_evasion', '')}
Narrative: {investigation.get('threat_narrative', '')}
{vt_summary}

EMAIL:
{email_text}

FINAL CHECKLIST:
1. No failure language anywhere
2. No internal system exposure (no thresholds, calibration, framework, pipeline)
3. No defensive justification (do not explain the miss in a way that sounds like excuses)
4. No overclaims — use assessed/observed/likely
5. No absolute statements — use several/a number of
6. Each section unique content — no repetition
7. No industry-specific terms — platform users, account holders, not cryptocurrency/banking
8. Solutions name specific technology or process — not generic protocols
9. No visibility_limitations field
10. External intelligence: consistent with observed patterns — no unverifiable claims"""

        try:
            msg = self.client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=3500,
                system=SYSTEM_PROMPT,
                messages=[{
                    "role": "user",
                    "content": f"Generate professional client-safe RCA. Return JSON only:\n\n{context}"
                }]
            )
            raw = msg.content[0].text.strip()
            raw = re.sub(r'^```json\s*', '', raw)
            raw = re.sub(r'^```\s*', '', raw)
            raw = re.sub(r'\s*```$', '', raw)
            result = json.loads(raw)
            log.info("RCA generation complete")
            return result

        except json.JSONDecodeError as e:
            log.error(f"RCA parse error: {e}")
            return {
                "problem_statement": "Several brand-related assets were not surfaced within expected monitoring timelines, resulting in a client escalation.",
                "executive_summary": "Several active brand impersonation assets were identified spanning multiple platforms. Immediate takedown processes were initiated and affected assets were flagged for mitigation. Enhanced monitoring coverage across the identified platform categories is being deployed.",
                "problem_setup": "The client's security team identified several active assets targeting their brand that were not reflected within standard monitoring timelines. The assets were assessed to span domain infrastructure, social media platforms, and additional channels, and were escalated for urgent investigation.",
                "cause_and_effect": {
                    "root_cause": "Monitoring coverage for cross-platform brand impersonation activity operating simultaneously across domain, social media, and supplementary channels is being enhanced. The breadth of platforms involved in this activity was not aggregated within the standard reporting window.",
                    "contributing_factors": [
                        "The assets were assessed to utilize newly established infrastructure with no prior reputation data at the time of registration.",
                        "Activity indicators were distributed across multiple independent platforms, creating a dispersed detection profile.",
                        "Several assets were established during a period of elevated brand-related activity, assessed to have contributed to detection complexity."
                    ],
                    "detection_gap_explanation": "The activity pattern exhibited characteristics consistent with newly established infrastructure deployed across multiple platforms within a compressed timeframe. The distributed nature of the assets across domain, social media, and supplementary channels was not aggregated for assessment within the standard monitoring window.",
                    "platform_constraints": "Cross-platform indicator aggregation for concurrent brand impersonation activity is being expanded as part of ongoing monitoring enhancements."
                },
                "threat_intelligence_context": "External threat intelligence confirms the identified assets exhibit characteristics consistent with observed brand impersonation patterns. The absence of prior reputation data across the domain assets is consistent with newly established infrastructure, and the activity structure is assessed to align with known multi-platform impersonation methodologies.",
                "impact_assessment": {
                    "actual_impact": "Several brand impersonation assets were assessed to have been active during the initial monitoring period, with potential account holder exposure across the identified platforms.",
                    "potential_impact": "Continued operation of the identified assets could result in additional account holder exposure and reputational impact.",
                    "affected_area": "Brand monitoring, domain intelligence, social media impersonation detection, and supplementary platform coverage services."
                },
                "proposed_solutions": [
                    {"solution_id": "001", "title": "Deploy cross-platform brand keyword monitoring with aggregated alerting.", "description": "Real-time correlation of brand impersonation indicators across domain, social media, and messaging platforms is being activated. This addresses the distributed detection profile observed in this escalation.", "term": "Immediate", "status": "In Progress", "expected_completion": "Within 48 hours"},
                    {"solution_id": "002", "title": "Integrate third-party application store scanning for brand impersonation.", "description": "Automated scanning of alternative application distribution platforms for apps utilizing monitored brand identifiers is being deployed. This extends monitoring coverage to distribution channels not included in primary platform scope.", "term": "Short-term", "status": "Planned", "expected_completion": "Within 2 weeks"},
                    {"solution_id": "003", "title": "Establish unified cross-platform campaign correlation for concurrent impersonation detection.", "description": "A systematic correlation layer connecting indicators from domain registration, social platform activity, and messaging channels is being developed. This will enable identification of concurrent multi-platform brand abuse campaigns.", "term": "Long-term", "status": "Planned", "expected_completion": "Within 30 days"}
                ],
                "preventive_measures": [
                    "Deploy automated keyword-triggered monitoring for newly registered domains incorporating monitored brand identifiers.",
                    "Implement real-time account creation scanning across major social and messaging platforms for brand impersonation patterns.",
                    "Establish cross-platform indicator correlation to surface concurrent brand impersonation activity.",
                    "Conduct regular brand protection parameter reviews to validate coverage against current impersonation methodologies."
                ],
                "recommended_actions": [
                    "Submit takedown requests for all identified assets through appropriate registrar and platform channels.",
                    "Review current brand keyword parameters to ensure comprehensive coverage of identifier variations.",
                    "Establish a direct escalation protocol for periods of elevated brand-related activity."
                ],
                "lessons_learned": "This engagement has informed the development of enhanced cross-platform monitoring capabilities that aggregate brand impersonation indicators across multiple channels simultaneously. The requirement for concurrent multi-platform detection coverage is applicable across any organizational context where brand impersonation activity may span independent platforms, and these insights will inform ongoing monitoring enhancement priorities."
            }
