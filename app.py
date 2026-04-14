import logging
import os
from flask import Flask, render_template, request, jsonify, send_file
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
log = logging.getLogger(__name__)

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Init DB on startup
from modules.database import init_db
init_db()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/tracker')
def tracker():
    return render_template('tracker.html')


@app.route('/takedowns')
def takedowns():
    return render_template('takedowns.html')


@app.route('/gap-library')
def gap_library():
    return render_template('gap_library.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({'error': 'Invalid request — no JSON received'}), 400

        email_text = (data.get('email_text') or '').strip()
        anthropic_key = (data.get('anthropic_key') or '').strip()
        vt_key = (data.get('vt_key') or '').strip()

        if not email_text:
            return jsonify({'error': 'Please paste an escalation email first.'}), 400
        if not anthropic_key:
            return jsonify({'error': 'Anthropic API key is required. Get yours free at console.anthropic.com'}), 400

        log.info(f"Analysis started — email length: {len(email_text)} chars")

        # Agent 1: Understand escalation
        from modules.escalation_agent import EscalationUnderstandingAgent
        log.info("Running Escalation Agent...")
        esc_agent = EscalationUnderstandingAgent(anthropic_key)
        escalation_summary = esc_agent.analyze(email_text)
        log.info(f"Escalation Agent done — type: {escalation_summary.get('escalation_type')}")

        # Agent 2: Investigate
        from modules.investigation_agent import InvestigationAgent
        log.info("Running Investigation Agent...")
        inv_agent = InvestigationAgent(anthropic_key)
        investigation = inv_agent.investigate(email_text, escalation_summary)
        log.info(f"Investigation Agent done — assets: {len(investigation.get('assets_investigated', []))}")

        # VT enrichment (optional)
        vt_data = {}
        if vt_key:
            try:
                from modules.virustotal import enrich_assets
                log.info("Running VirusTotal enrichment...")
                assets = escalation_summary.get('assets_extracted', [])
                vt_data = enrich_assets(assets, vt_key)
                log.info(f"VT done — {len(vt_data)} assets enriched")
            except Exception as vt_err:
                log.warning(f"VT enrichment failed (non-critical): {vt_err}")
                vt_data = {}

        # Agent 3: RCA
        from modules.rca_agent import RCAAgent
        log.info("Running RCA Agent...")
        rca_agent = RCAAgent(anthropic_key)
        rca = rca_agent.generate(email_text, escalation_summary, investigation, vt_data)
        log.info("RCA Agent done")

        result = {
            'escalation_summary': escalation_summary,
            'investigation': investigation,
            'vt_enrichment': vt_data,
            'rca': rca,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'email_text': email_text
        }

        # Save to DB
        try:
            from modules.database import save_escalation
            eid = save_escalation(result)
            result['escalation_id'] = eid
            log.info(f"Saved to DB — ID: {eid}")
        except Exception as db_err:
            log.warning(f"DB save failed (non-critical): {db_err}")

        return jsonify(result)

    except Exception as e:
        log.error(f"Analysis failed: {str(e)}", exc_info=True)
        err_msg = str(e)
        # Friendly error messages
        if '401' in err_msg or 'authentication' in err_msg.lower():
            return jsonify({'error': 'Invalid Anthropic API key. Please check your key at console.anthropic.com'}), 400
        elif '402' in err_msg or 'credit' in err_msg.lower() or 'balance' in err_msg.lower():
            return jsonify({'error': 'Insufficient Anthropic credits. Please add credits at console.anthropic.com/billing'}), 400
        elif 'timeout' in err_msg.lower():
            return jsonify({'error': 'Request timed out. Please try again.'}), 408
        elif 'JSONDecodeError' in err_msg or 'json' in err_msg.lower():
            return jsonify({'error': 'AI response parsing failed. Please try again — this is usually a temporary issue.'}), 500
        else:
            return jsonify({'error': f'Analysis error: {err_msg}'}), 500


@app.route('/api/escalations')
def api_escalations():
    from modules.database import get_all_escalations
    return jsonify(get_all_escalations())


@app.route('/api/escalations/<int:eid>')
def api_escalation_detail(eid):
    from modules.database import get_escalation
    esc = get_escalation(eid)
    return jsonify(esc) if esc else (jsonify({'error': 'Not found'}), 404)


@app.route('/api/escalations/<int:eid>/status', methods=['POST'])
def api_update_status(eid):
    from modules.database import update_escalation_status
    d = request.get_json(force=True)
    update_escalation_status(eid, d.get('status'), d.get('notes'))
    return jsonify({'ok': True})


@app.route('/api/takedowns')
def api_takedowns():
    from modules.database import get_all_takedowns
    return jsonify(get_all_takedowns())


@app.route('/api/takedowns/add', methods=['POST'])
def api_add_takedown():
    from modules.database import save_takedown
    d = request.get_json(force=True)
    save_takedown(d.get('escalation_id'), d.get('asset'), d.get('asset_type', 'Domain'), d.get('vt_verdict'))
    return jsonify({'ok': True})


@app.route('/api/takedowns/<int:tid>/update', methods=['POST'])
def api_update_takedown(tid):
    from modules.database import update_takedown
    d = request.get_json(force=True)
    update_takedown(tid, d.get('status'), d.get('notes'))
    return jsonify({'ok': True})


@app.route('/api/gaps')
def api_gaps():
    from modules.database import get_gap_library
    return jsonify(get_gap_library())


@app.route('/api/gaps/<int:gid>/use', methods=['POST'])
def api_use_gap(gid):
    from modules.database import increment_gap_usage
    increment_gap_usage(gid)
    return jsonify({'ok': True})


@app.route('/api/dashboard')
def api_dashboard():
    from modules.database import get_dashboard_stats
    return jsonify(get_dashboard_stats())


@app.route('/api/seed-demo', methods=['POST'])
def api_seed_demo():
    """Insert sample escalations so the dashboard has something to show."""
    try:
        from modules.database import save_escalation
        import random
        samples = [
            {'type':'domain_impersonation','platform':'Domain/Web','severity':'Critical','brand':'Acme Corp','summary':'Phishing domain mirroring brand login portal detected.'},
            {'type':'social_media_impersonation','platform':'Instagram, Twitter','severity':'High','brand':'GlobalBank','summary':'Multiple fake social accounts impersonating official brand.'},
            {'type':'dark_web_exposure','platform':'Dark Web','severity':'Critical','brand':'TechStart','summary':'Credential dump referencing brand users found on dark web forum.'},
            {'type':'mobile_app_abuse','platform':'Android, iOS','severity':'High','brand':'RetailBrand','summary':'Unauthorized mobile app mimicking official brand app found on third-party store.'},
            {'type':'missed_detection','platform':'Telegram','severity':'Medium','brand':'FinCo','summary':'Brand impersonation Telegram channel missed in scheduled sweep.'},
        ]
        for i, s in enumerate(samples):
            fake = {
                'timestamp': f'2026-0{i+1}-{10+i} 12:00:00',
                'email_text': f'Sample escalation for {s["brand"]}',
                'escalation_summary': {
                    'escalation_type': s['type'],
                    'platform_affected': s['platform'],
                    'severity': s['severity'],
                    'brand_targeted': s['brand'],
                    'assets_extracted': [f'fake-{s["brand"].lower().replace(" ","")}.com'],
                    'escalation_summary': s['summary'],
                    'detection_issue': 'Asset not surfaced within monitoring window.',
                    'client_impact': 'Potential user exposure.',
                    'ticket_reference': f'DEMO-00{i+1}',
                    'escalation_date': f'2026-0{i+1}-{10+i}',
                },
                'investigation': {
                    'threat_classification': 'Brand Abuse',
                    'attack_vector': 'Multi-platform impersonation.',
                    'victim_targeting': 'Platform users.',
                    'threat_actor_behavior': 'Newly registered infrastructure consistent with impersonation activity.',
                    'detection_evasion': 'No prior reputation data.',
                    'threat_narrative': 'Sample demo entry.',
                    'assets_investigated': [],
                },
                'vt_enrichment': {},
                'rca': {
                    'problem_statement': 'Demo escalation entry.',
                    'executive_summary': 'Demo data for dashboard testing.',
                    'cause_and_effect': {
                        'root_cause': 'Demo root cause.',
                        'contributing_factors': ['Factor A','Factor B'],
                        'detection_gap_explanation': 'Demo detection gap.',
                        'platform_constraints': 'Demo constraint statement.',
                    },
                    'proposed_solutions': [],
                    'preventive_measures': [],
                    'recommended_actions': [],
                    'lessons_learned': 'Demo lessons learned.',
                }
            }
            save_escalation(fake)
        return jsonify({'ok': True, 'seeded': len(samples)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/download/word', methods=['POST'])
def download_word():
    try:
        from modules.report_generator import generate_word_report
        data = request.get_json(force=True)
        filepath = generate_word_report(data)
        return send_file(
            filepath,
            as_attachment=True,
            download_name=f'ThreatMail_RCA_{datetime.now().strftime("%Y%m%d_%H%M%S")}.docx'
        )
    except Exception as e:
        log.error(f"Word download failed: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/download/pdf', methods=['POST'])
def download_pdf():
    try:
        from modules.report_generator import generate_pdf_report
        data = request.get_json(force=True)
        filepath = generate_pdf_report(data)
        return send_file(
            filepath,
            as_attachment=True,
            download_name=f'ThreatMail_RCA_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        )
    except Exception as e:
        log.error(f"PDF download failed: {e}")
        return jsonify({'error': f'PDF generation failed: {str(e)}. Try Word download instead.'}), 500


if __name__ == '__main__':
    print("\n" + "="*50)
    print("  ThreatMail AI — Starting...")
    print("  Open browser: http://127.0.0.1:5000")
    print("="*50 + "\n")
    app.run(debug=False, port=5000, host='127.0.0.1')
