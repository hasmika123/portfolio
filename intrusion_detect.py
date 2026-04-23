"""
intrusion_detect.py
────────────────────────────────────────────────────────────────────────────
AI-Based Intrusion Detection for Portfolio Contact Form
Computer Networking Project – Spring 2026 (Challenge Component)

What it does:
  1. Fetches recent contact form submissions from Supabase
  2. Sends them to Claude (claude-sonnet-4-20250514) for AI-based analysis
  3. Flags suspicious entries (XSS attempts, SQLi, spam, bot patterns)
  4. Prints a human-readable security report

Requirements:
  pip install supabase anthropic python-dotenv

Setup:
  Create a .env file with:
    SUPABASE_URL=https://your-project.supabase.co
    SUPABASE_KEY=your-service-role-key
    ANTHROPIC_API_KEY=your-anthropic-api-key
────────────────────────────────────────────────────────────────────────────
"""

import os
import json
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv()

# ── Imports (install via pip if missing) ───────────────────────────────────
try:
    from supabase import create_client, Client
except ImportError:
    raise ImportError("Run: pip install supabase")

try:
    import anthropic
except ImportError:
    raise ImportError("Run: pip install anthropic")


# ── Config ─────────────────────────────────────────────────────────────────
SUPABASE_URL   = os.environ.get("SUPABASE_URL")
SUPABASE_KEY   = os.environ.get("SUPABASE_KEY")      # Use service-role key for server scripts
ANTHROPIC_KEY  = os.environ.get("ANTHROPIC_API_KEY")
LOOKBACK_HOURS = 24                                    # Analyze submissions from the last N hours
SUSPICIOUS_THRESHOLD = 0.5                             # Flag entries with risk score >= this


def fetch_recent_submissions(supabase: Client, hours: int) -> list[dict]:
    """Fetch contact form submissions from the last `hours` hours."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    response = (
        supabase.table("contact_messages")
        .select("id, name, email, subject, message, submitted_at")
        .gte("submitted_at", cutoff)
        .order("submitted_at", desc=True)
        .execute()
    )

    return response.data or []


def analyze_with_ai(submissions: list[dict], client: anthropic.Anthropic) -> dict:
    """
    Send submissions to Claude for security analysis.
    Returns structured JSON with risk assessment per entry.
    """
    if not submissions:
        return {"summary": "No submissions to analyze.", "entries": []}

    submissions_json = json.dumps(submissions, indent=2, default=str)

    prompt = f"""You are a cybersecurity analyst reviewing web form submissions for a personal portfolio website.

Analyze the following contact form submissions for security threats and suspicious patterns.

For each submission, assess:
1. XSS attempts (e.g., <script> tags, javascript: URLs, event handlers in input)
2. SQL injection patterns (e.g., ' OR 1=1, UNION SELECT, DROP TABLE)
3. Spam indicators (repetitive content, gibberish, mass-submission patterns)
4. Bot behavior (unrealistic speed, identical messages, suspicious email domains)
5. Social engineering or phishing language

Submissions to analyze:
{submissions_json}

Respond ONLY with valid JSON in exactly this format, no markdown, no preamble:
{{
  "analyzed_at": "<ISO timestamp>",
  "total_submissions": <number>,
  "flagged_count": <number>,
  "overall_risk": "low|medium|high",
  "summary": "<2-3 sentence summary of findings>",
  "entries": [
    {{
      "id": "<submission id>",
      "risk_score": <0.0 to 1.0>,
      "risk_level": "safe|suspicious|dangerous",
      "threats_detected": ["<threat type>", ...],
      "explanation": "<brief explanation>"
    }}
  ]
}}"""

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}]
    )

    raw = message.content[0].text.strip()

    # Strip any accidental markdown code fences
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]

    return json.loads(raw)


def print_report(analysis: dict, submissions: list[dict]):
    """Print a formatted security report to the console."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    divider = "─" * 65

    print(f"\n{'═' * 65}")
    print(f"  🔐  PORTFOLIO CONTACT FORM — SECURITY ANALYSIS REPORT")
    print(f"  Generated: {now}")
    print(f"{'═' * 65}\n")

    print(f"  Total submissions analyzed : {analysis.get('total_submissions', 0)}")
    print(f"  Flagged entries            : {analysis.get('flagged_count', 0)}")
    risk = analysis.get('overall_risk', 'unknown').upper()
    risk_emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴"}.get(risk, "⚪")
    print(f"  Overall risk level         : {risk_emoji}  {risk}")
    print(f"\n  Summary: {analysis.get('summary', 'N/A')}\n")

    entries = analysis.get("entries", [])
    if not entries:
        print("  No individual entries to display.\n")
    else:
        for entry in entries:
            level = entry.get("risk_level", "safe").upper()
            emoji = {"SAFE": "✅", "SUSPICIOUS": "⚠️", "DANGEROUS": "🚨"}.get(level, "❓")
            print(divider)
            print(f"  {emoji}  Entry ID : {entry.get('id', 'N/A')}")
            print(f"     Risk Score : {entry.get('risk_score', 0):.2f}  |  Level: {level}")
            threats = entry.get("threats_detected", [])
            print(f"     Threats    : {', '.join(threats) if threats else 'None'}")
            print(f"     Note       : {entry.get('explanation', '')}")

    print(f"\n{'═' * 65}\n")


def save_report(analysis: dict, output_file: str = "security_report.json"):
    """Save the full analysis JSON to a file for record-keeping."""
    with open(output_file, "w") as f:
        json.dump(analysis, f, indent=2, default=str)
    print(f"  📄 Full report saved to: {output_file}\n")


def main():
    # Validate environment
    if not all([SUPABASE_URL, SUPABASE_KEY, ANTHROPIC_KEY]):
        raise EnvironmentError(
            "Missing environment variables. Ensure SUPABASE_URL, "
            "SUPABASE_KEY, and ANTHROPIC_API_KEY are set in your .env file."
        )

    print("Connecting to Supabase…")
    sb_client = create_client(SUPABASE_URL, SUPABASE_KEY)

    print(f"Fetching submissions from the last {LOOKBACK_HOURS} hours…")
    submissions = fetch_recent_submissions(sb_client, LOOKBACK_HOURS)
    print(f"Found {len(submissions)} submission(s).")

    if not submissions:
        print("No submissions found in the lookback window. Exiting.")
        return

    print("Sending to Claude for AI-based analysis…")
    ai_client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
    analysis = analyze_with_ai(submissions, ai_client)

    print_report(analysis, submissions)
    save_report(analysis)


if __name__ == "__main__":
    main()
