#!/usr/bin/env python3
"""mailer.py - Microsoft Graph sendMail for the CTI fleet.

Reuses the same Entra app registration the Go agent already uses to *read* the
CTI mailbox. Add the Mail.Send application permission and this sends as that
mailbox - no SMTP credentials anywhere on the box.

Only the orchestrator invokes this. Lanes never send mail.

Two modes:
  --html     a rendered digest, to the distribution list
  --message  a short escalation or question, to the operator

Usage:
  mailer.py --html digest.html                            # -> DIGEST_TO
  mailer.py --html d.html --text d.txt --subject "..."    # explicit subject
  mailer.py --to-operator --subject "Approve off-cycle send?" \
            --message "CVE-2026-1234 is on KEV and present on 305 hosts." \
            --board-id q17
  mailer.py --html d.html --to someone@example.com --require-approval
  mailer.py --html d.html --dry-run                       # render + validate only
  mailer.py --check                                       # verify token + Mail.Send

Environment (from ~/fleet/fleet.env):
  TENANT_ID CLIENT_ID CLIENT_SECRET
  GRAPH_MAILBOX         mailbox that sends as (required)
  DIGEST_TO             digest recipients, comma-separated (required)
  FLEET_OPERATOR_EMAIL  where --to-operator escalations go
  CTI_REPLY_MAILBOX     mailbox the operator replies to; defaults to GRAPH_MAILBOX
  FLEET_ALLOW_TO        allowlist; anything else needs --approve.
                        Defaults to DIGEST_TO, plus FLEET_OPERATOR_EMAIL.

Escalations to the operator are pre-approved - the orchestrator has to be able
to ask a question without needing permission to ask it. Every other
non-scheduled recipient still requires --approve.

There is deliberately no built-in default recipient. A hardcoded address is a
mis-send waiting to happen when this is deployed somewhere else, so the fleet
refuses to guess who should receive security findings.
"""
import argparse
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

FLEET_HOME = os.environ.get("FLEET_HOME", os.path.expanduser("~/fleet"))
GRAPH = "https://graph.microsoft.com/v1.0"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def log(m):
    print(f"[mailer] {m}", file=sys.stderr)


def die(m, code=1):
    log(f"ERROR: {m}")
    sys.exit(code)


def load_env():
    """Read fleet.env if present so cron/systemd runs do not need it exported."""
    path = os.path.join(FLEET_HOME, "fleet.env")
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def token():
    tenant = os.environ.get("TENANT_ID") or die("TENANT_ID not set")
    body = urllib.parse.urlencode({
        "client_id": os.environ.get("CLIENT_ID") or die("CLIENT_ID not set"),
        "client_secret": os.environ.get("CLIENT_SECRET") or die("CLIENT_SECRET not set"),
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }).encode()
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    try:
        req = urllib.request.Request(url, data=body, headers={
            "Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=30,
                                    context=ssl.create_default_context()) as r:
            return json.loads(r.read())["access_token"]
    except urllib.error.HTTPError as e:
        die(f"token request failed HTTP {e.code}: {e.read().decode()[:400]}")
    except Exception as e:                                      # noqa: BLE001
        die(f"token request failed: {e}")


def graph_post(path, payload, tok, retries=3):
    data = json.dumps(payload).encode()
    for attempt in range(retries):
        try:
            req = urllib.request.Request(f"{GRAPH}{path}", data=data, headers={
                "Authorization": f"Bearer {tok}",
                "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=60,
                                        context=ssl.create_default_context()) as r:
                return r.status, dict(r.headers), r.read().decode() or ""
        except urllib.error.HTTPError as e:
            detail = e.read().decode()[:600]
            if e.code == 403 and "MailboxNotEnabledForRESTAPI" not in detail:
                die("403 from Graph. The app registration is probably missing the "
                    "Mail.Send APPLICATION permission, or admin consent was never "
                    f"granted, or an Application Access Policy is blocking this "
                    f"mailbox.\n{detail}")
            if e.code in (429, 503) and attempt < retries - 1:
                wait = int(dict(e.headers).get("Retry-After", (attempt + 1) * 20))
                log(f"HTTP {e.code}, retrying in {wait}s")
                time.sleep(wait)
                continue
            die(f"Graph HTTP {e.code}: {detail}")
        except Exception as e:                                  # noqa: BLE001
            if attempt < retries - 1:
                time.sleep((attempt + 1) * 5)
                continue
            die(f"Graph request failed: {e}")
    return None


def check(tok, mailbox):
    """Confirm the token carries Mail.Send before the 6am run depends on it."""
    import base64
    claims = tok.split(".")[1]
    claims += "=" * (-len(claims) % 4)
    payload = json.loads(base64.urlsafe_b64decode(claims))
    roles = payload.get("roles", [])
    log(f"tenant={payload.get('tid')} app={payload.get('appid')}")
    log(f"granted application roles: {roles or '(none)'}")
    ok = True
    for need in ("Mail.Send", "Mail.Read"):
        if need in roles:
            log(f"  OK   {need}")
        else:
            log(f"  MISSING {need} - add it in Entra and grant admin consent")
            ok = False
    log(f"sending mailbox: {mailbox}")
    return 0 if ok else 1


def escalation_html(message, board_id=None):
    """Minimal HTML for a short escalation.

    Deliberately plain: this is a question or an alert, not a report. The
    reply instructions matter more than the styling - an escalation nobody
    knows how to answer just stalls the fleet.
    """
    import html as _h
    reply_to = (os.environ.get("CTI_REPLY_MAILBOX")
                or os.environ.get("GRAPH_MAILBOX") or "this mailbox")
    tag = f"[FLEET {board_id}]" if board_id else "[FLEET]"
    paras = "".join(
        f'<p style="margin:0 0 10px 0">{_h.escape(b).replace(chr(10), "<br>")}</p>'
        for b in message.split("\n\n") if b.strip())
    return f"""<!DOCTYPE html>
<html><body style="margin:0;padding:16px;background:#eef1f5">
<table width="100%" cellpadding="0" cellspacing="0" role="presentation">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" role="presentation"
       style="max-width:560px;background:#fff;border-radius:6px">
  <tr><td style="background:#12203a;padding:12px 18px;font:700 14px
                 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#fff">
    CTI Fleet</td></tr>
  <tr><td style="padding:16px 18px;font:400 14px/1.55 -apple-system,Segoe UI,
                 Helvetica,Arial,sans-serif;color:#1a202c">{paras}</td></tr>
  <tr><td style="padding:12px 18px 16px 18px;border-top:1px solid #e2e8f0;
                 font:400 12px/1.6 -apple-system,Segoe UI,Helvetica,Arial,
                 sans-serif;color:#4a5568">
    <b>To answer:</b> reply to this message, keeping
    <code>{_h.escape(tag)}</code> in the subject. The orchestrator reads
    {_h.escape(reply_to)} on its next check-in, posts your answer to the board,
    and the waiting lane picks it up.
  </td></tr>
</table></td></tr></table></body></html>"""


def main():
    load_env()
    ap = argparse.ArgumentParser(description="Send the CTI digest via Graph.")
    ap.add_argument("--html")
    ap.add_argument("--message", help="short plain-text body, wrapped in minimal "
                                      "HTML - for escalations, not digests")
    ap.add_argument("--text", help="plain-text alternative (logged, Graph sends one body)")
    ap.add_argument("--subject")
    ap.add_argument("--to", help="comma-separated; defaults to DIGEST_TO")
    ap.add_argument("--to-operator", action="store_true",
                    help="send to FLEET_OPERATOR_EMAIL. Pre-approved: telling the "
                         "operator something is not an outward-facing send.")
    ap.add_argument("--from-mailbox", default=os.environ.get("GRAPH_MAILBOX"))
    ap.add_argument("--attach", action="append", default=[],
                    help="file to attach (repeatable, keep under ~3MB total)")
    ap.add_argument("--board-id", help="board line id, so your reply can be "
                                       "matched back to the question")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--require-approval", action="store_true",
                    help="refuse unless --approve is also passed (off-cycle sends)")
    ap.add_argument("--approve", action="store_true",
                    help="the operator approved this specific off-cycle send")
    ap.add_argument("--save-to-sent", default="true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    if not args.from_mailbox:
        die("GRAPH_MAILBOX is not set - set it in fleet.env or pass --from-mailbox")

    if args.check:
        return check(token(), args.from_mailbox)
    if bool(args.html) == bool(args.message):
        die("pass exactly one of --html (a rendered digest) or --message "
            "(a short escalation)")
    if args.html and not os.path.exists(args.html):
        die(f"{args.html} does not exist")

    operator = (os.environ.get("FLEET_OPERATOR_EMAIL") or "").strip()
    if args.to_operator:
        if args.to:
            die("--to-operator and --to are mutually exclusive")
        if not operator:
            die("FLEET_OPERATOR_EMAIL is not set in fleet.env - the fleet has "
                "nowhere to escalate to")
        to_raw = operator
    else:
        to_raw = args.to or os.environ.get("DIGEST_TO") or ""
    recipients = [r.strip() for r in to_raw.split(",") if r.strip()]
    if not recipients:
        die("no recipients - set DIGEST_TO in fleet.env or pass --to. "
            "There is no default; the fleet will not guess who receives "
            "security findings.")
    for r in recipients:
        if not EMAIL_RE.match(r):
            die(f"{r!r} is not a valid address")

    # Autonomy gate. Scheduled digests to the allowlisted DL are pre-approved,
    # and so are escalations to the operator's own address - the orchestrator
    # must be able to ask a question without needing permission to ask it.
    # Anything else needs an explicit human OK on this specific send.
    #
    # FLEET_ALLOW_TO defaults to DIGEST_TO rather than to everything, so an
    # unconfigured deployment fails closed: the scheduled digest still works,
    # any other recipient needs --approve.
    allow_raw = os.environ.get("FLEET_ALLOW_TO") or os.environ.get("DIGEST_TO") or ""
    allow = {a.strip().lower() for a in allow_raw.split(",") if a.strip()}
    if operator:
        allow.add(operator.lower())
    outside = [r for r in recipients if r.lower() not in allow]
    if outside and not args.approve:
        die(f"recipients outside FLEET_ALLOW_TO: {', '.join(outside)}. "
            f"Post the draft to the board tagged [APPROVE] and re-run with "
            f"--approve once the operator says yes.")
    if args.require_approval and not args.approve:
        die("this send is marked as requiring approval and --approve was not passed")

    if args.html:
        with open(args.html, encoding="utf-8") as f:
            body = f.read()
    else:
        body = escalation_html(args.message, args.board_id)
    subject = args.subject or f"CTI Brief {datetime.now().strftime('%Y-%m-%d')}"
    if args.message and args.board_id and f"[FLEET {args.board_id}]" not in subject:
        subject = f"[FLEET {args.board_id}] {subject}"
    subject = " ".join(subject.split())[:255]

    message = {
        "subject": subject,
        "body": {"contentType": "HTML", "content": body},
        "toRecipients": [{"emailAddress": {"address": r}} for r in recipients],
        "importance": "high" if subject.startswith("[P1]") else "normal",
    }
    for path in args.attach:
        if not os.path.exists(path):
            log(f"skipping missing attachment {path}")
            continue
        import base64
        with open(path, "rb") as f:
            raw = f.read()
        if len(raw) > 3_000_000:
            log(f"skipping {path}: {len(raw)} bytes exceeds the inline attachment limit")
            continue
        message.setdefault("attachments", []).append({
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": os.path.basename(path),
            "contentType": "text/markdown" if path.endswith(".md") else "text/plain",
            "contentBytes": base64.b64encode(raw).decode(),
        })

    log(f"from   : {args.from_mailbox}")
    log(f"to     : {', '.join(recipients)}")
    log(f"subject: {subject}")
    log(f"size   : {len(body)} bytes html, {len(message.get('attachments', []))} attachment(s)")

    if args.dry_run:
        log("DRY RUN - nothing sent")
        out = {"dry_run": True, "mode": "html" if args.html else "message",
               "subject": subject, "to": recipients}
        if args.html:
            out["html"] = os.path.abspath(args.html)
        else:
            # No file to point at in message mode, so hand back the rendered
            # body: the orchestrator should be able to read what it almost sent.
            out["body"] = body
        print(json.dumps(out))
        return 0

    tok = token()
    payload = {"message": message,
               "saveToSentItems": str(args.save_to_sent).lower() == "true"}
    path = f"/users/{urllib.parse.quote(args.from_mailbox)}/sendMail"
    status, headers, _ = graph_post(path, payload, tok)

    # sendMail returns 202 with no body, so there is no message id to capture.
    # request-id is what you give Microsoft support when a mail goes missing.
    req_id = headers.get("request-id") or headers.get("client-request-id") or "unknown"
    log(f"sent - HTTP {status}, request-id {req_id}")
    print(json.dumps({"sent": True, "status": status, "request_id": req_id,
                      "subject": subject, "to": recipients,
                      "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
