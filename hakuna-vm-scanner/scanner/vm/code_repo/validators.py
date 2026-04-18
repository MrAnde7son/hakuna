"""Secret-validation command + template generation for Nuclei.

TruffleHog already does live verification for many detectors, but for those
that aren't (or for air-gapped deployments where TruffleHog skips verify),
we emit a Nuclei HTTP template that hits the provider's "whoami"/tokeninfo
endpoint with the raw secret as an auth header. The template is returned
as a string, not executed — it's up to the operator to run it against their
allowed validation target. We also emit a pre-built `nuclei` CLI command
pointing at a temp file so the operator can run it immediately.

We NEVER write the raw secret to persistent storage. The returned struct
references `{{secret}}` as a placeholder — the caller plugs it in at exec
time and discards.
"""

from __future__ import annotations

import textwrap
from typing import Any


# Map TruffleHog detector → (endpoint, header format, expected-status matcher)
VALIDATOR_RECIPES: dict[str, dict[str, Any]] = {
    "Slack": {
        "url": "https://slack.com/api/auth.test",
        "method": "POST",
        "headers": {"Authorization": "Bearer {{secret}}"},
        "match_body": '"ok":true',
    },
    "Slackbot": {
        "url": "https://slack.com/api/auth.test",
        "method": "POST",
        "headers": {"Authorization": "Bearer {{secret}}"},
        "match_body": '"ok":true',
    },
    "SlackWebhook": {
        "url": "{{secret}}",
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "body": '{"text":"hakuna-validation-ping"}',
        "match_status": 200,
    },
    "GitHub": {
        "url": "https://api.github.com/user",
        "method": "GET",
        "headers": {"Authorization": "Bearer {{secret}}", "Accept": "application/vnd.github+json"},
        "match_status": 200,
    },
    "GitLab": {
        "url": "https://gitlab.com/api/v4/user",
        "method": "GET",
        "headers": {"PRIVATE-TOKEN": "{{secret}}"},
        "match_status": 200,
    },
    "Stripe": {
        "url": "https://api.stripe.com/v1/charges?limit=1",
        "method": "GET",
        "headers": {"Authorization": "Bearer {{secret}}"},
        "match_status": 200,
    },
    "SendGrid": {
        "url": "https://api.sendgrid.com/v3/scopes",
        "method": "GET",
        "headers": {"Authorization": "Bearer {{secret}}"},
        "match_status": 200,
    },
    "Twilio": {
        # Twilio uses HTTP basic with SID:TOKEN — we only have the token here,
        # so we emit a generic "account info" probe that returns 401 without SID.
        "url": "https://api.twilio.com/2010-04-01/Accounts.json",
        "method": "GET",
        "headers": {"Authorization": "Basic {{secret}}"},
        "match_status": 200,
    },
    "Mailgun": {
        "url": "https://api.mailgun.net/v3/domains",
        "method": "GET",
        "headers": {"Authorization": "Basic {{secret}}"},
        "match_status": 200,
    },
    "Datadog": {
        "url": "https://api.datadoghq.com/api/v1/validate",
        "method": "GET",
        "headers": {"DD-API-KEY": "{{secret}}"},
        "match_body": '"valid":true',
    },
    "Heroku": {
        "url": "https://api.heroku.com/account",
        "method": "GET",
        "headers": {"Authorization": "Bearer {{secret}}", "Accept": "application/vnd.heroku+json; version=3"},
        "match_status": 200,
    },
}


def build_validation(detector: str, redacted_hint: str) -> dict[str, Any] | None:
    """Return a Nuclei template string + ready-to-run CLI command for the
    given detector. None if we don't have a recipe.

    The returned dict:
        {
            "detector": str,
            "template_yaml": str,          # Nuclei HTTP template
            "nuclei_cli": str,             # one-line command
            "note": str,                   # operator guidance
            "placeholder": "{{secret}}",   # where the raw value goes
        }
    """
    recipe = VALIDATOR_RECIPES.get(detector)
    if recipe is None:
        return None

    template_id = f"hakuna-validate-{detector.lower()}"
    matchers: list[str] = []
    if "match_status" in recipe:
        matchers.append(textwrap.dedent(f"""\
              - type: status
                status:
                  - {recipe['match_status']}
        """).rstrip())
    if "match_body" in recipe:
        matchers.append(textwrap.dedent(f"""\
              - type: word
                part: body
                words:
                  - '{recipe['match_body']}'
        """).rstrip())
    headers_yaml = "\n".join(
        f"          {k}: '{v}'" for k, v in (recipe.get("headers") or {}).items()
    )
    body_line = ""
    if "body" in recipe:
        body_line = f"        body: '{recipe['body']}'\n"

    template_yaml = textwrap.dedent(f"""\
        id: {template_id}
        info:
          name: Validate {detector} secret (hakuna EASM)
          author: hakuna
          severity: info
          tags: hakuna,secret-validation,{detector.lower()}
        http:
          - method: {recipe['method']}
            path:
              - "{recipe['url']}"
            headers:
    """) + headers_yaml + "\n" + body_line + "        matchers-condition: and\n        matchers:\n" + "\n".join(matchers) + "\n"

    nuclei_cli = (
        f"# Replace {{secret}} with the actual leaked value, then run:\n"
        f"echo 'example.com' | nuclei -t {template_id}.yaml -silent -jsonl"
    )

    note = (
        f"This template hits {recipe['url']} with the suspected {detector} "
        "secret and matches on a signal that the auth succeeded. A 'MATCHED' "
        "result means the key is still active — rotate immediately. The "
        "raw secret must be substituted for {{secret}} at runtime and "
        "MUST NOT be stored with the template."
    )

    return {
        "detector": detector,
        "template_yaml": template_yaml,
        "nuclei_cli": nuclei_cli,
        "note": note,
        "placeholder": "{{secret}}",
        "endpoint": recipe["url"],
    }


def has_recipe(detector: str) -> bool:
    return detector in VALIDATOR_RECIPES
