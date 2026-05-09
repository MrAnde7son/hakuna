"""Domains used for personal/free email accounts.

Signups from these domains never auto-claim a tenant and the
"join an existing org" lookup ignores them. This prevents a stranger
from joining (or impersonating) someone else's tenant just because
they happen to share a `gmail.com` address.

Kept as a static frozenset rather than a config table — these are
well-known providers and shouldn't be tenant-editable.
"""

PUBLIC_EMAIL_DOMAINS = frozenset({
    # Google
    "gmail.com", "googlemail.com",
    # Microsoft
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "outlook.co.uk", "hotmail.co.uk", "live.co.uk",
    # Apple
    "icloud.com", "me.com", "mac.com",
    # Yahoo
    "yahoo.com", "yahoo.co.uk", "yahoo.co.jp", "ymail.com", "rocketmail.com",
    # AOL
    "aol.com",
    # Proton
    "protonmail.com", "proton.me", "pm.me",
    # GMX
    "gmx.com", "gmx.net", "gmx.de",
    # Other generic providers
    "mail.com", "zoho.com", "yandex.com", "yandex.ru",
    "fastmail.com", "fastmail.fm", "tutanota.com", "tuta.io",
    "hey.com", "hushmail.com", "inbox.com",
    # China / Asia
    "qq.com", "163.com", "126.com", "sina.com", "sohu.com",
    "naver.com", "daum.net",
    # Disposable / suspicious
    "mailinator.com", "guerrillamail.com", "10minutemail.com",
    "tempmail.com", "trashmail.com", "throwaway.email",
})


def extract_domain(email: str) -> str:
    """Lowercase the domain part of an email. Returns '' for malformed input."""
    if not email or "@" not in email:
        return ""
    return email.rsplit("@", 1)[1].strip().lower()


def is_public_email_domain(domain: str) -> bool:
    return (domain or "").lower() in PUBLIC_EMAIL_DOMAINS
