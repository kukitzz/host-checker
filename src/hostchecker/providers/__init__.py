"""Import all provider modules so they self-register in the registry."""

from . import (  # noqa: F401
    abuseipdb,
    crtsh,
    greynoise,
    ipinfo,
    malwarebazaar,
    otx,
    shodan,
    threatfox,
    tor_exit,
    urlhaus,
    virustotal,
)
