# Email Validator API

Comprehensive email validation with zero external API dependencies — all checks are algorithmic or DNS-based.

## Features

- **Syntax validation** — RFC 5322 compliant
- **MX record lookup** — DNS check for mail server existence
- **Disposable email detection** — 550+ known throwaway domains
- **Role-based detection** — Detects admin@, info@, support@, etc.
- **Domain reputation** — MX, SPF, DKIM record checks
- **Typo suggestion** — Common misspellings (gmial→gmail, yaho→yahoo, etc.)
- **Risk scoring** — 0-100 score combining all checks
- **Batch validation** — Up to 100 emails at once

## Modes

### validate (default)
```json
{ "mode": "validate", "email": "user@gmail.com" }
```

### batch
```json
{ "mode": "batch", "emails": ["user@gmail.com", "test@mailinator.com"] }
```

### domain
```json
{ "mode": "domain", "domain": "gmail.com" }
```

### suggest
```json
{ "mode": "suggest", "email": "user@gmial.com" }
```

## Risk Score

| Score | Label | Meaning |
|-------|-------|---------|
| 0-10 | low | Safe to send |
| 11-30 | medium | Likely valid, minor concerns |
| 31-60 | high | Risky, may bounce |
| 61-100 | critical | Do not send |
