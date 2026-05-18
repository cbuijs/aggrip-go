# External Integrations & Category Best Practices

The `clean-dom` utility natively supports pulling high-fidelity domain intelligence via **DuckDuckGo Tracker Radar** and the **Cloudflare Radar API**.

You can preview all available categories in the console using the `--list-categories` flag:

```
clean-dom --list-categories

```

## Shorthand "default" Parameter

You can rapidly deploy the best-practice categories documented below without typing them manually by supplying `default` to the category flags. The parser natively substitutes the strict arrays automatically.

```
clean-dom \
  --ddg-block-categories default \
  --ddg-allow-categories default \
  --cf-block-categories default \
  --cf-allow-categories default \
  --cf-api-token "YOUR_TOKEN" \
  -o unbound \
  --out-blocklist filter.conf

```

## 1. DuckDuckGo Tracker Radar

DuckDuckGo Tracker Radar provides an open-source dataset evaluating thousands of third-party domains. Because tracking mechanisms overlap with essential website functionality, configuring these categories incorrectly can break target websites.

**Best-Practice Blocklist Categories**
Use these categories with `--ddg-block-categories` to maximize privacy and reduce tracking telemetry.

* `Advertising`

* `Ad Motivated Tracking`

* `Analytics`

* `Audience Measurement`

* `Action Pixels`

* `Session Replay`

* `Third-Party Analytics Marketing`

**Best-Practice Allowlist Categories**
Use these categories with `--ddg-allow-categories` to prevent blocking critical web infrastructure and authentication flows.

* `CDN` (Content Delivery Networks storing images/CSS/JS)

* `SSO` (Single Sign-On protocols like OAuth/SAML)

* `Embedded Content` (Video players, social media embeds)

* `Non-Tracking` (Domains strictly necessary for the application to function)

## 2. Cloudflare Radar API

Cloudflare Radar tracks live malicious activity, threats, and application trends globally. This integration requires an active Cloudflare API token provided via `--cf-api-token` or the `CF_API_TOKEN` environment variable.

**Best-Practice Blocklist Categories**
Use these categories with `--cf-block-categories` to harden network security against active threats.

* `Malware`

* `Phishing`

* `Spyware`

* `Botnet`

* `Command and Control`

* `Spam`

**Situational Filtering Categories**
These categories are highly dependent on your network environment (e.g., corporate/enterprise vs. home).

* `Proxy` / `Anonymizer` (Corporate environments generally block these to prevent bypass)

* `Adult Themes` (Standard for family-safe filtering)

* `Gambling` (Standard for corporate/family-safe filtering)

**Best-Practice Allowlist Categories**
Use these categories with `--cf-allow-categories` if you are generating strict, default-deny environments that need basic web architecture whitelisted.

* `Content Delivery Networks`

## Example Complex Execution

This pipeline command utilizes both services simultaneously. It securely blocks DDG trackers and Cloudflare threats while explicitly injecting CDN and SSO bounds into the allowlist to ensure users can still log in and view un-broken websites.

```
export CF_API_TOKEN="YOUR_CLOUDFLARE_TOKEN"

clean-dom \
  --ddg-block-categories "Advertising,Analytics,Session Replay" \
  --ddg-allow-categories "CDN,SSO,Embedded Content" \
  --cf-block-categories "Malware,Phishing,Spyware,Botnet" \
  -o unbound \
  --out-blocklist local-zone.conf \
  --out-allowlist local-allow.conf \
  -v

```


