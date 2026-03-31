# OAuth Security Checks — Burp Suite Extension

> **Author:** Mayur Patil ([@meppo](https://github.com/meppo))  
> **Version:** 1.1.0  
> **API:** Burp Suite Montoya API  
> **Language:** Java 11+

A Burp Suite extension that automates detection of common OAuth 2.0 / OpenID Connect security vulnerabilities, inspired by the [PortSwigger Web Security Academy OAuth labs](https://portswigger.net/web-security/oauth).

---

## 🔍 Checks Performed

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 1 | **Unvalidated Redirect URI** | 🔴 High | Tests whether `redirect_uri` can be pointed to an attacker-controlled domain, bypassed via path traversal, fragment injection, or URL encoding |
| 2 | **Exposed Client Registration Endpoint** | 🟠 Medium | Probes common paths (`/register`, `/oauth/register`, `/clients`, etc.) for open dynamic client registration |
| 3 | **Insufficient State Parameter Validation** | 🟠 Medium | Tests for missing state, static/predictable values, short tokens, and numeric-only state — CSRF vectors |
| 4 | **request_uri Parameter Supported** | 🔴 High | Checks OIDC discovery metadata and attempts SSRF via `request_uri` pointing to an external host |
| 5 | **Insecure Grant Type** | 🟠 Medium | Detects implicit flow (`response_type=token`), resource owner password credentials, device code, and other insecure grants in discovery docs |

---

## 📦 Installation

### Option A — Prebuilt JAR (recommended)

1. Download [`oauth-check-burp-extension.jar`](releases/latest) from the Releases page
2. In Burp Suite: **Extensions → Add → Java → select the JAR → Next**
3. Confirm the extension loaded in the **Output** tab — you should see:

```
================================================
  OAuth Security Checks
  Author : Mayur Patil (meppo)
  Version: 1.1.0
================================================
[OAuthCheck] Extension loaded. Proxy traffic to auto-detect OAuth flows.
```

### Option B — Build from source

**Requirements:** JDK 11+ (or JRE 21 with `jdk.compiler` module)

```bash
git clone https://github.com/meppo/oauth-check-burp-extension.git
cd oauth-check-burp-extension

# Compile
find src -name "*.java" > /tmp/sources.txt
javac -source 11 -target 11 -sourcepath src -d classes @/tmp/sources.txt

# Package
jar cfm oauth-check-burp-extension.jar manifest.mf -C classes com/
```

---

## 🚀 Usage

### Passive — Auto-detection
Just proxy your target application's traffic through Burp. The extension automatically detects OAuth authorization flows and queues security checks in the background. Findings appear in:
- The **OAuth Checks** tab (custom UI)
- Burp's native **Issue Activity** panel (Scanner integration)

### Active — Manual scan from UI tab
1. Go to the **OAuth Checks** tab in Burp Suite
2. Enter the target base URL (e.g. `https://target.com`)
3. Click **Scan**
4. Results populate the table with severity, check name, and evidence

### Right-click — From Proxy / Repeater
Right-click any request → **"Run OAuth Checks on this host"**  
The extension extracts the host and runs all 5 checks immediately.

---

## 🧪 Tested Against

- [PortSwigger Web Security Academy — OAuth labs](https://portswigger.net/web-security/oauth)
- Custom OAuth 2.0 authorization servers
- Spring Authorization Server
- Keycloak / Okta / Auth0 (discovery endpoint checks)

---

## 🏗️ Architecture

```
OAuthCheckExtension          ← BurpExtension entry point (Montoya API)
├── HttpHandler               ← Passive traffic sniffer (request side)
├── OAuthPassiveScanCheck     ← Burp Scanner integration (AuditResult)
├── OAuthScanPanel            ← Swing UI tab
└── OAuthScanner              ← Orchestrates all checks
    ├── RedirectUriCheck
    ├── ClientRegistrationCheck
    ├── StateParameterCheck
    ├── RequestUriCheck
    └── InsecureGrantTypeCheck

OAuthEndpointDetector         ← OIDC discovery + traffic pattern detection
HttpHelper                    ← Lightweight HTTP client (trust-all TLS)
OAuthCheckResult              ← Result data object (severity, evidence, remediation)
```

---

## 📁 Repository Structure

```
oauth-check-burp-extension/
├── src/
│   ├── burp/api/montoya/          ← Montoya API stubs (compile-time only)
│   └── com/portswigger/oauthcheck/
│       ├── OAuthCheckExtension.java
│       ├── OAuthScanner.java
│       ├── OAuthScanPanel.java
│       ├── OAuthEndpointDetector.java
│       ├── OAuthCheckResult.java
│       ├── HttpHelper.java
│       └── checks/
│           ├── RedirectUriCheck.java
│           ├── ClientRegistrationCheck.java
│           ├── StateParameterCheck.java
│           ├── RequestUriCheck.java
│           └── InsecureGrantTypeCheck.java
├── manifest.mf
├── build.sh
├── README.md
└── LICENSE
```

---

## ⚠️ Disclaimer

This tool is intended for **authorised security testing only**. Only use it against systems you have explicit permission to test. The author accepts no liability for misuse.

---

## 📜 License

MIT License — see [LICENSE](LICENSE)

---

## 🤝 Contributing

Pull requests welcome! If you find a new OAuth misconfiguration pattern worth detecting, open an issue or submit a PR with a new check class implementing the scanner interface.
