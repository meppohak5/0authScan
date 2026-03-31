package com.portswigger.oauthcheck;

import com.portswigger.oauthcheck.OAuthEndpointDetector.OAuthContext;
import com.portswigger.oauthcheck.OAuthCheckResult.*;
import java.util.*;

/**
 * OAuth Check 5 – Insecure Grant Type Supported
 *
 * Checks for deprecated or high-risk grant types:
 *  - Implicit (response_type=token) – exposes access tokens in URL fragments
 *  - Resource Owner Password Credentials – requires sharing user passwords
 *  - device_code – only appropriate for device flows, can be misused
 *  - client_credentials via URL params – secret exposure risk
 */
public class InsecureGrantTypeCheck {

    private static final String CHECK_NAME =
        "OAuth – Insecure Grant Type Supported";

    // Grant types mapped to their risk description
    private static final Object[][] GRANT_RISKS = {
        { "implicit",
          Severity.HIGH,
          "The implicit grant (response_type=token) returns access tokens in URL fragments, " +
          "which are logged in browser history, referrer headers, and proxy logs. " +
          "It was deprecated in OAuth 2.0 Security BCP (RFC 9700) and must not be used in new deployments.",
          "Remove implicit grant support. Use authorization_code with PKCE instead." },
        { "token",          // response_type alias
          Severity.HIGH,
          "response_type=token (implicit flow) returns access tokens in URL fragments.",
          "Use authorization_code with PKCE instead of the implicit grant." },
        { "password",
          Severity.HIGH,
          "Resource Owner Password Credentials (ROPC) grant requires the client to collect " +
          "and transmit the user's password to the authorization server, eliminating the " +
          "security benefit of OAuth delegation. It is deprecated in OAuth 2.1.",
          "Replace ROPC with authorization_code + PKCE. Never collect user passwords in clients." },
        { "urn:ietf:params:oauth:grant-type:device_code",
          Severity.LOW,
          "Device Authorization Grant is supported. If the authorization server does not " +
          "enforce short device code lifetimes and rate limiting, it may be susceptible to " +
          "social-engineering attacks using device-code phishing.",
          "Enforce short device code expiry (≤5 min), rate-limit polling, and warn users about " +
          "unsolicited device activation requests." },
    };

    public List<OAuthCheckResult> run(OAuthContext ctx) {
        List<OAuthCheckResult> results = new ArrayList<>();

        // ─ Test via discovery document ────────────────────────────────────────
        if (ctx.fromDiscovery && !ctx.grantTypesSupported.isEmpty()) {
            results.addAll(checkDiscoveryGrants(ctx));
        }

        // ─ Active probes against token / auth endpoints ───────────────────────
        results.addAll(probeImplicit(ctx));
        results.addAll(probePassword(ctx));

        if (results.isEmpty())
            results.add(info("No grant type information found via discovery or active probing."));

        return results;
    }

    private List<OAuthCheckResult> checkDiscoveryGrants(OAuthContext ctx) {
        List<OAuthCheckResult> out = new ArrayList<>();
        for (Object[] risk : GRANT_RISKS) {
            String grant = (String) risk[0];
            if (ctx.grantTypesSupported.contains(grant)) {
                out.add(new OAuthCheckResult(
                    CHECK_NAME + " [" + grant + " – advertised in discovery]",
                    true,
                    (String) risk[2],
                    (String) risk[3],
                    "grant_types_supported in discovery includes: " + grant +
                    "\nFull list: " + ctx.grantTypesSupported,
                    (Severity) risk[1], Confidence.CERTAIN,
                    "GET " + ctx.discoveryUrl,
                    ctx.discoveryBody != null
                        ? ctx.discoveryBody.substring(0, Math.min(ctx.discoveryBody.length(), 500))
                        : ""
                ));
            }
        }
        // Also flag if code is missing (means PKCE-capable flow is not available)
        if (!ctx.grantTypesSupported.contains("authorization_code")) {
            out.add(new OAuthCheckResult(
                CHECK_NAME + " [authorization_code not listed]",
                true,
                "The discovery document does not list authorization_code in grant_types_supported. " +
                "This suggests the server does not support the recommended secure grant type.",
                "Support authorization_code grant with PKCE (RFC 7636) as the primary grant type.",
                "grant_types_supported: " + ctx.grantTypesSupported,
                Severity.MEDIUM, Confidence.FIRM,
                "GET " + ctx.discoveryUrl, ""
            ));
        }
        return out;
    }

    /** Probe: try authorization endpoint with response_type=token (implicit). */
    private List<OAuthCheckResult> probeImplicit(OAuthContext ctx) {
        List<OAuthCheckResult> out = new ArrayList<>();
        if (ctx.authorizationEndpoint == null) return out;
        String clientId = ctx.observedClientId != null ? ctx.observedClientId : "test_client";
        String probeUrl = ctx.authorizationEndpoint
            + "?response_type=token"
            + "&client_id=" + clientId
            + "&scope=openid"
            + "&redirect_uri=https://example.com/cb"
            + "&state=implicitcheck";
        try {
            HttpHelper.Response r = HttpHelper.get(probeUrl);
            // Server accepted implicit: proceeds to login / does NOT immediately reject
            boolean rejected = r.statusCode == 400
                || r.body.toLowerCase().contains("unsupported_response_type")
                || r.body.toLowerCase().contains("response_type not supported");
            if (!rejected && (r.statusCode == 200 || r.statusCode == 302 || r.statusCode == 303)) {
                out.add(new OAuthCheckResult(
                    CHECK_NAME + " [Implicit grant accepted (active probe)]",
                    true,
                    "The authorization endpoint did not reject response_type=token. " +
                    "The implicit grant appears to be active.",
                    "Return unsupported_response_type error for response_type=token. " +
                    "Remove implicit grant support.",
                    "Probe: " + probeUrl + "\nHTTP " + r.statusCode + "\n"
                        + r.body.substring(0, Math.min(r.body.length(), 300)),
                    Severity.HIGH, Confidence.FIRM,
                    probeUrl,
                    "HTTP " + r.statusCode + "\n" + r.body.substring(0, Math.min(r.body.length(), 500))
                ));
            } else if (rejected) {
                out.add(new OAuthCheckResult(
                    CHECK_NAME + " [Implicit grant correctly rejected]",
                    false,
                    "Server correctly returned an error for response_type=token.",
                    "",
                    "HTTP " + r.statusCode,
                    Severity.INFO, Confidence.CERTAIN,
                    probeUrl, "HTTP " + r.statusCode
                ));
            }
        } catch (Exception e) {
            out.add(info("Error probing implicit grant: " + e.getMessage()));
        }
        return out;
    }

    /** Probe: try token endpoint with grant_type=password. */
    private List<OAuthCheckResult> probePassword(OAuthContext ctx) {
        List<OAuthCheckResult> out = new ArrayList<>();
        if (ctx.tokenEndpoint == null) return out;
        String body = "grant_type=password&username=test&password=test&scope=openid";
        try {
            Map<String,String> headers = new LinkedHashMap<>();
            headers.put("Content-Type", "application/x-www-form-urlencoded");
            HttpHelper.Response r = HttpHelper.post(ctx.tokenEndpoint, body, headers);

            // Server accepted: returns 200 with token JSON
            boolean accepted = r.statusCode == 200
                && (r.body.contains("access_token") || r.body.contains("token_type"));
            // Server processed (even invalid creds): not 400 "unsupported_grant_type"
            boolean processed = r.statusCode != 400
                || !r.body.toLowerCase().contains("unsupported_grant_type");

            if (accepted) {
                out.add(new OAuthCheckResult(
                    CHECK_NAME + " [ROPC grant – credentials accepted]",
                    true,
                    "The token endpoint accepted grant_type=password with test credentials " +
                    "and returned a token response. ROPC grant is enabled and appears to work " +
                    "with weak/guessable credentials.",
                    "Disable ROPC grant. Never accept user passwords in OAuth clients.",
                    "POST " + ctx.tokenEndpoint + "\n" + body + "\n\nHTTP " + r.statusCode
                        + "\n" + r.body.substring(0, Math.min(r.body.length(), 300)),
                    Severity.HIGH, Confidence.CERTAIN,
                    "POST " + ctx.tokenEndpoint + "\n" + body,
                    "HTTP " + r.statusCode + "\n" + r.body.substring(0, Math.min(r.body.length(), 500))
                ));
            } else if (processed && r.statusCode == 400
                    && !r.body.toLowerCase().contains("unsupported_grant_type")) {
                // Got invalid_client or invalid_grant – server supports ROPC but creds are wrong
                out.add(new OAuthCheckResult(
                    CHECK_NAME + " [ROPC grant – supported but creds rejected]",
                    true,
                    "The token endpoint supports grant_type=password (ROPC) but returned " +
                    "invalid_client or invalid_grant for test credentials. " +
                    "ROPC grant is enabled, which violates OAuth 2.1 security recommendations.",
                    "Disable ROPC grant. Replace with authorization_code + PKCE.",
                    "POST " + ctx.tokenEndpoint + "\n" + body + "\n\nHTTP " + r.statusCode
                        + "\n" + r.body.substring(0, Math.min(r.body.length(), 300)),
                    Severity.HIGH, Confidence.FIRM,
                    "POST " + ctx.tokenEndpoint + "\n" + body,
                    "HTTP " + r.statusCode + "\n" + r.body.substring(0, Math.min(r.body.length(), 500))
                ));
            } else {
                out.add(new OAuthCheckResult(
                    CHECK_NAME + " [ROPC grant – not supported]",
                    false,
                    "Token endpoint returned unsupported_grant_type for grant_type=password.",
                    "",
                    "HTTP " + r.statusCode,
                    Severity.INFO, Confidence.FIRM,
                    "POST " + ctx.tokenEndpoint, "HTTP " + r.statusCode
                ));
            }
        } catch (Exception e) {
            out.add(info("Error probing ROPC: " + e.getMessage()));
        }
        return out;
    }

    private OAuthCheckResult info(String msg) {
        return new OAuthCheckResult(CHECK_NAME, false, msg, "",
            msg, Severity.INFO, Confidence.TENTATIVE, "", "");
    }
}
