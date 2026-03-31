package com.portswigger.oauthcheck;

import com.portswigger.oauthcheck.OAuthEndpointDetector.OAuthContext;
import com.portswigger.oauthcheck.OAuthCheckResult.*;
import java.util.*;

/**
 * OAuth Check 1 – Unvalidated Redirects via redirect_uri
 *
 * Probes whether the authorization endpoint enforces a strict whitelist
 * for the redirect_uri parameter by substituting attacker-controlled
 * values and observing whether the server accepts them.
 */
public class RedirectUriCheck {

    private static final String CHECK_NAME = "OAuth – Unvalidated Redirects via redirect_uri";

    public List<OAuthCheckResult> run(OAuthContext ctx) {
        List<OAuthCheckResult> results = new ArrayList<>();

        if (ctx.authorizationEndpoint == null || ctx.authorizationEndpoint.isEmpty()) {
            results.add(info("No authorization endpoint detected – check skipped."));
            return results;
        }

        String clientId = ctx.observedClientId != null ? ctx.observedClientId : "test_client";

        // Build a base auth URL to mutate
        String baseAuth = ctx.authorizationEndpoint
            + "?response_type=code"
            + "&client_id=" + clientId
            + "&scope=openid"
            + "&state=checkstate123";

        // Test payloads: (label, redirect_uri value)
        String[][] payloads = {
            // 1. Completely different attacker domain
            { "Open redirect – attacker domain",
              "https://evil.com/callback" },
            // 2. Subdomain of legitimate domain (if we know it)
            { "Subdomain bypass",
              "https://evil." + safeDomain(ctx) + "/callback" },
            // 3. Path traversal from legitimate registered URI
            { "Path traversal bypass",
              ctx.observedRedirectUris.isEmpty()
                  ? "https://legitimate.example.com/../../../evil.com/callback"
                  : ctx.observedRedirectUris.get(0) + "/../../../evil" },
            // 4. Fragment injection
            { "Fragment bypass",
              "https://evil.com/callback#@legitimate.example.com" },
            // 5. URL-encoded bypass
            { "Encoded bypass",
              "https://evil.com%2fcallback" },
            // 6. Localhost (SSRF hint)
            { "Localhost redirect (SSRF)",
              "http://localhost/callback" },
        };

        for (String[] payload : payloads) {
            String label      = payload[0];
            String redirectUri = payload[1];
            String probeUrl   = HttpHelper.addParam(baseAuth, "redirect_uri", redirectUri);
            try {
                HttpHelper.Response r = HttpHelper.get(probeUrl);

                boolean suspicious = false;
                String  reason     = "";

                // Redirect accepted: server issued 302/303 pointing at our URI
                if ((r.statusCode == 302 || r.statusCode == 303 || r.statusCode == 307)) {
                    String location = r.getHeader("location");
                    if (location.contains("evil.com") || location.contains("localhost")
                            || location.startsWith(redirectUri.split("[?#]")[0])) {
                        suspicious = true;
                        reason = "Server redirected to attacker-controlled URI: " + location;
                    }
                }
                // 200 and body contains our redirect URI (e.g. SPA embedding)
                if (r.statusCode == 200 && r.body.contains("evil.com")) {
                    suspicious = true;
                    reason = "Response body contains attacker domain";
                }
                // No error for an unknown redirect_uri
                if (r.statusCode != 400 && r.statusCode != 401
                        && r.statusCode != 403 && r.statusCode != 404) {
                    if (!suspicious) {
                        reason = "Server returned HTTP " + r.statusCode +
                                 " (did not reject invalid redirect_uri)";
                        suspicious = true; // At minimum mark as tentative
                    }
                }

                if (suspicious) {
                    results.add(new OAuthCheckResult(
                        CHECK_NAME + " [" + label + "]",
                        true,
                        "The authorization endpoint did not reject a manipulated redirect_uri. " + reason,
                        "Implement a strict server-side whitelist of allowed redirect URIs. " +
                        "Reject requests where redirect_uri does not exactly match a pre-registered URI.",
                        "Probe URL: " + probeUrl + "\nHTTP " + r.statusCode + "\n"
                            + (r.hasHeader("location") ? "Location: " + r.getHeader("location") : "")
                            + "\nBody excerpt: " + r.body.substring(0, Math.min(r.body.length(), 300)),
                        Severity.HIGH,
                        suspicious && r.statusCode < 400 ? Confidence.FIRM : Confidence.TENTATIVE,
                        probeUrl,
                        "HTTP " + r.statusCode + "\n" + r.body.substring(0, Math.min(r.body.length(), 500))
                    ));
                } else {
                    results.add(new OAuthCheckResult(
                        CHECK_NAME + " [" + label + "] – Not vulnerable",
                        false,
                        "Server correctly rejected redirect_uri: " + redirectUri,
                        "",
                        "HTTP " + r.statusCode,
                        Severity.INFO, Confidence.CERTAIN,
                        probeUrl, "HTTP " + r.statusCode
                    ));
                }
            } catch (Exception e) {
                results.add(info("Error probing [" + label + "]: " + e.getMessage()));
            }
        }
        return results;
    }

    private String safeDomain(OAuthContext ctx) {
        try {
            java.net.URL u = new java.net.URL(ctx.authorizationEndpoint);
            return u.getHost();
        } catch (Exception e) {
            return "example.com";
        }
    }

    private OAuthCheckResult info(String msg) {
        return new OAuthCheckResult(CHECK_NAME, false, msg, "",
            msg, Severity.INFO, Confidence.TENTATIVE, "", "");
    }
}
