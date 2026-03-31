package com.portswigger.oauthcheck;

import com.portswigger.oauthcheck.OAuthEndpointDetector.OAuthContext;
import com.portswigger.oauthcheck.OAuthCheckResult.*;
import java.util.*;

/**
 * OAuth Check 4 – request_uri Parameter Supported (JAR SSRF risk)
 *
 * RFC 9101 (JWT-Secured Authorization Requests) defines the request_uri
 * parameter. When supported, the authorization server fetches the JWT from
 * an attacker-supplied URL, creating an SSRF vector.
 * Additionally, if request_uri_parameter_supported=true is advertised in the
 * discovery document, we probe whether the server actually fetches the URI.
 */
public class RequestUriCheck {

    private static final String CHECK_NAME =
        "OAuth – request_uri Parameter Supported";

    // Canary URLs that would prove server-side fetch (no real collaborator here,
    // so we use a resolvable but innocuous host and detect via error messages)
    private static final String[] SSRF_PROBES = {
        "http://169.254.169.254/latest/meta-data/",      // AWS IMDS
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.170.2/v2/metadata/",              // ECS
        "http://localhost:8080/.well-known/openid-configuration",
        "http://127.0.0.1/",
        "http://[::1]/",
        "https://burpcollaborator.net/oauth-requri-probe", // placeholder
    };

    public List<OAuthCheckResult> run(OAuthContext ctx) {
        List<OAuthCheckResult> results = new ArrayList<>();

        // ─ Check 1: Discovery doc advertises request_uri_parameter_supported ──
        if (ctx.fromDiscovery) {
            if (ctx.requestUriSupported) {
                results.add(new OAuthCheckResult(
                    CHECK_NAME + " [Advertised in discovery]",
                    true,
                    "The OIDC discovery document explicitly sets " +
                    "request_uri_parameter_supported=true. " +
                    "The authorization server will fetch JWTs from caller-supplied URLs, " +
                    "potentially enabling Server-Side Request Forgery (SSRF) attacks.",
                    "Disable request_uri support if JAR (RFC 9101) is not required. " +
                    "If it is required, implement strict URL allowlisting and disable " +
                    "fetching from private/internal network ranges.",
                    "Discovery URL: " + ctx.discoveryUrl + "\n" +
                    "request_uri_parameter_supported: true",
                    Severity.MEDIUM, Confidence.CERTAIN,
                    "GET " + ctx.discoveryUrl,
                    ctx.discoveryBody != null
                        ? ctx.discoveryBody.substring(0, Math.min(ctx.discoveryBody.length(), 500))
                        : ""
                ));
            } else {
                results.add(new OAuthCheckResult(
                    CHECK_NAME + " [Not advertised in discovery]",
                    false,
                    "Discovery document does not advertise request_uri_parameter_supported=true.",
                    "",
                    "request_uri_parameter_supported absent or false in " + ctx.discoveryUrl,
                    Severity.INFO, Confidence.FIRM,
                    "", ""
                ));
            }
        }

        // ─ Check 2: Probe authorization endpoint directly with request_uri ───
        if (ctx.authorizationEndpoint != null) {
            results.addAll(probeRequestUri(ctx));
        }

        if (results.isEmpty())
            results.add(info("No authorization endpoint or discovery doc found."));

        return results;
    }

    private List<OAuthCheckResult> probeRequestUri(OAuthContext ctx) {
        List<OAuthCheckResult> out = new ArrayList<>();
        String clientId = ctx.observedClientId != null ? ctx.observedClientId : "test_client";

        for (String ssrfTarget : SSRF_PROBES) {
            String probeUrl = ctx.authorizationEndpoint
                + "?response_type=code"
                + "&client_id=" + clientId;
            try {
                probeUrl = HttpHelper.addParam(probeUrl, "request_uri", ssrfTarget);
                HttpHelper.Response r = HttpHelper.get(probeUrl);

                // Indicators the server attempted to fetch the request_uri:
                // - 500 / timeout (fetch failed but was tried)
                // - Response body mentions "request_uri" fetch error
                // - Response contains metadata from the SSRF target
                boolean serverFetched = false;
                String reason = "";

                if (r.body.toLowerCase().contains("connection refused")
                        || r.body.toLowerCase().contains("unable to fetch")
                        || r.body.toLowerCase().contains("request_uri")
                        || r.body.toLowerCase().contains("invalid_request_uri")) {
                    serverFetched = true;
                    reason = "Response body contains indicators of server-side fetch attempt";
                }
                if (r.body.contains("ami-id") || r.body.contains("instance-id")
                        || r.body.contains("computeMetadata")) {
                    serverFetched = true;
                    reason = "CRITICAL: Response contains cloud metadata (SSRF confirmed)";
                }

                if (serverFetched) {
                    out.add(new OAuthCheckResult(
                        CHECK_NAME + " [SSRF probe – " + ssrfTarget + "]",
                        true,
                        "Authorization server appears to fetch the request_uri parameter value. " + reason,
                        "Implement an allowlist for request_uri values. Block access to private " +
                        "IP ranges (RFC 1918), link-local addresses (169.254.0.0/16), " +
                        "loopback (127.0.0.0/8), and cloud metadata endpoints.",
                        "Probe: " + probeUrl + "\nHTTP " + r.statusCode + "\n"
                            + r.body.substring(0, Math.min(r.body.length(), 400)),
                        Severity.HIGH, Confidence.FIRM,
                        probeUrl,
                        "HTTP " + r.statusCode + "\n" + r.body.substring(0, Math.min(r.body.length(), 500))
                    ));
                    break; // One confirmed finding is enough
                }
            } catch (Exception e) {
                // Timeout can indicate the server tried to connect to an internal host
                if (e.getMessage() != null && e.getMessage().toLowerCase().contains("timeout")) {
                    out.add(new OAuthCheckResult(
                        CHECK_NAME + " [Timeout – possible internal SSRF: " + ssrfTarget + "]",
                        true,
                        "Request timed out while probing request_uri=" + ssrfTarget +
                        ". This may indicate the server attempted to connect to an internal host.",
                        "Validate and allowlist request_uri values. Use a DNS rebinding-resistant " +
                        "HTTP client for outbound requests.",
                        "Probe timed out: " + probeUrl,
                        Severity.MEDIUM, Confidence.TENTATIVE,
                        probeUrl, "Timeout"
                    ));
                }
            }
        }
        return out;
    }

    private OAuthCheckResult info(String msg) {
        return new OAuthCheckResult(CHECK_NAME, false, msg, "",
            msg, Severity.INFO, Confidence.TENTATIVE, "", "");
    }
}
