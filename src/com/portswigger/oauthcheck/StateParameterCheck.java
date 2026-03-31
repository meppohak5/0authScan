package com.portswigger.oauthcheck;

import com.portswigger.oauthcheck.OAuthEndpointDetector.OAuthContext;
import com.portswigger.oauthcheck.OAuthCheckResult.*;
import java.util.*;

/**
 * OAuth Check 3 – Insufficient State Parameter Validation
 *
 * The OAuth 2.0 state parameter is a CSRF token.  Missing, static, short, or
 * numeric-only state values allow Cross-Site Request Forgery attacks against
 * the authorization flow.
 */
public class StateParameterCheck {

    private static final String CHECK_NAME =
        "OAuth – Insufficient State Parameter Validation";

    public List<OAuthCheckResult> run(OAuthContext ctx) {
        List<OAuthCheckResult> results = new ArrayList<>();

        // ─ Test 1: Missing state ──────────────────────────────────────────────
        results.addAll(testMissingState(ctx));

        // ─ Test 2: Observed state analysis ───────────────────────────────────
        if (ctx.observedState != null) {
            results.addAll(analyseObservedState(ctx));
        }

        // ─ Test 3: Static / predictable state ────────────────────────────────
        results.addAll(testStaticState(ctx));

        if (results.isEmpty())
            results.add(info("No authorization endpoint observed – cannot test state parameter."));

        return results;
    }

    /** Send an authorization request with no state= parameter. */
    private List<OAuthCheckResult> testMissingState(OAuthContext ctx) {
        List<OAuthCheckResult> out = new ArrayList<>();
        if (ctx.authorizationEndpoint == null) return out;

        String clientId = ctx.observedClientId != null ? ctx.observedClientId : "test_client";
        String probeUrl = ctx.authorizationEndpoint
            + "?response_type=code"
            + "&client_id=" + clientId
            + "&scope=openid"
            + "&redirect_uri=https://evil.com/callback";   // no &state=

        try {
            HttpHelper.Response r = HttpHelper.get(probeUrl);
            // If the server does NOT return 400/error and proceeds normally,
            // it accepts requests without state
            boolean accepted = r.statusCode == 200
                || r.statusCode == 302
                || r.statusCode == 303;
            boolean hasError = r.body.toLowerCase().contains("error")
                || r.body.toLowerCase().contains("invalid_request")
                || r.body.toLowerCase().contains("state");

            if (accepted && !hasError) {
                out.add(new OAuthCheckResult(
                    CHECK_NAME + " [Missing state accepted]",
                    true,
                    "The authorization server accepted an authorization request without a state parameter. " +
                    "This allows CSRF attacks: an attacker can craft a malicious authorization URL " +
                    "that, when visited by a victim, will bind the attacker's authorization code " +
                    "to the victim's session.",
                    "Always require the state parameter in authorization requests. " +
                    "Return an error (invalid_request) when state is absent. " +
                    "Ensure clients use a cryptographically random state of at least 128 bits " +
                    "and verify it on callback.",
                    "Probe URL (no state): " + probeUrl + "\n" +
                    "HTTP " + r.statusCode + "\n" +
                    r.body.substring(0, Math.min(r.body.length(), 400)),
                    Severity.HIGH, Confidence.FIRM,
                    probeUrl,
                    "HTTP " + r.statusCode + "\n" + r.body.substring(0, Math.min(r.body.length(), 500))
                ));
            } else {
                out.add(new OAuthCheckResult(
                    CHECK_NAME + " [Missing state – correctly rejected]",
                    false,
                    "Server correctly rejected the request missing the state parameter.",
                    "",
                    "HTTP " + r.statusCode,
                    Severity.INFO, Confidence.FIRM,
                    probeUrl, "HTTP " + r.statusCode
                ));
            }
        } catch (Exception e) {
            out.add(info("Error testing missing state: " + e.getMessage()));
        }
        return out;
    }

    /** Analyse the state value that was observed in traffic. */
    private List<OAuthCheckResult> analyseObservedState(OAuthContext ctx) {
        List<OAuthCheckResult> out = new ArrayList<>();
        String state = ctx.observedState;

        // Length check
        if (state.length() < 8) {
            out.add(new OAuthCheckResult(
                CHECK_NAME + " [State too short: " + state.length() + " chars]",
                true,
                "Observed state value '" + state + "' is only " + state.length()
                    + " characters. Short state values are vulnerable to brute force. "
                    + "NIST recommends at least 128 bits (22+ base64url chars) of entropy.",
                "Use a cryptographically random state of at least 128 bits (e.g. 32 hex chars or "
                    + "22 base64url chars). Generate it server-side with a CSPRNG.",
                "Observed state: " + state,
                Severity.MEDIUM, Confidence.CERTAIN,
                ctx.observedAuthRequest != null ? ctx.observedAuthRequest : "",
                ""
            ));
        }

        // Numeric-only check (likely sequential / predictable)
        if (state.matches("\\d+")) {
            out.add(new OAuthCheckResult(
                CHECK_NAME + " [State is numeric-only (predictable)]",
                true,
                "Observed state value '" + state + "' consists entirely of digits. "
                    + "Numeric states are often sequential counters with low entropy, "
                    + "making them trivially predictable.",
                "Replace numeric state values with cryptographically random strings.",
                "Observed state: " + state,
                Severity.HIGH, Confidence.FIRM,
                ctx.observedAuthRequest != null ? ctx.observedAuthRequest : "",
                ""
            ));
        }

        // Static well-known placeholder
        String lower = state.toLowerCase();
        if (lower.equals("state") || lower.equals("xyz") || lower.equals("random")
                || lower.equals("csrf") || lower.equals("test") || lower.equals("none")
                || lower.equals("null") || lower.equals("undefined")) {
            out.add(new OAuthCheckResult(
                CHECK_NAME + " [Static/hardcoded state value]",
                true,
                "Observed state value '" + state + "' appears to be a static placeholder. "
                    + "Static states provide zero CSRF protection.",
                "Use a per-request, cryptographically random state value tied to the user's session.",
                "Observed state: " + state,
                Severity.HIGH, Confidence.CERTAIN,
                ctx.observedAuthRequest != null ? ctx.observedAuthRequest : "",
                ""
            ));
        }
        return out;
    }

    /** Submit the same static state twice to check whether the server validates uniqueness. */
    private List<OAuthCheckResult> testStaticState(OAuthContext ctx) {
        List<OAuthCheckResult> out = new ArrayList<>();
        if (ctx.authorizationEndpoint == null) return out;

        String clientId = ctx.observedClientId != null ? ctx.observedClientId : "test_client";
        String staticState = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        String probe1 = ctx.authorizationEndpoint
            + "?response_type=code&client_id=" + clientId
            + "&scope=openid&redirect_uri=https://example.com/cb&state=" + staticState;

        try {
            HttpHelper.Response r1 = HttpHelper.get(probe1);
            HttpHelper.Response r2 = HttpHelper.get(probe1); // same state second time

            boolean both200 = (r1.statusCode == 200 || r1.statusCode == 302)
                           && (r2.statusCode == 200 || r2.statusCode == 302);
            if (both200) {
                out.add(new OAuthCheckResult(
                    CHECK_NAME + " [Repeated state value accepted]",
                    true,
                    "The authorization server accepted the same static state value in two separate "
                    + "requests. A well-behaved server should bind state to a session and reject replays.",
                    "Bind state to the user's authenticated session. Invalidate state after first use.",
                    "Both requests with state=" + staticState + " returned HTTP "
                        + r1.statusCode + " / " + r2.statusCode,
                    Severity.MEDIUM, Confidence.TENTATIVE,
                    probe1, "HTTP " + r2.statusCode
                ));
            }
        } catch (Exception e) {
            out.add(info("Error testing static state: " + e.getMessage()));
        }
        return out;
    }

    private OAuthCheckResult info(String msg) {
        return new OAuthCheckResult(CHECK_NAME, false, msg, "",
            msg, Severity.INFO, Confidence.TENTATIVE, "", "");
    }
}
