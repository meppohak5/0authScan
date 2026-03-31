package com.portswigger.oauthcheck;

import com.portswigger.oauthcheck.OAuthEndpointDetector.OAuthContext;
import com.portswigger.oauthcheck.OAuthCheckResult.*;
import java.util.*;

/**
 * OAuth Check 2 – Exposed Client Registration Endpoint
 *
 * RFC 7591 defines Dynamic Client Registration. If the endpoint is accessible
 * without authentication, an attacker can register arbitrary OAuth clients.
 */
public class ClientRegistrationCheck {

    private static final String CHECK_NAME = "OAuth – Exposed Client Registration Endpoint";

    private static final String[] REGISTRATION_PATHS = {
        "/register",
        "/oauth/register",
        "/oauth2/register",
        "/connect/register",
        "/clients",
        "/api/clients",
        "/oauth/clients",
        "/v1/clients",
        "/as/clients",
        "/client_registration",
        "/oauth/client_registration",
        "/api/oauth/clients",
    };

    private static final String REG_BODY =
        "{\"client_name\":\"OAuthCheckProbe\"," +
        "\"redirect_uris\":[\"https://evil.com/callback\"]," +
        "\"grant_types\":[\"authorization_code\"]," +
        "\"response_types\":[\"code\"]}";

    public List<OAuthCheckResult> run(OAuthContext ctx) {
        List<OAuthCheckResult> results = new ArrayList<>();

        // If OIDC discovery told us the registration endpoint, test that first
        Set<String> toTest = new LinkedHashSet<>();
        if (ctx.registrationEndpoint != null && !ctx.registrationEndpoint.isEmpty())
            toTest.add(ctx.registrationEndpoint);

        // Also test common paths against the base URL
        for (String path : REGISTRATION_PATHS)
            toTest.add(ctx.baseUrl + path);

        for (String endpoint : toTest) {
            // 1. GET the endpoint (some servers list clients)
            testGet(endpoint, results);
            // 2. POST a registration attempt
            testPost(endpoint, results);
        }

        if (results.isEmpty())
            results.add(info("No exposed registration endpoint found at common paths."));

        return results;
    }

    private void testGet(String endpoint, List<OAuthCheckResult> results) {
        try {
            HttpHelper.Response r = HttpHelper.get(endpoint);
            if (r.statusCode == 200 && (r.body.contains("client_id")
                    || r.body.contains("clients") || r.body.contains("registered"))) {
                results.add(new OAuthCheckResult(
                    CHECK_NAME + " [GET – client listing]",
                    true,
                    "The registration endpoint returned HTTP 200 and appears to list registered clients. " +
                    "Unauthenticated access to the client registry is a significant risk.",
                    "Require authentication (e.g. Bearer token with admin scope) to access " +
                    "the Dynamic Client Registration endpoint. Restrict registration to trusted parties.",
                    "GET " + endpoint + " → HTTP " + r.statusCode +
                    "\nBody: " + r.body.substring(0, Math.min(r.body.length(), 400)),
                    Severity.HIGH, Confidence.FIRM,
                    "GET " + endpoint,
                    "HTTP " + r.statusCode + "\n" + r.body.substring(0, Math.min(r.body.length(), 500))
                ));
            }
        } catch (Exception ignored) {}
    }

    private void testPost(String endpoint, List<OAuthCheckResult> results) {
        try {
            Map<String,String> headers = new LinkedHashMap<>();
            headers.put("Content-Type", "application/json");

            HttpHelper.Response r = HttpHelper.post(endpoint, REG_BODY, headers);

            boolean registered = (r.statusCode == 200 || r.statusCode == 201)
                && (r.body.contains("client_id") || r.body.contains("client_secret"));

            if (registered) {
                results.add(new OAuthCheckResult(
                    CHECK_NAME + " [POST – unauthenticated registration]",
                    true,
                    "Successfully registered a new OAuth client without authentication. " +
                    "An attacker can register clients to stage authorization code interception " +
                    "or impersonation attacks.",
                    "Require an initial access token (RFC 7591 §3.1) for Dynamic Client Registration. " +
                    "Log and alert on all registration attempts.",
                    "POST " + endpoint + "\nBody: " + REG_BODY +
                    "\nResponse: HTTP " + r.statusCode + "\n" +
                    r.body.substring(0, Math.min(r.body.length(), 400)),
                    Severity.HIGH, Confidence.CERTAIN,
                    "POST " + endpoint + "\n" + REG_BODY,
                    "HTTP " + r.statusCode + "\n" + r.body.substring(0, Math.min(r.body.length(), 500))
                ));
            } else if (r.statusCode != 404 && r.statusCode != 405) {
                // Endpoint exists but rejected our request – note it
                results.add(new OAuthCheckResult(
                    CHECK_NAME + " [POST – endpoint found, auth required]",
                    false,
                    "Registration endpoint found at " + endpoint +
                    " but returned HTTP " + r.statusCode + " (likely requires auth – good).",
                    "",
                    "HTTP " + r.statusCode + " from " + endpoint,
                    Severity.INFO, Confidence.FIRM,
                    "POST " + endpoint,
                    "HTTP " + r.statusCode
                ));
            }
        } catch (Exception ignored) {}
    }

    private OAuthCheckResult info(String msg) {
        return new OAuthCheckResult(CHECK_NAME, false, msg, "",
            msg, Severity.INFO, Confidence.TENTATIVE, "", "");
    }
}
