package com.portswigger.oauthcheck;

import java.net.URL;
import java.util.*;
import java.util.regex.*;

/**
 * Detects OAuth / OIDC endpoints in HTTP traffic and via .well-known discovery.
 */
public class OAuthEndpointDetector {

    // Patterns that identify OAuth-related requests
    private static final Pattern AUTH_ENDPOINT_PAT = Pattern.compile(
        "(?:response_type|client_id|redirect_uri|scope|state|code_challenge)=",
        Pattern.CASE_INSENSITIVE);

    private static final Pattern TOKEN_ENDPOINT_PAT = Pattern.compile(
        "(?:grant_type=|client_secret=|code=.*&redirect_uri=)",
        Pattern.CASE_INSENSITIVE);

    private static final Pattern REGISTRATION_PAT = Pattern.compile(
        "/(?:register|client[_-]?registration|clients)(?:[/?]|$)",
        Pattern.CASE_INSENSITIVE);

    private static final Pattern OIDC_DISCOVERY_BODY = Pattern.compile(
        "\"authorization_endpoint\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern TOKEN_EP_PAT = Pattern.compile(
        "\"token_endpoint\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern REG_EP_PAT = Pattern.compile(
        "\"registration_endpoint\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern REQ_URI_PAT = Pattern.compile(
        "\"request_uri_parameter_supported\"\\s*:\\s*(true|false)");
    private static final Pattern GRANT_TYPES_PAT = Pattern.compile(
        "\"grant_types_supported\"\\s*:\\s*(\\[[^]]+\\])");

    public static class OAuthContext {
        public String baseUrl;
        public String authorizationEndpoint;
        public String tokenEndpoint;
        public String registrationEndpoint;
        public String discoveryUrl;
        public String discoveryBody;
        public boolean requestUriSupported;
        public List<String> grantTypesSupported = new ArrayList<>();
        public boolean fromDiscovery;

        // Raw request info captured from observed traffic
        public String observedAuthRequest;
        public String observedTokenRequest;
        public List<String> observedRedirectUris = new ArrayList<>();
        public String observedState;
        public String observedClientId;
    }

    /**
     * Try to build an OAuthContext from a detected request URL and body.
     * Returns null if the request is not OAuth-related.
     */
    public static OAuthContext detect(String requestUrl, String requestBody,
                                       String responseBody) {
        String combined = (requestUrl + " " + requestBody).toLowerCase();
        boolean isAuth  = AUTH_ENDPOINT_PAT.matcher(combined).find();
        boolean isToken = TOKEN_ENDPOINT_PAT.matcher(combined).find();

        if (!isAuth && !isToken) return null;

        OAuthContext ctx = new OAuthContext();
        ctx.baseUrl = HttpHelper.baseUrl(requestUrl);

        if (isAuth) {
            ctx.authorizationEndpoint = stripQuery(requestUrl);
            ctx.observedAuthRequest   = requestUrl;
            ctx.observedClientId      = HttpHelper.getParam(requestUrl, "client_id");
            String ru = HttpHelper.getParam(requestUrl, "redirect_uri");
            if (ru != null && !ru.isEmpty()) ctx.observedRedirectUris.add(ru);
            ctx.observedState = HttpHelper.getParam(requestUrl, "state");
        }
        if (isToken) {
            ctx.tokenEndpoint = stripQuery(requestUrl);
            ctx.observedTokenRequest = requestUrl + "\n" + requestBody;
        }

        // Try OIDC discovery enrichment
        enrichFromDiscovery(ctx);
        return ctx;
    }

    /**
     * Given an already-detected base URL (e.g. from the UI), perform
     * full OIDC discovery and return the context.
     */
    public static OAuthContext fromBaseUrl(String baseUrl) {
        OAuthContext ctx = new OAuthContext();
        ctx.baseUrl = baseUrl;
        enrichFromDiscovery(ctx);
        return ctx;
    }

    private static void enrichFromDiscovery(OAuthContext ctx) {
        String[] paths = {
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/oauth/.well-known/openid-configuration",
            "/oauth2/.well-known/openid-configuration",
            "/.well-known/oauth2-authorization-server"
        };
        for (String path : paths) {
            String url = ctx.baseUrl + path;
            try {
                HttpHelper.Response r = HttpHelper.get(url);
                if (r.statusCode == 200 && r.body.contains("authorization_endpoint")) {
                    ctx.discoveryUrl  = url;
                    ctx.discoveryBody = r.body;
                    ctx.fromDiscovery  = true;
                    parseDiscovery(ctx, r.body);
                    return;
                }
            } catch (Exception ignored) {}
        }
    }

    private static void parseDiscovery(OAuthContext ctx, String body) {
        Matcher m;
        m = OIDC_DISCOVERY_BODY.matcher(body);
        if (m.find()) ctx.authorizationEndpoint = m.group(1);
        m = TOKEN_EP_PAT.matcher(body);
        if (m.find()) ctx.tokenEndpoint = m.group(1);
        m = REG_EP_PAT.matcher(body);
        if (m.find()) ctx.registrationEndpoint = m.group(1);
        m = REQ_URI_PAT.matcher(body);
        if (m.find()) ctx.requestUriSupported = "true".equalsIgnoreCase(m.group(1));
        m = GRANT_TYPES_PAT.matcher(body);
        if (m.find()) {
            String arr = m.group(1);
            Matcher inner = Pattern.compile("\"([^\"]+)\"").matcher(arr);
            while (inner.find()) ctx.grantTypesSupported.add(inner.group(1));
        }
    }

    private static String stripQuery(String url) {
        int q = url.indexOf('?');
        return q < 0 ? url : url.substring(0, q);
    }

    /** Quick check: does a URL look like it carries OAuth parameters? */
    public static boolean looksLikeOAuth(String url, String body) {
        String s = (url + " " + (body == null ? "" : body)).toLowerCase();
        return AUTH_ENDPOINT_PAT.matcher(s).find()
            || TOKEN_ENDPOINT_PAT.matcher(s).find();
    }
}
