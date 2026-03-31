package com.portswigger.oauthcheck;

import com.portswigger.oauthcheck.OAuthEndpointDetector.OAuthContext;
import java.util.*;

/**
 * Runs all 5 OAuth checks against a given context and returns a combined result list.
 */
public class OAuthScanner {

    private final RedirectUriCheck       redirectUriCheck       = new RedirectUriCheck();
    private final ClientRegistrationCheck clientRegistrationCheck = new ClientRegistrationCheck();
    private final StateParameterCheck    stateParameterCheck    = new StateParameterCheck();
    private final RequestUriCheck        requestUriCheck        = new RequestUriCheck();
    private final InsecureGrantTypeCheck insecureGrantTypeCheck = new InsecureGrantTypeCheck();

    public List<OAuthCheckResult> runAll(OAuthContext ctx) {
        List<OAuthCheckResult> all = new ArrayList<>();
        all.addAll(redirectUriCheck.run(ctx));
        all.addAll(clientRegistrationCheck.run(ctx));
        all.addAll(stateParameterCheck.run(ctx));
        all.addAll(requestUriCheck.run(ctx));
        all.addAll(insecureGrantTypeCheck.run(ctx));
        return all;
    }

    /** Convenience: run against a raw base URL (uses OIDC discovery). */
    public List<OAuthCheckResult> runFromUrl(String baseUrl) {
        OAuthContext ctx = OAuthEndpointDetector.fromBaseUrl(baseUrl);
        return runAll(ctx);
    }
}
