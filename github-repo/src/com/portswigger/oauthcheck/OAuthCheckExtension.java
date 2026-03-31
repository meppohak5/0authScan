package com.portswigger.oauthcheck;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import com.portswigger.oauthcheck.OAuthEndpointDetector.OAuthContext;

import javax.swing.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * OAuthCheckExtension – Burp Suite Montoya API extension.
 *
 * Author : Mayur Patil (meppo)
 * Version: 1.1.0
 *
 * Checks:
 *  1. OAuth – Unvalidated Redirects (redirect_uri manipulation)
 *  2. OAuth – Exposed Client Registration Endpoint
 *  3. OAuth – Insufficient State Parameter Validation
 *  4. OAuth – request_uri Parameter Supported (SSRF vector)
 *  5. OAuth – Insecure Grant Type Supported (implicit / password)
 */
public class OAuthCheckExtension implements BurpExtension {

    private static final String EXT_NAME    = "OAuth Security Checks";
    private static final String EXT_AUTHOR  = "Mayur Patil (meppo)";
    private static final String EXT_VERSION = "1.1.0";

    private Logging        logging;
    private OAuthScanPanel panel;

    /** Cache of already-scanned base URLs to avoid hammering the same host. */
    private final Set<String> scannedUrls = ConcurrentHashMap.newKeySet();

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXT_NAME);
        logging = api.logging();
        logging.logToOutput("================================================");
        logging.logToOutput("  " + EXT_NAME);
        logging.logToOutput("  Author : " + EXT_AUTHOR);
        logging.logToOutput("  Version: " + EXT_VERSION);
        logging.logToOutput("================================================");

        // ── UI tab ────────────────────────────────────────────────────────────
        panel = new OAuthScanPanel();
        api.userInterface().registerSuiteTab("OAuth Checks", panel);

        // ── Passive HTTP traffic sniffer ──────────────────────────────────────
        // FIX: Do NOT call initiatingRequest() on HttpResponseReceived —
        //      that method does not exist in the real Montoya API.
        //      Instead use the request on the handler's RequestToBeSent.
        api.http().registerHttpHandler(new HttpHandler() {

            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(
                    HttpRequestToBeSent req) {
                try {
                    String url  = req.url();
                    String body = req.bodyToString();
                    if (OAuthEndpointDetector.looksLikeOAuth(url, body)) {
                        String base = HttpHelper.baseUrl(url);
                        if (scannedUrls.add(base)) {
                            logging.logToOutput(
                                "[OAuthCheck] OAuth traffic detected – queuing scan for " + base);
                            // Fire async; response body not needed for detection
                            runChecksAsync(url, body, "", api);
                        }
                    }
                } catch (Exception ignored) {}
                return RequestToBeSentAction.continueWith(req);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(
                    HttpResponseReceived resp) {
                // Nothing needed here – detection is done on the request side
                return ResponseReceivedAction.continueWith(resp);
            }
        });

        // ── Passive scan check (Burp Scanner integration) ─────────────────────
        api.scanner().registerScanCheck(new OAuthPassiveScanCheck());

        // ── Context-menu shortcut ──────────────────────────────────────────────
        api.userInterface().registerContextMenuItemsProvider(
            new ContextMenuItemsProvider() {
                @Override
                public List<JMenuItem> provideMenuItems(ContextMenuEvent event) {
                    List<JMenuItem> items = new ArrayList<>();
                    JMenuItem item = new JMenuItem("Run OAuth Checks on this host");
                    item.addActionListener(e -> {
                        List<HttpRequestResponse> selected =
                            event.selectedRequestResponses();
                        if (!selected.isEmpty()) {
                            String url  = selected.get(0).request().url();
                            String base = HttpHelper.baseUrl(url);
                            SwingUtilities.invokeLater(() -> {
                                panel.setTargetUrl(base);
                                panel.startScan();
                            });
                        }
                    });
                    items.add(item);
                    return items;
                }
            }
        );

        logging.logToOutput("[OAuthCheck] Extension loaded. Proxy traffic to auto-detect OAuth flows.");
    }

    // ── Async runner ──────────────────────────────────────────────────────────

    private void runChecksAsync(String requestUrl, String requestBody,
                                 String responseBody, MontoyaApi api) {
        Thread t = new Thread(() -> {
            try {
                OAuthContext ctx = OAuthEndpointDetector.detect(
                    requestUrl, requestBody, responseBody);
                if (ctx == null) return;

                OAuthScanner scanner = new OAuthScanner();
                List<OAuthCheckResult> results = scanner.runAll(ctx);

                SwingUtilities.invokeLater(() -> {
                    for (OAuthCheckResult r : results) {
                        if (r.isVulnerable()) panel.addResult(r);
                    }
                });

                long vulns = results.stream()
                    .filter(OAuthCheckResult::isVulnerable).count();
                logging.logToOutput(
                    "[OAuthCheck] Scan complete for " + requestUrl +
                    " → " + vulns + " potential issue(s) found.");
            } catch (Exception ex) {
                logging.logToError("[OAuthCheck] Async scan error: " + ex.getMessage());
            }
        }, "OAuthCheck-Scanner");
        t.setDaemon(true);
        t.start();
    }

    // ── Passive ScanCheck ─────────────────────────────────────────────────────

    /**
     * FIX: passiveAudit() and activeAudit() MUST return AuditResult (not List<AuditIssue>).
     * Burp calls AuditResult.auditIssues() on the returned object — returning null caused NPE.
     */
    private class OAuthPassiveScanCheck implements ScanCheck {

        @Override
        public AuditResult passiveAudit(HttpRequestResponse baseRR) {
            List<AuditIssue> issues = new ArrayList<>();
            try {
                String url  = baseRR.request().url();
                String body = baseRR.request().bodyToString();

                if (!OAuthEndpointDetector.looksLikeOAuth(url, body)) {
                    return AuditResult.noIssues();   // ← never null
                }

                OAuthContext ctx = OAuthEndpointDetector.detect(
                    url, body,
                    baseRR.response() != null ? baseRR.response().bodyToString() : "");
                if (ctx == null) return AuditResult.noIssues();

                OAuthScanner scanner = new OAuthScanner();
                List<OAuthCheckResult> results = scanner.runAll(ctx);

                for (OAuthCheckResult r : results) {
                    if (!r.isVulnerable()) continue;
                    issues.add(AuditIssue.auditIssue(
                        r.getCheckName(),
                        r.getDetail(),
                        r.getRemediation(),
                        url,
                        mapSeverity(r.getSeverity()),
                        mapConfidence(r.getConfidence()),
                        "", "",
                        AuditIssueSeverity.MEDIUM,
                        Collections.singletonList(baseRR)
                    ));
                }
            } catch (Exception ex) {
                logging.logToError("[OAuthCheck] passiveAudit error: " + ex.getMessage());
            }
            return AuditResult.auditResult(issues);  // ← always non-null
        }

        @Override
        public AuditResult activeAudit(HttpRequestResponse baseRR,
                                        AuditInsertionPoint pt) {
            return AuditResult.noIssues();           // ← always non-null
        }

        @Override
        public ConsolidationAction consolidateIssues(AuditIssue newIssue,
                                                      AuditIssue existingIssue) {
            return newIssue.name().equals(existingIssue.name())
                ? ConsolidationAction.KEEP_EXISTING
                : ConsolidationAction.KEEP_BOTH;
        }

        private AuditIssueSeverity mapSeverity(OAuthCheckResult.Severity s) {
            switch (s) {
                case HIGH:   return AuditIssueSeverity.HIGH;
                case MEDIUM: return AuditIssueSeverity.MEDIUM;
                case LOW:    return AuditIssueSeverity.LOW;
                default:     return AuditIssueSeverity.INFORMATION;
            }
        }

        private AuditIssueConfidence mapConfidence(OAuthCheckResult.Confidence c) {
            switch (c) {
                case CERTAIN:  return AuditIssueConfidence.CERTAIN;
                case FIRM:     return AuditIssueConfidence.FIRM;
                default:       return AuditIssueConfidence.TENTATIVE;
            }
        }
    }
}
