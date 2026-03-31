package com.portswigger.oauthcheck;

/**
 * Holds the result of a single OAuth check probe.
 */
public class OAuthCheckResult {

    public enum Severity { HIGH, MEDIUM, LOW, INFO }
    public enum Confidence { CERTAIN, FIRM, TENTATIVE }

    private final String checkName;
    private final boolean vulnerable;
    private final String detail;
    private final String remediation;
    private final String evidence;
    private final Severity severity;
    private final Confidence confidence;
    private final String requestSent;
    private final String responseReceived;

    public OAuthCheckResult(String checkName, boolean vulnerable, String detail,
                            String remediation, String evidence,
                            Severity severity, Confidence confidence,
                            String requestSent, String responseReceived) {
        this.checkName      = checkName;
        this.vulnerable     = vulnerable;
        this.detail         = detail;
        this.remediation    = remediation;
        this.evidence       = evidence;
        this.severity       = severity;
        this.confidence     = confidence;
        this.requestSent    = requestSent;
        this.responseReceived = responseReceived;
    }

    public String   getCheckName()        { return checkName; }
    public boolean  isVulnerable()        { return vulnerable; }
    public String   getDetail()           { return detail; }
    public String   getRemediation()      { return remediation; }
    public String   getEvidence()         { return evidence; }
    public Severity getSeverity()         { return severity; }
    public Confidence getConfidence()     { return confidence; }
    public String   getRequestSent()      { return requestSent; }
    public String   getResponseReceived() { return responseReceived; }
}
