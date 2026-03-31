package burp.api.montoya.scanner;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;

public interface ScanCheck {
    AuditResult passiveAudit(HttpRequestResponse baseRequestResponse);
    AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint);
    ConsolidationAction consolidateIssues(
        burp.api.montoya.scanner.audit.issues.AuditIssue newIssue,
        burp.api.montoya.scanner.audit.issues.AuditIssue existingIssue);
}
