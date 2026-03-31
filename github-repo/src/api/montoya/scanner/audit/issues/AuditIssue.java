package burp.api.montoya.scanner.audit.issues;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import java.util.List;
public interface AuditIssue {
    String name();
    String detail();
    String remediation();
    AuditIssueSeverity severity();
    AuditIssueConfidence confidence();
    HttpService httpService();
    List<HttpRequestResponse> requestResponses();
    static AuditIssue auditIssue(
            String name, String detail, String remediation,
            String baseUrl, AuditIssueSeverity severity, AuditIssueConfidence confidence,
            String background, String remediationBackground,
            AuditIssueSeverity typicalSeverity, List<HttpRequestResponse> requestResponses) {
        return new AuditIssue() {
            public String name() { return name; }
            public String detail() { return detail; }
            public String remediation() { return remediation; }
            public AuditIssueSeverity severity() { return severity; }
            public AuditIssueConfidence confidence() { return confidence; }
            public HttpService httpService() { return null; }
            public List<HttpRequestResponse> requestResponses() { return requestResponses; }
        };
    }
}