package burp.api.montoya.scanner;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import java.util.List;
import java.util.Collections;

public interface AuditResult {
    List<AuditIssue> auditIssues();

    static AuditResult auditResult(List<AuditIssue> issues) {
        return () -> issues;
    }

    static AuditResult noIssues() {
        return Collections::emptyList;
    }
}
