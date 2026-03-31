package burp.api.montoya.scanner;
import burp.api.montoya.core.Registration;
public interface Scanner {
    Registration registerScanCheck(ScanCheck scanCheck);
}
