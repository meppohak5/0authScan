package burp.api.montoya;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.http.Http;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.persistence.Persistence;
public interface MontoyaApi {
    Extension extension();
    Logging logging();
    Http http();
    Scanner scanner();
    UserInterface userInterface();
    Persistence persistence();
}
