package burp.api.montoya.http;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.handler.HttpHandler;
public interface Http {
    HttpRequestResponse sendRequest(HttpRequest request);
    Registration registerHttpHandler(HttpHandler handler);
}
