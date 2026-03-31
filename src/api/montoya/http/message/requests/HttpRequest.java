package burp.api.montoya.http.message.requests;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.core.ByteArray;
import java.util.List;
public interface HttpRequest {
    HttpService httpService();
    String method();
    String path();
    String url();
    List<HttpHeader> headers();
    String bodyToString();
    ByteArray body();
    boolean hasHeader(String name);
    String headerValue(String name);
    HttpRequest withPath(String path);
    HttpRequest withBody(String body);
    HttpRequest withAddedHeader(String name, String value);
    HttpRequest withUpdatedHeader(String name, String value);
}