package burp.api.montoya.http.message.responses;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.core.ByteArray;
import java.util.List;
public interface HttpResponse {
    short statusCode();
    String reasonPhrase();
    List<HttpHeader> headers();
    String bodyToString();
    ByteArray body();
    boolean hasHeader(String name);
    String headerValue(String name);
}