package burp.api.montoya.http.handler;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ToolType;
public interface HttpRequestToBeSent extends HttpRequest {
    boolean isFromTool(ToolType... types);
}