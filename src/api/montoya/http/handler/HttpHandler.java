package burp.api.montoya.http.handler;
public interface HttpHandler {
    RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent);
    ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived);
}