package burp.api.montoya.http.message;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.HttpService;
public interface HttpRequestResponse {
    HttpRequest request();
    HttpResponse response();
    HttpService httpService();
    static HttpRequestResponse httpRequestResponse(HttpRequest req, HttpResponse resp) {
        return new HttpRequestResponse() {
            public HttpRequest request() { return req; }
            public HttpResponse response() { return resp; }
            public HttpService httpService() { return req != null ? req.httpService() : null; }
        };
    }
}