package burp.api.montoya.http.handler;
import burp.api.montoya.http.message.requests.HttpRequest;
public interface RequestToBeSentAction {
    static RequestToBeSentAction continueWith(HttpRequest request) {
        return new RequestToBeSentAction(){};
    }
}