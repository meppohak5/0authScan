package burp.api.montoya.http.handler;

import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Real Montoya API does NOT expose initiatingRequest() on HttpResponseReceived.
 * The correct way to access the originating request is via the HttpRequestResponse
 * object provided to the HTTP handler pair. We keep this interface clean.
 */
public interface HttpResponseReceived extends HttpResponse {
    // No initiatingRequest() — access request via HttpRequestResponse wrapper
}
