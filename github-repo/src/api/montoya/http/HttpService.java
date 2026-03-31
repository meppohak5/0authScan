package burp.api.montoya.http;
public interface HttpService {
    String host();
    int port();
    boolean secure();
    static HttpService httpService(String host, int port, boolean secure) {
        return new HttpService() {
            public String host() { return host; }
            public int port() { return port; }
            public boolean secure() { return secure; }
        };
    }
}