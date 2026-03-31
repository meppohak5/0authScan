package burp.api.montoya.http.message;
public interface HttpHeader {
    String name();
    String value();
    static HttpHeader httpHeader(String name, String value) {
        return new HttpHeader() {
            public String name() { return name; }
            public String value() { return value; }
        };
    }
}