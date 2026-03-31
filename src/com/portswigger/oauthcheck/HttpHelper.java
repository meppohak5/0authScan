package com.portswigger.oauthcheck;

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Lightweight HTTP helper used by all OAuth checks.
 * Makes raw GET / POST requests without going through Burp's Http API
 * so that probes are sent regardless of Burp's scope settings.
 */
public class HttpHelper {

    public static class Response {
        public final int    statusCode;
        public final Map<String, String> headers;
        public final String body;
        public final String rawRequest;

        public Response(int statusCode, Map<String, String> headers,
                        String body, String rawRequest) {
            this.statusCode = statusCode;
            this.headers    = headers;
            this.body       = body;
            this.rawRequest = rawRequest;
        }

        public boolean hasHeader(String name) {
            return headers.containsKey(name.toLowerCase());
        }
        public String getHeader(String name) {
            return headers.getOrDefault(name.toLowerCase(), "");
        }
        @Override public String toString() {
            return "HTTP " + statusCode + "\n" + body.substring(0, Math.min(body.length(), 500));
        }
    }

    private static final int TIMEOUT_MS = 8000;

    /** Trust-all SSL context (we are a security testing tool). */
    private static SSLSocketFactory trustAllFactory() {
        try {
            TrustManager[] tm = new TrustManager[]{ new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
            }};
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tm, new SecureRandom());
            return ctx.getSocketFactory();
        } catch (Exception e) {
            return (SSLSocketFactory) SSLSocketFactory.getDefault();
        }
    }

    public static Response get(String urlStr) throws Exception {
        return get(urlStr, Collections.emptyMap());
    }

    public static Response get(String urlStr, Map<String,String> extraHeaders) throws Exception {
        return send("GET", urlStr, null, extraHeaders);
    }

    public static Response post(String urlStr, String body,
                                Map<String,String> extraHeaders) throws Exception {
        return send("POST", urlStr, body, extraHeaders);
    }

    private static Response send(String method, String urlStr, String body,
                                  Map<String,String> extraHeaders) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn;
        if ("https".equalsIgnoreCase(url.getProtocol())) {
            HttpsURLConnection https =
                (HttpsURLConnection) url.openConnection();
            https.setSSLSocketFactory(trustAllFactory());
            https.setHostnameVerifier((h, s) -> true);
            conn = https;
        } else {
            conn = (HttpURLConnection) url.openConnection();
        }
        conn.setRequestMethod(method);
        conn.setConnectTimeout(TIMEOUT_MS);
        conn.setReadTimeout(TIMEOUT_MS);
        conn.setInstanceFollowRedirects(false);
        conn.setRequestProperty("User-Agent", "OAuthCheck-BurpExtension/1.0");
        conn.setRequestProperty("Accept", "application/json, text/html, */*");
        for (Map.Entry<String,String> h : extraHeaders.entrySet())
            conn.setRequestProperty(h.getKey(), h.getValue());

        if (body != null) {
            conn.setDoOutput(true);
            byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
            conn.setRequestProperty("Content-Length", String.valueOf(bodyBytes.length));
            try (OutputStream os = conn.getOutputStream()) {
                os.write(bodyBytes);
            }
        }

        // Build raw request string for evidence
        StringBuilder rawReq = new StringBuilder();
        rawReq.append(method).append(" ").append(url.getFile()).append(" HTTP/1.1\r\n");
        rawReq.append("Host: ").append(url.getHost()).append("\r\n");
        conn.getRequestProperties().forEach((k, v) ->
            rawReq.append(k).append(": ").append(String.join(", ", v)).append("\r\n"));
        rawReq.append("\r\n");
        if (body != null) rawReq.append(body);

        int status;
        try { status = conn.getResponseCode(); }
        catch (IOException e) { status = -1; }

        Map<String,String> respHeaders = new LinkedHashMap<>();
        conn.getHeaderFields().forEach((k, v) -> {
            if (k != null) respHeaders.put(k.toLowerCase(), String.join(", ", v));
        });

        InputStream is;
        try { is = conn.getInputStream(); }
        catch (IOException e) { is = conn.getErrorStream(); }
        String respBody = "";
        if (is != null) {
            try (BufferedReader br =
                     new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) sb.append(line).append("\n");
                respBody = sb.toString();
            }
        }
        conn.disconnect();
        return new Response(status, respHeaders, respBody, rawReq.toString());
    }

    /** Extract base URL (scheme://host[:port]) from a full URL string. */
    public static String baseUrl(String urlStr) {
        try {
            URL u = new URL(urlStr);
            int port = u.getPort();
            return u.getProtocol() + "://" + u.getHost()
                   + (port > 0 ? ":" + port : "");
        } catch (Exception e) {
            return urlStr;
        }
    }

    /** Append a query parameter to a URL. */
    public static String addParam(String url, String key, String value) {
        String sep = url.contains("?") ? "&" : "?";
        try {
            return url + sep + key + "=" + URLEncoder.encode(value, "UTF-8");
        } catch (Exception e) {
            return url + sep + key + "=" + value;
        }
    }

    /** Replace the value of a query parameter in a URL. */
    public static String replaceParam(String url, String key, String newValue) {
        try {
            String encoded = URLEncoder.encode(newValue, "UTF-8");
            // Replace existing value if present
            String result = url.replaceAll(
                "([?&]" + Pattern.quote(key) + "=)[^&]*",
                "$1" + encoded.replace("\\", "\\\\").replace("$", "\\$"));
            if (result.equals(url)) {
                // Parameter not present; add it
                result = addParam(url, key, newValue);
            }
            return result;
        } catch (Exception e) {
            return url;
        }
    }

    /** Extract a query-param value from a URL. */
    public static String getParam(String url, String key) {
        try {
            String query = new URL(url).getQuery();
            if (query == null) return null;
            for (String pair : query.split("&")) {
                String[] kv = pair.split("=", 2);
                if (kv[0].equals(key)) return kv.length > 1 ? URLDecoder.decode(kv[1], "UTF-8") : "";
            }
        } catch (Exception ignored) {}
        return null;
    }
}
