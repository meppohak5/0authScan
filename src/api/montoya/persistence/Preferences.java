package burp.api.montoya.persistence;
public interface Preferences {
    String getString(String key);
    void setString(String key, String value);
    Boolean getBoolean(String key);
    void setBoolean(String key, boolean value);
}