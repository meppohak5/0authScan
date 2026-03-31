package burp.api.montoya.ui;
import burp.api.montoya.core.Registration;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import java.awt.Component;
public interface UserInterface {
    Registration registerContextMenuItemsProvider(ContextMenuItemsProvider provider);
    Registration registerSuiteTab(String caption, Component component);
}
