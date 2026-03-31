package burp.api.montoya.ui.contextmenu;
import java.util.List;
import javax.swing.JMenuItem;
public interface ContextMenuItemsProvider {
    List<JMenuItem> provideMenuItems(ContextMenuEvent event);
}