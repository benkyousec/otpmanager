package twofactor.ui;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Adds "Register 2FA codes from response" to Burp's context menus. Building the
 * menu item is cheap; the actual scanning happens on a background thread.
 */
public final class TwoFactorContextMenuProvider implements ContextMenuItemsProvider
{
    private final TwoFactorTab tab;

    public TwoFactorContextMenuProvider(TwoFactorTab tab)
    {
        this.tab = tab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        List<HttpRequestResponse> candidates = new ArrayList<>();

        Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();

        if (editor.isPresent() && editor.get().requestResponse().hasResponse())
        {
            candidates.add(editor.get().requestResponse());
        }

        for (HttpRequestResponse requestResponse : event.selectedRequestResponses())
        {
            if (requestResponse != null && requestResponse.hasResponse() && !candidates.contains(requestResponse))
            {
                candidates.add(requestResponse);
            }
        }

        if (candidates.isEmpty())
        {
            return List.of();
        }

        JMenuItem item = new JMenuItem("Register 2FA codes from response");
        item.addActionListener(e -> tab.offerFromResponses(candidates));
        return List.of(item);
    }
}
