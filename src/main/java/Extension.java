import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import twofactor.AccountStore;
import twofactor.ui.TwoFactorContextMenuProvider;
import twofactor.ui.TwoFactorTab;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 2FA Code Generator - generates TOTP/HOTP codes in Burp Suite.
 *
 * Accounts can be registered from {@code otpauth://} URIs, QR code images
 * (file or clipboard), Google Authenticator migration payloads, or directly
 * from provisioning data found in HTTP responses.
 */
public class Extension implements BurpExtension
{
    private AccountStore store;
    private ExecutorService worker;
    private TwoFactorTab tab;
    private Registration tabRegistration;
    private Registration contextMenuRegistration;

    @Override
    public void initialize(MontoyaApi montoyaApi)
    {
        montoyaApi.extension().setName("OTP Manager");

        worker = Executors.newSingleThreadExecutor(runnable ->
        {
            Thread thread = new Thread(runnable, "2fa-code-generator-worker");
            thread.setDaemon(true);
            return thread;
        });

        store = new AccountStore(montoyaApi);

        try
        {
            store.load();
        }
        catch (RuntimeException e)
        {
            montoyaApi.logging().logToError("Could not load stored 2FA accounts: " + e.getMessage());
        }

        tab = new TwoFactorTab(montoyaApi, store, worker);
        TwoFactorContextMenuProvider contextMenuProvider = new TwoFactorContextMenuProvider(tab);

        tabRegistration = montoyaApi.userInterface().registerSuiteTab("OTP Manager", tab);
        contextMenuRegistration = montoyaApi.userInterface().registerContextMenuItemsProvider(contextMenuProvider);

        montoyaApi.extension().registerUnloadingHandler(this::unload);

        montoyaApi.logging().logToOutput("2FA Code Generator loaded. "
                + store.size() + " account(s) available. Use the '2FA Codes' suite tab to add more.");
    }

    private void unload()
    {
        try
        {
            if (tab != null)
            {
                tab.dispose();
            }
        }
        catch (RuntimeException ignored)
        {
            // Best effort during unload.
        }

        deregister(tabRegistration);
        deregister(contextMenuRegistration);

        if (worker != null)
        {
            worker.shutdownNow();
        }
    }

    private static void deregister(Registration registration)
    {
        if (registration == null)
        {
            return;
        }

        try
        {
            if (registration.isRegistered())
            {
                registration.deregister();
            }
        }
        catch (RuntimeException ignored)
        {
            // Best effort during unload.
        }
    }
}
