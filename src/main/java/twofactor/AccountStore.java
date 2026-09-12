package twofactor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe registry of registered accounts.
 *
 * <p>Accounts are persisted in Burp's project-scoped extension data so they
 * survive project save/load and extension reload. Secrets are stored in
 * plaintext (Burp does not offer an encrypted store), which is why persistence
 * can be switched off entirely via {@link #setPersistenceEnabled(boolean)}.</p>
 */
public final class AccountStore
{
    private static final String ACCOUNT_KEY_PREFIX = "twofactor.account.";
    private static final String PREFERENCE_PERSIST = "twofactor.persist";

    private final MontoyaApi api;
    private final List<TwoFactorAccount> accounts = new ArrayList<>();
    private final List<Runnable> changeListeners = new CopyOnWriteArrayList<>();

    private boolean persistenceEnabled = true;

    public AccountStore(MontoyaApi api)
    {
        this.api = api;
    }

    public synchronized void load()
    {
        Boolean preference = api.persistence().preferences().getBoolean(PREFERENCE_PERSIST);
        persistenceEnabled = preference == null || preference;

        accounts.clear();

        if (!persistenceEnabled)
        {
            return;
        }

        PersistedObject data = api.persistence().extensionData();

        for (String key : Set.copyOf(data.childObjectKeys()))
        {
            if (!key.startsWith(ACCOUNT_KEY_PREFIX))
            {
                continue;
            }

            PersistedObject child = data.getChildObject(key);

            if (child == null)
            {
                continue;
            }

            try
            {
                TwoFactorAccount parsed = read(child, key.substring(ACCOUNT_KEY_PREFIX.length()));
                accounts.add(parsed);

                if (!key.equals(ACCOUNT_KEY_PREFIX + parsed.id()))
                {
                    // Legacy/renamed key - normalise it.
                    accounts.remove(parsed);
                    data.deleteChildObject(key);
                    data.setChildObject(ACCOUNT_KEY_PREFIX + parsed.id(), write(parsed));
                    accounts.add(parsed);
                }
            }
            catch (RuntimeException e)
            {
                api.logging().logToError("Skipping unreadable stored 2FA account '" + key + "': " + e.getMessage());
                data.deleteChildObject(key);
            }
        }
    }

    /**
     * Merges incoming accounts into the store.
     *
     * <p>New accounts are added. Accounts that already exist (same secret and
     * parameters) are skipped, except for HOTP accounts where the incoming
     * counter is higher - the counter is then advanced, which lets team members
     * hand over in-progress HOTP testing.</p>
     */
    public synchronized MergeResult merge(List<TwoFactorAccount> incoming)
    {
        int added = 0;
        int updated = 0;
        int skipped = 0;
        boolean changed = false;

        for (TwoFactorAccount candidate : incoming)
        {
            if (candidate == null)
            {
                continue;
            }

            TwoFactorAccount existing = findDuplicate(candidate);

            if (existing == null)
            {
                accounts.add(candidate);
                added++;
                changed = true;
            }
            else if (existing.type() == OtpType.HOTP
                    && candidate.type() == OtpType.HOTP
                    && candidate.counter() > existing.counter())
            {
                existing.setCounter(candidate.counter());
                save(existing);
                updated++;
                changed = true;
            }
            else
            {
                skipped++;
            }
        }

        if (added > 0)
        {
            save();
        }

        if (changed)
        {
            notifyChanged();
        }

        return new MergeResult(added, updated, skipped);
    }

    public synchronized void remove(TwoFactorAccount account)
    {
        if (accounts.remove(account))
        {
            delete(account);
            notifyChanged();
        }
    }

    public synchronized void clear()
    {
        if (accounts.isEmpty())
        {
            return;
        }

        accounts.clear();
        deleteAll();
        notifyChanged();
    }

    public synchronized List<TwoFactorAccount> accounts()
    {
        return new ArrayList<>(accounts);
    }

    public synchronized int size()
    {
        return accounts.size();
    }

    /**
     * Persists a change to an individual account (for example an incremented
     * HOTP counter or an edited label).
     */
    public synchronized void accountUpdated(TwoFactorAccount account)
    {
        save(account);
        notifyChanged();
    }

    public synchronized boolean isPersistenceEnabled()
    {
        return persistenceEnabled;
    }

    public synchronized void setPersistenceEnabled(boolean enabled)
    {
        if (persistenceEnabled == enabled)
        {
            return;
        }

        persistenceEnabled = enabled;
        api.persistence().preferences().setBoolean(PREFERENCE_PERSIST, enabled);

        if (enabled)
        {
            save();
        }
        else
        {
            deleteAll();
        }

        notifyChanged();
    }

    public void addChangeListener(Runnable listener)
    {
        changeListeners.add(listener);
    }

    private TwoFactorAccount findDuplicate(TwoFactorAccount candidate)
    {
        for (TwoFactorAccount existing : accounts)
        {
            if (existing.isDuplicateOf(candidate))
            {
                return existing;
            }
        }

        return null;
    }

    private void notifyChanged()
    {
        for (Runnable listener : changeListeners)
        {
            listener.run();
        }
    }

    private void save()
    {
        if (!persistenceEnabled)
        {
            return;
        }

        for (TwoFactorAccount account : accounts)
        {
            save(account);
        }
    }

    private void save(TwoFactorAccount account)
    {
        if (!persistenceEnabled)
        {
            return;
        }

        try
        {
            api.persistence().extensionData().setChildObject(ACCOUNT_KEY_PREFIX + account.id(), write(account));
        }
        catch (RuntimeException e)
        {
            api.logging().logToError("Unable to persist 2FA account: " + e.getMessage());
        }
    }

    private void delete(TwoFactorAccount account)
    {
        try
        {
            api.persistence().extensionData().deleteChildObject(ACCOUNT_KEY_PREFIX + account.id());
        }
        catch (RuntimeException e)
        {
            api.logging().logToError("Unable to remove stored 2FA account: " + e.getMessage());
        }
    }

    private void deleteAll()
    {
        PersistedObject data = api.persistence().extensionData();

        for (String key : Set.copyOf(data.childObjectKeys()))
        {
            if (key.startsWith(ACCOUNT_KEY_PREFIX))
            {
                data.deleteChildObject(key);
            }
        }
    }

    private static PersistedObject write(TwoFactorAccount account)
    {
        PersistedObject child = PersistedObject.persistedObject();
        child.setString("id", account.id());
        child.setString("issuer", account.issuer());
        child.setString("account", account.account());
        child.setString("secret", account.secret());
        child.setString("type", account.type().name());
        child.setString("algorithm", account.algorithm().name());
        child.setInteger("digits", account.digits());
        child.setLong("period", account.period());
        child.setLong("counter", account.counter());
        child.setLong("createdAt", account.createdAt());
        return child;
    }

    private static TwoFactorAccount read(PersistedObject child, String fallbackId)
    {
        String id = orEmpty(child.getString("id"));
        String issuer = orEmpty(child.getString("issuer"));
        String account = orEmpty(child.getString("account"));
        String secret = orEmpty(child.getString("secret"));

        if (secret.isEmpty())
        {
            throw new IllegalArgumentException("missing secret");
        }

        OtpType type = OtpType.parse(orEmpty(child.getString("type")));
        OtpAlgorithm algorithm = OtpAlgorithm.parse(orEmpty(child.getString("algorithm")));

        Integer digits = child.getInteger("digits");
        Long period = child.getLong("period");
        Long counter = child.getLong("counter");
        Long createdAt = child.getLong("createdAt");

        return new TwoFactorAccount(
                id.isEmpty() ? fallbackId : id,
                issuer,
                account,
                secret,
                type == null ? OtpType.TOTP : type,
                algorithm == null ? OtpAlgorithm.SHA1 : algorithm,
                digits == null ? OtpCodeGenerator.DEFAULT_DIGITS : digits,
                period == null ? OtpCodeGenerator.DEFAULT_PERIOD : period,
                counter == null ? 0L : counter,
                createdAt == null ? 0L : createdAt);
    }

    private static String orEmpty(String value)
    {
        return value == null ? "" : value;
    }

    public record MergeResult(int added, int updated, int skipped)
    {
    }
}
