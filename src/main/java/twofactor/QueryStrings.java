package twofactor;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Lenient {@code application/x-www-form-urlencoded} query parsing. Keys are
 * lower-cased; the first occurrence of a key wins. Malformed pairs are skipped
 * rather than throwing, because provisioning URIs are frequently hand-edited.
 */
final class QueryStrings
{
    private QueryStrings()
    {
    }

    static Map<String, String> parse(String query)
    {
        Map<String, String> values = new LinkedHashMap<>();

        if (query == null || query.isEmpty())
        {
            return values;
        }

        for (String pair : query.split("&"))
        {
            if (pair.isEmpty())
            {
                continue;
            }

            int separator = pair.indexOf('=');
            String rawKey = separator >= 0 ? pair.substring(0, separator) : pair;
            String rawValue = separator >= 0 ? pair.substring(separator + 1) : "";

            String key = decode(rawKey).trim().toLowerCase();

            if (key.isEmpty() || values.containsKey(key))
            {
                continue;
            }

            values.put(key, decode(rawValue));
        }

        return values;
    }

    static String decode(String value)
    {
        if (value == null)
        {
            return "";
        }

        try
        {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        }
        catch (IllegalArgumentException e)
        {
            // Invalid percent-encoding (common in hand-edited URIs) - return raw.
            return value;
        }
    }
}
