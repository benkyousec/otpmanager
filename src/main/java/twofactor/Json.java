package twofactor;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON reader/writer used for the import/export format.
 *
 * <p>Deliberately self-contained rather than using Burp's JSON DOM: it keeps
 * the transfer format unit-testable without a Burp runtime, and the parser is
 * hardened against hostile input (bounded nesting depth, strict syntax).</p>
 */
final class Json
{
    private static final int MAX_DEPTH = 100;

    private Json()
    {
    }

    public static Object parse(String text)
    {
        if (text == null)
        {
            throw new IllegalArgumentException("JSON is null");
        }

        Parser parser = new Parser(text);
        return parser.parseDocument();
    }

    public static String escape(String value)
    {
        if (value == null)
        {
            return "";
        }

        StringBuilder builder = new StringBuilder(value.length() + 2);

        for (int i = 0; i < value.length(); i++)
        {
            char c = value.charAt(i);

            switch (c)
            {
                case '"' -> builder.append("\\\"");
                case '\\' -> builder.append("\\\\");
                case '\n' -> builder.append("\\n");
                case '\r' -> builder.append("\\r");
                case '\t' -> builder.append("\\t");
                case '\b' -> builder.append("\\b");
                case '\f' -> builder.append("\\f");
                default ->
                {
                    if (c < 0x20)
                    {
                        builder.append(String.format("\\u%04x", (int) c));
                    }
                    else
                    {
                        builder.append(c);
                    }
                }
            }
        }

        return builder.toString();
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asObject(Object node, String context)
    {
        if (node instanceof Map<?, ?> map)
        {
            return (Map<String, Object>) map;
        }

        throw new IllegalArgumentException(context + " is not a JSON object");
    }

    public static List<Object> asArray(Object node, String context)
    {
        if (node instanceof List<?> list)
        {
            return new ArrayList<>(list);
        }

        throw new IllegalArgumentException(context + " is not a JSON array");
    }

    public static String optString(Map<String, Object> object, String key, String fallback)
    {
        Object value = object.get(key);
        return value instanceof String string ? string : fallback;
    }

    public static long optLong(Map<String, Object> object, String key, long fallback)
    {
        Object value = object.get(key);

        if (value instanceof Number number)
        {
            return number.longValue();
        }

        return fallback;
    }

    public static boolean optBoolean(Map<String, Object> object, String key, boolean fallback)
    {
        Object value = object.get(key);

        if (value instanceof Boolean bool)
        {
            return bool;
        }

        return fallback;
    }

    private static final class Parser
    {
        private final String text;
        private int position;
        private int depth;

        private Parser(String text)
        {
            this.text = text;
        }

        private Object parseDocument()
        {
            skipWhitespace();
            Object value = parseValue();
            skipWhitespace();

            if (position != text.length())
            {
                throw error("Unexpected trailing content");
            }

            return value;
        }

        private Object parseValue()
        {
            if (depth > MAX_DEPTH)
            {
                throw error("Maximum nesting depth exceeded");
            }

            char c = peek();

            return switch (c)
            {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> parseString();
                case 't' -> parseKeyword("true", Boolean.TRUE);
                case 'f' -> parseKeyword("false", Boolean.FALSE);
                case 'n' -> parseKeyword("null", null);
                default -> parseNumber();
            };
        }

        private Map<String, Object> parseObject()
        {
            depth++;
            Map<String, Object> object = new LinkedHashMap<>();
            position++;
            skipWhitespace();

            if (peek() == '}')
            {
                position++;
                depth--;
                return object;
            }

            while (true)
            {
                skipWhitespace();

                if (peek() != '"')
                {
                    throw error("Expected a property name");
                }

                String key = parseString();
                skipWhitespace();

                if (peek() != ':')
                {
                    throw error("Expected ':'");
                }

                position++;
                skipWhitespace();
                object.put(key, parseValue());
                skipWhitespace();

                char c = peek();

                if (c == ',')
                {
                    position++;
                    continue;
                }

                if (c == '}')
                {
                    position++;
                    break;
                }

                throw error("Expected ',' or '}'");
            }

            depth--;
            return object;
        }

        private List<Object> parseArray()
        {
            depth++;
            List<Object> list = new ArrayList<>();
            position++;
            skipWhitespace();

            if (peek() == ']')
            {
                position++;
                depth--;
                return list;
            }

            while (true)
            {
                skipWhitespace();
                list.add(parseValue());
                skipWhitespace();

                char c = peek();

                if (c == ',')
                {
                    position++;
                    continue;
                }

                if (c == ']')
                {
                    position++;
                    break;
                }

                throw error("Expected ',' or ']'");
            }

            depth--;
            return list;
        }

        private String parseString()
        {
            position++;
            StringBuilder builder = new StringBuilder();

            while (true)
            {
                if (position >= text.length())
                {
                    throw error("Unterminated string");
                }

                char c = text.charAt(position++);

                if (c == '"')
                {
                    return builder.toString();
                }

                if (c != '\\')
                {
                    if (c < 0x20)
                    {
                        throw error("Unescaped control character in string");
                    }

                    builder.append(c);
                    continue;
                }

                if (position >= text.length())
                {
                    throw error("Unterminated escape sequence");
                }

                char escape = text.charAt(position++);

                switch (escape)
                {
                    case '"' -> builder.append('"');
                    case '\\' -> builder.append('\\');
                    case '/' -> builder.append('/');
                    case 'b' -> builder.append('\b');
                    case 'f' -> builder.append('\f');
                    case 'n' -> builder.append('\n');
                    case 'r' -> builder.append('\r');
                    case 't' -> builder.append('\t');
                    case 'u' ->
                    {
                        if (position + 4 > text.length())
                        {
                            throw error("Invalid unicode escape");
                        }

                        String hex = text.substring(position, position + 4);

                        try
                        {
                            builder.append((char) Integer.parseInt(hex, 16));
                        }
                        catch (NumberFormatException e)
                        {
                            throw error("Invalid unicode escape '" + hex + "'");
                        }

                        position += 4;
                    }
                    default -> throw error("Invalid escape '\\" + escape + "'");
                }
            }
        }

        private Object parseNumber()
        {
            int start = position;

            if (peek() == '-')
            {
                position++;
            }

            boolean floatingPoint = false;

            while (position < text.length())
            {
                char c = text.charAt(position);

                if (c >= '0' && c <= '9')
                {
                    position++;
                }
                else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-')
                {
                    floatingPoint = true;
                    position++;
                }
                else
                {
                    break;
                }
            }

            String number = text.substring(start, position);

            if (number.isEmpty() || number.equals("-"))
            {
                throw error("Invalid number");
            }

            if (floatingPoint)
            {
                try
                {
                    return Double.valueOf(number);
                }
                catch (NumberFormatException ignored)
                {
                    throw error("Invalid number '" + number + "'");
                }
            }

            try
            {
                return Long.valueOf(number);
            }
            catch (NumberFormatException e)
            {
                try
                {
                    return Double.valueOf(number);
                }
                catch (NumberFormatException ignored)
                {
                    throw error("Invalid number '" + number + "'");
                }
            }
        }

        private Object parseKeyword(String keyword, Object value)
        {
            if (!text.startsWith(keyword, position))
            {
                throw error("Invalid literal");
            }

            position += keyword.length();
            return value;
        }

        private char peek()
        {
            if (position >= text.length())
            {
                throw error("Unexpected end of input");
            }

            return text.charAt(position);
        }

        private void skipWhitespace()
        {
            while (position < text.length() && Character.isWhitespace(text.charAt(position)))
            {
                position++;
            }
        }

        private IllegalArgumentException error(String message)
        {
            return new IllegalArgumentException("Invalid JSON at position " + position + ": " + message);
        }
    }
}
