package twofactor;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonTest
{
    @Test
    void parsesObjectsArraysAndScalars()
    {
        Object parsed = Json.parse("{\"a\": 1, \"b\": [true, false, null], \"c\": \"x\", \"d\": 1.5}");

        Map<String, Object> object = Json.asObject(parsed, "root");
        assertEquals(1L, object.get("a"));
        assertEquals("x", object.get("c"));
        assertEquals(1.5, object.get("d"));
        assertInstanceOf(List.class, object.get("b"));

        List<Object> array = Json.asArray(object.get("b"), "b");
        assertEquals(Boolean.TRUE, array.get(0));
        assertEquals(Boolean.FALSE, array.get(1));
        assertNull(array.get(2));
    }

    @Test
    void handlesEscapesAndUnicode()
    {
        Object parsed = Json.parse("{\"text\": \"quote:\\\" slash:\\\\ newline:\\n tab:\\t unicode:\\u0041 emoji:\\ud83d\\ude00\"}");
        String text = Json.optString(Json.asObject(parsed, "root"), "text", "");

        assertTrue(text.contains("quote:\""));
        assertTrue(text.contains("slash:\\"));
        assertTrue(text.contains("newline:\n"));
        assertTrue(text.contains("tab:\t"));
        assertTrue(text.contains("unicode:A"));
        assertTrue(text.contains("\uD83D\uDE00"));
    }

    @Test
    void escapesForOutput()
    {
        String escaped = Json.escape("a\"b\\c\nd\te\u0001");

        assertEquals("a\\\"b\\\\c\\nd\\te\\u0001", escaped);
        // Round-trip through the parser.
        Object parsed = Json.parse("{\"v\": \"" + escaped + "\"}");
        assertEquals("a\"b\\c\nd\te\u0001", Json.optString(Json.asObject(parsed, "root"), "v", null));
    }

    @Test
    void readsOptionalsWithDefaults()
    {
        Map<String, Object> object = Json.asObject(Json.parse("{\"s\": \"v\", \"n\": 7, \"b\": true}"), "root");

        assertEquals("v", Json.optString(object, "s", "fallback"));
        assertEquals("fallback", Json.optString(object, "missing", "fallback"));
        assertEquals(7L, Json.optLong(object, "n", -1));
        assertEquals(-1L, Json.optLong(object, "missing", -1));
        assertTrue(Json.optBoolean(object, "b", false));
        assertFalse(Json.optBoolean(object, "missing", false));
    }

    @Test
    void rejectsMalformedInput()
    {
        assertThrows(IllegalArgumentException.class, () -> Json.parse("{"));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("{\"a\": }"));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("{\"a\": 1,}"));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("[1, 2"));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("{} trailing"));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("\"unterminated"));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("nul"));
        assertThrows(IllegalArgumentException.class, () -> Json.parse(""));
        assertThrows(IllegalArgumentException.class, () -> Json.parse(null));
    }

    @Test
    void rejectsExcessiveNesting()
    {
        String deep = "[".repeat(200) + "]".repeat(200);
        assertThrows(IllegalArgumentException.class, () -> Json.parse(deep));
    }

    @Test
    void asObjectAndArrayValidateTypes()
    {
        assertThrows(IllegalArgumentException.class, () -> Json.asObject(Json.parse("[]"), "x"));
        assertThrows(IllegalArgumentException.class, () -> Json.asArray(Json.parse("{}"), "x"));
    }
}
