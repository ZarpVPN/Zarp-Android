package io.github.feg55.zarp.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Locale

class LangTest {
    @Before
    fun setUp() = TestLang.english()

    @Test
    fun `every language has the same keys and placeholders as English`() {
        val en = L.keys("en")
        assertTrue(en.size > 100)
        for (lang in L.languages.map { it.code }) {
            assertEquals("keys of $lang", en, L.keys(lang))
            for (key in en) {
                val value = L.raw(lang, key)!!
                assertEquals("placeholders of $lang/$key", L.placeholders(L.raw("en", key)!!), L.placeholders(value))
                assertTrue("$lang/$key is empty", value.isNotBlank())
                assertFalse("$lang/$key has an em dash", value.contains('\u2014'))
                assertFalse("$lang/$key has an en dash", value.contains('\u2013'))
            }
        }
    }

    @Test
    fun `follows the system language, English when unsupported`() {
        L.init(open = { java.io.File("src/main/assets", it).inputStream() }, setting = null, systemLocale = Locale.forLanguageTag("ru-RU"))
        assertEquals("ru", L.current.value)
        assertEquals("Подключено", L.t("status.connected"))
        L.init(open = { java.io.File("src/main/assets", it).inputStream() }, setting = null, systemLocale = Locale.forLanguageTag("ja-JP"))
        assertEquals("en", L.current.value)
        L.setLanguage("zh")
        assertEquals("zh", L.current.value)
        L.setLanguage(null)
        assertEquals("en", L.current.value)
    }

    @Test
    fun `formats placeholders like Zarp`() {
        assertEquals("✔ A: connection 10 ms, ping 20 ms", L.t("log.testOk", "A", 10, 20))
        assertEquals("a {5} b", L.format("a {5} b", listOf("x")))
        // language files write a line break as backslash + n
        assertEquals("line\nbreak", L.parse("k = line" + '\\' + "nbreak")["k"])
        assertEquals("missing.key", L.t("missing.key"))
    }

    @Test fun `Persian follows system locale and switches direction with the language`() {
        L.init(open = { java.io.File("src/main/assets", it).inputStream() }, setting = null, systemLocale = Locale.forLanguageTag("fa-IR"))
        assertEquals("fa", L.current.value)
        assertTrue(L.isRtl(L.current.value))
        assertEquals("تنظیمات", L.t("tab.settings"))
        L.setLanguage("ru")
        assertFalse(L.isRtl(L.current.value))
    }

    @Test
    fun `direct strategies are translated, technical names are not`() {
        L.setLanguage("de")
        val direct = StrategyCatalog.builtIn.single { it.id == StrategyCatalog.DIRECT_ID }
        assertEquals("Direkt (ohne Umgehung)", direct.name)
        assertEquals("WARP QUIC: fake google ×6", StrategyCatalog.builtIn.first().name)
    }
}
