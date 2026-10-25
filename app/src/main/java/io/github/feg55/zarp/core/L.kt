package io.github.feg55.zarp.core

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.InputStream
import java.util.Locale

/**
 * UI strings, port of Zarp's L.cs: one `key = value` file per language in
 * assets/lang, English is the reference. Follows the system language unless the
 * user picked one with the globe button.
 */
object L {
    data class Language(val code: String, val nativeName: String)

    val languages = listOf(
        Language("en", "English"),
        Language("ru", "Русский"),
        Language("es", "Español"),
        Language("pt", "Português"),
        Language("zh", "中文"),
        Language("hi", "हिन्दी"),
        Language("fr", "Français"),
        Language("de", "Deutsch"),
        Language("fa", "فارسی"),
    )

    private var open: ((String) -> InputStream)? = null
    private val tables = HashMap<String, Map<String, String>>()

    /** Language the user picked; null follows the system. */
    @Volatile
    var setting: String? = null
        private set

    @Volatile
    var systemLanguage: String = "en"
        private set

    private val _current = MutableStateFlow("en")

    /** Language in use; the UI recomposes when it changes. */
    val current: StateFlow<String> = _current.asStateFlow()

    fun init(open: (String) -> InputStream, setting: String?, systemLocale: Locale = Locale.getDefault()) {
        this.open = open
        tables.clear()
        systemLanguage = supportedOrEnglish(systemLocale.language)
        this.setting = setting?.takeIf { isSupported(it) }
        _current.value = this.setting ?: systemLanguage
    }

    fun isSupported(code: String?): Boolean = code != null && languages.any { it.code == code }
    fun isRtl(code: String): Boolean = code == "fa"

    fun supportedOrEnglish(code: String?): String = if (isSupported(code)) code!! else "en"

    /** null returns to the system language. */
    fun setLanguage(code: String?) {
        setting = code?.takeIf { isSupported(it) }
        _current.value = setting ?: systemLanguage
    }

    fun onSystemLocaleChanged(locale: Locale) {
        systemLanguage = supportedOrEnglish(locale.language)
        if (setting == null) _current.value = systemLanguage
    }

    fun t(key: String, vararg args: Any?): String = tIn(_current.value, key, *args)

    fun tIn(language: String, key: String, vararg args: Any?): String {
        val text = table(language)[key] ?: table("en")[key] ?: return key
        return format(text, args.map { it?.toString().orEmpty() })
    }

    /** Keys of a language file, for tests. */
    fun keys(language: String): Set<String> = table(language).keys

    fun raw(language: String, key: String): String? = table(language)[key]

    @Synchronized
    private fun table(language: String): Map<String, String> = tables.getOrPut(language) {
        val o = open ?: return@getOrPut emptyMap()
        runCatching { o("lang/$language.txt").use { parse(it.readBytes().toString(Charsets.UTF_8)) } }.getOrDefault(emptyMap())
    }

    fun parse(text: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for (raw in text.lines()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val i = line.indexOf('=')
            if (i <= 0) continue
            out[line.substring(0, i).trim()] = line.substring(i + 1).trim().replace("\\n", "\n")
        }
        return out
    }

    /** .NET-style {0}, {1}... placeholders, as in Zarp's language files. */
    fun format(text: String, args: List<String>): String {
        if (args.isEmpty()) return text
        val sb = StringBuilder(text.length + 16)
        var i = 0
        while (i < text.length) {
            val c = text[i]
            if (c == '{') {
                val end = text.indexOf('}', i + 1)
                val n = if (end > i) text.substring(i + 1, end).toIntOrNull() else null
                if (n != null && n in args.indices) {
                    sb.append(args[n])
                    i = end + 1
                    continue
                }
            }
            sb.append(c)
            i++
        }
        return sb.toString()
    }

    /** Placeholders used in a string, for the consistency test. */
    fun placeholders(text: String): Set<Int> =
        Regex("\\{(\\d+)}").findAll(text).map { it.groupValues[1].toInt() }.toSet()
}

/** A string to be shown in the current language when it is displayed. */
data class Msg(val key: String, val args: List<String>) {
    constructor(key: String, vararg args: Any?) : this(key, args.map { it?.toString().orEmpty() })

    override fun toString(): String = L.t(key, *args.toTypedArray())
}
