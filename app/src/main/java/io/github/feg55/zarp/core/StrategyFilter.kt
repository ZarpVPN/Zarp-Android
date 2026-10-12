package io.github.feg55.zarp.core

object StrategyFilter {
    val countries = listOf("all", "ru", "ir", "cn")

    fun selected(value: String): Set<String> =
        if (value == "all") emptySet() else value.split(',').filter { it in countries && it != "all" }.toSet()

    fun toggle(value: String, country: String): String {
        if (country == "all") return "all"
        val current = selected(value)
        val next = if (country in current) current - country else current + country
        return countries.filter { it in next }.joinToString(",").ifEmpty { "all" }
    }

    fun matches(strategy: Strategy, country: String): Boolean {
        val selected = selected(country)
        return selected.isEmpty() ||
            (strategy.usesDesync && strategy.countries.any { it in selected })
    }

    fun apply(strategies: List<Strategy>, country: String): List<Strategy> =
        strategies.filter { matches(it, country) }
}
