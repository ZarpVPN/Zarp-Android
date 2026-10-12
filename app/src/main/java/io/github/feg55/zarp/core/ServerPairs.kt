package io.github.feg55.zarp.core

/** Strategy first, then every compatible server, exactly as in the desktop scan. */
object ServerPairs {
    fun compatible(strategy: Strategy, server: ProxyProfile): Boolean =
        strategy.profile == null && strategy.usesDesync && strategy.supported &&
            strategy.transport == server.outerTransport && (server.outerTransport == Transport.MasqueH3 || server.hasTls)

    fun build(strategies: List<Strategy>, servers: List<ProxyProfile>, allowPlain: Boolean = false): List<Strategy> {
        val names = names(servers)
        val pairs = strategies.flatMap { strategy ->
            servers.mapIndexedNotNull { index, server ->
                if (!compatible(strategy, server)) null else strategy.copy(
                    id = strategy.id + "@" + server.id,
                    title = strategy.title.removePrefix("WARP ") + " + " + names[index],
                    nameKey = null,
                    profile = server,
                )
            }
        }
        return if (!allowPlain) pairs else pairs + servers.mapIndexed { index, server ->
            Strategy("server-plain@" + server.id, names[index], server.outerTransport, "", profile = server, plain = true)
        }
    }

    fun names(servers: List<ProxyProfile>): List<String> {
        val originals = servers.map { it.displayName }
        val used = mutableSetOf<String>()
        return servers.mapIndexed { index, server ->
            val base = if (originals.count { it.equals(originals[index], true) } > 1) originals[index] + " [" + server.endpoint + "]" else originals[index]
            var unique = base
            var suffix = 2
            while (!used.add(unique.lowercase())) { unique = "$base #$suffix"; suffix++ }
            unique
        }
    }

    fun profiles(settings: AppSettings): List<ProxyProfile> {
        val links = if (Subscription.isUrl(settings.proxyUri)) settings.subscription
            ?.takeIf { it.source == Subscription.sourceId(settings.proxyUri) }?.links.orEmpty()
        else listOf(settings.proxyUri)
        return links.take(Subscription.MAX_SERVERS).mapNotNull { runCatching { ProxyProfile.parse(it) }.getOrNull() }.distinctBy { it.id }
    }
}
