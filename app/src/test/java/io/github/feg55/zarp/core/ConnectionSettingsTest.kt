package io.github.feg55.zarp.core

import java.math.BigInteger
import java.net.InetAddress
import org.junit.Assert.*
import org.junit.Test

class ConnectionSettingsTest {
    @Test fun `endpoints validate addresses without DNS and retain explicit ports`() {
        assertEquals(listOf("162.159.198.2:8443", "[2606:4700::1]:443"),
            EndpointParser.parse("# comment\n162.159.198.2:8443\n[2606:4700::1]:443\n162.159.198.2:8443"))
        assertTrue(EndpointParser.parse(" \n# defaults").isEmpty())
        listOf("example.com:443", "1.2.3.4:0", "1.2.3.4:65536", "127.1:443", "256.1.1.1:443",
            "1.2.3.4", "1.2.3.4:443x", "[abc]:443", "::1:443", "1.2.3.4:443:80").forEach {
            assertTrue(it, runCatching { EndpointParser.parse(it) }.isFailure)
        }
    }

    @Test fun `custom endpoint pool overrides the defaults for both transports`() {
        val pool = WarpEndpoints()
        val addresses = listOf("1.2.3.4:443", "5.6.7.8:8443")
        assertEquals(addresses + addresses, List(4) { pool.next(Transport.MasqueH3, addresses) })
        assertEquals("1.2.3.4:443", pool.next(Transport.MasqueH2, addresses))
    }

    @Test fun `country filters exclude direct and untagged custom strategies`() {
        val all = StrategyCatalog.builtIn
        assertEquals(all, StrategyFilter.apply(all, "all"))
        for (country in listOf("ru", "ir", "cn")) {
            val visible = StrategyFilter.apply(all, country)
            assertTrue(visible.isNotEmpty())
            assertTrue(visible.all { it.usesDesync && country in it.countries })
        }
        assertFalse(StrategyFilter.apply(all, "cn").any { "vk" in it.args })
        val custom = StrategyCatalog.parseCustom("Mine | h2 | --lua-desync=multisplit:pos=2 | cn,ir\nUntagged | h2 | --lua-desync=multisplit:pos=2")
        assertEquals(listOf("custom-mine"), StrategyFilter.apply(custom, "cn").map { it.id })
        assertTrue(StrategyFilter.apply(custom, "ru").isEmpty())
    }

    @Test fun `multiple countries form a union and All restores direct strategies`() {
        val all = StrategyCatalog.builtIn
        val selected = StrategyFilter.toggle("cn", "ru")
        assertEquals("ru,cn", selected)
        assertEquals((StrategyFilter.apply(all, "ru") + StrategyFilter.apply(all, "cn")).toSet(),
            StrategyFilter.apply(all, selected).toSet())
        assertFalse(StrategyFilter.apply(all, selected).any { !it.usesDesync })
        assertEquals("cn", StrategyFilter.toggle(selected, "ru"))
        assertEquals("all", StrategyFilter.toggle("cn", "cn"))
        assertEquals(all, StrategyFilter.apply(all, StrategyFilter.toggle(selected, "all")))
    }

    @Test fun `routing migration preserves the exact existing LAN and country selection`() {
        val migrated = RoutingSettings.migrate(false, setOf("cn", "ir"))
        assertTrue(migrated.enabled)
        assertEquals(setOf("geoip:cn", "geoip:ir"), RoutingPreset.lines(migrated.active()!!.direct).toSet())
        assertFalse(migrated.active()!!.direct.contains("private"))
        assertEquals("geoip:private", RoutingSettings.migrate(true, emptySet()).active()!!.direct)
        assertNull(RoutingSettings.migrate(false, emptySet()).active())
        assertEquals(migrated, RoutingSettings.decode(RoutingSettings.encode(migrated)))
    }

    @Test fun `editing one preset preserves other rules and source URLs`() {
        val original = RoutingSettings(enabled = true, selectedPreset = "cn", geoipUrl = "https://example.com/custom.dat")
        val edited = original.active()!!.withRules("block", "# ads\ngeosite:category-ads-all\n")
        val saved = original.replace(edited)
        assertEquals(original.active()!!.direct, saved.active()!!.direct)
        assertEquals(original.presets.filter { it.id != "cn" }, saved.presets.filter { it.id != "cn" })
        assertEquals(original.geoipUrl, saved.geoipUrl)
        assertFalse(saved.active()!!.rulesJson().contains("# ads"))
        assertTrue(RoutingSettings.validSource("https://example.com/path/geoip.dat?version=1"))
        listOf("http://example.com/db", "file:///db", "https://user:pass@example.com/db", "https://example.com:99999/db", "https://example.com/db#part").forEach {
            assertFalse(it, RoutingSettings.validSource(it))
        }
    }

    private fun contains(routes: List<VpnRoutes.Route>, address: String): Boolean {
        val bytes = InetAddress.getByName(address).address
        val ip = BigInteger(1, bytes)
        return routes.any {
            val start = BigInteger(1, InetAddress.getByName(it.address).address)
            val size = BigInteger.ONE.shiftLeft(bytes.size * 8 - it.prefix)
            ip >= start && ip < start + size
        }
    }

    @Test fun `LAN route exclusions preserve public IPv4 and IPv6`() {
        val v4 = VpnRoutes.internet(false, true)
        for (ip in listOf("10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.1.2", "100.64.0.1", "127.0.0.1", "239.255.255.250")) assertFalse(ip, contains(v4, ip))
        for (ip in listOf("1.1.1.1", "8.8.8.8", "172.15.255.255", "172.32.0.0", "192.169.0.1", "162.159.198.2")) assertTrue(ip, contains(v4, ip))
        val v6 = VpnRoutes.internet(true, true)
        for (ip in listOf("::", "::1", "fc00::1", "fd66:7a61:7270::1", "fe80::1", "ff02::1")) assertFalse(ip, contains(v6, ip))
        assertTrue(contains(v6, "2606:4700::1111"))
        assertEquals(listOf(VpnRoutes.Route("0.0.0.0", 0)), VpnRoutes.internet(false, false))
    }

    @Test fun `links preserve encoded credentials and omit them from strategy and errors`() {
        val trojan = ProxyProfile.parse("trojan://p%40ss%2Bword@proxy.example:443?sni=front.example")
        assertEquals("\"p@ss+word\"", trojan.outbound["password"].toString())
        assertFalse(trojan.strategy().name.contains("p@ss"))
        assertEquals(Transport.Trojan, trojan.transport)
        val hy2 = ProxyProfile.parse("hy2://secret@proxy.example/?obfs=salamander&obfs-password=key")
        assertEquals("proxy.example:443", hy2.endpoint)
        val vless = ProxyProfile.parse("vless://00000000-0000-4000-8000-000000000001@proxy.example:443?security=tls&type=ws&path=%2Fsocket&host=front.example")
        assertTrue(vless.outbound.toString().contains("/socket"))
        assertFalse(StrategyFilter.matches(vless.strategy(), "cn"))
        assertTrue(ServerPairs.build(StrategyCatalog.builtIn, listOf(vless)).all { StrategyFilter.matches(it, "cn") })
        listOf("trojan://my-secret@host:99999", "trojan://my-secret@host:443?type=xhttp", "vless://bad@host:443", "https://my-secret@host:443").forEach {
            assertEquals("proxy.invalid", runCatching { ProxyProfile.parse(it) }.exceptionOrNull()?.message)
        }
    }
}
