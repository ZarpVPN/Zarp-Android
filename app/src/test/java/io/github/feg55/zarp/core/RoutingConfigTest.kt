package io.github.feg55.zarp.core

import io.github.feg55.zarp.masque.ProxyConfig
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

class RoutingConfigTest {
    @Test fun `routing keeps health probes on proxy and enables domain detection before user rules`() {
        val outbound = buildJsonObject { put("type", "socks"); put("tag", "proxy"); put("server", "127.0.0.1"); put("server_port", 1234) }
        val block = buildJsonObject { put("domain", "blocked.example"); put("action", "reject") }
        val config = Json.parseToJsonElement(ProxyConfig.build(outbound, false, JsonArray(listOf(block)), "9.9.9.9,1.1.1.1")).jsonObject
        val route = config.getValue("route").jsonObject
        val rules = route.getValue("rules").jsonArray
        assertEquals("sniff", rules[0].jsonObject.getValue("action").jsonPrimitive.content)
        assertEquals("proxy", rules[1].jsonObject.getValue("outbound").jsonPrimitive.content)
        assertEquals("www.cloudflare.com", rules[1].jsonObject.getValue("domain").jsonArray[0].jsonPrimitive.content)
        assertEquals(block, rules.last())
        assertEquals("proxy", route.getValue("final").jsonPrimitive.content)
        val dns = config.getValue("dns").jsonObject
        assertTrue(dns.getValue("reverse_mapping").jsonPrimitive.boolean)
        assertEquals("9.9.9.9", dns.getValue("servers").jsonArray[1].jsonObject.getValue("server").jsonPrimitive.content)
    }
}
