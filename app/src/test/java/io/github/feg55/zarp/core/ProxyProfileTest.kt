package io.github.feg55.zarp.core

import java.net.URLEncoder
import java.util.Base64
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/** Desktop accept/reject vectors, with synthetic credentials and documentation hosts. */
class ProxyProfileTest {
    private val credential = "00000000-0000-4000-8000-000000000001"
    private val base = "vless://" + credential + "@server.example.com:443?"
    private val key = "A".repeat(43)
    private val pin = "ab".repeat(32)
    private fun escaped(value: String) = URLEncoder.encode(value, "UTF-8")
    private fun profile(query: String) = ProxyProfile.parse(base + query)
    private fun stream(profile: ProxyProfile) = profile.xrayOutbound!!.getValue("streamSettings").jsonObject
    @Before fun language() = TestLang.english()

    @Test fun blankServerNamesDefaultToTheLinkHost() {
        for (parameter in listOf("sni=", "sni=%20%20", "peer=", "sni=&peer=other.example.com")) {
            for (network in listOf("tcp", "xhttp")) {
                val p = profile("security=tls&type=" + network + "&" + parameter)
                val tls = if (network == "xhttp") stream(p).getValue("tlsSettings").jsonObject else p.outbound.getValue("tls").jsonObject
                assertEquals("server.example.com", tls.getValue(if (network == "xhttp") "serverName" else "server_name").jsonPrimitive.content)
            }
        }
        assertEquals("other.example.com", profile("security=tls&peer=other.example.com").outbound.getValue("tls").jsonObject.getValue("server_name").jsonPrimitive.content)
        val failure = runCatching { profile("security=tls&sni=example.com%00") }.exceptionOrNull() as ProxyLinkException
        assertEquals(LinkIssue(LinkIssueKind.InvalidValue, "sni"), failure.issue)
    }

    @Test fun underscoreHostsKeepCredentialsPortAndTlsName() {
        val p = ProxyProfile.parse(base.replace("server.example.com:443", "server_name.example.com:8443") + "security=tls")
        assertEquals("server_name.example.com", p.host)
        assertEquals(8443, p.port)
        assertEquals(credential, p.outbound.getValue("uuid").jsonPrimitive.content)
        assertEquals(p.host, p.outbound.getValue("tls").jsonObject.getValue("server_name").jsonPrimitive.content)
        val xhttp = ProxyProfile.parse(base.replace("server.example.com", "server_name.example.com") + "type=xhttp&security=tls")
        assertEquals("server_name.example.com", xhttp.xrayOutbound!!.getValue("settings").jsonObject.getValue("vnext").jsonArray.single().jsonObject.getValue("address").jsonPrimitive.content)
        val hy2 = ProxyProfile.parse("hy2://test%40password@server_name.example.com?security=tls")
        assertEquals(443, hy2.port)
        assertEquals("test@password", hy2.outbound.getValue("password").jsonPrimitive.content)
    }

    @Test fun invalidAuthoritiesHaveNamedErrorsAndIpv6StillWorks() {
        for ((address, issue) in listOf(
            "_server.example.com:443" to LinkIssue(LinkIssueKind.InvalidValue, "host"),
            "server_name.example.com" to LinkIssue(LinkIssueKind.MissingParameter, "port"),
            "server_name.example.com:bad" to LinkIssue(LinkIssueKind.InvalidValue, "port"),
            "server_name.example.com:999999999999" to LinkIssue(LinkIssueKind.InvalidValue, "port"),
            "server_name.example.com:65536" to LinkIssue(LinkIssueKind.InvalidValue, "port"),
            ":443" to LinkIssue(LinkIssueKind.MissingParameter, "host"),
        )) {
            val failure = runCatching { ProxyProfile.parse("vless://" + credential + "@" + address + "?security=tls") }.exceptionOrNull() as ProxyLinkException
            assertEquals(address, issue, failure.issue)
            assertFalse(failure.msg.toString().contains(credential))
            assertFalse(failure.msg.toString().contains(address))
        }
        val ipv6 = ProxyProfile.parse(base.replace("server.example.com:443", "[2001:db8::1]:8443") + "security=tls")
        assertEquals("2001:db8::1", ipv6.host)
        assertEquals(8443, ipv6.port)
    }

    @Test fun xhttpModesDefaultsAndStableIdentity() {
        for (mode in listOf("auto", "packet-up", "stream-up", "stream-one")) {
            val p = profile("type=xhttp&security=tls&mode=" + mode + "#Example")
            val settings = stream(p).getValue("xhttpSettings").jsonObject
            assertEquals(mode, settings.getValue("mode").jsonPrimitive.content)
            assertEquals("/", settings.getValue("path").jsonPrimitive.content)
            assertEquals(Transport.MasqueH2, p.outerTransport)
            assertTrue(p.id.matches(Regex("proxy-[0-9a-f]{24}")))
            assertEquals(p.id, profile("type=xhttp&security=tls&mode=" + mode + "#Renamed").id)
        }
        val plain = stream(profile("type=xhttp&path="))
        assertEquals("none", plain.getValue("security").jsonPrimitive.content)
        assertEquals("server.example.com", plain.getValue("xhttpSettings").jsonObject.getValue("host").jsonPrimitive.content)
        assertFalse(plain.containsKey("tlsSettings"))
        assertNotEquals(profile("type=xhttp&mode=auto").id, profile("type=xhttp&mode=stream-up").id)
    }

    @Test fun tlsPinsNamesPaddingAndExtraTypes() {
        val p = profile("type=xhttp&security=tls&sni=tls.example.com&alpn=h2,%20http/1.1&fp=firefox&pcs=" +
            "AB:".repeat(31) + "AB," + pin + "&vcn=tls.example.com,*.example.com&mode=stream-up&path=%2Fp")
        val tls = stream(p).getValue("tlsSettings").jsonObject
        assertEquals(pin + "," + pin, tls.getValue("pinnedPeerCertSha256").jsonPrimitive.content)
        assertEquals(JsonArray(listOf(JsonPrimitive("h2"), JsonPrimitive("http/1.1"))), tls["alpn"])
        assertEquals("tls.example.com,*.example.com", tls.getValue("verifyPeerCertByName").jsonPrimitive.content)
        assertEquals("firefox", tls.getValue("fingerprint").jsonPrimitive.content)
        assertFalse(stream(p).getValue("xhttpSettings").jsonObject.containsKey("host"))
        val extra = """{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"16-32"},"noGRPCHeader":true}"""
        val settings = stream(profile("type=xhttp&extra=" + escaped(extra) + "&x_padding_bytes=10")).getValue("xhttpSettings").jsonObject
        assertEquals(Json.parseToJsonElement(extra), settings["extra"])
        assertFalse(settings.containsKey("xPaddingBytes"))
        assertEquals("12-24", stream(profile("type=xhttp&x_padding_bytes=12-24")).getValue("xhttpSettings").jsonObject.getValue("xPaddingBytes").jsonPrimitive.content)
        assertFalse(stream(profile("type=xhttp&extra=%7B%7D")).getValue("xhttpSettings").jsonObject.containsKey("extra"))
    }

    @Test fun realityAndResolvedAddressContract() {
        val p = profile("type=xhttp&security=reality&pbk=" + key + "&sid=0123abcd&spx=%2F&pqv=" +
            "A".repeat(2603) + "&support-x25519mlkem768=1")
        val r = stream(p).getValue("realitySettings").jsonObject
        assertEquals("chrome", r.getValue("fingerprint").jsonPrimitive.content)
        assertEquals(key, r.getValue("publicKey").jsonPrimitive.content)
        assertEquals("0123abcd", r.getValue("shortId").jsonPrimitive.content)
        assertEquals("/", r.getValue("spiderX").jsonPrimitive.content)
        assertEquals(2603, r.getValue("mldsa65Verify").jsonPrimitive.content.length)
        val node = p.buildXrayOutbound("203.0.113.5").getValue("settings").jsonObject.getValue("vnext").jsonArray.single().jsonObject
        assertEquals("203.0.113.5", node.getValue("address").jsonPrimitive.content)
        assertEquals("server.example.com", r.getValue("serverName").jsonPrimitive.content)
        val user = node.getValue("users").jsonArray.single().jsonObject
        assertEquals("none", user.getValue("encryption").jsonPrimitive.content)
        assertEquals("", user.getValue("flow").jsonPrimitive.content)
    }

    @Test fun echVariantsAreCanonicalAndDisableSingBoxUtls() {
        val bytes = byteArrayOf(0, 4, -1, -2, -3, -4)
        val canonical = Base64.getEncoder().encodeToString(bytes)
        for (encoder in listOf(Base64.getEncoder(), Base64.getUrlEncoder())) {
            for (padding in listOf(true, false)) {
                val encoded = (if (padding) encoder else encoder.withoutPadding()).encodeToString(bytes)
                val p = profile("security=tls&fp=chrome&ech=" + escaped(encoded))
                val tls = p.outbound.getValue("tls").jsonObject
                assertTrue(p.hasEch)
                assertFalse(tls.containsKey("utls"))
                assertEquals(canonical, tls.getValue("ech").jsonObject.getValue("config").jsonArray[1].jsonPrimitive.content)
                assertEquals(canonical, stream(profile("type=xhttp&security=tls&ech=" + escaped(encoded))).getValue("tlsSettings").jsonObject.getValue("echConfigList").jsonPrimitive.content)
            }
        }
        assertTrue(ProxyProfile.parse("trojan://test-password@server.example.com:443?ech=" + escaped(canonical)).hasEch)
        assertTrue(ProxyProfile.parse("hy2://test-password@server.example.com?ech=" + escaped(canonical)).hasEch)
        for (query in listOf("ech=abc", "security=tls&ech=AAYEAQIDBA", "security=none&ech=" + escaped(canonical),
            "security=reality&pbk=" + key + "&ech=" + escaped(canonical))) {
            assertNotNull(ProxyProfile.explain(base + query))
        }
    }

    @Test fun exactH3AlpnControlsOuterTransport() {
        assertEquals(Transport.MasqueH3, profile("type=xhttp&security=tls&alpn=h3").outerTransport)
        for (alpn in listOf("h3,h2", "h2,h3", "h3,h3", "h2", "")) {
            assertEquals(Transport.MasqueH2, profile("type=xhttp&security=tls&alpn=" + alpn).outerTransport)
        }
        assertEquals(Transport.MasqueH3, ProxyProfile.parse("hy2://test-password@server.example.com:443?obfs=salamander&obfs-password=test-obfs").outerTransport)
    }

    @Test fun rejectedParametersAreNamedAndNeverExposeValues() {
        val vectors = listOf(
            "type=xhttp&mode=bogus" to "mode", "type=xhttp&mode=AUTO" to "mode",
            "type=xhttp&extra=nope" to "", "type=xhttp&extra=%5B1%5D" to "",
            "type=xhttp&extra=%22text%22" to "", "type=xhttp&extra=%7B%22a%22" to "",
            "type=xhttp&security=tls&allowInsecure=1" to "", "type=xhttp&insecure=true" to "",
            "type=xhttp&security=tls&flow=xtls-rprx-vision" to "flow",
            "type=ws&mode=auto" to "mode", "mode=auto" to "mode", "type=grpc&extra=%7B%7D" to "extra",
            "type=xhttp&security=tls&spx=%2F" to "spx", "spx=%2F" to "spx",
            "type=xhttp&security=reality&pbk=" + key + "&spx=abc" to "spx",
            "type=xhttp&security=reality&pbk=" + key + "&pqv=short" to "pqv",
            "type=xhttp&security=tls&pqv=" + "A".repeat(2603) to "pqv",
            "type=xhttp&security=reality&pbk=" + key + "&pcs=" + pin to "pcs",
            "type=xhttp&pcs=" + pin to "pcs", "security=tls&pcs=" + pin to "pcs",
            "type=xhttp&security=reality&pbk=" + key + "&vcn=server.example.com" to "vcn",
            "type=xhttp&security=tls&pcs=" + "a".repeat(63) to "pcs",
            "type=xhttp&security=tls&pcs=" + "g".repeat(64) to "pcs",
            "type=xhttp&security=tls&pcs=," to "pcs",
            "type=xhttp&security=tls&pcs=" + List(9) { pin }.joinToString(",") to "pcs",
            "type=xhttp&security=tls&vcn=bad%20name" to "vcn", "type=xhttp&security=tls&vcn=-x" to "vcn",
            "type=xhttp&security=tls&vcn=," to "vcn",
            "type=xhttp&security=tls&vcn=" + List(9) { "example.com" }.joinToString(",") to "vcn",
            "type=xhttp&fm=%7B%7D" to "fm", "type=splithttp" to "splithttp", "type=kcp" to "kcp",
            "type=xhttp&security=xtls" to "xtls", "mport=1000-2000" to "mport",
            "encryption=mlkem768" to "encryption", "security=reality" to "pbk",
            "type=xhttp&security=reality&pbk=" + key + "&alpn=h3" to "alpn",
            "type=xhttp&security=none&alpn=h3" to "alpn", "type=xhttp&fp=chrome" to "fp",
            "security=tls&ech=not-a-config" to "ech",
        )
        for ((query, parameter) in vectors) {
            val failure = runCatching { profile(query) }.exceptionOrNull() as? ProxyLinkException
            assertNotNull("Must reject parameter " + parameter, failure)
            assertEquals(parameter, failure!!.parameter)
            assertEquals("proxy.invalid", failure.message)
            for (secret in listOf(credential, pin, key, "bogus", "not-a-config")) {
                assertFalse(failure.msg.toString().contains(secret))
            }
        }
        for (scheme in listOf("trojan", "hy2")) {
            assertEquals("xhttp", (runCatching { ProxyProfile.parse(scheme + "://test-password@server.example.com:443?type=xhttp") }.exceptionOrNull() as ProxyLinkException).parameter)
        }
        assertNull(ProxyProfile.explain(base + "type=xhttp&security=tls&allowInsecure=0&insecure=false"))
        assertEquals(LinkIssueKind.MissingParameter, (runCatching { profile("security=reality") }.exceptionOrNull() as ProxyLinkException).issue.kind)
        assertEquals(LinkIssueKind.InvalidValue, (runCatching { profile("type=xhttp&mode=bogus") }.exceptionOrNull() as ProxyLinkException).issue.kind)
        for (parameter in listOf("type", "security")) {
            val failure = runCatching { profile(parameter + "=test-password") }.exceptionOrNull() as ProxyLinkException
            assertEquals(parameter, failure.parameter)
            assertFalse(failure.msg.toString().contains("test-password"))
        }
    }

    @Test fun downloadSettingsOnlyUsePairedDestinationAndOuterTransport() {
        fun link(extra: String, alpn: String = "h2") = "type=xhttp&security=tls&alpn=" + alpn + "&extra=" + escaped(extra)
        assertNull(ProxyProfile.explain(base + link("""{"downloadSettings":{"address":"server.example.com","port":443,"network":"xhttp","security":"tls","tlsSettings":{"alpn":["h2"]}}}""")))
        for (extra in listOf(
            """{"downloadSettings":{"address":"other.example.com","port":443}}""",
            """{"downloadSettings":{"address":"server.example.com","port":8443}}""",
            """{"downloadSettings":{"address":"server.example.com","port":443,"tlsSettings":{"alpn":["h3"]}}}""",
            """{"downloadSettings":{"network":"tcp"}}""",
            """{"downloadSettings":{"security":"none"}}""",
        )) assertNotNull(ProxyProfile.explain(base + link(extra)))
    }
}
