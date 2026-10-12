package io.github.feg55.zarp.core

import io.github.feg55.zarp.masque.ProxyConfig
import java.io.File
import java.net.URLEncoder
import kotlinx.serialization.json.*
import org.junit.Assert.assertEquals
import org.junit.Test

/** Checked-in Kotlin output is also instantiated by the real Go engines. */
class OutboundContractTest {
    @Test fun kotlinAndNativeOutboundContract() {
        TestLang.english()
        val id = "00000000-0000-4000-8000-000000000001"
        val vless = "vless://" + id + "@server.example.com:443?"
        val ech = "AGT+DQBgAAAgACDQZFLoHh1xlPP29uOXeX+5/9lB5fpBFIBzpBXF/V+GVgAkAAEAAQABAAIAAQADAAIAAQACAAIAAgADAAMAAQADAAIAAwADABFjb3Zlci5leGFtcGxlLmNvbQAA"
        fun escaped(value: String) = URLEncoder.encode(value, "UTF-8")
        val cases = linkedMapOf(
            "vless-tls" to vless + "security=tls",
            "vless-reality" to vless + "security=reality&pbk=" + "A".repeat(43),
            "vless-ws" to vless + "security=tls&type=ws&host=front.example.com&path=%2Fp",
            "vless-grpc" to vless + "security=tls&type=grpc&serviceName=example",
            "vless-httpupgrade" to vless + "security=tls&type=httpupgrade&host=front.example.com&path=%2Fp",
            "vless-ech" to vless + "security=tls&fp=chrome&ech=" + escaped(ech),
            "trojan-tls" to "trojan://test-password@server.example.com:443?security=tls",
            "trojan-ech" to "trojan://test-password@server.example.com:443?ech=" + escaped(ech),
            "hysteria2" to "hy2://test-password@server.example.com:443",
            "hysteria2-salamander" to "hy2://test-password@server.example.com:443?obfs=salamander&obfs-password=test-obfs",
            "hysteria2-ech" to "hy2://test-password@server.example.com:443?ech=" + escaped(ech),
            "xhttp-h3" to vless + "type=xhttp&security=tls&alpn=h3&mode=packet-up",
            "xhttp-reality" to vless + "type=xhttp&security=reality&pbk=" + "A".repeat(43) + "&sid=0123&spx=%2F",
            "xhttp-ech" to vless + "type=xhttp&security=tls&ech=" + escaped(ech),
            "xhttp-extra" to vless + "type=xhttp&security=tls&extra=" + escaped("""{"xPaddingBytes":"10-20","xmux":{"maxConcurrency":"16-32"}}"""),
            "xhttp-download" to vless + "type=xhttp&security=tls&alpn=h2&mode=packet-up&extra=" + escaped(
                """{"downloadSettings":{"address":"server.example.com","port":443,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"server.example.com","alpn":["h2"]},"xhttpSettings":{"path":"/","mode":"packet-up"}}}"""),
        )
        for (mode in listOf("auto", "packet-up", "stream-up", "stream-one")) {
            cases["xhttp-tls-" + mode] = vless + "type=xhttp&security=tls&mode=" + mode + "&pcs=" + "ab".repeat(32) + "&vcn=server.example.com"
            cases["xhttp-none-" + mode] = vless + "type=xhttp&mode=" + mode
        }
        val directory = File("../core/zarpcore/testdata/kotlin")
        val json = Json { prettyPrint = true }
        for ((name, link) in cases) {
            val p = ProxyProfile.parse(link)
            val dial = if (p.xrayOutbound == null) buildJsonObject {
                put("type", "zarp-dial"); put("tag", "server-dial"); put("server", p.host); put("server_port", p.port)
            } else null
            val generated = buildJsonObject {
                put("host", p.host); put("address", "203.0.113.5"); put("port", p.port)
                put("quic", p.outerTransport == Transport.MasqueH3)
                put("config", Json.parseToJsonElement(ProxyConfig.build(p.outbound, ipv6 = true, dns = "192.0.2.53", serverDial = dial)))
                p.xrayOutbound?.let { put("xray", p.buildXrayOutbound("203.0.113.5")) }
            }
            val file = File(directory, name + ".json")
            // Explicit developer-only regeneration. Normal tests never rewrite expectations.
            if (System.getenv("ZARP_WRITE_CONTRACT") == "1") {
                directory.mkdirs()
                file.writeText(json.encodeToString(JsonObject.serializer(), generated) + "\n")
            }
            assertEquals(name, Json.parseToJsonElement(file.readText()), generated)
        }
    }
}
