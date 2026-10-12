package io.github.feg55.zarp.trafficprobe;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.json.JSONObject;

/** A separate UID proves per-app selection; results never contain URLs or error values. */
public final class ProbeReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        final PendingResult pending = goAsync();
        run(context, intent, pending::finish);
    }
    static void run(Context context, Intent intent, Runnable complete) {
        final boolean directOnly = intent.getBooleanExtra("directOnly", false);
        new Thread(() -> {
            JSONObject result = new JSONObject();
            try {
                JSONObject input = new JSONObject(read(new File(context.getCacheDir(), "verification-config.json")));
                java.security.cert.Certificate certificate = CertificateFactory.getInstance("X.509")
                    .generateCertificate(new java.io.ByteArrayInputStream(input.getString("certificate").getBytes(StandardCharsets.UTF_8)));
                KeyStore keys = KeyStore.getInstance(KeyStore.getDefaultType());
                keys.load(null);
                keys.setCertificateEntry("verification-ca", certificate);
                TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                managers.init(keys);
                SSLContext tls = SSLContext.getInstance("TLS");
                tls.init(null, managers.getTrustManagers(), null);
                ConnectivityManager cm = context.getSystemService(ConnectivityManager.class);
                NetworkCapabilities capabilities = cm.getNetworkCapabilities(cm.getActiveNetwork());
                result.put("vpn", capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
                JSONObject urls = input.getJSONObject("urls");
                for (String name : new String[] { "proxy", "blocked", "direct" }) {
                    if (directOnly && !"direct".equals(name)) continue;
                    try (java.net.Socket raw = new java.net.Socket()) {
                        java.net.URL url = new java.net.URL(urls.getString(name));
                        int port = url.getPort() == -1 ? 443 : url.getPort();
                        raw.setSoTimeout(1500);
                        raw.connect(new java.net.InetSocketAddress(url.getHost(), port), 1500);
                        try (javax.net.ssl.SSLSocket socket = (javax.net.ssl.SSLSocket) tls.getSocketFactory().createSocket(raw, url.getHost(), port, true)) {
                            javax.net.ssl.SSLParameters parameters = socket.getSSLParameters();
                            parameters.setEndpointIdentificationAlgorithm("HTTPS");
                            socket.setSSLParameters(parameters);
                            socket.startHandshake();
                            socket.getOutputStream().write(("GET " + url.getPath() + " HTTP/1.1\r\nHost: " + url.getHost() + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                            socket.getOutputStream().flush();
                            String body = read(socket.getInputStream());
                            result.put(name, body.startsWith("HTTP/1.1 200") && body.contains("verification=ok"));
                        }
                    } catch (Exception error) {
                        result.put(name, false);
                        result.put(name + "Error", error.getClass().getSimpleName());
                    }
                }
                result.put("ready", true);
            } catch (Exception error) {
                try { result.put("setupError", error.getClass().getSimpleName()); } catch (Exception ignored) { }
            } finally {
                try (FileOutputStream output = new FileOutputStream(new File(context.getCacheDir(), "verification-result.json"))) {
                    output.write(result.toString().getBytes(StandardCharsets.UTF_8));
                } catch (Exception ignored) { }
                complete.run();
            }
        }, "zarp-traffic-verification").start();
    }
    private static String read(File file) throws Exception {
        try (FileInputStream input = new FileInputStream(file)) { return read(input); }
    }
    private static String read(java.io.InputStream input) throws Exception {
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int size;
        while ((size = input.read(buffer)) >= 0) {
            output.write(buffer, 0, size);
            if (output.size() > 65536) throw new java.io.IOException("verification input too large");
        }
        return new String(output.toByteArray(), StandardCharsets.UTF_8);
    }
}
