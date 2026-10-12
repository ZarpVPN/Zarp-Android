package io.github.feg55.zarp.trafficprobe;

/** Foreground entry point for devices that defer shell broadcasts to new apps. */
public final class ProbeActivity extends android.app.Activity {
    @Override public void onCreate(android.os.Bundle state) {
        super.onCreate(state);
        ProbeReceiver.run(this, getIntent(), () -> runOnUiThread(this::finish));
    }
}
