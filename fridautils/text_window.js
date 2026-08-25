Java.perform(function () {
    const ActivityThread = Java.use("android.app.ActivityThread");
    const app = ActivityThread.currentApplication();
    if (app === null) return;

    const Activity = Java.use("android.app.Activity");
    const TextView = Java.use("android.widget.TextView");
    const FrameLayoutParams = Java.use("android.widget.FrameLayout$LayoutParams");
    const Gravity = Java.use("android.view.Gravity");
    const JString = Java.use("java.lang.String");

    // ambil activity paling atas
    const activity = Java.cast(
        ActivityThread.currentActivity(),
        Activity
    );

    const decorView = activity.getWindow().getDecorView();

    const tv = TextView.$new(activity);
    tv.setText(JString.$new("HELLO FRIDA"));
    tv.setTextSize(18);

    const params = FrameLayoutParams.$new(
        FrameLayoutParams.WRAP_CONTENT.value,
        FrameLayoutParams.WRAP_CONTENT.value
    );

    params.gravity.value = Gravity.TOP.value | Gravity.LEFT.value;
    params.leftMargin.value = 20;
    params.topMargin.value = 100;

    decorView.addView(tv, params);

    console.log("[+] TEXT BERHASIL DITAMBAHKAN");
});




