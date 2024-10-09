# File Inject

This Python script was developed to make the analysis of an Android React Native or Flutter application easier.
It helps with uploading and reloading of the `index.android.bundle`/`libflutter.so` file to the device in near
real-time,
while hooking the right React Native and Flutter classes to override the original file.

The need for writing a tool specifically for this job came during a Penetration Testing engagement. In fact, there are
not many security tools for RN Android apps, and currently none that focus on replacing the `index.android.bundle` at
runtime. This should be the ultimate goal, because leaving the target application's files untouched is always the
superior choice compared to modifying them and repacking.

For the blog post story behind this tool, I invite you to
read https://newsroom.bedefended.com/hooking-react-native-applications-with-frida/.

In this repo there is included a demo RN application, with its source code, too.

## Demo

https://github.com/user-attachments/assets/ddcb1961-f7ff-4fe9-bc28-eda6e24844cb

## Installation

It is recommended to install React Native Inject through `pipx`, which will take care of creating the virtual
environment while making the tool globally available to you.

```bash
pipx install git+https://github.com/BeDefended/file-inject
```

## Usage

First, you'd need to extract the `index.android.bundle` file from the target app. Usually this done by obtaining the
APK, unzipping it and getting the bundle from the `assets` subdirectory. In a similar way the process is done for
Flutter-based applications. Then, the usage of `file-inject` is
as follows:

```commandline
file-inject [-h] [--script SCRIPT] package bundle

positional arguments:
  package          Package name of the application
  bundle           Path to the index.android.bundle

options:
  -h, --help       show this help message and exit
  --script SCRIPT  Path to the custom Frida script, if required.
  --no-reload      Disables reloading, if unwanted or if it causes issues.
```

The script takes two arguments: the target application in the form of pacakge name and the path on the host to the
`index.android.bundle` or `libflutter.so`, which is then monitored for changes and pushed to the device.

Optionally, you can also pass the `--script` argument to point to a custom Frida script, in case the target application
is obfuscated or requires specific tweaking compared to the more general Frida script that is included.

Example:

```commandline
file-inject com.myproject index.android.bundle.js
```

or:

```commandline
file-inject com.myproject libflutter.so
```

As a prerequisite, make sure that you have a working ADB server and the device is connected:

```commandline
$ adb devices                             
List of devices attached
22222AAAA22222  device
```

Also, the Android device should be rooted and properly set for Frida instrumentation. The root permission is required
because the goal is to not change anything in the target application, which makes using this script with Frida Gadget
out of scope.

For customization of the Frida script, an example file `flutter.js` is provided. Note that file-inject will
automatically
replace `com.myproject` with the package name passed as argument.
