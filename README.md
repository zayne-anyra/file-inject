# React Native Inject

This Python script was developed to make the analysis of an Android React Native application easier. It helps with
uploading and reloading of the `index.android.bundle` file to the device in near real-time, while hooking the right
React Native classes to override the original bundle file.

The need for writing a tool specifically for this job came during a Penetration Testing engagement. In fact, there are
not many security tools for RN Android apps, and currently none that focus on replacing the `index.android.bundle` at
runtime. This should be the ultimate goal, because leaving the target application's files untouched is always the
superior choice compared to modifying them and repacking.

For the blog post story behind this tool, I invite you to
read https://newsroom.bedefended.com/hooking-react-native-applications-with-frida/.

In this repo there is included a demo RN application, with its source code, too.

## Demo

## Installation

It is recommended to install React Native Inject through `pipx`, which will take care of creating the virtual
environment while
making the tool globally available to you.

```bash
pipx install git+https://github.com/BeDefended/react-native-inject
```

## Usage

First, you'd need to extract the `index.android.bundle` file from the target app. Usually this done by obtaining the
APK, unzipping it and getting the bundle from the `assets` subdirectory. Then, the usage of 'react-native-inject` is
as follows:

```commandline
react-native-inject [-h] [--script SCRIPT] package bundle

positional arguments:
  package          Package name of the application
  bundle           Path to the index.android.bundle

options:
  -h, --help       show this help message and exit
  --script SCRIPT  Path to the custom Frida script, if required.
  --no-reload      Disables reloading, if unwanted or if it causes issues.
```

The script takes two arguments: the target application in the form of pacakge name and the path on the host to the
`index.android.bundle`, which is then monitored for changes and pushed to the device.

Optionally, you can also pass the `--script` argument to point to a custom Frida script, in case the target application
is obfuscated or requires specific tweaking compared to the more general Frida script that is included.

Example:

```bash
react-native-inject com.myproject index.android.bundle.js
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
