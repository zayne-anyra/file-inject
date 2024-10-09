#!/usr/bin/python3

#  Copyright 2024 BeDefended S.r.l. (https://github.com/bedefended)
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.

import argparse
import os
import subprocess
import threading
import time
from datetime import datetime

import frida
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.observers import Observer

frida_script = """
    Java.perform(function () {
  try {
    let MainApplication = Java.use("com.myproject.MainApplication$1");
    MainApplication["getUseDeveloperSupport"].implementation = function () {
      return true;
    };

    let DevInternalSettings = Java.use(
      "com.facebook.react.devsupport.DevInternalSettings"
    );
    DevInternalSettings["isRemoteJSDebugEnabled"].implementation = function () {
      return false;
    };

    let DevSupportManagerBase = Java.use(
      "com.facebook.react.devsupport.DevSupportManagerBase"
    );
    DevSupportManagerBase["hasUpToDateJSBundleInCache"].implementation =
      function () {
        console.log(
          `[i] Injected successfully using react.devsupport!`
        );
        return true;
      };
  } catch (error) {
    console.log("[!] Error trying react.devsupport method.");
  }
});

Java.perform(function () {
  try {
    let ReactNativeHost = Java.use("com.facebook.react.ReactNativeHost");
    ReactNativeHost["getJSBundleFile"].implementation = function () {
      console.log(
        `[i] Injected successfully using react.ReactNativeHost!`
      );
      return "/data/user/0/com.myproject/files/BridgeReactNativeDevBundle.js";
    };
  } catch (error) {
    console.log("[!] Error trying react.ReactNativeHost method." );
  }
});
    """

session = None


class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, file_path: str, target_app: str):
        self.file_path = file_path
        self.target_app = target_app
        self.push_file_to_device()
        # Fix occasional timing bug
        self.last_uploaded = datetime.now()

    def on_modified(self, event: FileSystemEvent):
        if (
            event.src_path == self.file_path
            and (datetime.now() - self.last_uploaded).total_seconds() > 3
        ):
            # print(f"File {self.file_path} has been modified. Uploading to device...")
            self.push_file_to_device()

    def push_file_to_device(self):
        try:
            subprocess.run(
                [
                    "adb",
                    "push",
                    self.file_path,
                    f"/data/local/tmp/{os.path.basename(self.file_path)}",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            subprocess.run(
                [
                    "adb",
                    "shell",
                    "su",
                    "-c",
                    "cp",
                    f"/data/local/tmp/{os.path.basename(self.file_path)}",
                    f"/data/user/0/{self.target_app}/files/{os.path.basename(self.file_path)}",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            print(f"[i] {os.path.basename(self.file_path)} uploaded successfully.")
            self.last_uploaded = datetime.now()

            global session
            if session is not None:
                session.detach()
                spawn_app(self.target_app)
        except subprocess.CalledProcessError as e:
            print(f"Error occurred while pushing the file: {str(e)}")


def monitor_file(file_path: str, target_app: str, noreload: bool):
    event_handler = FileChangeHandler(file_path, target_app)
    if noreload:
        event_handler.push_file_to_device()
        return
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(file_path), recursive=False)
    observer.start()


def spawn_app(package: str):
    global session
    global frida_script
    print(f"\n[i] Spawning {package}.")
    pid = frida.get_usb_device().spawn(package)
    session = frida.get_usb_device().attach(pid)
    script = session.create_script(frida_script)
    script.load()
    frida.get_usb_device().resume(pid)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=str, help="Package name of the application")
    parser.add_argument("bundle", type=str, help="Path to the index.android.bundle")
    parser.add_argument(
        "--script",
        type=str,
        help="Path to the custom Frida script, if required.",
    )
    parser.add_argument(
        "--no-reload",
        action="store_true",
        help="Disables reloading, if unwanted or if it causes issues.",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.bundle):
        print(f"'{args.bundle}' file doesn't exist!")
        exit(1)

    if args.script and not os.path.isfile(args.script):
        print(f"'{args.script}' file doesn't exist!")
        exit(1)
    elif args.script:
        global frida_script
        with open(args.script, "r") as file:
            frida_script = file.read()

    try:
        frida.get_usb_device()
        subprocess.run(
            [
                "adb",
                "shell",
                "pm",
                "list",
                "packages",
                "|",
                "grep",
                f"^package:{args.package}$",
            ],
            stdout=subprocess.PIPE,
            check=True,
        )
    except frida.InvalidArgumentError:
        print(f"No Frida USB devices found!")
        exit(1)
    except subprocess.CalledProcessError:
        print(f"'{args.package}' package name not found!")
        exit(1)
    except Exception as e:
        print(f"Error! {e}")
        exit(1)

    frida_script = frida_script.replace("com.myproject", args.package)
    frida_script = frida_script.replace("BridgeReactNativeDevBundle.js", args.bundle)

    x = threading.Thread(
        target=monitor_file,
        args=(os.path.abspath(args.bundle), args.package, args.no_reload),
        daemon=True,
    )
    x.start()
    y = threading.Thread(target=spawn_app, args=(args.package,), daemon=True)
    y.start()

    try:
        while True:
            time.sleep(100)
    except (KeyboardInterrupt, SystemExit):
        print("Received keyboard interrupt, quitting threads and cleaning device.")
        subprocess.run(
            [
                "adb",
                "shell",
                "su",
                "-c",
                "rm",
                f"/data/user/0/{args.package}/files/{args.bundle}",
            ],
            check=True,
        )

        subprocess.run(
            ["adb", "shell", "su", "-c", "rm", f"/data/local/tmp/{args.bundle}"],
            check=True,
        )


if __name__ == "__main__":
    main()
