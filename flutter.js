//  Copyright 2024 BeDefended S.r.l. (https://github.com/bedefended)
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

Java.perform(function () {

    let FlutterJNI = Java.use("io.flutter.embedding.engine.FlutterJNI");
    FlutterJNI["loadLibrary"].implementation = function () {
        console.log(`[i] Injected successfully using FlutterJNI.loadLibrary!`);
        Java.use('java.lang.System')["load"]("/data/user/0/com.myproject/files/libflutter.so");
    };

});
