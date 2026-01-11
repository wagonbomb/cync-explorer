/**
 * Frida BLE Hook for GE Cync App
 *
 * This script hooks Android BLE APIs to capture all Bluetooth
 * Low Energy communication with GE Cync devices.
 *
 * Usage:
 *   frida -U -f com.ge.cbyge -l frida_ble_hook.js --no-pause
 *
 * Or attach to running app:
 *   frida -U com.ge.cbyge -l frida_ble_hook.js
 */

console.log("[*] Cync BLE Protocol Capture Starting...");

// Helper to convert bytes to hex string
function bytesToHex(bytes) {
    if (!bytes) return "(null)";
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
        hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}

// Hook BluetoothGattCharacteristic.setValue()
Java.perform(function() {
    console.log("[*] Hooking GATT operations...\n");

    // ========== BluetoothGatt Writes ==========

    var BluetoothGatt = Java.use("android.bluetooth.BluetoothGatt");

    // writeCharacteristic (API < 33)
    BluetoothGatt.writeCharacteristic.overload('android.bluetooth.BluetoothGattCharacteristic').implementation = function(char) {
        var uuid = char.getUuid().toString();
        var value = char.getValue();
        console.log("[WRITE] UUID: " + uuid);
        console.log("        Data: " + bytesToHex(value));
        console.log("        Handle: 0x" + char.getInstanceId().toString(16));
        console.log("");
        return this.writeCharacteristic(char);
    };

    // writeCharacteristic (API 33+)
    try {
        BluetoothGatt.writeCharacteristic.overload(
            'android.bluetooth.BluetoothGattCharacteristic',
            '[B',
            'int'
        ).implementation = function(char, value, writeType) {
            var uuid = char.getUuid().toString();
            console.log("[WRITE] UUID: " + uuid);
            console.log("        Data: " + bytesToHex(value));
            console.log("        WriteType: " + writeType);
            console.log("");
            return this.writeCharacteristic(char, value, writeType);
        };
    } catch(e) {
        console.log("[*] API 33+ write hook not needed");
    }

    // writeDescriptor
    BluetoothGatt.writeDescriptor.overload('android.bluetooth.BluetoothGattDescriptor').implementation = function(desc) {
        var uuid = desc.getUuid().toString();
        var charUuid = desc.getCharacteristic().getUuid().toString();
        var value = desc.getValue();
        console.log("[DESC_WRITE] Desc UUID: " + uuid);
        console.log("             Char UUID: " + charUuid);
        console.log("             Data: " + bytesToHex(value));
        console.log("");
        return this.writeDescriptor(desc);
    };

    // setCharacteristicNotification
    BluetoothGatt.setCharacteristicNotification.implementation = function(char, enable) {
        var uuid = char.getUuid().toString();
        console.log("[NOTIFY] UUID: " + uuid);
        console.log("         Enable: " + enable);
        console.log("");
        return this.setCharacteristicNotification(char, enable);
    };

    // ========== BluetoothGattCallback ==========

    var BluetoothGattCallback = Java.use("android.bluetooth.BluetoothGattCallback");

    // onCharacteristicChanged (notifications received)
    BluetoothGattCallback.onCharacteristicChanged.overload(
        'android.bluetooth.BluetoothGatt',
        'android.bluetooth.BluetoothGattCharacteristic'
    ).implementation = function(gatt, char) {
        var uuid = char.getUuid().toString();
        var value = char.getValue();
        console.log("[NOTIFY_RX] UUID: " + uuid);
        console.log("            Data: " + bytesToHex(value));
        console.log("");
        this.onCharacteristicChanged(gatt, char);
    };

    // onCharacteristicWrite
    BluetoothGattCallback.onCharacteristicWrite.implementation = function(gatt, char, status) {
        var uuid = char.getUuid().toString();
        console.log("[WRITE_CB] UUID: " + uuid);
        console.log("           Status: " + status);
        console.log("");
        this.onCharacteristicWrite(gatt, char, status);
    };

    // ========== Native Library Hooks (libBleLib.so) ==========

    try {
        var libBleLib = Module.findBaseAddress("libBleLib.so");
        if (libBleLib) {
            console.log("[*] Found libBleLib.so at " + libBleLib);

            // Hook trsmitr_send_pkg_encode
            var trsmitr_send_pkg_encode = Module.findExportByName("libBleLib.so", "trsmitr_send_pkg_encode");
            if (trsmitr_send_pkg_encode) {
                Interceptor.attach(trsmitr_send_pkg_encode, {
                    onEnter: function(args) {
                        console.log("[NATIVE] trsmitr_send_pkg_encode called");
                        this.arg0 = args[0];
                        this.arg1 = args[1];
                    },
                    onLeave: function(retval) {
                        console.log("[NATIVE] trsmitr_send_pkg_encode returned");
                    }
                });
            }

            // Hook made_session_key
            var made_session_key = Module.findExportByName("libBleLib.so", "made_session_key");
            if (made_session_key) {
                Interceptor.attach(made_session_key, {
                    onEnter: function(args) {
                        console.log("[NATIVE] made_session_key called");
                        // Args might be: name, password, session_key_out
                    },
                    onLeave: function(retval) {
                        console.log("[NATIVE] made_session_key returned");
                    }
                });
            }

            // Hook getCommandRequestData
            var getCommandRequestData = Module.findExportByName("libBleLib.so", "Java_com_thingclips_ble_jni_BLEJniLib_getCommandRequestData");
            if (getCommandRequestData) {
                Interceptor.attach(getCommandRequestData, {
                    onEnter: function(args) {
                        console.log("[NATIVE] getCommandRequestData called");
                    },
                    onLeave: function(retval) {
                        if (retval) {
                            var env = Java.vm.getEnv();
                            var jarray = retval;
                            try {
                                var len = env.getArrayLength(jarray);
                                var buf = env.getByteArrayElements(jarray, null);
                                var bytes = Memory.readByteArray(buf, len);
                                console.log("[NATIVE] getCommandRequestData result: " + bytesToHex(new Uint8Array(bytes)));
                                env.releaseByteArrayElements(jarray, buf, 0);
                            } catch(e) {
                                console.log("[NATIVE] Could not read result: " + e);
                            }
                        }
                    }
                });
            }

        } else {
            console.log("[*] libBleLib.so not yet loaded, waiting...");

            // Set up module load listener
            var listener = Interceptor.attach(Module.findExportByName(null, "dlopen"), {
                onEnter: function(args) {
                    this.path = args[0].readCString();
                },
                onLeave: function(retval) {
                    if (this.path && this.path.indexOf("libBleLib.so") !== -1) {
                        console.log("[*] libBleLib.so loaded!");
                        // Could re-run native hooks here
                    }
                }
            });
        }
    } catch(e) {
        console.log("[*] Native hook error: " + e);
    }

    // ========== BLEJniLib Java Class Hooks ==========

    try {
        var BLEJniLib = Java.use("com.thingclips.ble.jni.BLEJniLib");

        BLEJniLib.getNormalRequestData.implementation = function(arr) {
            console.log("[JNI] getNormalRequestData input: " + bytesToHex(arr));
            var result = this.getNormalRequestData(arr);
            console.log("[JNI] getNormalRequestData output: " + bytesToHex(result));
            console.log("");
            return result;
        };

        BLEJniLib.getCommandRequestData.implementation = function(arr) {
            console.log("[JNI] getCommandRequestData input: " + bytesToHex(arr));
            var result = this.getCommandRequestData(arr);
            console.log("[JNI] getCommandRequestData output: " + bytesToHex(result));
            console.log("");
            return result;
        };

        BLEJniLib.parseDataRecived.implementation = function(arr) {
            console.log("[JNI] parseDataRecived input: " + bytesToHex(arr));
            var result = this.parseDataRecived(arr);
            console.log("[JNI] parseDataRecived output: " + bytesToHex(result));
            console.log("");
            return result;
        };

        BLEJniLib.madeSessionKey.implementation = function(name, password) {
            console.log("[JNI] madeSessionKey");
            console.log("      Name: " + name);
            console.log("      Password: " + password);
            var result = this.madeSessionKey(name, password);
            console.log("      Result: " + bytesToHex(result));
            console.log("");
            return result;
        };

        console.log("[*] BLEJniLib hooks installed");

    } catch(e) {
        console.log("[*] BLEJniLib not found: " + e);
    }

    console.log("[*] All hooks installed!");
    console.log("[*] Now interact with the Cync app to capture BLE traffic\n");
});
