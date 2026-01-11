/**
 * Simplified Frida BLE Hook for GE Cync App
 *
 * Focuses on capturing the essential BLE write/notify operations.
 *
 * Usage:
 *   frida -U -f com.ge.cbyge -l frida_simple_hook.js --no-pause
 */

console.log("=".repeat(60));
console.log("Cync BLE Protocol Capture");
console.log("=".repeat(60));
console.log("");
console.log("Instructions:");
console.log("1. Open Cync app");
console.log("2. Go to add a new device");
console.log("3. Start pairing process");
console.log("4. Watch for BLE traffic below");
console.log("");
console.log("=".repeat(60));

function toHex(arr) {
    if (!arr) return "(null)";
    var hex = "";
    for (var i = 0; i < arr.length; i++) {
        hex += ("0" + (arr[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}

Java.perform(function() {

    // Hook BluetoothGatt.writeCharacteristic
    var BluetoothGatt = Java.use("android.bluetooth.BluetoothGatt");

    BluetoothGatt.writeCharacteristic.overload(
        'android.bluetooth.BluetoothGattCharacteristic'
    ).implementation = function(char) {
        var uuid = char.getUuid().toString();
        var data = char.getValue();

        // Only log Telink characteristics (1911, 1912) and Mesh (2adb, 2add)
        if (uuid.indexOf("1911") !== -1 ||
            uuid.indexOf("1912") !== -1 ||
            uuid.indexOf("2adb") !== -1 ||
            uuid.indexOf("2add") !== -1) {
            console.log("");
            console.log("[WRITE] " + uuid.substring(4, 8));
            console.log("  -> " + toHex(data));
        }

        return this.writeCharacteristic(char);
    };

    // Hook notification callback
    var BluetoothGattCallback = Java.use("android.bluetooth.BluetoothGattCallback");

    BluetoothGattCallback.onCharacteristicChanged.overload(
        'android.bluetooth.BluetoothGatt',
        'android.bluetooth.BluetoothGattCharacteristic'
    ).implementation = function(gatt, char) {
        var uuid = char.getUuid().toString();
        var data = char.getValue();

        // Only log relevant characteristics
        if (uuid.indexOf("1911") !== -1 ||
            uuid.indexOf("1912") !== -1 ||
            uuid.indexOf("2adc") !== -1 ||
            uuid.indexOf("2ade") !== -1) {
            console.log("");
            console.log("[NOTIFY] " + uuid.substring(4, 8));
            console.log("  <- " + toHex(data));
        }

        this.onCharacteristicChanged(gatt, char);
    };

    // Hook setCharacteristicNotification
    BluetoothGatt.setCharacteristicNotification.implementation = function(char, enable) {
        var uuid = char.getUuid().toString();
        console.log("");
        console.log("[SUBSCRIBE] " + uuid.substring(4, 8) + " = " + enable);
        return this.setCharacteristicNotification(char, enable);
    };

    // Hook native session key generation
    try {
        var BLEJniLib = Java.use("com.thingclips.ble.jni.BLEJniLib");

        BLEJniLib.madeSessionKey.implementation = function(name, password) {
            console.log("");
            console.log("[SESSION KEY]");
            console.log("  Name: " + name);
            console.log("  Password: " + password);
            var result = this.madeSessionKey(name, password);
            console.log("  Key: " + toHex(result));
            return result;
        };

        console.log("[OK] Native hooks installed");
    } catch(e) {
        console.log("[WARN] Could not hook native lib: " + e);
    }

    console.log("[OK] BLE hooks installed - waiting for traffic...");
    console.log("");
});
