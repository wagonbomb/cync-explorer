# DEX Analysis: classes4.dex


**File Size**: 5.2 MB
**Total Classes**: 2,652
**Analysis Date**: 2026-01-10 00:26
**Tool**: JADX + Custom Python Analyzer

---

## Table of Contents

1. [Overview Statistics](#overview-statistics)
2. [BLE-Related Classes](#ble-related-classes)
3. [Package Structure](#package-structure)
4. [String Constants & UUIDs](#string-constants-&-uuids)
5. [BLE Write Operations](#ble-write-operations)
6. [Command Sequences](#command-sequences)
7. [Method Index](#method-index)
8. [Full Class List](#full-class-list)

---

## Overview Statistics

| Metric | Count |
| --- | --- |
| Total Classes | 2,652 |
| Total Methods | 36,751 |
| Total Fields | 85,885 |
| Total Packages | 208 |
| BLE-Related Classes | 2,028 |
| UUIDs Found | 86 |
| BLE Write Operations | 27 |
| Command Sequences | 0 |

## BLE-Related Classes

Found 2028 BLE-related classes:

### Manufacture [CRITICAL]


- **Full Name**: `com.thingclips.crypto.Manufacture`
- **Package**: `com.thingclips.crypto`
- **Methods**: 37
- **Fields**: 55
- **Source**: `com\thingclips\crypto\Manufacture.java`

**Key Methods**:
  - `pdqppqb()`
  - `getKey()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - *(... and 27 more)*

**Notable Strings**:
  - `"SERVICE_UUID"`
  - `"PAIR_UUID"`
  - `"COMMAND_UUID"`
  - `"OTA_UUID"`
  - `"NOTIFY_UUID"`
  - *(... and 1 more)*

---

### BleGattCharacterData [CRITICAL]


- **Full Name**: `com.thingclips.sdk.ble.core.ability.model.BleGattCharacterData`
- **Package**: `com.thingclips.sdk.ble.core.ability.model`
- **Implements**: `Parcelable`
- **Methods**: 18
- **Fields**: 6
- **Source**: `core\ability\model\BleGattCharacterData.java`

**Key Methods**:
  - `createFromParcel()`
  - `BleGattCharacterData()`
  - `newArray()`
  - `BleGattCharacterData()`
  - `describeContents()`
  - `getDescriptors()`
  - `ArrayList()`
  - `getPermissions()`
  - `getProperty()`
  - `getUuid()`
  - *(... and 8 more)*

**Notable Strings**:
  - `"BleGattCharacter{uuid="`

---

### BleGattDescriptorData [CRITICAL]


- **Full Name**: `com.thingclips.sdk.ble.core.ability.model.BleGattDescriptorData`
- **Package**: `com.thingclips.sdk.ble.core.ability.model`
- **Implements**: `Parcelable`
- **Methods**: 15
- **Fields**: 4
- **Source**: `core\ability\model\BleGattDescriptorData.java`

**Key Methods**:
  - `createFromParcel()`
  - `BleGattDescriptorData()`
  - `newArray()`
  - `BleGattDescriptorData()`
  - `describeContents()`
  - `getmPermissions()`
  - `getmUuid()`
  - `getmValue()`
  - `setmPermissions()`
  - `setmUuid()`
  - *(... and 5 more)*

**Notable Strings**:
  - `"BleGattDescriptor{mUuid="`

---

### BleConnectAbilityResponse [CRITICAL]


- **Full Name**: `com.thingclips.sdk.ble.core.ability.response.BleConnectAbilityResponse`
- **Package**: `com.thingclips.sdk.ble.core.ability.response`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\ability\response\BleConnectAbilityResponse.java`

**Key Methods**:
  - `onResponse()`

---

### bdpdqbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.ble.core.commRod.bdpdqbp`
- **Package**: `com.thingclips.sdk.ble.core.commRod`
- **Implements**: `LeScanResponse`
- **Methods**: 24
- **Fields**: 39
- **Source**: `ble\core\commRod\BleCommRodScanner.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `bdpdqbp()`
  - `onDeviceFounded()`
  - `onScanCancel()`
  - `onScanStart()`
  - `onScanStop()`
  - `bleScanResponseOnResult()`
  - `containNormal()`
  - `containSigMesh()`
  - `containSingleBle()`
  - *(... and 14 more)*

**Notable Strings**:
  - `",uuid = "`

---

### bdpdqbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.ble.core.manager.bdpdqbp`
- **Package**: `com.thingclips.sdk.ble.core.manager`
- **Implements**: `bppdpdq.qddqppb`
- **Methods**: 52
- **Fields**: 62
- **Source**: `ble\core\manager\bdpdqbp.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `C0310bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `onDeviceFounded()`
  - `onScanCancel()`
  - `onScanStart()`
  - `onScanStop()`
  - *(... and 42 more)*

**Notable Strings**:
  - `"shareLogic called. curBean.devUuid = "`
  - `",uuid = "`
  - `"thingMesh  , getMac = "`
  - `"SigMesh  , getMac = "`

---

### BluetoothClient [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.BluetoothClient`
- **Package**: `com.thingclips.sdk.blelib`
- **Implements**: `IBluetoothClient`
- **Methods**: 46
- **Fields**: 2
- **Source**: `thingclips\sdk\blelib\BluetoothClient.java`

**Key Methods**:
  - `BluetoothClient()`
  - `NullPointerException()`
  - `clearRequest()`
  - `closeBluetooth()`
  - `configMtu()`
  - `connect()`
  - `disconnect()`
  - `discoveryServices()`
  - `getBondState()`
  - `getConnectStatus()`
  - *(... and 36 more)*

---

### BluetoothClientImpl [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.BluetoothClientImpl`
- **Package**: `com.thingclips.sdk.blelib`
- **Implements**: `IBluetoothClient, ProxyInterceptor, Handler.Callback`
- **Methods**: 134
- **Fields**: 78
- **Source**: `thingclips\sdk\blelib\BluetoothClientImpl.java`

**Key Methods**:
  - `ArrayList()`
  - `HashMap()`
  - `ServiceConnection()`
  - `onServiceConnected()`
  - `onServiceDisconnected()`
  - `BluetoothClientImpl()`
  - `HandlerThread()`
  - `Handler()`
  - `LinkedList()`
  - `LinkedList()`
  - *(... and 124 more)*

**Notable Strings**:
  - `"BluetoothClientImpl"`
  - `"BluetoothService registered"`
  - `"BluetoothService not registered"`
  - `"IBluetoothService = %s"`

---

### BluetoothServiceImpl [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.BluetoothServiceImpl`
- **Package**: `com.thingclips.sdk.blelib`
- **Extends**: `IBluetoothService.Stub`
- **Implements**: `Handler.Callback`
- **Methods**: 9
- **Fields**: 36
- **Source**: `thingclips\sdk\blelib\BluetoothServiceImpl.java`

**Key Methods**:
  - `Handler()`
  - `BluetoothServiceImpl()`
  - `getInstance()`
  - `BluetoothServiceImpl()`
  - `callBluetoothApi()`
  - `BleGeneralResponse()`
  - `onResponse()`
  - `Bundle()`
  - `handleMessage()`

---

### Constants [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.Constants`
- **Package**: `com.thingclips.sdk.blelib`
- **Methods**: 1
- **Fields**: 85
- **Source**: `thingclips\sdk\blelib\Constants.java`

**Key Methods**:
  - `getStatusText()`

**Notable Strings**:
  - `"extra.character.uuid"`
  - `"extra.descriptor.uuid"`
  - `"extra.gatt.profile"`
  - `"extra.service.uuid"`

---

### IBluetoothClient [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.IBluetoothClient`
- **Package**: `com.thingclips.sdk.blelib`
- **Methods**: 33
- **Fields**: 0
- **Source**: `thingclips\sdk\blelib\IBluetoothClient.java`

**Key Methods**:
  - `clearRequest()`
  - `configMtu()`
  - `connect()`
  - `disconnect()`
  - `discoveryServices()`
  - `indicate()`
  - `notify()`
  - `notifyMesh()`
  - `onlyDisconnect()`
  - `read()`
  - *(... and 23 more)*

---

### BleConnectDispatcher [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.BleConnectDispatcher`
- **Package**: `com.thingclips.sdk.blelib.connect`
- **Implements**: `IBleConnectDispatcher, RuntimeChecker, Handler.Callback`
- **Methods**: 36
- **Fields**: 20
- **Source**: `sdk\blelib\connect\BleConnectDispatcher.java`

**Key Methods**:
  - `LinkedList()`
  - `Handler()`
  - `BleConnectDispatcher()`
  - `BleConnectWorker()`
  - `addNewRequest()`
  - `isRequestMatch()`
  - `newInstance()`
  - `BleConnectDispatcher()`
  - `scheduleNextRequest()`
  - `checkRuntime()`
  - *(... and 26 more)*

---

### BleConnectManager [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.BleConnectManager`
- **Package**: `com.thingclips.sdk.blelib.connect`
- **Methods**: 22
- **Fields**: 9
- **Source**: `sdk\blelib\connect\BleConnectManager.java`

**Key Methods**:
  - `clearRequest()`
  - `configMtu()`
  - `connect()`
  - `disconnect()`
  - `discoveryService()`
  - `getBleConnectMaster()`
  - `getWorkerLooper()`
  - `HandlerThread()`
  - `indicate()`
  - `notify()`
  - *(... and 12 more)*

---

### BleConnectMaster [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.BleConnectMaster`
- **Package**: `com.thingclips.sdk.blelib.connect`
- **Implements**: `IBleConnectMaster, ProxyInterceptor, Handler.Callback`
- **Methods**: 27
- **Fields**: 6
- **Source**: `sdk\blelib\connect\BleConnectMaster.java`

**Key Methods**:
  - `BleConnectMaster()`
  - `Handler()`
  - `getConnectDispatcher()`
  - `newInstance()`
  - `BleConnectMaster()`
  - `clearRequest()`
  - `configMtu()`
  - `connect()`
  - `disconnect()`
  - `discoveryService()`
  - *(... and 17 more)*

---

### BleConnectWorker [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.BleConnectWorker`
- **Package**: `com.thingclips.sdk.blelib.connect`
- **Implements**: `Handler.Callback, IBleConnectWorker, IBluetoothGattResponse, ProxyInterceptor, RuntimeChecker`
- **Methods**: 57
- **Fields**: 123
- **Source**: `sdk\blelib\connect\BleConnectWorker.java`

**Key Methods**:
  - `BleConnectWorker()`
  - `IllegalStateException()`
  - `Handler()`
  - `HashMap()`
  - `broadcastCharacterChanged()`
  - `Intent()`
  - `broadcastConnectStatus()`
  - `Intent()`
  - `connectGattApi21()`
  - `getAddress()`
  - *(... and 47 more)*

**Notable Strings**:
  - `"connectGatt"`
  - `"gatt = device.connectGatt(autoConnect = "`
  - `"character: uuid = "`
  - `"closeGatt for %s"`
  - `"disconnect but gatt is null!"`
  - *(... and 16 more)*

---

### IBleConnectMaster [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.IBleConnectMaster`
- **Package**: `com.thingclips.sdk.blelib.connect`
- **Methods**: 19
- **Fields**: 0
- **Source**: `sdk\blelib\connect\IBleConnectMaster.java`

**Key Methods**:
  - `clearRequest()`
  - `configMtu()`
  - `connect()`
  - `disconnect()`
  - `discoveryService()`
  - `indicate()`
  - `notify()`
  - `notifyMesh()`
  - `onBluetoothStateChanged()`
  - `onlyDisconnect()`
  - *(... and 9 more)*

---

### IBluetoothGattResponse [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.listener.IBluetoothGattResponse`
- **Package**: `com.thingclips.sdk.blelib.connect.listener`
- **Methods**: 9
- **Fields**: 0
- **Source**: `blelib\connect\listener\IBluetoothGattResponse.java`

**Key Methods**:
  - `onCharacteristicChanged()`
  - `onCharacteristicRead()`
  - `onCharacteristicWrite()`
  - `onConnectionStateChange()`
  - `onDescriptorRead()`
  - `onDescriptorWrite()`
  - `onMtuChanged()`
  - `onReadRemoteRssi()`
  - `onServicesDiscovered()`

---

### ReadCharacterListener [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.listener.ReadCharacterListener`
- **Package**: `com.thingclips.sdk.blelib.connect.listener`
- **Extends**: `GattResponseListener`
- **Methods**: 1
- **Fields**: 0
- **Source**: `blelib\connect\listener\ReadCharacterListener.java`

**Key Methods**:
  - `onCharacteristicRead()`

---

### ReadDescriptorListener [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.listener.ReadDescriptorListener`
- **Package**: `com.thingclips.sdk.blelib.connect.listener`
- **Extends**: `GattResponseListener`
- **Methods**: 1
- **Fields**: 0
- **Source**: `blelib\connect\listener\ReadDescriptorListener.java`

**Key Methods**:
  - `onDescriptorRead()`

---

### WriteCharacterListener [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.listener.WriteCharacterListener`
- **Package**: `com.thingclips.sdk.blelib.connect.listener`
- **Extends**: `GattResponseListener`
- **Methods**: 1
- **Fields**: 0
- **Source**: `blelib\connect\listener\WriteCharacterListener.java`

**Key Methods**:
  - `onCharacteristicWrite()`

---

### WriteDescriptorListener [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.listener.WriteDescriptorListener`
- **Package**: `com.thingclips.sdk.blelib.connect.listener`
- **Extends**: `GattResponseListener`
- **Methods**: 1
- **Fields**: 0
- **Source**: `blelib\connect\listener\WriteDescriptorListener.java`

**Key Methods**:
  - `onDescriptorWrite()`

---

### BleIndicateRequest [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.BleIndicateRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Extends**: `BleRequest`
- **Implements**: `WriteDescriptorListener`
- **Methods**: 5
- **Fields**: 3
- **Source**: `blelib\connect\request\BleIndicateRequest.java`

**Key Methods**:
  - `BleIndicateRequest()`
  - `openIndicate()`
  - `onDescriptorWrite()`
  - `processRequest()`
  - `if()`

---

### BleMeshNotifyRequest [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.BleMeshNotifyRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Extends**: `BleRequest`
- **Implements**: `WriteDescriptorListener`
- **Methods**: 5
- **Fields**: 3
- **Source**: `blelib\connect\request\BleMeshNotifyRequest.java`

**Key Methods**:
  - `BleMeshNotifyRequest()`
  - `openNotify()`
  - `onDescriptorWrite()`
  - `processRequest()`
  - `if()`

---

### BleNotifyRequest [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.BleNotifyRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Extends**: `BleRequest`
- **Implements**: `WriteDescriptorListener`
- **Methods**: 5
- **Fields**: 3
- **Source**: `blelib\connect\request\BleNotifyRequest.java`

**Key Methods**:
  - `BleNotifyRequest()`
  - `openNotify()`
  - `onDescriptorWrite()`
  - `processRequest()`
  - `if()`

---

### BleReadDescriptorRequest [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.BleReadDescriptorRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Extends**: `BleRequest`
- **Implements**: `ReadDescriptorListener`
- **Methods**: 5
- **Fields**: 4
- **Source**: `blelib\connect\request\BleReadDescriptorRequest.java`

**Key Methods**:
  - `BleReadDescriptorRequest()`
  - `startRead()`
  - `onDescriptorRead()`
  - `processRequest()`
  - `if()`

---

### BleReadRequest [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.BleReadRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Extends**: `BleRequest`
- **Implements**: `ReadCharacterListener`
- **Methods**: 5
- **Fields**: 3
- **Source**: `blelib\connect\request\BleReadRequest.java`

**Key Methods**:
  - `BleReadRequest()`
  - `startRead()`
  - `onCharacteristicRead()`
  - `processRequest()`
  - `if()`

---

### BleUnnotifyRequest [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.BleUnnotifyRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Extends**: `BleRequest`
- **Implements**: `WriteDescriptorListener`
- **Methods**: 5
- **Fields**: 3
- **Source**: `blelib\connect\request\BleUnnotifyRequest.java`

**Key Methods**:
  - `BleUnnotifyRequest()`
  - `closeNotify()`
  - `onDescriptorWrite()`
  - `processRequest()`
  - `if()`

---

### BleWriteDescriptorRequest [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.BleWriteDescriptorRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Extends**: `BleRequest`
- **Implements**: `WriteDescriptorListener`
- **Methods**: 5
- **Fields**: 5
- **Source**: `blelib\connect\request\BleWriteDescriptorRequest.java`

**Key Methods**:
  - `BleWriteDescriptorRequest()`
  - `startWrite()`
  - `onDescriptorWrite()`
  - `processRequest()`
  - `if()`

---

### BleWriteNoRspRequest [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.BleWriteNoRspRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Extends**: `BleRequest`
- **Implements**: `WriteCharacterListener`
- **Methods**: 5
- **Fields**: 4
- **Source**: `blelib\connect\request\BleWriteNoRspRequest.java`

**Key Methods**:
  - `BleWriteNoRspRequest()`
  - `startWrite()`
  - `onCharacteristicWrite()`
  - `processRequest()`
  - `if()`

---

### BleWriteRequest [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.BleWriteRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Extends**: `BleRequest`
- **Implements**: `WriteCharacterListener`
- **Methods**: 5
- **Fields**: 4
- **Source**: `blelib\connect\request\BleWriteRequest.java`

**Key Methods**:
  - `BleWriteRequest()`
  - `startWrite()`
  - `onCharacteristicWrite()`
  - `processRequest()`
  - `if()`

---

### BluetoothGattResponse [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.connect.response.BluetoothGattResponse`
- **Package**: `com.thingclips.sdk.blelib.connect.response`
- **Extends**: `BluetoothGattCallback`
- **Methods**: 10
- **Fields**: 1
- **Source**: `blelib\connect\response\BluetoothGattResponse.java`

**Key Methods**:
  - `BluetoothGattResponse()`
  - `onCharacteristicChanged()`
  - `onCharacteristicRead()`
  - `onCharacteristicWrite()`
  - `onConnectionStateChange()`
  - `onDescriptorRead()`
  - `onDescriptorWrite()`
  - `onMtuChanged()`
  - `onReadRemoteRssi()`
  - `onServicesDiscovered()`

---

### BleGattCharacter [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.model.BleGattCharacter`
- **Package**: `com.thingclips.sdk.blelib.model`
- **Implements**: `Parcelable`
- **Methods**: 18
- **Fields**: 6
- **Source**: `sdk\blelib\model\BleGattCharacter.java`

**Key Methods**:
  - `createFromParcel()`
  - `BleGattCharacter()`
  - `newArray()`
  - `BleGattCharacter()`
  - `describeContents()`
  - `getDescriptors()`
  - `ArrayList()`
  - `getPermissions()`
  - `getProperty()`
  - `getUuid()`
  - *(... and 8 more)*

**Notable Strings**:
  - `"BleGattCharacter{uuid="`

---

### BleGattDescriptor [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.model.BleGattDescriptor`
- **Package**: `com.thingclips.sdk.blelib.model`
- **Implements**: `Parcelable`
- **Methods**: 15
- **Fields**: 4
- **Source**: `sdk\blelib\model\BleGattDescriptor.java`

**Key Methods**:
  - `createFromParcel()`
  - `BleGattDescriptor()`
  - `newArray()`
  - `BleGattDescriptor()`
  - `describeContents()`
  - `getmPermissions()`
  - `getmUuid()`
  - `getmValue()`
  - `setmPermissions()`
  - `setmUuid()`
  - *(... and 5 more)*

**Notable Strings**:
  - `"BleGattDescriptor{mUuid="`

---

### BleGattProfile [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.model.BleGattProfile`
- **Package**: `com.thingclips.sdk.blelib.model`
- **Implements**: `Parcelable`
- **Methods**: 18
- **Fields**: 15
- **Source**: `sdk\blelib\model\BleGattProfile.java`

**Key Methods**:
  - `createFromParcel()`
  - `BleGattProfile()`
  - `newArray()`
  - `BleGattProfile()`
  - `ArrayList()`
  - `BleGattService()`
  - `addServices()`
  - `containsCharacter()`
  - `describeContents()`
  - `getBluetoothGattServiceList()`
  - *(... and 8 more)*

---

### BleGattService [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.model.BleGattService`
- **Package**: `com.thingclips.sdk.blelib.model`
- **Implements**: `Parcelable, Comparable`
- **Methods**: 16
- **Fields**: 12
- **Source**: `sdk\blelib\model\BleGattService.java`

**Key Methods**:
  - `createFromParcel()`
  - `BleGattService()`
  - `newArray()`
  - `BleGattService()`
  - `ParcelUuid()`
  - `compareTo()`
  - `getUUID()`
  - `describeContents()`
  - `getCharacters()`
  - `ArrayList()`
  - *(... and 6 more)*

---

### BluetoothUtils [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.utils.BluetoothUtils`
- **Package**: `com.thingclips.sdk.blelib.utils`
- **Methods**: 32
- **Fields**: 31
- **Source**: `sdk\blelib\utils\BluetoothUtils.java`

**Key Methods**:
  - `checkMainThread()`
  - `closeBluetooth()`
  - `getBluetoothAdapter()`
  - `getBluetoothManager()`
  - `getBluetoothState()`
  - `getBondState()`
  - `getRemoteDevice()`
  - `getBondedBluetoothClassicDevices()`
  - `ArrayList()`
  - `getConnectStatus()`
  - *(... and 22 more)*

**Notable Strings**:
  - `"bluetooth"`
  - `"android.hardware.bluetooth_le"`

---

### BluetoothGattProxyHandler [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.utils.hook.BluetoothGattProxyHandler`
- **Package**: `com.thingclips.sdk.blelib.utils.hook`
- **Implements**: `InvocationHandler`
- **Methods**: 2
- **Fields**: 1
- **Source**: `blelib\utils\hook\BluetoothGattProxyHandler.java`

**Key Methods**:
  - `BluetoothGattProxyHandler()`
  - `invoke()`

---

### BluetoothManagerProxyHandler [CRITICAL]


- **Full Name**: `com.thingclips.sdk.blelib.utils.hook.BluetoothManagerProxyHandler`
- **Package**: `com.thingclips.sdk.blelib.utils.hook`
- **Implements**: `InvocationHandler`
- **Methods**: 3
- **Fields**: 2
- **Source**: `blelib\utils\hook\BluetoothManagerProxyHandler.java`

**Key Methods**:
  - `BluetoothManagerProxyHandler()`
  - `invoke()`
  - `BluetoothGattProxyHandler()`

**Notable Strings**:
  - `"android.bluetooth.IBluetoothGatt"`
  - `"android.bluetooth.IBluetoothManager"`
  - `"getBluetoothGatt"`
  - `"getBluetoothGatt"`

---

### ThingBlueMeshPlugin [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluemesh.ThingBlueMeshPlugin`
- **Package**: `com.thingclips.sdk.bluemesh`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingBlueMeshPlugin`
- **Methods**: 34
- **Fields**: 2
- **Source**: `thingclips\sdk\bluemesh\ThingBlueMeshPlugin.java`

**Key Methods**:
  - `dependencies()`
  - `getMeshControl()`
  - `getMeshEventHandler()`
  - `dbqpbdp()`
  - `getMeshInstance()`
  - `getMeshManager()`
  - `getMeshStatusInstance()`
  - `getSigMeshInstance()`
  - `getThingBlueMeshClient()`
  - `getThingBlueMeshConfig()`
  - *(... and 24 more)*

---

### MeshLocalBean [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluemesh.bean.MeshLocalBean`
- **Package**: `com.thingclips.sdk.bluemesh.bean`
- **Methods**: 0
- **Fields**: 4
- **Source**: `sdk\bluemesh\bean\MeshLocalBean.java`

---

### MeshRelationBean [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluemesh.bean.MeshRelationBean`
- **Package**: `com.thingclips.sdk.bluemesh.bean`
- **Methods**: 4
- **Fields**: 2
- **Source**: `sdk\bluemesh\bean\MeshRelationBean.java`

**Key Methods**:
  - `getIsOnline()`
  - `getNodeId()`
  - `setIsOnline()`
  - `setNodeId()`

---

### MeshSubDevWifiStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluemesh.bean.MeshSubDevWifiStatus`
- **Package**: `com.thingclips.sdk.bluemesh.bean`
- **Methods**: 5
- **Fields**: 7
- **Source**: `sdk\bluemesh\bean\MeshSubDevWifiStatus.java`

**Key Methods**:
  - `HashMap()`
  - `MeshSubDevWifiStatus()`
  - `getCloudStatus()`
  - `setDevCloudStatus()`
  - `toString()`

**Notable Strings**:
  - `"MeshSubDevWifiStatus"`
  - `"MeshSubDevWifiStatus{nodeId='"`

---

### SubDevGetDpBean [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluemesh.bean.SubDevGetDpBean`
- **Package**: `com.thingclips.sdk.bluemesh.bean`
- **Methods**: 4
- **Fields**: 2
- **Source**: `sdk\bluemesh\bean\SubDevGetDpBean.java`

**Key Methods**:
  - `getDevId()`
  - `getDpId()`
  - `setDevId()`
  - `setDpId()`

---

### BlueMeshCallback [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluemesh.mesh.utils.BlueMeshCallback`
- **Package**: `com.thingclips.sdk.bluemesh.mesh.utils`
- **Extends**: `Handler`
- **Implements**: `BlueMeshGroupUpdateEvent, pqdbbqp`
- **Methods**: 7
- **Fields**: 9
- **Source**: `bluemesh\mesh\utils\BlueMeshCallback.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `BlueMeshCallback()`
  - `startWait()`
  - `onDestroy()`
  - `onEvent()`

**Notable Strings**:
  - `"BlueMeshCallback"`
  - `"BlueMeshCallback"`
  - `"receive BlueMeshGroupUpdateEventModel1 "`

---

### bbbddqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbbddqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 5
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\bbbddqb.java`

**Key Methods**:
  - `bbbddqb()`
  - `pdqppqb()`
  - `qddqppb()`
  - `qddqppb()`
  - `bdpdqbp()`

---

### bbbdppp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbbdppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Implements**: `ITemporaryCallBack`
- **Methods**: 28
- **Fields**: 27
- **Source**: `thingclips\sdk\bluetooth\bbbdppp.java`

**Key Methods**:
  - `onHandler()`
  - `ArrayList()`
  - `HashMap()`
  - `onHandler()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `ArrayList()`
  - `HashMap()`
  - `ArrayList()`
  - *(... and 18 more)*

**Notable Strings**:
  - `"bluetooth open"`
  - `"bluetooth close"`

---

### bbbdqpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbbdqpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pdbpddd`
- **Implements**: `BleWriteResponse`
- **Methods**: 16
- **Fields**: 25
- **Source**: `thingclips\sdk\bluetooth\bbbdqpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onResponse()`
  - `bppdpdq()`
  - `onResponse()`
  - `pdqppqb()`
  - `onResponse()`
  - `bdpdqbp()`
  - `if()`
  - `bppdpdq()`
  - `pdqppqb()`
  - *(... and 6 more)*

**Notable Strings**:
  - `"SigMeshAction"`

---

### bbbpbqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbbpbqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbqpdbd`
- **Methods**: 62
- **Fields**: 115
- **Source**: `thingclips\sdk\bluetooth\bbbpbqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `qpppdqb()`
  - `pbddddb()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - *(... and 52 more)*

**Notable Strings**:
  - `"ThingMeshParse"`
  - `"ThingMeshParse"`
  - `"ThingMeshParse"`
  - `"ThingMeshParse"`
  - `"ThingMeshParse"`
  - *(... and 2 more)*

---

### bbbpdpd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbbpdpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbqpdbd`
- **Implements**: `IResultCallback`
- **Methods**: 74
- **Fields**: 145
- **Source**: `thingclips\sdk\bluetooth\bbbpdpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `if()`
  - `if()`
  - *(... and 64 more)*

---

### bbddbqp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbddbqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `dbbpbbq`
- **Methods**: 38
- **Fields**: 39
- **Source**: `thingclips\sdk\bluetooth\bbddbqp.java`

**Key Methods**:
  - `bbddbqp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `getSigMeshBean()`
  - `getSigMeshList()`
  - `ArrayList()`
  - `onDestroy()`
  - `pbbppqb()`
  - `pbddddb()`
  - `pbpdpdp()`
  - *(... and 28 more)*

---

### bbdddqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbdddqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bbbdqpb`
- **Methods**: 3
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\bbdddqd.java`

**Key Methods**:
  - `bbdddqd()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### bbddqbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbddqbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Business`
- **Methods**: 5
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\bbddqbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ApiParams()`
  - `bdpdqbp()`

---

### bbpbdqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbpbdqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqpqppd`
- **Methods**: 3
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\bbpbdqq.java`

**Key Methods**:
  - `pbpdpdp()`
  - `pdqppqb()`
  - `qddqppb()`

---

### bbpdppb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbpdppb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dqpbpbd`
- **Methods**: 2
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\bbpdppb.java`

**Key Methods**:
  - `bbpdppb()`
  - `bpbbqdb()`

---

### bbpdqpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbpdqpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 6
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bbpdqpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `getBlueMeshBean()`
  - `getBlueMeshList()`
  - `onDestroy()`
  - `removeBlueMesh()`
  - `updateBuleMesh()`

---

### bbppddp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbppddp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pdbpddd`
- **Implements**: `Handler.Callback`
- **Methods**: 16
- **Fields**: 39
- **Source**: `thingclips\sdk\bluetooth\bbppddp.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `bbppddp()`
  - `qddqppb()`
  - `bppdpdq()`
  - `pdqppqb()`
  - *(... and 6 more)*

**Notable Strings**:
  - `"meshAddress: "`
  - `"mMeshIndex: "`

---

### bbpqqpq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbpqqpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pdbpddd`
- **Implements**: `BleWriteResponse`
- **Methods**: 61
- **Fields**: 83
- **Source**: `thingclips\sdk\bluetooth\bbpqqpq.java`

**Key Methods**:
  - `Handler()`
  - `RunnableC0313bdpdqbp()`
  - `run()`
  - `pdqppqb()`
  - `run()`
  - `bdpdqbp()`
  - `onResponse()`
  - `bppdpdq()`
  - `onResponse()`
  - `pbbppqb()`
  - *(... and 51 more)*

---

### bbqdbpd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbqdbpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 26
- **Fields**: 51
- **Source**: `thingclips\sdk\bluetooth\bbqdbpd.java`

**Key Methods**:
  - `bbqdbpd()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `LightModeStatus()`
  - `ThingVendorTidModelStatus()`
  - `ThingVendorTidReportModelStatus()`
  - `VendorModelStatus()`
  - `GroupDeviceGetStatus()`
  - `ThingVendorModelStatus()`
  - `VendorTimeRequestStatus()`
  - *(... and 16 more)*

**Notable Strings**:
  - `"SigMeshNotifyParseModel"`

---

### bbqqpqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbqqpqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qppbddd`
- **Methods**: 3
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bbqqpqb.java`

**Key Methods**:
  - `bbqqpqb()`
  - `qddqppb()`
  - `bdpdqbp()`

---

### bdbbdpd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdbbdpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqpqppd`
- **Methods**: 8
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\bdbbdpd.java`

**Key Methods**:
  - `bdbbdpd()`
  - `bdpdqbp()`
  - `pbpdbqp()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `qddqppb()`
  - `bdpdqbp()`

---

### bdbbdqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdbbdqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `ISigMeshPreCtrl`
- **Methods**: 13
- **Fields**: 15
- **Source**: `thingclips\sdk\bluetooth\bdbbdqb.java`

**Key Methods**:
  - `Handler()`
  - `AtomicBoolean()`
  - `ArrayList()`
  - `SigMeshBean()`
  - `disConnect()`
  - `disconnectPreCtrl()`
  - `inConfig()`
  - `isConnect()`
  - `onPerFail()`
  - `onPreCtrlConnectFinish()`
  - *(... and 3 more)*

**Notable Strings**:
  - `"SigMeshPreCtrlFastBase"`
  - `"defaultPreCtrlMeshId"`
  - `"[PRE_CONTROL] startConnect return ,because the SigMeshSearchDeviceBeans is empty"`
  - `"[PRE_CONTROL] the meshConnectStatusListener is null, warning!!!"`

---

### bddddpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bddddpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IMeshAdvPreControl`
- **Methods**: 10
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\bddddpp.java`

**Key Methods**:
  - `ppdqdqd()`
  - `flash()`
  - `off()`
  - `m322on()`
  - `reverse()`
  - `flash()`
  - `if()`
  - `off()`
  - `m323on()`
  - `reverse()`

---

### bddpbbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bddpbbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqpqppd`
- **Methods**: 7
- **Fields**: 14
- **Source**: `thingclips\sdk\bluetooth\bddpbbd.java`

**Key Methods**:
  - `bddpbbd()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `qddqppb()`
  - `bddpbbd()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`

---

### bddppdb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bddppdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqpqppd`
- **Methods**: 7
- **Fields**: 12
- **Source**: `thingclips\sdk\bluetooth\bddppdb.java`

**Key Methods**:
  - `bddppdb()`
  - `pbpdbqp()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `qddqppb()`
  - `bddppdb()`
  - `pdqppqb()`

---

### bdpddpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdpddpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqbdppb`
- **Implements**: `pdbpddd.pdqppqb`
- **Methods**: 107
- **Fields**: 83
- **Source**: `thingclips\sdk\bluetooth\bdpddpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bpbbqdb()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onSuccess()`
  - `onError()`
  - `bdpdqbp()`
  - *(... and 97 more)*

**Notable Strings**:
  - `"SigMeshBatchActivatorIm"`
  - `",meshAddress:"`
  - `"saveRemoteGroupDeviceLocalId onFailure, blueMeshSubDevBean.devId:"`
  - `"saveRemoteGroupDeviceLocalId onSuccess, blueMeshSubDevBean.devId:"`
  - `"-------------step----onGroupConfirmRetry-------------meshAddress:"`
  - *(... and 5 more)*

---

### bdqbpbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdqbpbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bdqbpbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onDestroy()`

---

### bdqdqqp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdqdqqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\bdqdqqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `FastDefaultNodeIdModelState()`
  - `FastSetAddressModelState()`
  - `FastConfirmProvisionState()`
  - `FastGroupConfirmState()`

**Notable Strings**:
  - `"SigMeshFastParseModel"`

---

### bdqpppq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdqpppq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `dpdpqpd`
- **Methods**: 21
- **Fields**: 22
- **Source**: `thingclips\sdk\bluetooth\bdqpppq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `bdqpppq()`
  - *(... and 11 more)*

---

### bdqqbbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdqqbbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `IResultWithDataCallback`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bdqqbbd.java`

**Key Methods**:
  - `onTidReceive()`

---

### bpbbpdd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpbbpdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `qddbbpb`
- **Methods**: 13
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\bpbbpdd.java`

**Key Methods**:
  - `bqddqpq()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onSearchCanceled()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onSearchCanceled()`
  - *(... and 3 more)*

---

### bpbdqdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpbdqdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 10
- **Source**: `thingclips\sdk\bluetooth\bpbdqdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `SigMeshSearchDeviceBean()`

**Notable Strings**:
  - `"SigMeshSearchUtils"`

---

### bpbqbbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpbqbbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `ppqqdpb`
- **Methods**: 12
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\bpbqbbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ConfigNetworkTransmitStatus()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `bpbqbbq()`
  - `bdpdqbp()`
  - `ppbbdpd()`
  - *(... and 2 more)*

---

### bpbqdqp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpbqdqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 5
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\bpbqdqp.java`

**Key Methods**:
  - `bpbqdqp()`
  - `dpdbqdp()`
  - `pdqppqb()`
  - `qddqppb()`
  - `bpbqdqp()`

---

### bpbqqdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpbqqdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 52
- **Source**: `thingclips\sdk\bluetooth\bpbqqdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`

**Notable Strings**:
  - `"ble_config_sigmesh"`
  - `"wifi_config_mesh_gateway"`
  - `"ble_config_sigmesh_quick"`
  - `"ble_config_bluemesh"`
  - `"mesh_network_transmit"`
  - *(... and 21 more)*

---

### bpddbpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpddbpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 16
- **Source**: `thingclips\sdk\bluetooth\bpddbpb.java`

**Key Methods**:
  - `Random()`
  - `bdpdqbp()`
  - `bdpdqbp()`

**Notable Strings**:
  - `"MeshAdvDataFactory"`

---

### bpdppdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpdppdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingMeshService`
- **Methods**: 1
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\bpdppdp.java`

**Key Methods**:
  - `passThroughByLocal()`

**Notable Strings**:
  - `"thingble_ThingMeshService"`

---

### bpdpppq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpdpppq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pdbpddd`
- **Implements**: `pdbpddd.pdqppqb`
- **Methods**: 24
- **Fields**: 19
- **Source**: `thingclips\sdk\bluetooth\bpdpppq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `onUnSecretNotify()`
  - `pdqppqb()`
  - `onFailure()`
  - *(... and 14 more)*

**Notable Strings**:
  - `"ResetMeshAddressAction"`
  - `"prepare update mesh address -->"`
  - `"resetDeviceAddress mMeshAddress: "`
  - `"meshAddress: "`

---

### bpdqdpq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpdqdpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Handler`
- **Implements**: `pqdbbqp, qqpdddb`
- **Methods**: 14
- **Fields**: 29
- **Source**: `thingclips\sdk\bluetooth\bpdqdpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bpdqdpq()`
  - `onDestroy()`
  - `onEventMainThread()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `dppdpdp()`
  - `ArrayList()`
  - *(... and 4 more)*

**Notable Strings**:
  - `"SigMeshCommandCallBack"`
  - `"SigMeshCommandCallBack"`
  - `"SigMeshCommandCallBack"`
  - `">>>>>>>>SigMeshCommandCallBack:"`
  - `"SigMeshCommandCallBack"`
  - *(... and 16 more)*

---

### bpdqqdb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpdqqdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `ppqqdpb`
- **Methods**: 21
- **Fields**: 27
- **Source**: `thingclips\sdk\bluetooth\bpdqqdb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `Handler()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ConfigModelPublicationStatus()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 11 more)*

**Notable Strings**:
  - `"provisionedMeshNode is null"`

---

### bppdqbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bppdqbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dbbbbdb`
- **Methods**: 53
- **Fields**: 171
- **Source**: `thingclips\sdk\bluetooth\bppdqbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pbddddb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `pppbppp()`
  - `StringBuilder()`
  - *(... and 43 more)*

---

### bppqbqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bppqbqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 8
- **Fields**: 17
- **Source**: `thingclips\sdk\bluetooth\bppqbqb.java`

**Key Methods**:
  - `ArrayList()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ScanDeviceBean()`
  - `if()`

**Notable Strings**:
  - `"out_of_mesh"`
  - `"MeshScanFilter"`
  - `"out_of_mesh"`
  - `"MeshProvider"`
  - `"SIG Mesh"`
  - *(... and 1 more)*

---

### bppqdpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bppqdpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 6
- **Fields**: 10
- **Source**: `thingclips\sdk\bluetooth\bppqdpb.java`

**Key Methods**:
  - `bppqdpb()`
  - `pdqppqb()`
  - `qddqppb()`
  - `ArrayList()`
  - `qddqppb()`
  - `bdpdqbp()`

---

### bpqddqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpqddqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `com.thingclips.sdk.bluetooth.pbpdpdp<SigMeshBean>`
- **Implements**: `ISigMeshControl`
- **Methods**: 118
- **Fields**: 158
- **Source**: `thingclips\sdk\bluetooth\bpqddqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `onDevInfoUpdate()`
  - `onDpUpdate()`
  - `onNetworkStatusChanged()`
  - `onRemoved()`
  - `onStatusChanged()`
  - `pbbppqb()`
  - `pbddddb()`
  - `onError()`
  - *(... and 108 more)*

**Notable Strings**:
  - `"MeshController"`
  - `"clearDpPoll,meshId:"`
  - `"connect MeshConnectBuilder is null"`
  - `"connect wireMeshConnectImpl is not null"`
  - `"removeDpFromDpPoll,meshId:"`
  - *(... and 4 more)*

---

### bpqqqpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpqqqpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BasePresenter`
- **Implements**: `IBlueMeshManager`
- **Methods**: 23
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\bpqqqpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bpqqqpp()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `getInstance()`
  - `createBlueMesh()`
  - `getBlueMeshBean()`
  - *(... and 13 more)*

---

### bqbbpdd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqbbpdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bbbdqpb`
- **Methods**: 5
- **Fields**: 17
- **Source**: `thingclips\sdk\bluetooth\bqbbpdd.java`

**Key Methods**:
  - `bqbbpdd()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`

---

### bqbdqdd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqbdqdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Business`
- **Methods**: 6
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\bqbdqdd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `pdqppqb()`

**Notable Strings**:
  - `"sourceMeshId"`
  - `"targetMeshId"`
  - `"sourceMeshId"`
  - `"targetMeshId"`
  - `"sourceMeshId"`
  - *(... and 7 more)*

---

### bqbpbdd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqbpbdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `qdpdpbq, bdqbpbb`
- **Methods**: 37
- **Fields**: 26
- **Source**: `thingclips\sdk\bluetooth\bqbpbdd.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `run()`
  - `onConnectAndNotificationSuccess()`
  - `onModuleFail()`
  - `pdqppqb()`
  - `pdqppqb()`
  - *(... and 27 more)*

**Notable Strings**:
  - `"SigMeshBatchConnectModule"`

---

### bqdbbqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqdbbqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 5
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\bqdbbqq.java`

**Key Methods**:
  - `bqdbbqq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `qddqppb()`
  - `bdpdqbp()`

---

### bqddbpd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqddbpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Handler`
- **Implements**: `pqdbbqp, qqpdddb`
- **Methods**: 7
- **Fields**: 13
- **Source**: `thingclips\sdk\bluetooth\bqddbpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bqddbpd()`
  - `onDestroy()`
  - `onEventMainThread()`
  - `bdpdqbp()`

**Notable Strings**:
  - `"SigMeshCommandCallBack"`
  - `"SigMeshCommandCallBack"`
  - `"SigMeshCommandCallBack"`
  - `"SigMeshCommandCallBack"`
  - `"SigMeshCommandCallBack"`

---

### bqddbqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqddbqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bbbdqpb`
- **Methods**: 17
- **Fields**: 27
- **Source**: `thingclips\sdk\bluetooth\bqddbqd.java`

**Key Methods**:
  - `bqddbqd()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `StringBuilder()`
  - `StringBuilder()`
  - `StringBuilder()`
  - `StringBuilder()`
  - `StringBuilder()`
  - `StringBuilder()`
  - *(... and 7 more)*

---

### bqddqpq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqddqpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `LeScanResponse`
- **Methods**: 25
- **Fields**: 45
- **Source**: `thingclips\sdk\bluetooth\bqddqpq.java`

**Key Methods**:
  - `ArrayList()`
  - `bdpdqbp()`
  - `filter()`
  - `filterOnly()`
  - `bppdpdq()`
  - `filter()`
  - `filterOnly()`
  - `pdqppqb()`
  - `filter()`
  - `filterOnly()`
  - *(... and 15 more)*

**Notable Strings**:
  - `"BlueMeshSearch"`
  - `"found mesh device,mac address is :"`
  - `"out_of_mesh"`
  - `"searchDeviceUnConnect uuid"`
  - `"serviceUUIDs is empty"`
  - *(... and 1 more)*

---

### bqdpqdd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqdpqdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 14
- **Fields**: 53
- **Source**: `thingclips\sdk\bluetooth\bqdpqdd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `qdbpbqd()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `JSONObject()`
  - `if()`
  - `if()`
  - `if()`
  - *(... and 4 more)*

---

### bqdqdqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqdqdqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `pdbpddd.pdqppqb`
- **Methods**: 63
- **Fields**: 35
- **Source**: `thingclips\sdk\bluetooth\bqdqdqq.java`

**Key Methods**:
  - `bqdqdqq()`
  - `ConcurrentHashMap()`
  - `pbdpddb()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `qddqppb()`
  - *(... and 53 more)*

**Notable Strings**:
  - `"SigMeshLocalManager"`
  - `"initMeshTransport error, provisionedMeshNode is null "`
  - `"----initMeshTransport  nodeMac is---"`

---

### bqdqqqp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqdqqqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqpqqbb`
- **Methods**: 5
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\bqdqqqp.java`

**Key Methods**:
  - `bqdqqqp()`
  - `getAid()`
  - `getAkf()`
  - `getParameters()`
  - `parseStatusParameters()`

---

### bqpbddq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqpbddq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\bqpbddq.java`

**Notable Strings**:
  - `"com.thingclips.smart.meshlib"`

---

### bqpdppq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqpdppq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdbqdp`
- **Methods**: 26
- **Fields**: 53
- **Source**: `thingclips\sdk\bluetooth\bqpdppq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `StringBuilder()`
  - `StringBuilder()`
  - `pbbppqb()`
  - `StringBuilder()`
  - `StringBuilder()`
  - `pdqppqb()`
  - `pdqppqb()`
  - *(... and 16 more)*

---

### bqpdpqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqpdpqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bqpdpqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onDestroy()`

---

### bqpdqdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqpdqdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Handler`
- **Implements**: `pqdbbqp, BlueMeshQueryGroupDevEvent`
- **Methods**: 8
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\bqpdqdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `HashSet()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bqpdqdp()`
  - `startWait()`
  - `onDestroy()`
  - `onEvent()`

**Notable Strings**:
  - `"BlueMeshCallback"`
  - `"BlueMeshCallback"`
  - `"receive BlueMeshQueryGroupDevEventModel "`

---

### bqpdqqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqpdqqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 18
- **Fields**: 24
- **Source**: `thingclips\sdk\bluetooth\bqpdqqd.java`

**Key Methods**:
  - `bqpdqqd()`
  - `StringBuilder()`
  - `pdqppqb()`
  - `bqpdqqd()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pppbppp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - *(... and 8 more)*

**Notable Strings**:
  - `"sig_mesh"`
  - `"sig_mesh_iv_index"`
  - `"sig_mesh_storage"`
  - `"sig_mesh_address"`
  - `"sig_mesh_seq"`
  - *(... and 1 more)*

---

### bqppdpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqppdpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bqppdpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### bqpqbqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqpqbqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BleConnectStatusListener`
- **Implements**: `Runnable`
- **Methods**: 31
- **Fields**: 17
- **Source**: `thingclips\sdk\bluetooth\bqpqbqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `Handler()`
  - `bdpdqbp()`
  - `onConnectStatusChanged()`
  - `bppdpdq()`
  - `run()`
  - `pdqppqb()`
  - `onResponse()`
  - `pppbppp()`
  - `onResponse()`
  - *(... and 21 more)*

**Notable Strings**:
  - `"ConnectSigMesh"`

---

### bqqppbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqqppbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 5
- **Fields**: 9
- **Source**: `thingclips\sdk\bluetooth\bqqppbp.java`

**Key Methods**:
  - `bqqppbp()`
  - `pdqppqb()`
  - `qddqppb()`
  - `qddqppb()`
  - `bdpdqbp()`

---

### dbbbbdb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbbbbdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bqpdppq`
- **Implements**: `Runnable`
- **Methods**: 52
- **Fields**: 161
- **Source**: `thingclips\sdk\bluetooth\dbbbbdb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `run()`
  - `pdqppqb()`
  - `run()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - *(... and 42 more)*

---

### dbbpbbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbbpbbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 14
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dbbpbbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bppdpdq()`
  - `getSigMeshBean()`
  - `getSigMeshList()`
  - `onDestroy()`
  - `pdqppqb()`
  - `pdqppqb()`
  - *(... and 4 more)*

---

### dbbqppd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbbqppd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BluetoothGattCallback`
- **Methods**: 10
- **Fields**: 21
- **Source**: `thingclips\sdk\bluetooth\dbbqppd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onConnectionStateChange()`
  - `StringBuilder()`
  - `bdpdqbp()`
  - `dbbqppd()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

**Notable Strings**:
  - `"blue_RawGattConnect"`
  - `"mBluetoothGatt is not empty"`
  - `"openAutoGatt: address :"`
  - `"openGatt failed: connectGatt return null!"`
  - `"connectGatt"`
  - *(... and 2 more)*

---

### dbdddqp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbdddqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bbpqqpq`
- **Implements**: `Runnable`
- **Methods**: 44
- **Fields**: 54
- **Source**: `thingclips\sdk\bluetooth\dbdddqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `onFailure()`
  - `pbbppqb()`
  - `onResponse()`
  - `HashMap()`
  - `bdpdqbp()`
  - `run()`
  - *(... and 34 more)*

**Notable Strings**:
  - `"meshCategoryExt"`

---

### dbddpbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbddpbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 64
- **Source**: `thingclips\sdk\bluetooth\dbddpbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### dbddqqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbddqqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 18
- **Fields**: 18
- **Source**: `thingclips\sdk\bluetooth\dbddqqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pbddddb()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `qpppdqb()`
  - `bdpdqbp()`
  - *(... and 8 more)*

---

### dbdqbbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbdqbbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\dbdqbbb.java`

**Key Methods**:
  - `bdpdqbp()`

**Notable Strings**:
  - `"ThingMeshFittingsParse"`

---

### dbpdbdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbpdbdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Business`
- **Implements**: `IThingBlueMeshBusiness<BusinessResponse>`
- **Methods**: 39
- **Fields**: 38
- **Source**: `thingclips\sdk\bluetooth\dbpdbdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `qddqppb()`
  - *(... and 29 more)*

**Notable Strings**:
  - `"thing.m.device.ble.mesh.local.id.alloc"`
  - `"thing.m.my.group.mesh.list"`
  - `"thing.m.device.ble.mesh.node.alloc"`
  - `"thing.m.mesh.relation.list"`
  - `"thing.m.device.sig.mesh.list"`
  - *(... and 15 more)*

---

### dbpqbpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbpqbpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<HashMap<String`
- **Methods**: 12
- **Fields**: 31
- **Source**: `thingclips\sdk\bluetooth\dbpqbpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bppdpdq()`
  - `HashMap()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `HashMap()`
  - `ArrayList()`
  - *(... and 2 more)*

---

### dbpqbqp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbpqbqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dbpqbqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### dbpqqbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbpqqbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Handler`
- **Implements**: `IResultCallback`
- **Methods**: 56
- **Fields**: 58
- **Source**: `thingclips\sdk\bluetooth\dbpqqbp.java`

**Key Methods**:
  - `dbpqqbp()`
  - `HashMap()`
  - `ConcurrentHashMap()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `if()`
  - `ArrayList()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - *(... and 46 more)*

**Notable Strings**:
  - `"ThingSigMeshLocalOnlineManager"`
  - `"meshId"`
  - `"sigmesh-handler-thread"`
  - `"getDevStatus error mesh is null, meshId "`
  - `"setSubDeviceStatus() called with: meshId = ["`
  - *(... and 5 more)*

---

### dbqbdbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbqbdbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dbqbdbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### dbqddbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbqddbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `ppddqpb`
- **Implements**: `pbbpbdb`
- **Methods**: 16
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\dbqddbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onError()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `onError()`
  - `dbqddbp()`
  - `qbqbbdd()`
  - `bdpdqbp()`
  - `pbpdpdp()`
  - *(... and 6 more)*

---

### dbqpbdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbqpbdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IMeshEventHandler`
- **Methods**: 5
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\dbqpbdp.java`

**Key Methods**:
  - `convertIdToCodeMap()`
  - `dpCacheUpdate()`
  - `getDevListStatus()`
  - `onLineStatusCacheUpdate()`
  - `rawParser()`

---

### dbqpddd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbqpddd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 21
- **Fields**: 51
- **Source**: `thingclips\sdk\bluetooth\dbqpddd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `ThingSigMeshBean()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `ThingSigMeshBean()`
  - `pdqppqb()`
  - `SearchDeviceBean()`
  - `bdpdqbp()`
  - *(... and 11 more)*

**Notable Strings**:
  - `"MeshUtil"`
  - `"MeshUtil"`
  - `"MeshUtil"`

---

### dbqpdqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbqpdqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `bbpdqpp`
- **Methods**: 15
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\dbqpdqq.java`

**Key Methods**:
  - `dbqpdqq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `getBlueMeshBean()`
  - `getBlueMeshList()`
  - `ArrayList()`
  - `onDestroy()`
  - `removeBlueMesh()`
  - `updateBuleMesh()`
  - `dbqpdqq()`
  - *(... and 5 more)*

---

### dbqpppd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbqpppd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqpqppd`
- **Methods**: 6
- **Fields**: 12
- **Source**: `thingclips\sdk\bluetooth\dbqpppd.java`

**Key Methods**:
  - `dbqpppd()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `qddqppb()`
  - `dbqpppd()`
  - `IllegalArgumentException()`

---

### dbqpppq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbqpppq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dbqpppq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onDestroy()`
  - `pdqppqb()`

---

### dbqqppp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbqqppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Business`
- **Methods**: 7
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\dbqqppp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ApiParams()`
  - `bdpdqbp()`
  - `HashMap()`
  - `bdpdqbp()`
  - `ApiParams()`
  - `HashMap()`

**Notable Strings**:
  - `"meshId"`

---

### dbqqqdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbqqqdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `dpdpqpd`
- **Methods**: 12
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\dbqqqdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `dbqqqdq()`
  - `bdpdqbp()`
  - `pppbdbp()`
  - `pdqppqb()`
  - *(... and 2 more)*

---

### ddbbddp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbbddp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `dpdpqpd`
- **Methods**: 16
- **Fields**: 17
- **Source**: `thingclips\sdk\bluetooth\ddbbddp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `if()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `ddbbddp()`
  - `pdqppqb()`
  - `StringBuilder()`
  - *(... and 6 more)*

---

### ddbdbqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbdbqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBlueMeshGroup`
- **Methods**: 79
- **Fields**: 33
- **Source**: `thingclips\sdk\bluetooth\ddbdbqq.java`

**Key Methods**:
  - `dddbppp()`
  - `pbqdpqb()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onError()`
  - *(... and 69 more)*

**Notable Strings**:
  - `"ThingBlueMeshLocalGroup"`
  - `"mesh group address is not able:"`
  - `"mesh_off_line"`
  - `"mesh group address is not able:"`
  - `"mesh_off_line"`
  - *(... and 6 more)*

---

### ddbdppp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbdppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 2
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\ddbdppp.java`

**Key Methods**:
  - `ddbdppp()`
  - `qddqppb()`

---

### ddbpdpq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbpdpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\ddbpdpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `FastDefaultNodeIdModelState()`
  - `FastSetAddressModelState()`
  - `FastConfirmProvisionState()`

**Notable Strings**:
  - `"SigMeshFastParseModel"`

---

### ddbpqbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbpqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `ppqqdpb`
- **Methods**: 12
- **Fields**: 10
- **Source**: `thingclips\sdk\bluetooth\ddbpqbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ConfigCompositionDataStatus()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `ddbpqbb()`
  - `bdpdqbp()`
  - `ppbdqqp()`
  - *(... and 2 more)*

---

### dddbppp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dddbppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `pdbpddd.pdqppqb`
- **Methods**: 35
- **Fields**: 16
- **Source**: `thingclips\sdk\bluetooth\dddbppp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `pppbppp()`
  - *(... and 25 more)*

**Notable Strings**:
  - `"ThingBlueMeshGroupControl"`

---

### dddbqdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dddbqdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 23
- **Source**: `thingclips\sdk\bluetooth\dddbqdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `StringBuffer()`
  - `SearchDeviceBean()`

**Notable Strings**:
  - `"out_of_mesh"`

---

### ddddbdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddddbdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `pdbpddd.pdqppqb`
- **Methods**: 7
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\ddddbdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `ddddbdq()`
  - `bdpdqbp()`
  - `dqqdbqp()`
  - `bdpdqbp()`

**Notable Strings**:
  - `"ResetMeshNameAndPassword"`
  - `"reset mesh Name onFailure"`
  - `"reset mesh Name Success"`

---

### ddddpdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddddpdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\ddddpdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### dddqpdb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dddqpdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `MeshLocalOnlineStatusUpdateEvent, MqttConnectStatusEvent, NetWorkStatusEvent, DevUpdateEvent, DeviceUpdateEvent, MeshOnlineStatusUpdateEvent, MeshDpUpdateEvent, MeshRawReportEvent, MeshBatchReportEvent, ZigbeeSubDevDpUpdateEvent, MeshDeviceRelationUpdateEvent`
- **Methods**: 49
- **Fields**: 50
- **Source**: `thingclips\sdk\bluetooth\dddqpdb.java`

**Key Methods**:
  - `HashMap()`
  - `CopyOnWriteArrayList()`
  - `bdpdqbp()`
  - `run()`
  - `dddqpdb()`
  - `getDevListCacheManager()`
  - `getInstance()`
  - `dddqpdb()`
  - `isServiceConnect()`
  - `netStatusCheck()`
  - *(... and 39 more)*

**Notable Strings**:
  - `"meshId"`

---

### dddqqqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dddqqqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dddqqqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### ddpdbbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddpdbbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 56
- **Source**: `thingclips\sdk\bluetooth\ddpdbbp.java`

**Notable Strings**:
  - `"mesh group address is not able"`
  - `"pre_ctrl_mesh_action_nodeid_is_null"`
  - `"pre_ctrl_mesh_action_is_null"`
  - `"The mesh has not been initialized"`

---

### ddpdbdb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddpdbdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\ddpdbdb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### ddppbpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddppbpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BasePresenter`
- **Implements**: `dqddqpb`
- **Methods**: 35
- **Fields**: 57
- **Source**: `thingclips\sdk\bluetooth\ddppbpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onBluetoothStateChanged()`
  - `bdpdqbp()`
  - `run()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `onUnSecretNotify()`
  - *(... and 25 more)*

**Notable Strings**:
  - `"ThingBlueMeshConnectImpl"`
  - `"bluetoothClosed or stopSearch"`

---

### ddppdbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddppdbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `ppqqdpb`
- **Methods**: 13
- **Fields**: 13
- **Source**: `thingclips\sdk\bluetooth\ddppdbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ConfigAppKeyStatus()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `ddppdbq()`
  - `bdpdqbp()`
  - `ApplicationKey()`
  - *(... and 3 more)*

---

### ddpqqqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddpqqqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\ddpqqqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### dpbbdqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpbbdqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\dpbbdqq.java`

**Key Methods**:
  - `bdpdqbp()`

---

### dpbbpqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpbbpqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Handler`
- **Implements**: `dbqbdbp`
- **Methods**: 135
- **Fields**: 104
- **Source**: `thingclips\sdk\bluetooth\dpbbpqd.java`

**Key Methods**:
  - `ArrayList()`
  - `ArrayList()`
  - `HashMap()`
  - `RunnableC0316bdpdqbp()`
  - `run()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - *(... and 125 more)*

**Notable Strings**:
  - `"ThingSigMeshProvisioningImpl"`
  - `"disconnect mesh ble connect because the mac is different!"`

---

### dpbppdd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpbppdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dpbppdd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### dpdbddb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpdbddb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IDeviceMqttProtocolListener<MQ_1_ConnectStatusChangeBean>`
- **Methods**: 11
- **Fields**: 22
- **Source**: `thingclips\sdk\bluetooth\dpdbddb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onResult()`
  - `pdqppqb()`
  - `onConnectStatusChanged()`
  - `dpdbddb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 1 more)*

**Notable Strings**:
  - `", meshId = "`

---

### dpdbqdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpdbqdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 10
- **Fields**: 23
- **Source**: `thingclips\sdk\bluetooth\dpdbqdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `StringBuilder()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `StringBuilder()`
  - `StringBuilder()`
  - `bdpdqbp()`

---

### dpddbbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpddbbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Implements**: `IThingBlueMeshDevice`
- **Methods**: 104
- **Fields**: 112
- **Source**: `thingclips\sdk\bluetooth\dpddbbb.java`

**Key Methods**:
  - `HashMap()`
  - `HashMap()`
  - `Timer()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bpdqdpq()`
  - `pdqppqb()`
  - `onFailure()`
  - *(... and 94 more)*

**Notable Strings**:
  - `"ThingSigMeshDevice"`
  - `"mesh_off_line"`
  - `"mesh_off_line"`
  - `"mesh_off_line"`
  - `"mesh_address_error"`
  - *(... and 3 more)*

---

### dpddddp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpddddp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `IMeshCommonControl>`
- **Implements**: `IThingMeshManager`
- **Methods**: 56
- **Fields**: 49
- **Source**: `thingclips\sdk\bluetooth\dpddddp.java`

**Key Methods**:
  - `SigMeshGlobalConfiguration()`
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `pqppbdp()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - *(... and 46 more)*

**Notable Strings**:
  - `"thingmesh_ThingAllMeshManager"`
  - `"addMeshConnectTask: builderList size = "`
  - `"connectMesh: connect task is full, please wait "`
  - `"The mesh has not been initialized yet. Please call initmesh to initialize the mesh first"`
  - `"The mesh has not been initialized yet. Please call initmesh to initialize the mesh first"`
  - *(... and 3 more)*

---

### dpdddpq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpdddpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BaseModel`
- **Implements**: `BleConnectResponse`
- **Methods**: 36
- **Fields**: 49
- **Source**: `thingclips\sdk\bluetooth\dpdddpq.java`

**Key Methods**:
  - `bppdpdq()`
  - `onConnectStatusChanged()`
  - `pdqppqb()`
  - `onResponse()`
  - `qddqppb()`
  - `onResponse()`
  - `dpdddpq()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `ThingSigMeshBean()`
  - *(... and 26 more)*

**Notable Strings**:
  - `"SigMeshLogin"`
  - `"stopConnect  mMeshLogin:"`

---

### dpdpbdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpdpbdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BasePresenter`
- **Implements**: `IThingExtBlueMeshOta, bbpqqpq.qpppdqb`
- **Methods**: 65
- **Fields**: 60
- **Source**: `thingclips\sdk\bluetooth\dpdpbdq.java`

**Key Methods**:
  - `qddqppb()`
  - `C0317bdpdqbp()`
  - `onConnectStatusChanged()`
  - `pdqppqb()`
  - `onConnectAndNotificationSuccess()`
  - `onModuleFail()`
  - `bdpdqbp()`
  - `run()`
  - `SearchDeviceBean()`
  - `pdqppqb()`
  - *(... and 55 more)*

**Notable Strings**:
  - `"ThingSigMeshOtaImpl"`
  - `"BlueMeshBean is null , please connect"`

---

### dpdqqdd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpdqqdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `qdpdpbq, dqdpqpq`
- **Methods**: 35
- **Fields**: 24
- **Source**: `thingclips\sdk\bluetooth\dpdqqdd.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `run()`
  - `onConnectAndNotificationSuccess()`
  - `onModuleFail()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - *(... and 25 more)*

**Notable Strings**:
  - `"SigMeshFastPreCtrlConnectModule"`

---

### dppbddb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dppbddb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `IMeshCommonControl>`
- **Methods**: 6
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\dppbddb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bpqddqq()`
  - `pqqdqpq()`
  - `bdpdqbp()`
  - `bpqddqq()`
  - `pqqdqpq()`

---

### dppdqpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dppdqpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IBlueMeshActivatorListener`
- **Methods**: 7
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\dppdqpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onStep()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### dpppbbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpppbbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BasePresenter`
- **Implements**: `ICheckDevActiveStatusByTokenListener, IThingBlueMeshActivator`
- **Methods**: 12
- **Fields**: 17
- **Source**: `thingclips\sdk\bluetooth\dpppbbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `dpppbbd()`
  - `getFailMap()`
  - `onDestroy()`
  - `onDevOnline()`
  - `bdpdqbp()`
  - `onFind()`
  - `onFindErrorList()`
  - *(... and 2 more)*

**Notable Strings**:
  - `"ThingBlueMeshActivatorStatusImpl"`

---

### dpppbdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpppbdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbqpdbd`
- **Methods**: 12
- **Fields**: 13
- **Source**: `thingclips\sdk\bluetooth\dpppbdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `HashMap()`
  - `if()`
  - `bdpdqbp()`
  - *(... and 2 more)*

---

### dpppdpq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpppdpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 25
- **Source**: `thingclips\sdk\bluetooth\dpppdpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `StringBuffer()`
  - `SearchDeviceBean()`

**Notable Strings**:
  - `"out_of_mesh"`

---

### dppqddd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dppqddd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IResultCallback`
- **Methods**: 32
- **Fields**: 46
- **Source**: `thingclips\sdk\bluetooth\dppqddd.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `onError()`
  - `StringBuilder()`
  - `onSuccess()`
  - `dppqddd()`
  - `bdpdqbp()`
  - `onError()`
  - `StringBuilder()`
  - `onSuccess()`
  - *(... and 22 more)*

**Notable Strings**:
  - `"queryMeshLanStatus onError, gwId: "`
  - `"queryMeshLanStatus onSuccess, gwId: "`
  - `"queryMeshLanStatus return , dev is empty!"`
  - `"queryMeshLanStatus error, devModel is null"`

---

### dpqdqbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpqdqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Business.ResultListener<Boolean>`
- **Methods**: 76
- **Fields**: 56
- **Source**: `thingclips\sdk\bluetooth\dpqdqbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `run()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `pbddddb()`
  - `onError()`
  - *(... and 66 more)*

**Notable Strings**:
  - `"contain other meshId"`
  - `"not a sigmesh ,ble or beacon device"`
  - `"remove device, not a sigmesh or ble device"`

---

### dpqdqbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpqdqbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 5
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\dpqdqbp.java`

**Key Methods**:
  - `dpqdqbp()`
  - `pdqppqb()`
  - `qddqppb()`
  - `qddqppb()`
  - `bdpdqbp()`

---

### dpqqpqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpqqpqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qbdpdpp`
- **Methods**: 4
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\dpqqpqq.java`

**Key Methods**:
  - `dpqqpqq()`
  - `pbddddb()`
  - `pdqppqb()`
  - `qddqppb()`

---

### dqbbqbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqbbqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dqpbpbd`
- **Methods**: 15
- **Fields**: 25
- **Source**: `thingclips\sdk\bluetooth\dqbbqbb.java`

**Key Methods**:
  - `dqbbqbb()`
  - `bdpdqbp()`
  - `bpbbqdb()`
  - `bqqppqq()`
  - `dpdbqdp()`
  - `pdqppqb()`
  - `qddqppb()`
  - `ArrayList()`
  - `if()`
  - `if()`
  - *(... and 5 more)*

---

### dqbqdbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqbqdbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\dqbqdbq.java`

**Notable Strings**:
  - `"thing.m.device.sig.mesh.node.alloc.batch"`
  - `"thing.m.device.ble.mesh.join"`
  - `"thing.m.device.ble.mesh.local.id.alloc"`
  - `"thing.m.device.ble.mesh.node.alloc"`

---

### dqbqdqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqbqdqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 7
- **Fields**: 21
- **Source**: `thingclips\sdk\bluetooth\dqbqdqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `qpppdqb()`

---

### dqbqpqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqbqpqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dqbqpqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onFinish()`

---

### dqdbddp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqdbddp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 86
- **Fields**: 133
- **Source**: `thingclips\sdk\bluetooth\dqdbddp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bpbbqdb()`
  - `IllegalArgumentException()`
  - `bppdpdq()`
  - `StringBuilder()`
  - `bpqqdpq()`
  - `bqqppqq()`
  - `dbbpbbb()`
  - `dpdbqdp()`
  - *(... and 76 more)*

**Notable Strings**:
  - `"SigMeshUtil"`

---

### dqdbqbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqdbqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pdbpddd`
- **Implements**: `BleNotifyResponse`
- **Methods**: 20
- **Fields**: 23
- **Source**: `thingclips\sdk\bluetooth\dqdbqbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onNotify()`
  - `onResponse()`
  - `bppdpdq()`
  - `onResponse()`
  - `pdqppqb()`
  - `onResponse()`
  - `bdpdqbp()`
  - `onUnSecretNotify()`
  - *(... and 10 more)*

---

### dqddqpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqddqpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 6
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dqddqpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `getStatus()`
  - `startSearch()`
  - `stopConnect()`
  - `stopSearch()`

---

### dqdpbbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqdpbbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbqpdbd`
- **Methods**: 28
- **Fields**: 99
- **Source**: `thingclips\sdk\bluetooth\dqdpbbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `HashMap()`
  - `if()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 18 more)*

**Notable Strings**:
  - `"Method not decompiled: com.thingclips.sdk.bluetooth.dqdpbbd.bdpdqbp(com.thingclips.smart.android.blemesh.bean.DpsParseBean, int, java.lang.Object):com.thingclips.smart.android.blemesh.bean.DpsParseBean"`

---

### dqdpqpq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqdpqpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dqdpqpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onDestroy()`

---

### dqdqbbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqdqbbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Handler.Callback`
- **Methods**: 26
- **Fields**: 31
- **Source**: `thingclips\sdk\bluetooth\dqdqbbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `ArrayList()`
  - `Handler()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `CopyOnWriteArrayList()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - *(... and 16 more)*

**Notable Strings**:
  - `"   meshAddress:"`
  - `"provisionedMeshNode is null"`
  - `"bind model fail provisionedMeshNode is null"`

---

### dqpbpbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqpbpbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 13
- **Fields**: 24
- **Source**: `thingclips\sdk\bluetooth\dqpbpbd.java`

**Key Methods**:
  - `dqpbpbd()`
  - `bdpdqbp()`
  - `bpbbqdb()`
  - `dpdbqdp()`
  - `pdqppqb()`
  - `qddqppb()`
  - `ArrayList()`
  - `if()`
  - `if()`
  - `if()`
  - *(... and 3 more)*

---

### dqppddd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqppddd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bbpqqpq`
- **Implements**: `pqdqbpp.pppbppp`
- **Methods**: 78
- **Fields**: 73
- **Source**: `thingclips\sdk\bluetooth\dqppddd.java`

**Key Methods**:
  - `RunnableC0318bdpdqbp()`
  - `run()`
  - `pdqppqb()`
  - `run()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `onUnSecretNotify()`
  - `if()`
  - *(... and 68 more)*

---

### dqqbbqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqqbbqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqpqppd`
- **Methods**: 5
- **Fields**: 12
- **Source**: `thingclips\sdk\bluetooth\dqqbbqb.java`

**Key Methods**:
  - `dqqbbqb()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `qddqppb()`
  - `dqqbbqb()`

---

### dqqbpdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqqbpdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Business`
- **Implements**: `pdbbpqd`
- **Methods**: 23
- **Fields**: 22
- **Source**: `thingclips\sdk\bluetooth\dqqbpdq.java`

**Key Methods**:
  - `C0319bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `C0319bdpdqbp()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - *(... and 13 more)*

**Notable Strings**:
  - `"meshId"`
  - `"meshId"`
  - `"thing.m.device.ble.mesh.join"`
  - `"meshId"`
  - `"thing.m.device.ble.mesh.join"`
  - *(... and 3 more)*

---

### dqqdbqp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqqdbqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pdbpddd`
- **Implements**: `BleReadResponse`
- **Methods**: 27
- **Fields**: 40
- **Source**: `thingclips\sdk\bluetooth\dqqdbqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bppdpdq()`
  - `onResponse()`
  - `if()`
  - `C0320bdpdqbp()`
  - `onResponse()`
  - `bdpdqbp()`
  - *(... and 17 more)*

**Notable Strings**:
  - `"ResetMeshAction"`
  - `"set mesh failure"`
  - `"set mesh failure"`
  - `"set mesh failure"`

---

### pbbpppd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbbpppd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pbbpppd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pbbqbqp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbbqbqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBlueMeshClient`
- **Methods**: 22
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\pbbqbqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `handleMessage()`
  - `pbbqbqp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `onError()`
  - `getInstance()`
  - `startConnect()`
  - `pdqppqb()`
  - `destroyMesh()`
  - *(... and 12 more)*

**Notable Strings**:
  - `"ThingBlueMeshClient huohuo"`
  - `"startConnect fail mBlueMeshBean is null"`
  - `"mesh stopSearch"`

---

### pbdbppp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbdbppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 8
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\pbdbppp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bddppdb()`
  - `bdpdqbp()`
  - `qpqdddp()`
  - `bdpdqbp()`
  - `bddpddp()`

---

### pbddbqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbddbqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pbddbqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pbdpddb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbdpddb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bppdqbp`
- **Methods**: 24
- **Fields**: 24
- **Source**: `thingclips\sdk\bluetooth\pbdpddb.java`

**Key Methods**:
  - `pbdpddb()`
  - `bdpdqbp()`
  - `Handler()`
  - `bppdpdq()`
  - `pbpdbqp()`
  - `pbpdpdp()`
  - `pbddddb()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `qpppdqb()`
  - *(... and 14 more)*

**Notable Strings**:
  - `"createVendorMeshMessage"`

---

### pbpdpdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbpdpdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BlueMeshBean>`
- **Implements**: `IMeshCommonControl`
- **Methods**: 16
- **Fields**: 12
- **Source**: `thingclips\sdk\bluetooth\pbpdpdp.java`

**Key Methods**:
  - `CopyOnWriteArrayList()`
  - `pbpdpdp()`
  - `qdbpbqd()`
  - `clearDevice()`
  - `disConnectWireNodeId()`
  - `isInConfig()`
  - `getStatus()`
  - `isMeshLocalOnLine()`
  - `getStatus()`
  - `onDestroy()`
  - *(... and 6 more)*

**Notable Strings**:
  - `"thingble_AbsMeshController"`
  - `"registerMeshDevListener no connect permission"`
  - `"unRegisterMeshDevListener no connect permission"`

---

### pbppbbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbppbbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 16
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\pbppbbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bbbpdpd()`
  - `bbbpbqd()`
  - *(... and 6 more)*

**Notable Strings**:
  - `"ParseMeshUtils"`

---

### pbqbppd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbqbppd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `dpdpqpd`
- **Methods**: 11
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\pbqbppd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `pbqbppd()`
  - `bdpdqbp()`
  - `bqddbqd()`
  - `pdqppqb()`
  - *(... and 1 more)*

---

### pbqbqdb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbqbqdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `LeScanResponse, BluetoothStateChangedListener`
- **Methods**: 23
- **Fields**: 23
- **Source**: `thingclips\sdk\bluetooth\pbqbqdb.java`

**Key Methods**:
  - `SafeHandler()`
  - `HashMap()`
  - `HashMap()`
  - `HashSet()`
  - `HashMap()`
  - `bdpdqbp()`
  - `run()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - *(... and 13 more)*

**Notable Strings**:
  - `"[onBluetoothStateChanged] There is no device in the last scan. Do not start the scan."`
  - `"[onBluetoothStateChanged] open, start scan Beacon"`

---

### pbqdpqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbqdpqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `pdbpddd.pdqppqb`
- **Methods**: 23
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\pbqdpqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - *(... and 13 more)*

**Notable Strings**:
  - `"ThingBlueMeshControl"`

---

### pbqpdbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbqpdbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Implements**: `qqbbppq`
- **Methods**: 22
- **Fields**: 41
- **Source**: `thingclips\sdk\bluetooth\pbqpdbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pppbppp()`
  - `pdqppqb()`
  - `pppbppp()`
  - *(... and 12 more)*

**Notable Strings**:
  - `"ThingMeshParse"`
  - `"meshAddress: "`
  - `"ThingMeshParse"`
  - `"ThingMeshParse"`
  - `"ThingMeshParse"`
  - *(... and 2 more)*

---

### pbqpqdb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbqpqdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdqb`
- **Implements**: `dpdqqdd.qpppdqb, dpdqqdd.pbbppqb`
- **Methods**: 30
- **Fields**: 29
- **Source**: `thingclips\sdk\bluetooth\pbqpqdb.java`

**Key Methods**:
  - `ddbpdpq()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - *(... and 20 more)*

**Notable Strings**:
  - `"SigMeshPreCtrlFastPrepare"`
  - `"defaultPreCtrlMeshId"`
  - `"defaultPreCtrlMeshId"`
  - `"[PRE_CONTROL] dealWithReceiveMessage: meshMessage src = 0x"`
  - `"， meshMessage = "`
  - *(... and 4 more)*

---

### pbqqppq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbqqppq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 7
- **Fields**: 19
- **Source**: `thingclips\sdk\bluetooth\pbqqppq.java`

**Key Methods**:
  - `pbqqppq()`
  - `bdpdqbp()`
  - `dpdbqdp()`
  - `pdqppqb()`
  - `qddqppb()`
  - `ArrayList()`
  - `pbqqppq()`

---

### pbqqqqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbqqqqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `dpdpqpd`
- **Methods**: 11
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\pbqqqqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `pbqqqqd()`
  - `bdpdqbp()`
  - `bbdddqd()`
  - `pdqppqb()`
  - *(... and 1 more)*

---

### pdbbpqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdbbpqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 7
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pdbbpqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`

---

### pdbbqdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdbbqdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqpqppd`
- **Methods**: 3
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\pdbbqdq.java`

**Key Methods**:
  - `pbpdpdp()`
  - `pdqppqb()`
  - `qddqppb()`

---

### pdbdqqp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdbdqqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `bpdpppq.qddqppb`
- **Methods**: 7
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\pdbdqqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `pdbdqqp()`
  - `bdpdqbp()`
  - `ddpbbqq()`
  - `bdpdqbp()`

**Notable Strings**:
  - `"ResetMeshDeviceAddress"`
  - `"reset mesh onError "`
  - `"reset mesh Address Success"`

---

### pdbpbdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdbpbdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pdbpbdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pdbpddd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdbpddd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `BleWriteResponse`
- **Methods**: 20
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pdbpddd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onResponse()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - *(... and 10 more)*

---

### pdbqbqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdbqbqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 10
- **Fields**: 17
- **Source**: `thingclips\sdk\bluetooth\pdbqbqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `bdpdqbp()`

**Notable Strings**:
  - `"tyble_mesh_LinkageParseUtils"`
  - `"getLinkageData error, blueMeshLinkageBean is null"`

---

### pdpbbpd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdpbbpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `ppqqdpb`
- **Methods**: 6
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\pdpbbpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdpbbpd()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pdpqbpq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdpqbpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBlueMeshGroup`
- **Methods**: 73
- **Fields**: 79
- **Source**: `thingclips\sdk\bluetooth\pdpqbpq.java`

**Key Methods**:
  - `HashMap()`
  - `HashMap()`
  - `Handler()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - *(... and 63 more)*

**Notable Strings**:
  - `"ThingSigMeshGroup"`
  - `"[SigMesh_Group] operatorDevice onError, errorCode:"`
  - `"[SigMesh_Group] operatorDevice onSuccess ,isAdd:"`
  - `"[SigMesh_Group] mq203 , meshId:"`
  - `"[SigMesh_Group] mqtt success"`
  - *(... and 22 more)*

---

### pdpqddq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdpqddq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BleConnectStatusListener`
- **Implements**: `IThingBleAbility`
- **Methods**: 67
- **Fields**: 29
- **Source**: `thingclips\sdk\bluetooth\pdpqddq.java`

**Key Methods**:
  - `BluetoothClient()`
  - `bdpdqbp()`
  - `onNotify()`
  - `onResponse()`
  - `bpbbqdb()`
  - `onResponse()`
  - `bppdpdq()`
  - `onResponse()`
  - `dpdbqdp()`
  - `onResponse()`
  - *(... and 57 more)*

---

### pdpqqpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdpqqpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pdbpddd`
- **Implements**: `BleWriteResponse`
- **Methods**: 12
- **Fields**: 22
- **Source**: `thingclips\sdk\bluetooth\pdpqqpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onResponse()`
  - `pdqppqb()`
  - `onResponse()`
  - `pdpqqpp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - *(... and 2 more)*

---

### pdqbbbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdqbbbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BaseModel`
- **Implements**: `pdqddpb.qddqppb`
- **Methods**: 37
- **Fields**: 37
- **Source**: `thingclips\sdk\bluetooth\pdqbbbp.java`

**Key Methods**:
  - `bppdpdq()`
  - `bdpdqbp()`
  - `onFailure()`
  - `pdqppqb()`
  - `onResponse()`
  - `qddqppb()`
  - `onConnectStatusChanged()`
  - `if()`
  - `pdqbbbp()`
  - `bdpdqbp()`
  - *(... and 27 more)*

**Notable Strings**:
  - `"MeshLogin"`
  - `"mesh login code: "`
  - `"stopConnect  mMeshLogin:"`
  - `"found blueMesh "`

---

### pdqbbqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdqbbqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqqpbpb`
- **Implements**: `qdpdpbq`
- **Methods**: 14
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\pdqbbqq.java`

**Key Methods**:
  - `pdqbbqq()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pbbppqb()`
  - `qpppdqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `if()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - *(... and 4 more)*

**Notable Strings**:
  - `"  authKeyUUIDBean is null"`
  - `"  authKeyUUIDBean is null"`

---

### pdqddpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdqddpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pdbpddd`
- **Implements**: `BleReadResponse`
- **Methods**: 19
- **Fields**: 31
- **Source**: `thingclips\sdk\bluetooth\pdqddpb.java`

**Key Methods**:
  - `SecureRandom()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bppdpdq()`
  - `onResponse()`
  - `if()`
  - `pdqppqb()`
  - `onResponse()`
  - *(... and 9 more)*

---

### pdqpppb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdqpppb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TimerTask`
- **Implements**: `IThingBlueMeshDevice`
- **Methods**: 68
- **Fields**: 49
- **Source**: `thingclips\sdk\bluetooth\pdqpppb.java`

**Key Methods**:
  - `pbqdpqb()`
  - `dddbppp()`
  - `Timer()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `run()`
  - `pbbppqb()`
  - `onError()`
  - *(... and 58 more)*

**Notable Strings**:
  - `"ThingBlueMeshDevice"`
  - `"mesh_off_line"`
  - `"bluemesh not support standard dp"`
  - `"bluemesh not support standard dp"`
  - `"mesh_off_line"`
  - *(... and 5 more)*

---

### pdqpqbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdqpqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IMeshDataAnalysis`
- **Methods**: 15
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pdqpqbb.java`

**Key Methods**:
  - `getDeviceType()`
  - `getMeshCategory()`
  - `getProductSubType()`
  - `getProductType()`
  - `mustConnected()`
  - `needShutDownHeartBeat()`
  - `supportFast()`
  - `supportPreControl()`
  - `getDeviceType()`
  - `getProductSubType()`
  - *(... and 5 more)*

---

### pdqqdpq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdqqdpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 5
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\pdqqdpq.java`

**Key Methods**:
  - `pdqqdpq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `qddqppb()`
  - `bdpdqbp()`

---

### ppbbbdb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppbbbdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\ppbbbdb.java`

**Notable Strings**:
  - `"out_of_mesh"`

---

### ppbpdqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppbpdqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Handler`
- **Implements**: `qqpdddb`
- **Methods**: 8
- **Fields**: 9
- **Source**: `thingclips\sdk\bluetooth\ppbpdqd.java`

**Key Methods**:
  - `AtomicInteger()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `ppbpdqd()`
  - `onEventMainThread()`
  - `bdpdqbp()`
  - `bdpdqbp()`

**Notable Strings**:
  - `"SigMeshCommandWaitTask"`

---

### ppbpqqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppbpqqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBlueMeshConfig`
- **Methods**: 10
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\ppbpqqq.java`

**Key Methods**:
  - `newCheckMeshDeviceActivator()`
  - `dpppbbd()`
  - `newActivator()`
  - `qpqqqbp()`
  - `newSigActivator()`
  - `qppqdbd()`
  - `newThingBlueMeshSearch()`
  - `qpdbbbp()`
  - `newWifiActivator()`
  - `qqdpdbp()`

---

### ppbqpbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppbqpbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 11
- **Fields**: 35
- **Source**: `thingclips\sdk\bluetooth\ppbqpbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `IllegalArgumentException()`
  - `pdqppqb()`
  - `IllegalArgumentException()`
  - `bdpdqbp()`
  - `SigMeshSearchDeviceBean()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `UnprovisionedBeacon()`
  - *(... and 1 more)*

---

### ppbqqdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppbqqdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\ppbqqdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### ppdddqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppdddqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IDeviceMqttProtocolListener<MQ_25_MeshOnlineStatusUpdateBean>`
- **Methods**: 40
- **Fields**: 19
- **Source**: `thingclips\sdk\bluetooth\ppdddqb.java`

**Key Methods**:
  - `CopyOnWriteArrayList()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bppdpdq()`
  - `qddqppb()`
  - `pppbppp()`
  - `pbbppqb()`
  - `qpppdqb()`
  - `bdpdqbp()`
  - `onResult()`
  - *(... and 30 more)*

**Notable Strings**:
  - `"ThingMeshInitialize"`
  - `"requestMeshRelationList"`

---

### ppddqpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppddqpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `dbqpdqd, qqpbpbq`
- **Methods**: 35
- **Fields**: 23
- **Source**: `thingclips\sdk\bluetooth\ppddqpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `Handler()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `onError()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `onError()`
  - *(... and 25 more)*

**Notable Strings**:
  - `"ThingBlueMeshLocalActivator"`

---

### ppdqdqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppdqdqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IMeshAdvTransmitter`
- **Methods**: 11
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\ppdqdqd.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `pdqppqb()`
  - `getMeshAdvDataFactory()`
  - `bpddbpb()`
  - `send()`
  - `advertise()`
  - `bdpdqbp()`
  - *(... and 1 more)*

**Notable Strings**:
  - `"MeshAdvTransmitter"`
  - `"[MESH_ADV] sender onBluetoothNameChange, mac :"`
  - `"[MESH_ADV] sender onSuccess, mac :"`
  - `"[MESH_ADV] sender onError, mac :"`
  - `"[MESH_ADV] mac is empty"`

---

### pppbbdd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pppbbdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Business`
- **Methods**: 14
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\pppbbdd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ApiParams()`
  - `pdqppqb()`
  - `ApiParams()`
  - `bdpdqbp()`
  - `ApiParams()`
  - `bdpdqbp()`
  - `qbqbqbb()`
  - `ArrayList()`
  - `BlueMeshSubDevBean()`
  - *(... and 4 more)*

---

### pppbdbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pppbdbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bbbdqpb`
- **Methods**: 8
- **Fields**: 17
- **Source**: `thingclips\sdk\bluetooth\pppbdbp.java`

**Key Methods**:
  - `pppbdbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `StringBuilder()`
  - `StringBuilder()`
  - `StringBuilder()`
  - `StringBuilder()`

---

### pppbpdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pppbpdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `ddqqqpb, pppbppq.pbpdbqp, pppbppq.pbpdpdp, qpbqddb`
- **Methods**: 66
- **Fields**: 97
- **Source**: `thingclips\sdk\bluetooth\pppbpdp.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pbpdpdp()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pbbppqb()`
  - *(... and 56 more)*

**Notable Strings**:
  - `"thingmesh_SigMeshConnectImpl"`
  - `"getMeshSourceIdAndReInit error with wire node"`
  - `"getMeshSourceIdAndReInit success with wire node"`
  - `"----prepare7---- Query the status of devices in the current mesh network,mesh is == "`
  - `"initMeshTransport error "`
  - *(... and 7 more)*

---

### pppbppq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pppbppq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BluetoothStateListener`
- **Implements**: `qdpdpbq, bqpdpqq, qddbbpb`
- **Methods**: 59
- **Fields**: 52
- **Source**: `thingclips\sdk\bluetooth\pppbppq.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `onBluetoothStateChanged()`
  - `pbbppqb()`
  - `bdpdqbp()`
  - *(... and 49 more)*

**Notable Strings**:
  - `"thingmesh_SigMeshConnectModule"`
  - `"mesh is already connected,proxy node mac is:"`

---

### pppdddq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pppdddq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BlueMeshBean`
- **Methods**: 12
- **Fields**: 9
- **Source**: `thingclips\sdk\bluetooth\pppdddq.java`

**Key Methods**:
  - `pppdddq()`
  - `getDeviceAddress()`
  - `ArrayList()`
  - `getMacAdress()`
  - `getSessionKey()`
  - `getStatus()`
  - `getVendorId()`
  - `setMacAdress()`
  - `setSessionKey()`
  - `setStatus()`
  - *(... and 2 more)*

---

### pppqpdb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pppqpdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbqpqdb`
- **Implements**: `pdbpddd.pdqppqb`
- **Methods**: 25
- **Fields**: 16
- **Source**: `thingclips\sdk\bluetooth\pppqpdb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onError()`
  - `onReceive()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 15 more)*

**Notable Strings**:
  - `"SigMeshPreCtrlFastImpl"`
  - `"[PRE_CONTROL] onReceiveMessage: meshMessage src = 0x"`
  - `"， meshMessage = "`
  - `"defaultPreCtrlMeshId"`
  - `"defaultPreCtrlMeshId"`
  - *(... and 6 more)*

---

### ppqbdpd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppqbdpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBlueMeshSearch`
- **Methods**: 14
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\ppqbdpd.java`

**Key Methods**:
  - `bqddqpq()`
  - `Handler()`
  - `bdpdqbp()`
  - `HashMap()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `onSearchCanceled()`
  - `bdpdqbp()`
  - *(... and 4 more)*

---

### ppqdpdb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppqdpdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 10
- **Fields**: 19
- **Source**: `thingclips\sdk\bluetooth\ppqdpdb.java`

**Key Methods**:
  - `ppqdpdb()`
  - `MMKVManager()`
  - `pdqppqb()`
  - `ppqdpdb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

**Notable Strings**:
  - `"bule_mesh"`
  - `"bule_mesh_storage"`

---

### ppqpbpd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppqpbpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Handler`
- **Implements**: `qpbqddb, ISigMeshRssi`
- **Methods**: 30
- **Fields**: 40
- **Source**: `thingclips\sdk\bluetooth\ppqpbpd.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `pdqppqb()`
  - `bqddqpq()`
  - `pqpbdqq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `BleReadRssiResponse()`
  - `onResponse()`
  - `ppqpbpd()`
  - *(... and 20 more)*

**Notable Strings**:
  - `"MeshActivatedDeviceRssiManager"`
  - `"[Mesh Rssi] read success, code:"`
  - `"[Mesh Rssi] read fail, code:"`
  - `"[Mesh Rssi] ready to read remote rssi, mac:"`
  - `"[Mesh Rssi] readRemoteRssi, searchTime :"`
  - *(... and 10 more)*

---

### ppqpddd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppqpddd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TimerTask`
- **Implements**: `pdbpddd.pdqppqb`
- **Methods**: 21
- **Fields**: 34
- **Source**: `thingclips\sdk\bluetooth\ppqpddd.java`

**Key Methods**:
  - `C0323bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bpdqdpq()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `bpdqdpq()`
  - `bdpdqbp()`
  - `run()`
  - *(... and 11 more)*

**Notable Strings**:
  - `"ThingMeshController"`
  - `"ThingMeshController"`
  - `"ThingMeshController"`

---

### ppqppqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppqppqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 23
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\ppqppqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `pppbppp()`
  - `qddqppb()`
  - `qddqppb()`
  - *(... and 13 more)*

---

### ppqqdpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppqqdpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\ppqqdpb.java`

**Key Methods**:
  - `bdpdqbp()`

---

### ppqqqpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppqqqpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BaseModel`
- **Implements**: `qqqddbb`
- **Methods**: 101
- **Fields**: 84
- **Source**: `thingclips\sdk\bluetooth\ppqqqpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bpbbqdb()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - *(... and 91 more)*

**Notable Strings**:
  - `"BlueMeshModel"`
  - `"ble mesh is not exist"`
  - `"ble mesh is not exist"`
  - `"ble mesh is not exist"`
  - `"dismissMeshSubDev"`
  - *(... and 1 more)*

---

### ppqqqpd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppqqqpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqpqppd`
- **Methods**: 3
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\ppqqqpd.java`

**Key Methods**:
  - `pbpdpdp()`
  - `pdqppqb()`
  - `qddqppb()`

---

### pqbqbdb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqbqbdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Implements**: `IMeshLocalController`
- **Methods**: 41
- **Fields**: 29
- **Source**: `thingclips\sdk\bluetooth\pqbqbdb.java`

**Key Methods**:
  - `Timer()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `run()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `pppbppp()`
  - `onFailure()`
  - *(... and 31 more)*

**Notable Strings**:
  - `"MeshController"`
  - `"mesh_off_line"`
  - `"mesh_off_line"`
  - `"[passThroughByLocal] thingmesh not support."`
  - `"mesh_off_line"`
  - *(... and 4 more)*

---

### pqdddbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqdddbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bbbdqpb`
- **Methods**: 4
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\pqdddbq.java`

**Key Methods**:
  - `pqdddbq()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `StringBuilder()`

---

### pqdpddq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqdpddq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 15
- **Fields**: 17
- **Source**: `thingclips\sdk\bluetooth\pqdpddq.java`

**Key Methods**:
  - `pqdpddq()`
  - `bdpdqbp()`
  - `pqdpddq()`
  - `HashMap()`
  - `HashMap()`
  - `bdpdqbp()`
  - `MeshSubDevWifiStatus()`
  - `bdpdqbp()`
  - `HashMap()`
  - `MeshSubDevWifiStatus()`
  - *(... and 5 more)*

**Notable Strings**:
  - `"MeshCloudStatusManager"`
  - `"meshSubDevWifiStatusList:"`

---

### pqdqbpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqdqbpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pdbpddd`
- **Implements**: `BleNotifyResponse`
- **Methods**: 32
- **Fields**: 69
- **Source**: `thingclips\sdk\bluetooth\pqdqbpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `onNotify()`
  - `StringBuilder()`
  - `onResponse()`
  - `bppdpdq()`
  - `onResponse()`
  - `pdqppqb()`
  - `onNotify()`
  - *(... and 22 more)*

**Notable Strings**:
  - `"SigMeshNotificationAction"`

---

### pqpbdqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqpbdqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `pqddpbq`
- **Methods**: 14
- **Fields**: 10
- **Source**: `thingclips\sdk\bluetooth\pqpbdqq.java`

**Key Methods**:
  - `dbpdbdq()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bpbbbbb()`
  - `ivIndexReport()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - *(... and 4 more)*

---

### pqpbpqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqpbpqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bbbbddp`
- **Methods**: 5
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\pqpbpqq.java`

**Key Methods**:
  - `pqpbpqq()`
  - `ArrayList()`
  - `pppbppp()`
  - `qddqppb()`
  - `IllegalArgumentException()`

---

### pqpdbbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqpdbbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pqpdbbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pqppbdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqppbdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BasePresenter`
- **Implements**: `IMeshManager`
- **Methods**: 51
- **Fields**: 18
- **Source**: `thingclips\sdk\bluetooth\pqppbdp.java`

**Key Methods**:
  - `ppqqqpb()`
  - `dbpdbdq()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - *(... and 41 more)*

---

### pqppbqp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqppbqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 6
- **Fields**: 17
- **Source**: `thingclips\sdk\bluetooth\pqppbqp.java`

**Key Methods**:
  - `pqppbqp()`
  - `dpdbqdp()`
  - `pdqppqb()`
  - `qddqppb()`
  - `ArrayList()`
  - `pqppbqp()`

---

### pqqdqpq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqqdqpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbpdpdp<BlueMeshBean>`
- **Implements**: `IThingMeshControl`
- **Methods**: 56
- **Fields**: 28
- **Source**: `thingclips\sdk\bluetooth\pqqdqpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `run()`
  - `bdpdqbp()`
  - `pbbppqb()`
  - `onError()`
  - `onSuccess()`
  - *(... and 46 more)*

**Notable Strings**:
  - `"ThingMeshController"`
  - `"mesh_off_line"`
  - `"thingmesh device not support connect"`
  - `"thingmesh device not support disconnect"`
  - `"mesh_off_line"`
  - *(... and 3 more)*

---

### pqqpdpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqqpdpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\pqqpdpp.java`

**Notable Strings**:
  - `"com.thingclips.smart.thingmesh"`

---

### pqqpdpq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqqpdpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `qqbdddp`
- **Methods**: 15
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\pqqpdpq.java`

**Key Methods**:
  - `pqqpdpq()`
  - `pqqppdd()`
  - `bdpdqbp()`
  - `onError()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `getConnectMeshNodeId()`
  - `getStatus()`
  - `startSearch()`
  - *(... and 5 more)*

---

### pqqppdd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqqppdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BasePresenter`
- **Implements**: `qqbdddp, dpbpppp`
- **Methods**: 102
- **Fields**: 94
- **Source**: `thingclips\sdk\bluetooth\pqqppdd.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `bdpdqbp()`
  - `bbqdbpd()`
  - `bdpdqbp()`
  - `onBluetoothStateChanged()`
  - `bppdpdq()`
  - `run()`
  - `pbbppqb()`
  - `bdpdqbp()`
  - `if()`
  - *(... and 92 more)*

**Notable Strings**:
  - `"ThingSigMeshConnectImpl"`
  - `"initSigMeshLocalManager error "`
  - `"bluetoothClosed or stopSearch"`
  - `"stopMeshLogin"`
  - `"uploadIvIndex, meshId:"`
  - *(... and 5 more)*

---

### pqqqqbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqqqqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 12
- **Fields**: 12
- **Source**: `thingclips\sdk\bluetooth\pqqqqbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 2 more)*

---

### qbbqqdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbbqqdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `dbqpdqd, qdddbbq, bpbbqqp`
- **Methods**: 74
- **Fields**: 68
- **Source**: `thingclips\sdk\bluetooth\qbbqqdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `Handler()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `onError()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 64 more)*

**Notable Strings**:
  - `"ThingSigMeshProvisioningActivator"`
  - `"sigmesh single config time out"`
  - `"sigmesh config time out"`
  - `"unprovisionedMeshNode is null when get nodeId"`
  - `"sigmesh config time %d ms"`
  - *(... and 1 more)*

---

### qbdbdbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbdbdbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Handler.Callback`
- **Methods**: 14
- **Fields**: 35
- **Source**: `thingclips\sdk\bluetooth\qbdbdbd.java`

**Key Methods**:
  - `qbdbdbd()`
  - `Handler()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `HashMap()`
  - `handleMessage()`
  - `if()`
  - `if()`
  - `onEventFailed()`
  - `pdqppqb()`
  - *(... and 4 more)*

**Notable Strings**:
  - `"SigMeshActivatorLastHelp"`
  - `"reactiveMesh"`
  - `"sigmesh_config"`
  - `"sigmesh_config_reconnect"`
  - `"the mesh is connected"`
  - *(... and 6 more)*

---

### qbddddb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbddddb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `ThingSigMeshParser`
- **Methods**: 14
- **Fields**: 33
- **Source**: `thingclips\sdk\bluetooth\qbddddb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `qbddddb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `pdqppqb()`
  - *(... and 4 more)*

**Notable Strings**:
  - `"ThingSigMeshParser"`

---

### qbdppbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbdppbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Business`
- **Methods**: 20
- **Fields**: 26
- **Source**: `thingclips\sdk\bluetooth\qbdppbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ApiParams()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `ApiParams()`
  - `qddqppb()`
  - `ApiParams()`
  - `bdpdqbp()`
  - `ApiParams()`
  - `pdqppqb()`
  - *(... and 10 more)*

**Notable Strings**:
  - `"thing.m.device.ble.mesh.create"`
  - `"thing.m.sig.mesh.iv.index.report"`
  - `"thing.m.device.ble.mesh.local.id.alloc"`
  - `"thing.m.device.ble.mesh.dismiss"`
  - `"thing.m.device.ble.mesh.leave"`
  - *(... and 18 more)*

---

### qbpdddq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbpdddq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingSigMeshClient`
- **Methods**: 34
- **Fields**: 16
- **Source**: `thingclips\sdk\bluetooth\qbpdddq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `handleMessage()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `onError()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `onError()`
  - `qbpdddq()`
  - `qddqppb()`
  - *(... and 24 more)*

**Notable Strings**:
  - `"ThingSigMeshClient"`
  - `"startConnect fail mBlueMeshBean is null"`
  - `"mesh stopSearch"`
  - `"startConnect fail mBlueMeshBean is null"`
  - `"startConnect fail mBlueMeshBean is null"`

---

### qbpdpdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbpdpdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bbbdqpb`
- **Methods**: 3
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\qbpdpdp.java`

**Key Methods**:
  - `qbpdpdp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qbqbbdd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbqbbdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `pdbpddd.pdqppqb`
- **Methods**: 7
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\qbqbbdd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `qbqbbdd()`
  - `bdpdqbp()`
  - `bbpdqpd()`
  - `bdpdqbp()`

---

### qbqbqbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbqbqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 12
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\qbqbqbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ArrayList()`
  - *(... and 2 more)*

---

### qbqddpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbqddpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Business.ResultListener<BeaconMeshBean>`
- **Methods**: 56
- **Fields**: 24
- **Source**: `thingclips\sdk\bluetooth\qbqddpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `qpbdppq()`
  - *(... and 46 more)*

---

### qbqpqbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbqpqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qbqpqbb.java`

**Key Methods**:
  - `getDeviceBeanByMac()`
  - `registCustomCodeForFetchMeshToken()`
  - `registCustomCodeForFetchNodeId()`
  - `registCustomCodeForFinale()`

---

### qdbbpbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdbbpbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqpqppd`
- **Methods**: 6
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\qdbbpbp.java`

**Key Methods**:
  - `qdbbpbp()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `qddqppb()`
  - `qdbbpbp()`
  - `IllegalArgumentException()`

---

### qdbdddp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdbdddp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BaseModel`
- **Implements**: `qqbbpbp`
- **Methods**: 26
- **Fields**: 30
- **Source**: `thingclips\sdk\bluetooth\qdbdddp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `handleMessage()`
  - `pdqppqb()`
  - `qdbdddp()`
  - `Handler()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onDestroy()`
  - `remove()`
  - `bdpdqbp()`
  - *(... and 16 more)*

**Notable Strings**:
  - `"BlueMeshControlModel"`
  - `"meshId"`
  - `"controlBlueMesh"`
  - `"meshId"`
  - `"controlBlueMesh"`
  - *(... and 4 more)*

---

### qdbpbpd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdbpbpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqpqppd`
- **Methods**: 3
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\qdbpbpd.java`

**Key Methods**:
  - `pbpdpdp()`
  - `pdqppqb()`
  - `qddqppb()`

---

### qdbpbqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdbpbqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BasePresenter`
- **Implements**: `IThingBlueMesh`
- **Methods**: 29
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\qdbpbqd.java`

**Key Methods**:
  - `ppqqqpb()`
  - `qdbpbqd()`
  - `getDevListCacheManager()`
  - `addGroup()`
  - `addSubDev()`
  - `broadcastDps()`
  - `getDataByDpIds()`
  - `getMeshGroupLocalId()`
  - `getMeshSubDevBean()`
  - `getDevListCacheManager()`
  - *(... and 19 more)*

**Notable Strings**:
  - `"thing.m.device.ble.mesh.local.id.alloc"`

---

### qddbbpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qddbbpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qddbbpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onSearchCanceled()`

---

### qddbddp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qddbddp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<HashMap<String`
- **Methods**: 25
- **Fields**: 18
- **Source**: `thingclips\sdk\bluetooth\qddbddp.java`

**Key Methods**:
  - `qddbddp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `qdbpbqd()`
  - `pbbppqb()`
  - `pbddddb()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `pppbppp()`
  - *(... and 15 more)*

---

### qddbqpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qddbqpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Handler.Callback`
- **Methods**: 25
- **Fields**: 28
- **Source**: `thingclips\sdk\bluetooth\qddbqpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `Handler()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pqdqqbd()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - *(... and 15 more)*

**Notable Strings**:
  - `"ObtainAuthKeyUuid"`
  - `"ObtainAuthKeyUuid time out try "`
  - `"Obtain AuthKey Uuid Fail"`
  - `"sendObtainAuthKeyUuidCommand trySendCount:"`

---

### qdddbbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdddbbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 25
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qdddbbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bpbbqdb()`
  - `bppdpdq()`
  - `bqqppqq()`
  - `dpdqppp()`
  - *(... and 15 more)*

---

### qddpqpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qddpqpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `dqdpbpq`
- **Methods**: 18
- **Fields**: 44
- **Source**: `thingclips\sdk\bluetooth\qddpqpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `qddpqpp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - *(... and 8 more)*

**Notable Strings**:
  - `"ThingMeshDeviceConnect"`

---

### qdpdpbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdpdpbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qdpdpbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### qdppbqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdppbqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Business.ResultListener<ArrayList<Integer>>`
- **Methods**: 9
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\qdppbqb.java`

**Key Methods**:
  - `dbpdbdq()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

**Notable Strings**:
  - `"FastSigMeshNodeModule"`

---

### qdppdpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdppdpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qdppdpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qdpqbpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdpqbpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Implements**: `ITemporaryCallBack`
- **Methods**: 30
- **Fields**: 29
- **Source**: `thingclips\sdk\bluetooth\qdpqbpp.java`

**Key Methods**:
  - `onHandler()`
  - `pdqppqb()`
  - `ArrayList()`
  - `HashMap()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `MeshLogUploadDataBean()`
  - `HashMap()`
  - *(... and 20 more)*

**Notable Strings**:
  - `"bluetooth open"`
  - `"bluetooth close"`

---

### qdqbppp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdqbppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BasePresenter`
- **Implements**: `IThingExtBlueMeshOta, bbpqqpq.qpppdqb`
- **Methods**: 46
- **Fields**: 39
- **Source**: `thingclips\sdk\bluetooth\qdqbppp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `run()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `StringBuilder()`
  - `pdqppqb()`
  - `run()`
  - *(... and 36 more)*

**Notable Strings**:
  - `"ThingBlueMeshOtaImpl"`
  - `"initConnect meshAddress:"`
  - `"BlueMeshBean is null , please connect"`

---

### qdqdpdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdqdpdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Methods**: 17
- **Fields**: 17
- **Source**: `thingclips\sdk\bluetooth\qdqdpdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `qpqdddp()`
  - `qbddddb()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `HashMap()`
  - `JSONObject()`
  - `pdqppqb()`
  - `qddqppb()`
  - `pdqppqb()`
  - *(... and 7 more)*

**Notable Strings**:
  - `"SigMeshDpParserFactory"`

---

### qdqqbpd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdqqbpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BasePresenter`
- **Implements**: `ISigMeshManager`
- **Methods**: 15
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\qdqqbpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `qdqqbpd()`
  - `getInstance()`
  - `createSigMesh()`
  - `getSigMeshBean()`
  - `getSigMeshList()`
  - `onDestroy()`
  - `requestSigMeshList()`
  - *(... and 5 more)*

---

### qdqqbqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdqqbqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 5
- **Fields**: 10
- **Source**: `thingclips\sdk\bluetooth\qdqqbqb.java`

**Key Methods**:
  - `qdqqbqb()`
  - `HashSet()`
  - `ArrayList()`
  - `pdqppqb()`
  - `qddqppb()`

**Notable Strings**:
  - `"thing_sigmesh"`
  - `"thing_sigmesh"`

---

### qdqqppb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdqqppb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBlueMeshGroup`
- **Methods**: 121
- **Fields**: 157
- **Source**: `thingclips\sdk\bluetooth\qdqqppb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `dpdbqdp()`
  - *(... and 111 more)*

**Notable Strings**:
  - `"ThingSigMeshLocalGroup"`
  - `"[SigMesh_Group] operatorDevice onError , isAdd:"`
  - `"[SigMesh_Group] operatorDevice onSuccess , isAdd:"`
  - `"[SigMesh_Group] sendCommandStart onError:"`
  - `"[SigMesh_Group] sendCommandStart onSuccess:"`
  - *(... and 15 more)*

---

### qpbdddp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpbdddp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BaseEventSender`
- **Methods**: 14
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qpbdddp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 4 more)*

---

### qpbdppq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpbdppq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Business`
- **Methods**: 7
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\qpbdppq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ApiParams()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ApiParams()`

**Notable Strings**:
  - `"thing.m.beacon.mesh.source.id.alloc"`
  - `"meshId"`
  - `"thing.m.device.beacon.mesh.create"`

---

### qpbdqpd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpbdqpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qpbdqpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qpbpqpq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpbpqpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbqpdbd`
- **Methods**: 8
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\qpbpqpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ArrayList()`

---

### qpbqddb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpbqddb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qpbqddb.java`

**Key Methods**:
  - `filterDevice()`

---

### qpdbbbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpdbbbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBlueMeshSearch`
- **Methods**: 4
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\qpdbbbp.java`

**Key Methods**:
  - `qpdbbbp()`
  - `ppqbdpd()`
  - `startSearch()`
  - `stopSearch()`

---

### qpdbpbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpdbpbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IMeshStatusListener`
- **Methods**: 5
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\qpdbpbd.java`

**Key Methods**:
  - `qpdbpbd()`
  - `getInstance()`
  - `getMeshDeviceCacheDps()`
  - `getMeshDeviceCloudStatus()`
  - `getMeshDeviceLocalStatus()`

---

### qpddppb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpddppb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 17
- **Fields**: 23
- **Source**: `thingclips\sdk\bluetooth\qpddppb.java`

**Key Methods**:
  - `Handler()`
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `HashMap()`
  - `qpddppb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - *(... and 7 more)*

**Notable Strings**:
  - `"SigMeshBatchActivatorBase"`
  - `"isSingleMeshDevice:"`
  - `"[onPerSuccess] mac is NOT in meshLogTokenMap"`
  - `"[onPerSuccess] mac is NOT in meshLogTokenMap"`

---

### qppbddd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qppbddd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bbbdqpb`
- **Implements**: `pdbpddd.pdqppqb`
- **Methods**: 18
- **Fields**: 17
- **Source**: `thingclips\sdk\bluetooth\qppbddd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `qppbddd()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `StringBuilder()`
  - *(... and 8 more)*

---

### qppbppb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qppbppb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\qppbppb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`

**Notable Strings**:
  - `"MeshDeviceUtils"`
  - `"meshCategoryExt"`
  - `"meshCategoryExt"`
  - `"meshCategoryExt"`
  - `"meshCategoryExt"`

---

### qppddpd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qppddpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 5
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\qppddpd.java`

**Key Methods**:
  - `qppddpd()`
  - `pdqppqb()`
  - `qddqppb()`
  - `qddqppb()`
  - `bdpdqbp()`

---

### qpppbpq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpppbpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TimerTask`
- **Implements**: `pdbpddd.pdqppqb`
- **Methods**: 8
- **Fields**: 16
- **Source**: `thingclips\sdk\bluetooth\qpppbpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bpdqdpq()`
  - `qpppbpq()`
  - `run()`
  - `bdpdqbp()`
  - `bdpdqbp()`

**Notable Strings**:
  - `"MeshController, nodeId:"`
  - `"MeshController, nodeId:"`

---

### qpppqpq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpppqpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBeaconManager, BluetoothStateChangedListener`
- **Methods**: 53
- **Fields**: 23
- **Source**: `thingclips\sdk\bluetooth\qpppqpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `qpppqpq()`
  - `getInstance()`
  - `isBeacon2Group()`
  - `registerBluetoothStateListener()`
  - `Handler()`
  - `addBeaconMonitor()`
  - `ArrayList()`
  - `ArrayList()`
  - *(... and 43 more)*

**Notable Strings**:
  - `"resetFactoryLocal, bluetooth is disable"`
  - `"startScanBeacon fail, bluetooth is disable"`
  - `"startScanBeacon fail, bluetooth is disable"`

---

### qppqdbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qppqdbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Handler`
- **Implements**: `IThingBlueMeshActivator, qbqpqbb`
- **Methods**: 116
- **Fields**: 144
- **Source**: `thingclips\sdk\bluetooth\qppqdbd.java`

**Key Methods**:
  - `HashMap()`
  - `ConcurrentHashMap()`
  - `ArrayList()`
  - `HashMap()`
  - `pppbppp()`
  - `pbpdpdp()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bpbbqdb()`
  - *(... and 106 more)*

**Notable Strings**:
  - `"ThingSigMeshActivatorImpl"`
  - `"mesh address already full"`
  - `"meshAddress: "`
  - `"meshCategoryExt"`
  - `"mesh Activator normalBeanList's size :"`

---

### qpqbqqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqbqqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qpqbqqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qpqdddp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqdddp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `ThingSigMeshParser`
- **Methods**: 19
- **Fields**: 31
- **Source**: `thingclips\sdk\bluetooth\qpqdddp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `qpqdddp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `ArrayList()`
  - *(... and 9 more)*

---

### qpqddqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqddqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Handler.Callback`
- **Methods**: 25
- **Fields**: 29
- **Source**: `thingclips\sdk\bluetooth\qpqddqd.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `qpqddqd()`
  - `qpbdppq()`
  - `bdbdqdp()`
  - `SafeHandler()`
  - `mergeGroupAndDevice()`
  - `ArrayList()`
  - `notifyDeviceOnlineChange()`
  - `DeviceOnlineStatusEventModel()`
  - `addBeaconMonitor()`
  - *(... and 15 more)*

---

### qpqpbqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqpbqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Handler`
- **Implements**: `IResultCallback`
- **Methods**: 53
- **Fields**: 81
- **Source**: `thingclips\sdk\bluetooth\qpqpbqb.java`

**Key Methods**:
  - `CopyOnWriteArrayList()`
  - `ArrayBlockingQueue()`
  - `ArrayBlockingQueue()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - *(... and 43 more)*

**Notable Strings**:
  - `"MeshBatchExecutionHelper"`
  - `"mesh_off_line"`
  - `"mesh_off_line"`
  - `"mesh_off_line"`
  - `"groupBatchQueryByDevId mesh is offline"`
  - *(... and 1 more)*

---

### qpqqbpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqqbpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 6
- **Fields**: 34
- **Source**: `thingclips\sdk\bluetooth\qpqqbpp.java`

**Key Methods**:
  - `ArrayList()`
  - `bdpdqbp()`
  - `Ret()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qpqqbqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqqbqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 6
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\qpqqbqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `bdpdqbp()`

**Notable Strings**:
  - `"thingmesh_"`

---

### qpqqddb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqqddb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qpqddqd`
- **Implements**: `IThingBeaconManager, qpqpqbb`
- **Methods**: 64
- **Fields**: 67
- **Source**: `thingclips\sdk\bluetooth\qpqqddb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `ArrayList()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pbbppqb()`
  - `onError()`
  - `onSuccess()`
  - *(... and 54 more)*

**Notable Strings**:
  - `"query status fail, bluetooth is disable"`

---

### qpqqddp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqqddp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqpqppd`
- **Methods**: 8
- **Fields**: 14
- **Source**: `thingclips\sdk\bluetooth\qpqqddp.java`

**Key Methods**:
  - `qpqqddp()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `qddqppb()`
  - `qpqqddp()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`

---

### qpqqqbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqqqbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBlueMeshActivator, qbqpqbb`
- **Methods**: 36
- **Fields**: 37
- **Source**: `thingclips\sdk\bluetooth\qpqqqbp.java`

**Key Methods**:
  - `HashMap()`
  - `HashMap()`
  - `HashMap()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - *(... and 26 more)*

**Notable Strings**:
  - `"ThingBlueMeshActivatorImpl"`
  - `"mesh address already full"`
  - `"meshAddress: "`

---

### qqbbppq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqbbppq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 10
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qqbbppq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `qddqppb()`

---

### qqbdddp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqbdddp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 8
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qqbdddp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `getConnectMeshNodeId()`
  - `getStatus()`
  - `startSearch()`
  - `stopConnect()`
  - `stopSearch()`

---

### qqbdppb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqbdppb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qpddppb`
- **Implements**: `bqbpbdd.qpppdqb, bqbpbdd.pbbppqb`
- **Methods**: 52
- **Fields**: 60
- **Source**: `thingclips\sdk\bluetooth\qqbdppb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `run()`
  - `pppbppp()`
  - *(... and 42 more)*

**Notable Strings**:
  - `"SigMeshBatchActivatorPrepare"`
  - `"ReceiveMessage: meshMessage src = 0x"`
  - `"， meshMessage = "`

---

### qqbpqbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqbpqbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IMeshLocalController`
- **Methods**: 61
- **Fields**: 64
- **Source**: `thingclips\sdk\bluetooth\qqbpqbd.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `Timer()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 51 more)*

**Notable Strings**:
  - `"MeshController"`
  - `"mesh_off_line"`
  - `"mesh_off_line"`
  - `"mesh_off_line"`
  - `"mesh is offline"`
  - *(... and 17 more)*

---

### qqdpbbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqdpbbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 29
- **Fields**: 126
- **Source**: `thingclips\sdk\bluetooth\qqdpbbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `dqdbqdd()`
  - `if()`
  - `bppdpdq()`
  - `BLEDpBean()`
  - `pdqppqb()`
  - `ThingAdvertisingData()`
  - `if()`
  - `ThingAdvertisingData()`
  - `pppbppp()`
  - *(... and 19 more)*

---

### qqdpdbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqdpdbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qpqqqbp`
- **Implements**: `IThingActivatorGetToken`
- **Methods**: 15
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\qqdpdbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - `dbpdbdq()`
  - `qqdpdbp()`
  - `dppdqpp()`
  - `initLocalActivator()`
  - *(... and 5 more)*

**Notable Strings**:
  - `"ThingBlueMeshWifiActivatorImpl2"`

---

### qqdqqpd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqdqqpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qpppdqb`
- **Implements**: `IThingDataCallback<String>`
- **Methods**: 48
- **Fields**: 30
- **Source**: `thingclips\sdk\bluetooth\qqdqqpd.java`

**Key Methods**:
  - `LinkedBlockingQueue()`
  - `ConcurrentHashMap()`
  - `dbqqppp()`
  - `HashSet()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `ArrayList()`
  - `bppdpdq()`
  - `onError()`
  - *(... and 38 more)*

**Notable Strings**:
  - `"get meshId error:"`
  - `"getMeshId success, meshId = "`

---

### qqpbpbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpbpbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 10
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qqpbpbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`

---

### qqppqdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqppqdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 3
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\qqppqdp.java`

**Key Methods**:
  - `qqppqdp()`
  - `pdqppqb()`
  - `qddqppb()`

---

### qqpqpbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpqpbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BleConnectStatusListener`
- **Implements**: `pdqddpb.qddqppb`
- **Methods**: 24
- **Fields**: 13
- **Source**: `thingclips\sdk\bluetooth\qqpqpbq.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `onConnectStatusChanged()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `onFailure()`
  - `pdqppqb()`
  - `onResponse()`
  - *(... and 14 more)*

**Notable Strings**:
  - `"ConnectAndLoginMesh"`

---

### qqpqpqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpqpqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<HashMap<String`
- **Implements**: `BluetoothStateChangedListener, NormalBleConnectManager.pbbppqb`
- **Methods**: 58
- **Fields**: 44
- **Source**: `thingclips\sdk\bluetooth\qqpqpqd.java`

**Key Methods**:
  - `C0326bdpdqbp()`
  - `RunnableC0325bdpdqbp()`
  - `run()`
  - `C0326bdpdqbp()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - *(... and 48 more)*

**Notable Strings**:
  - `"onBluetoothChanged() called with: isOpen = ["`

---

### qqpqqbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpqqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 11
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\qqpqqbb.java`

**Key Methods**:
  - `getAid()`
  - `getAkf()`
  - `getAszmic()`
  - `getDst()`
  - `getMessage()`
  - `getOpCode()`
  - `getParameters()`
  - `getSrc()`
  - `getSrcAddress()`
  - `setMessage()`
  - *(... and 1 more)*

**Notable Strings**:
  - `"MeshMessage{mAszmic=0, OpCode="`

---

### qqqbqbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqqbqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `dqddqpb`
- **Methods**: 13
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\qqqbqbb.java`

**Key Methods**:
  - `qqqbqbb()`
  - `ddppbpb()`
  - `bdpdqbp()`
  - `onError()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `getStatus()`
  - `pdqppqb()`
  - `startSearch()`
  - `stopConnect()`
  - *(... and 3 more)*

---

### qqqbqdb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqqbqdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBlueMeshGroup`
- **Methods**: 75
- **Fields**: 47
- **Source**: `thingclips\sdk\bluetooth\qqqbqdb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `pbbppqb()`
  - *(... and 65 more)*

**Notable Strings**:
  - `"ThingBlueMeshGroup"`
  - `"mesh_off_line"`
  - `"mesh_off_line"`
  - `"mesh_off_line"`

---

### qqqddbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqqddbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `IModel`
- **Methods**: 20
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qqqddbb.java`

**Key Methods**:
  - `addSubDev()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 10 more)*

---

### qqqdpdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqqdpdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqpqppd`
- **Methods**: 9
- **Fields**: 16
- **Source**: `thingclips\sdk\bluetooth\qqqdpdp.java`

**Key Methods**:
  - `qqqdpdp()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `qddqppb()`
  - `StringBuilder()`
  - `qqqdpdp()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`

---

### qqqpbpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqqpbpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Runnable`
- **Methods**: 32
- **Fields**: 15
- **Source**: `thingclips\sdk\bluetooth\qqqpbpb.java`

**Key Methods**:
  - `HashMap()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bppdpdq()`
  - `qddqppb()`
  - `Handler()`
  - `pbbppqb()`
  - `run()`
  - `pppbppp()`
  - `run()`
  - *(... and 22 more)*

**Notable Strings**:
  - `"  authKeyUUIDBean is null"`

---

### qqqqbpd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqqqbpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqpqppd`
- **Methods**: 7
- **Fields**: 13
- **Source**: `thingclips\sdk\bluetooth\qqqqbpd.java`

**Key Methods**:
  - `qqqqbpd()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `qddqppb()`
  - `qqqqbpd()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`

---

### pdqppqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.cache.business.pdqppqb`
- **Package**: `com.thingclips.sdk.cache.business`
- **Implements**: `ISmartCacheManager`
- **Methods**: 59
- **Fields**: 49
- **Source**: `sdk\cache\business\pdqppqb.java`

**Key Methods**:
  - `SmartCacheEntityManager()`
  - `SmartCacheRelationManager()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `addBlueMesh()`
  - `addDevice()`
  - `addDeviceIntoGroup()`
  - `relation()`
  - `addDeviceIntoMesh()`
  - `relation()`
  - *(... and 49 more)*

---

### PluginManager [CRITICAL]


- **Full Name**: `com.thingclips.sdk.core.PluginManager`
- **Package**: `com.thingclips.sdk.core`
- **Methods**: 15
- **Fields**: 30
- **Source**: `thingclips\sdk\core\PluginManager.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `Object()`
  - `createInstance()`
  - `init()`
  - `initAllManager()`
  - `StringBuilder()`
  - `StringBuilder()`
  - `notifyReturn()`
  - `service()`
  - *(... and 5 more)*

**Notable Strings**:
  - `"com.thingclips.smart.interior.api.IThingBlueMeshPlugin"`
  - `"com.thingclips.sdk.bluemesh.ThingBlueMeshPlugin"`

---

### bdbbqqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bdbbqqd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `qpppdbb`
- **Implements**: `IResultCallback`
- **Methods**: 8
- **Fields**: 6
- **Source**: `thingclips\sdk\device\bdbbqqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bdbbqqd()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `bdpdqbp()`

---

### bddbqbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bddbqbq`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `Business.ResultListener<Boolean>`
- **Methods**: 59
- **Fields**: 29
- **Source**: `thingclips\sdk\device\bddbqbq.java`

**Key Methods**:
  - `qqpbpdq()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 49 more)*

---

### bddqdbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bddqdbd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `BasePresenter`
- **Implements**: `IThingOta, OtaUpdateEvent, OtaProgressEvent, RomUpdateProgressEvent, RomUpdateEvent`
- **Methods**: 90
- **Fields**: 72
- **Source**: `thingclips\sdk\device\bddqdbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bpbbqdb()`
  - `onError()`
  - `onSuccess()`
  - `ArrayList()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 80 more)*

---

### bddqpdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bddqpdp`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `ppqpqpd`
- **Implements**: `IResultCallback`
- **Methods**: 10
- **Fields**: 8
- **Source**: `thingclips\sdk\device\bddqpdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bddqpdp()`
  - `bddbqbq()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `qpppdqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

**Notable Strings**:
  - `"ThingOTAMeshGwTask"`

---

### bddqqbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bddqqbb`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `bpqqdpq`
- **Methods**: 5
- **Fields**: 2
- **Source**: `thingclips\sdk\device\bddqqbb.java`

**Key Methods**:
  - `bddqqbb()`
  - `bdpdqbp()`
  - `onNetworkStatusChanged()`
  - `onStatusChanged()`
  - `bdpdqbp()`

**Notable Strings**:
  - `"event_MeshDeviceEventProcessor"`

---

### bdpqqdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bdpqqdq`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `qpqbppd, ISubDevListener, NetWorkStatusEvent`
- **Methods**: 15
- **Fields**: 23
- **Source**: `thingclips\sdk\device\bdpqqdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `bdpqqdq()`
  - `qbdppbq()`
  - `bdpdqbp()`
  - `onDestroy()`
  - `onEvent()`
  - `onSubDevAdded()`
  - `onSubDevDpUpdate()`
  - `onSubDevInfoUpdate()`
  - *(... and 5 more)*

**Notable Strings**:
  - `"meshId: "`

---

### bdqqqbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bdqqqbp`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `OtaUpdateEvent, OtaProgressEvent, RomUpdateProgressEvent, RomUpdateEvent, ProductUpgradeEvent`
- **Methods**: 20
- **Fields**: 28
- **Source**: `thingclips\sdk\device\bdqqqbp.java`

**Key Methods**:
  - `AtomicInteger()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bdqqqbp()`
  - `bdpdqbp()`
  - `bddbqbq()`
  - `onEvent()`
  - `ThingDevUpgradeStatusBean()`
  - `onEventMainThread()`
  - *(... and 10 more)*

---

### bpqqdpq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bpqqdpq`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingDevEventListener`
- **Methods**: 15
- **Fields**: 13
- **Source**: `thingclips\sdk\device\bpqqdpq.java`

**Key Methods**:
  - `bpqqdpq()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onDevInfoUpdate()`
  - `if()`
  - `onDpUpdate()`
  - `onMeshRelationChanged()`
  - `onMqttEvent()`
  - `onNetworkStatusChanged()`
  - *(... and 5 more)*

---

### bqbppdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bqbppdq`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `Business`
- **Methods**: 23
- **Fields**: 27
- **Source**: `thingclips\sdk\device\bqbppdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 13 more)*

**Notable Strings**:
  - `"meshId"`
  - `"meshId"`

---

### bqqppqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bqqppqq`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IDevCloudControl`
- **Methods**: 32
- **Fields**: 34
- **Source**: `thingclips\sdk\device\bqqppqq.java`

**Key Methods**:
  - `ddbdqbd()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `onDestroy()`
  - `pdqppqb()`
  - `queryCameraData()`
  - `JSONObject()`
  - *(... and 22 more)*

---

### dbpbdpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.dbpbdpb`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `AbsThingDevice`
- **Implements**: `IResultCallback`
- **Methods**: 41
- **Fields**: 36
- **Source**: `thingclips\sdk\device\dbpbdpb.java`

**Key Methods**:
  - `C0328bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `C0328bdpdqbp()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - *(... and 31 more)*

**Notable Strings**:
  - `"thingmesh device do not support rn getDp:"`

---

### dbpqpqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.dbpqpqd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Implements**: `NetWorkStatusEvent, IDevResponseWithoutDpDataListener, ILocalDpMessageRespListener, ILocalOnlineStatusListener, IDeviceHardwareFindListener, Handler.Callback, pqdppqd.bdpdqbp`
- **Methods**: 75
- **Fields**: 106
- **Source**: `thingclips\sdk\device\dbpqpqd.java`

**Key Methods**:
  - `ThreadPoolExecutor()`
  - `Handler()`
  - `ddbdqbd()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - *(... and 65 more)*

---

### ddbbppb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.ddbbppb`
- **Package**: `com.thingclips.sdk.device`
- **Methods**: 13
- **Fields**: 31
- **Source**: `thingclips\sdk\device\ddbbppb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `File()`
  - `bppdpdq()`
  - `File()`
  - `pdqppqb()`
  - `qddqppb()`
  - `File()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `File()`
  - *(... and 3 more)*

---

### ddbdpqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.ddbdpqb`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `Business`
- **Methods**: 16
- **Fields**: 15
- **Source**: `thingclips\sdk\device\ddbdpqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ApiParams()`
  - `bppdpdq()`
  - `ApiParams()`
  - `pdqppqb()`
  - `ApiParams()`
  - `qddqppb()`
  - `ApiParams()`
  - `bdpdqbp()`
  - `ApiParams()`
  - *(... and 6 more)*

---

### ddbpqbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.ddbpqbb`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `qpdbdpd`
- **Implements**: `IGroupListener`
- **Methods**: 15
- **Fields**: 37
- **Source**: `thingclips\sdk\device\ddbpqbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onDpCodeUpdate()`
  - `onDpUpdate()`
  - `onGroupInfoUpdate()`
  - `onGroupRemoved()`
  - `pdqppqb()`
  - `ddbpqbb()`
  - `bdpdqbp()`
  - `dismissGroup()`
  - `pdqppqb()`
  - *(... and 5 more)*

---

### dddddqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.dddddqd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Implements**: `com.thingclips.sdk.device.dqqbdqb`
- **Methods**: 243
- **Fields**: 395
- **Source**: `thingclips\sdk\device\dddddqd.java`

**Key Methods**:
  - `Handler()`
  - `dqbpdbq()`
  - `bbpqdqb()`
  - `bdpdqbp()`
  - `run()`
  - `bdqqbqd()`
  - `run()`
  - `bpbbqdb()`
  - `onSuccess()`
  - `onError()`
  - *(... and 233 more)*

**Notable Strings**:
  - `"meshId"`
  - `"The sub-device has bluetooth capability, should not be removed: "`
  - `"meshId"`
  - `", meshId = "`
  - `"meshId:"`
  - *(... and 1 more)*

---

### dddpppb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.dddpppb`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `Comparator<UpgradeInfoBean>`
- **Methods**: 24
- **Fields**: 34
- **Source**: `thingclips\sdk\device\dddpppb.java`

**Key Methods**:
  - `compare()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `pppbppp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `qpppdqb()`
  - *(... and 14 more)*

---

### ddqdbbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.ddqdbbd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Implements**: `Handler.Callback, IThingDevEventListener`
- **Methods**: 37
- **Fields**: 49
- **Source**: `thingclips\sdk\device\ddqdbbd.java`

**Key Methods**:
  - `ddqdbbd()`
  - `Handler()`
  - `ConcurrentHashMap()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdqbdpp()`
  - `bppdpdq()`
  - `bdqbdpp()`
  - *(... and 27 more)*

---

### ddqqbbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.ddqqbbq`
- **Package**: `com.thingclips.sdk.device`
- **Methods**: 3
- **Fields**: 15
- **Source**: `thingclips\sdk\device\ddqqbbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `HashMap()`

**Notable Strings**:
  - `"sigmesh_ota_reconnect"`
  - `"blemesh_ota_reconnect"`

---

### dpbbdqq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.dpbbdqq`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingDeviceOperate`
- **Methods**: 35
- **Fields**: 53
- **Source**: `thingclips\sdk\device\dpbbdqq.java`

**Key Methods**:
  - `dpbbdqq()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `getCategory()`
  - `getDeviceBizPropBean()`
  - `getDeviceRespBean()`
  - `getDps()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `getHgwBean()`
  - *(... and 25 more)*

---

### dpdbddb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.dpdbddb`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `DeviceOnlineStatusEvent, DeviceDpsUpdateEvent, NetWorkStatusEvent, DeviceUpdateEvent, ZigbeeSubDevDpUpdateEvent, MeshRelationUpdateEvent, DevUpdateEvent, SubDeviceRelationUpdateEvent`
- **Methods**: 34
- **Fields**: 49
- **Source**: `thingclips\sdk\device\dpdbddb.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `onResult()`
  - `bppdpdq()`
  - `run()`
  - `pdqppqb()`
  - `onResult()`
  - `pppbppp()`
  - *(... and 24 more)*

**Notable Strings**:
  - `"MeshRelationUpdateEventModel event = ["`
  - `"MQ_25_MeshOnlineStatusUpdateBean: bean online = "`
  - `", meshId = "`
  - `"SubDeviceRelationUpdateEventModel event meshId = "`

---

### dpdqppp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.dpdqppp`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `BaseModel`
- **Implements**: `IDevModel`
- **Methods**: 134
- **Fields**: 86
- **Source**: `thingclips\sdk\device\dpdqppp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bpbbqdb()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `bqqppqq()`
  - *(... and 124 more)*

---

### dppdqpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.dppdqpp`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `MqttMessageRespParseListener, IThingDeviceCommunicationListener`
- **Methods**: 18
- **Fields**: 22
- **Source**: `thingclips\sdk\device\dppdqpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `getLocalKey()`
  - `getTopicSuffix()`
  - `isDataUpdated()`
  - `if()`
  - `if()`
  - `onMqttDpReceivedError()`
  - `onMqttDpReceivedSuccess()`
  - `if()`
  - *(... and 8 more)*

---

### dpqqbqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.dpqqbqd`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `NetWorkStatusEvent, DevUpdateEvent, qpqbppd, DeviceUpdateEvent, DeviceDpsUpdateEvent, qqqpdpb, ZigbeeSubDevDpUpdateEvent, IDeviceMqttProtocolListener`
- **Methods**: 19
- **Fields**: 18
- **Source**: `thingclips\sdk\device\dpqqbqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `DpsInfoBean()`
  - `dpqqbqd()`
  - `IllegalArgumentException()`
  - `bdpdqbp()`
  - `onDestroy()`
  - `onEvent()`
  - `onEventMainThread()`
  - `onResult()`
  - *(... and 9 more)*

---

### dqddqdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.dqddqdp`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IMeshRegister`
- **Methods**: 43
- **Fields**: 102
- **Source**: `thingclips\sdk\device\dqddqdp.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `dqddqdp()`
  - `bdpdqbp()`
  - `HashMap()`
  - `onEvent()`
  - `onEventMainThread()`
  - `pdqppqb()`
  - `registerMeshDevListener()`
  - `CopyOnWriteArrayList()`
  - *(... and 33 more)*

**Notable Strings**:
  - `"mesh_event_center"`
  - `"meshId"`
  - `"MeshLocalOnlineStatusUpdateEventModel model = ["`
  - `"[onEvent] model.getMeshId is Empty!!! return"`
  - `"MeshDpUpdateEventModel model is empty."`
  - *(... and 14 more)*

---

### dqdpbbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.dqdpbbd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `Business`
- **Implements**: `Business.ResultListener<ArrayList<ApiResponeBean>>`
- **Methods**: 66
- **Fields**: 62
- **Source**: `thingclips\sdk\device\dqdpbbd.java`

**Key Methods**:
  - `C0329bdpdqbp()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `DeviceBatchDataBean()`
  - `if()`
  - `C0329bdpdqbp()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 56 more)*

**Notable Strings**:
  - `"meshId"`
  - `"meshId"`
  - `"uuids"`

---

### OTACode [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.OTACode`
- **Package**: `com.thingclips.sdk.device`
- **Methods**: 0
- **Fields**: 21
- **Source**: `thingclips\sdk\device\OTACode.java`

---

### pbpqqdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.pbpqqdp`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `BaseModel`
- **Implements**: `qbpppdb`
- **Methods**: 83
- **Fields**: 83
- **Source**: `thingclips\sdk\device\pbpqqdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pbbppqb()`
  - `pbddddb()`
  - `onError()`
  - `onSuccess()`
  - `pbpdbqp()`
  - *(... and 73 more)*

---

### pbqdddb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.pbqdddb`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `Business.ResultListener<GroupRespBean>`
- **Methods**: 38
- **Fields**: 30
- **Source**: `thingclips\sdk\device\pbqdddb.java`

**Key Methods**:
  - `bqbppdq()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `GroupUpdateEventModel()`
  - `GroupUpdateEventModel()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `ArrayList()`
  - *(... and 28 more)*

---

### pdpbbpd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.pdpbbpd`
- **Package**: `com.thingclips.sdk.device`
- **Methods**: 7
- **Fields**: 10
- **Source**: `thingclips\sdk\device\pdpbbpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `GroupBean()`
  - `if()`
  - `bdpdqbp()`
  - `GroupDeviceBean()`
  - `bdpdqbp()`
  - `ArrayList()`

---

### pdpbbqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.pdpbbqb`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingDevListCacheManager`
- **Methods**: 82
- **Fields**: 109
- **Source**: `thingclips\sdk\device\pdpbbqb.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `bdpdqbp()`
  - `pdpbbqb()`
  - `addDev()`
  - `ArrayList()`
  - *(... and 72 more)*

**Notable Strings**:
  - `"device/meshId/mac"`
  - `"bluetooth"`
  - `"bluetooth"`

---

### pdpqqpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.pdpqqpp`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `DeviceUpdateEvent, IDeviceMqttProtocolListener, ZigbeeSubDevDpUpdateEvent, MeshRelationUpdateEvent, DeviceOnlineStatusEvent, SubDeviceRelationUpdateEvent`
- **Methods**: 25
- **Fields**: 43
- **Source**: `thingclips\sdk\device\pdpqqpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `pdqppqb()`
  - `run()`
  - `pdpqqpp()`
  - `bdpdqbp()`
  - `onEvent()`
  - `ArrayList()`
  - `ArrayList()`
  - `onEventMainThread()`
  - *(... and 15 more)*

**Notable Strings**:
  - `"mMeshId="`
  - `"MeshRelationUpdateEventModel: .....event meshId =  "`
  - `" meshId: "`
  - `"SubDeviceRelationUpdateEventModel event meshId = "`

---

### pdqbqdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.pdqbqdq`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `ppqpqpd`
- **Implements**: `IDownloader.OnDownloaderListener`
- **Methods**: 36
- **Fields**: 53
- **Source**: `thingclips\sdk\device\pdqbqdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onDownloadError()`
  - `onDownloadFinish()`
  - `if()`
  - `onDownloadProgress()`
  - `bppdpdq()`
  - `onConnectStatusChanged()`
  - `pdqppqb()`
  - `onFail()`
  - `onSendSuccess()`
  - *(... and 26 more)*

**Notable Strings**:
  - `"ThingOTAMeshSubTask"`
  - `"after ota success , connect wire node meshId:"`
  - `"[startUpgrade] Mesh Ota upgrade fail,code:"`
  - `"[startUpgrade] Mesh Ota send success"`
  - `"[startUpgrade] Mesh Ota upgrade progress:"`
  - *(... and 20 more)*

---

### pdqdbdd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.pdqdbdd`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingDeviceDataCacheManager`
- **Methods**: 149
- **Fields**: 148
- **Source**: `thingclips\sdk\device\pdqdbdd.java`

**Key Methods**:
  - `dqdpbbd()`
  - `bqbppdq()`
  - `ddbdpqb()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `bpbbqdb()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - *(... and 139 more)*

**Notable Strings**:
  - `"addDeviceToMesh: "`
  - `" meshId: "`
  - `"addGroupToMesh: "`
  - `" meshId: "`

---

### pdqdqbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.pdqdqbd`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IResultCallback`
- **Methods**: 33
- **Fields**: 44
- **Source**: `thingclips\sdk\device\pdqdqbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `HashMap()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `if()`
  - `bppdpdq()`
  - *(... and 23 more)*

---

### pppbppp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.pppbppp`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `bpqqdpq`
- **Methods**: 14
- **Fields**: 13
- **Source**: `thingclips\sdk\device\pppbppp.java`

**Key Methods**:
  - `pppbppp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `onMeshRelationChanged()`
  - `onMqttEvent()`
  - `onNetworkStatusChanged()`
  - `onStatusChanged()`
  - `if()`
  - `onSubDevRelationChanged()`
  - `bdpdqbp()`
  - *(... and 4 more)*

**Notable Strings**:
  - `"MQ_25_MeshOnlineStatusUpdateBean: bean online = "`
  - `", meshId = "`

---

### pqdqpdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.pqdqpdp`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingMeshGroup`
- **Methods**: 4
- **Fields**: 2
- **Source**: `thingclips\sdk\device\pqdqpdp.java`

**Key Methods**:
  - `pqdqpdp()`
  - `pqdqqbd()`
  - `bdpdqbp()`
  - `publishDps()`

---

### pqdqqbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.pqdqqbd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `BaseModel`
- **Implements**: `IThingGroupModel`
- **Methods**: 107
- **Fields**: 86
- **Source**: `thingclips\sdk\device\pqdqqbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bpbbqdb()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `bqqppqq()`
  - *(... and 97 more)*

---

### pqqpdpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.pqqpdpp`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `ppqpqpd`
- **Implements**: `IDownloader.OnDownloaderListener`
- **Methods**: 41
- **Fields**: 54
- **Source**: `thingclips\sdk\device\pqqpdpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onDownloadError()`
  - `onDownloadFinish()`
  - `onDownloadProgress()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `onFail()`
  - *(... and 31 more)*

**Notable Strings**:
  - `"[start] Bluetooth is not available"`
  - `"Bluetooth is not available"`

---

### qbdppbq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.qbdppbq`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingGateway`
- **Methods**: 15
- **Fields**: 9
- **Source**: `thingclips\sdk\device\qbdppbq.java`

**Key Methods**:
  - `qbdppbq()`
  - `dpdqppp()`
  - `broadcastDps()`
  - `getSubDevList()`
  - `isMqttConnect()`
  - `multicastDps()`
  - `onDestroy()`
  - `publishDps()`
  - `publishDpsByHttp()`
  - `publishDpsByMqtt()`
  - *(... and 5 more)*

---

### qbpppdb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.qbpppdb`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `IModel`
- **Methods**: 26
- **Fields**: 0
- **Source**: `thingclips\sdk\device\qbpppdb.java`

**Key Methods**:
  - `addZigBeeGroup()`
  - `addZigBeeScene()`
  - `autoConfigExecute()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `gatewayRouterConfigExecute()`
  - *(... and 16 more)*

---

### qbqppdb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.qbqppdb`
- **Package**: `com.thingclips.sdk.device`
- **Methods**: 12
- **Fields**: 3
- **Source**: `thingclips\sdk\device\qbqppdb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ArrayList()`
  - *(... and 2 more)*

---

### qdddqdp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.qdddqdp`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `IOtaMqttListener`
- **Implements**: `IThingOTAService`
- **Methods**: 92
- **Fields**: 76
- **Source**: `thingclips\sdk\device\qdddqdp.java`

**Key Methods**:
  - `pbpdbqp()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 82 more)*

---

### qdqbdbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.qdqbdbd`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingDeviceListManager, ForeGroundStatusEvent, NetWorkStatusEvent, qqqpdpb, ZigbeeSubDevDpUpdateEvent, IDeviceMqttProtocolListener`
- **Methods**: 139
- **Fields**: 69
- **Source**: `thingclips\sdk\device\qdqbdbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onSuccess()`
  - `onError()`
  - `pbbppqb()`
  - `run()`
  - `pbddddb()`
  - `run()`
  - *(... and 129 more)*

---

### qpppdbb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.qpppdbb`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `ppbqqdd`
- **Implements**: `IResultCallback`
- **Methods**: 10
- **Fields**: 10
- **Source**: `thingclips\sdk\device\qpppdbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `qpppdbb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`

---

### qpppqdb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.qpppqdb`
- **Package**: `com.thingclips.sdk.device`
- **Methods**: 6
- **Fields**: 6
- **Source**: `thingclips\sdk\device\qpppqdb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `qpqddpb()`
  - `dbpbdpb()`
  - `bdpdqbp()`
  - `qbqppdq()`
  - `bdpdqbp()`

---

### qpqddpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.qpqddpb`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `dbpbdpb`
- **Methods**: 3
- **Fields**: 1
- **Source**: `thingclips\sdk\device\qpqddpb.java`

**Key Methods**:
  - `qpqddpb()`
  - `publishDps()`
  - `bdbbqqd()`

**Notable Strings**:
  - `"ThingWifiMeshDevice"`

---

### qqdbbpp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.qqdbbpp`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IEventCenter, IDeviceMqttProtocolListener`
- **Methods**: 56
- **Fields**: 115
- **Source**: `thingclips\sdk\device\qqdbbpp.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `CopyOnWriteArrayList()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `qqdbbpp()`
  - `bdpdqbp()`
  - `qqdbbpp()`
  - `bppdpdq()`
  - `onEvent()`
  - *(... and 46 more)*

**Notable Strings**:
  - `"subDeviceMeshRelationUpdate 通知网关设备ThingGateway中注册的子设备监听 "`
  - `"subDeviceMeshRelationUpdate 通知子设备 "`
  - `", meshId:"`
  - `"meshId"`
  - `"SubDeviceRelationUpdateEventModel event meshId = "`
  - *(... and 6 more)*

---

### qqpbpdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.qqpbpdq`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `Business`
- **Methods**: 28
- **Fields**: 40
- **Source**: `thingclips\sdk\device\qqpbpdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pbddddb()`
  - `pbpdbqp()`
  - `ApiParams()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `pppbppp()`
  - `pqdbppq()`
  - *(... and 18 more)*

**Notable Strings**:
  - `"dynMeshSubdevOta"`

---

### qqpqqbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.qqpqqbd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `bpqqdpq`
- **Methods**: 26
- **Fields**: 49
- **Source**: `thingclips\sdk\device\qqpqqbd.java`

**Key Methods**:
  - `qqpqqbd()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `onDevInfoUpdate()`
  - `if()`
  - `onDpUpdate()`
  - `onMeshRelationChanged()`
  - `onMqttEvent()`
  - `if()`
  - `onStatusChanged()`
  - *(... and 16 more)*

**Notable Strings**:
  - `"meshId"`
  - `" meshId: "`

---

### ThingGroupPlugin [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.ThingGroupPlugin`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingGroupPlugin`
- **Methods**: 9
- **Fields**: 0
- **Source**: `thingclips\sdk\device\ThingGroupPlugin.java`

**Key Methods**:
  - `dependencies()`
  - `getGroupCacheInstance()`
  - `init()`
  - `newGroupInstance()`
  - `ThingGroupManager()`
  - `newGroupModelInstance()`
  - `pqdqqbd()`
  - `newMeshGroupInstance()`
  - `pqdqpdp()`

---

### DeviceMeta [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bean.DeviceMeta`
- **Package**: `com.thingclips.sdk.device.bean`
- **Methods**: 0
- **Fields**: 4
- **Source**: `sdk\device\bean\DeviceMeta.java`

**Notable Strings**:
  - `"meshCategory"`

---

### DevUpgradeInfoBean [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bean.DevUpgradeInfoBean`
- **Package**: `com.thingclips.sdk.device.bean`
- **Methods**: 4
- **Fields**: 2
- **Source**: `sdk\device\bean\DevUpgradeInfoBean.java`

**Key Methods**:
  - `getOta()`
  - `getProductUpgrade()`
  - `setOta()`
  - `setProductUpgrade()`

---

### OtaProgressEventBean [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bean.OtaProgressEventBean`
- **Package**: `com.thingclips.sdk.device.bean`
- **Methods**: 19
- **Fields**: 10
- **Source**: `sdk\device\bean\OtaProgressEventBean.java`

**Key Methods**:
  - `getCid()`
  - `getDevId()`
  - `getFirmwareType()`
  - `getGid()`
  - `getMeshId()`
  - `getProgress()`
  - `getRemainTime()`
  - `getStatusText()`
  - `getStatusTitle()`
  - `setCid()`
  - *(... and 9 more)*

---

### BlueMeshProperty [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bean.cache.BlueMeshProperty`
- **Package**: `com.thingclips.sdk.device.bean.cache`
- **Implements**: `IBlueMeshProperty`
- **Methods**: 15
- **Fields**: 31
- **Source**: `device\bean\cache\BlueMeshProperty.java`

**Key Methods**:
  - `BlueMeshProperty()`
  - `getCacheObj()`
  - `getBlueMeshBean()`
  - `getCode()`
  - `getEndTime()`
  - `getKey()`
  - `getLocalKey()`
  - `getMeshId()`
  - `getName()`
  - `getPassword()`
  - *(... and 5 more)*

---

### DeviceProperty [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bean.cache.DeviceProperty`
- **Package**: `com.thingclips.sdk.device.bean.cache`
- **Implements**: `IDeviceProperty`
- **Methods**: 133
- **Fields**: 217
- **Source**: `device\bean\cache\DeviceProperty.java`

**Key Methods**:
  - `DeviceProperty()`
  - `getDeviceCache()`
  - `if()`
  - `if()`
  - `if()`
  - `if()`
  - `if()`
  - `hasWifi()`
  - `isAllMeshLocalOnline()`
  - `isHasTypedCommunication()`
  - *(... and 123 more)*

**Notable Strings**:
  - `"bluetooth"`
  - `"bluetooth"`

---

### GroupProperty [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bean.cache.GroupProperty`
- **Package**: `com.thingclips.sdk.device.bean.cache`
- **Implements**: `IGroupProperty`
- **Methods**: 28
- **Fields**: 56
- **Source**: `device\bean\cache\GroupProperty.java`

**Key Methods**:
  - `GroupProperty()`
  - `getCacheObj()`
  - `getDeviceCache()`
  - `getCategory()`
  - `getDevIds()`
  - `ArrayList()`
  - `getDeviceBeans()`
  - `ArrayList()`
  - `getDeviceNum()`
  - `getDisplayOrder()`
  - *(... and 18 more)*

---

### SigMeshProperty [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.bean.cache.SigMeshProperty`
- **Package**: `com.thingclips.sdk.device.bean.cache`
- **Extends**: `BlueMeshProperty`
- **Implements**: `ISigMeshProperty`
- **Methods**: 4
- **Fields**: 9
- **Source**: `device\bean\cache\SigMeshProperty.java`

**Key Methods**:
  - `SigMeshProperty()`
  - `getCacheObj()`
  - `getMeshKey()`
  - `getSigMeshBean()`

---

### SmartCacheEntityManager [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.cache.SmartCacheEntityManager`
- **Package**: `com.thingclips.sdk.device.cache`
- **Implements**: `ISmartCacheManager.Entity`
- **Methods**: 54
- **Fields**: 67
- **Source**: `sdk\device\cache\SmartCacheEntityManager.java`

**Key Methods**:
  - `CacheManager()`
  - `EntityKey()`
  - `equals()`
  - `hashCode()`
  - `EntityKey()`
  - `run()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bppdpdq()`
  - `clear()`
  - *(... and 44 more)*

**Notable Strings**:
  - `"SmartCacheEntityManager: put wrong blue mesh type"`
  - `"SmartCacheEntityManager: put wrong sig mesh type"`

---

### AbsThingDevice [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.presenter.AbsThingDevice`
- **Package**: `com.thingclips.sdk.device.presenter`
- **Extends**: `TypeReference<HashMap<String`
- **Implements**: `IThingDevice`
- **Methods**: 93
- **Fields**: 73
- **Source**: `sdk\device\presenter\AbsThingDevice.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onSuccess()`
  - `onError()`
  - `bdpdqbp()`
  - `pbbppqb()`
  - `onDevInfoUpdate()`
  - `onDpUpdate()`
  - *(... and 83 more)*

---

### bdpdqbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.presnter.bdpdqbp`
- **Package**: `com.thingclips.sdk.device.presnter`
- **Implements**: `qbqddpp`
- **Methods**: 77
- **Fields**: 108
- **Source**: `sdk\device\presnter\bdpdqbp.java`

**Key Methods**:
  - `ArrayList()`
  - `C0336bdpdqbp()`
  - `C0336bdpdqbp()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `compare()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - *(... and 67 more)*

**Notable Strings**:
  - `"Bluetooth and Mesh only support 1 device upgrade at the same time"`
  - `"upgrade task is ThingOTAMeshGwTask"`
  - `"upgrade task is ThingGwOTATask mesh"`
  - `"upgrade task is ThingOTAMeshSubTask"`
  - `"upgrade task is ThingOTAMeshSubTask"`
  - *(... and 2 more)*

---

### bppdpdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.share.bppdpdq`
- **Package**: `com.thingclips.sdk.device.share`
- **Methods**: 27
- **Fields**: 0
- **Source**: `sdk\device\share\bppdpdq.java`

**Key Methods**:
  - `addShare()`
  - `addShareUserForGroup()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - *(... and 17 more)*

---

### pdqppqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.share.pdqppqb`
- **Package**: `com.thingclips.sdk.device.share`
- **Extends**: `Business`
- **Methods**: 55
- **Fields**: 60
- **Source**: `sdk\device\share\pdqppqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ApiParams()`
  - `bppdpdq()`
  - `ApiParams()`
  - `pbbppqb()`
  - `ApiParams()`
  - `pdqppqb()`
  - `ApiParams()`
  - `pppbppp()`
  - `ApiParams()`
  - *(... and 45 more)*

**Notable Strings**:
  - `"thing.m.sharing.mesh.remove"`
  - `"thing.m.sharing.mesh.add"`
  - `"meshId"`
  - `"meshIds"`
  - `"meshId"`
  - *(... and 6 more)*

---

### pppbppp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.share.pppbppp`
- **Package**: `com.thingclips.sdk.device.share`
- **Implements**: `IThingHomeDeviceShare`
- **Methods**: 55
- **Fields**: 26
- **Source**: `sdk\device\share\pppbppp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `bppdpdq()`
  - `onSuccess()`
  - `onError()`
  - `pbbppqb()`
  - `onSuccess()`
  - `onError()`
  - `pbddddb()`
  - *(... and 45 more)*

---

### qddqppb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.share.qddqppb`
- **Package**: `com.thingclips.sdk.device.share`
- **Implements**: `com.thingclips.sdk.device.share.bppdpdq`
- **Methods**: 142
- **Fields**: 90
- **Source**: `sdk\device\share\qddqppb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bpbbqdb()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `bpqqdpq()`
  - *(... and 132 more)*

---

### UserReceivedShareInfoBean [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.share.bean.UserReceivedShareInfoBean`
- **Package**: `com.thingclips.sdk.device.share.bean`
- **Methods**: 16
- **Fields**: 8
- **Source**: `device\share\bean\UserReceivedShareInfoBean.java`

**Key Methods**:
  - `getDevices()`
  - `getGroups()`
  - `getMeshes()`
  - `getMobile()`
  - `getName()`
  - `getNameWithoutRemark()`
  - `getReceivedName()`
  - `getRemarkName()`
  - `setDevices()`
  - `setGroups()`
  - *(... and 6 more)*

---

### UserShareInfoBean [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.share.bean.UserShareInfoBean`
- **Package**: `com.thingclips.sdk.device.share.bean`
- **Methods**: 18
- **Fields**: 9
- **Source**: `device\share\bean\UserShareInfoBean.java`

**Key Methods**:
  - `getDevices()`
  - `getGroups()`
  - `getMemberName()`
  - `getMeshes()`
  - `getMobile()`
  - `getName()`
  - `getNameWithoutRemark()`
  - `getRemarkName()`
  - `isAutoSharing()`
  - `setAutoSharing()`
  - *(... and 8 more)*

---

### DevUtil [CRITICAL]


- **Full Name**: `com.thingclips.sdk.device.utils.DevUtil`
- **Package**: `com.thingclips.sdk.device.utils`
- **Methods**: 142
- **Fields**: 124
- **Source**: `sdk\device\utils\DevUtil.java`

**Key Methods**:
  - `checkReceiveCommond()`
  - `if()`
  - `if()`
  - `if()`
  - `if()`
  - `if()`
  - `if()`
  - `checkSendCommond()`
  - `checkSendCommond()`
  - `checkSendCommondWithProductId()`
  - *(... and 132 more)*

---

### bpbbqdb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.hardware.bpbbqdb`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `BasePresenter`
- **Implements**: `Handler.Callback, IConfig`
- **Methods**: 46
- **Fields**: 56
- **Source**: `thingclips\sdk\hardware\bpbbqdb.java`

**Key Methods**:
  - `qqpppdp()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 36 more)*

---

### dbddpbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.hardware.dbddpbp`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `IThingActivator, ISubDevListener, IDeviceHardwareResponseListener, IDeviceMqttProtocolListener`
- **Methods**: 52
- **Fields**: 70
- **Source**: `thingclips\sdk\hardware\dbddpbp.java`

**Key Methods**:
  - `ArrayList()`
  - `Handler()`
  - `bdpdqbp()`
  - `qqpppdp()`
  - `HashMap()`
  - `C0343bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `bdpdqbp()`
  - `handleMessage()`
  - *(... and 42 more)*

---

### dbqbbpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.hardware.dbqbbpb`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `IThingActivator, ISubDevListener, IDeviceHardwareResponseListener, IDeviceMqttProtocolListener`
- **Methods**: 66
- **Fields**: 94
- **Source**: `thingclips\sdk\hardware\dbqbbpb.java`

**Key Methods**:
  - `ArrayList()`
  - `AtomicBoolean()`
  - `Handler()`
  - `bdpdqbp()`
  - `qqpppdp()`
  - `HashMap()`
  - `C0344bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `bdpdqbp()`
  - *(... and 56 more)*

---

### pqdppqd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.hardware.pqdppqd`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `BaseEventSender`
- **Methods**: 2
- **Fields**: 1
- **Source**: `thingclips\sdk\hardware\pqdppqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

**Notable Strings**:
  - `"subDeviceAdd meshId: "`

---

### pqqqbbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.hardware.pqqqbbp`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `IThingDeviceActivator`
- **Methods**: 112
- **Fields**: 56
- **Source**: `thingclips\sdk\hardware\pqqqbbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `pbddddb()`
  - *(... and 102 more)*

---

### qqpqqbd [CRITICAL]


- **Full Name**: `com.thingclips.sdk.hardware.qqpqqbd`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `BasePresenter`
- **Implements**: `IThingDataCallback<DeviceBean>`
- **Methods**: 36
- **Fields**: 40
- **Source**: `thingclips\sdk\hardware\qqpqqbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `onDevOnline()`
  - `onFind()`
  - `onFindErrorList()`
  - `qqpqqbd()`
  - `AtomicInteger()`
  - `dqqbdqb()`
  - `HashMap()`
  - *(... and 26 more)*

---

### qqqpdpb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.hardware.qqqpdpb`
- **Package**: `com.thingclips.sdk.hardware`
- **Methods**: 4
- **Fields**: 53
- **Source**: `thingclips\sdk\hardware\qqqpdpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`

**Notable Strings**:
  - `"wifi_config_sigmesh_subdevice"`

---

### o000O00O [CRITICAL]


- **Full Name**: `com.thingclips.sdk.home.o000O00O`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `IThingHomeDataManager`
- **Methods**: 73
- **Fields**: 27
- **Source**: `thingclips\sdk\home\o000O00O.java`

**Key Methods**:
  - `OooO00o()`
  - `onSuccess()`
  - `onError()`
  - `OooO0O0()`
  - `onSuccess()`
  - `onError()`
  - `OooO0OO()`
  - `onSuccess()`
  - `onError()`
  - `OooO0O0()`
  - *(... and 63 more)*

---

### o000O0o [CRITICAL]


- **Full Name**: `com.thingclips.sdk.home.o000O0o`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `IThingHome`
- **Methods**: 57
- **Fields**: 20
- **Source**: `thingclips\sdk\home\o000O0o.java`

**Key Methods**:
  - `OooO00o()`
  - `onError()`
  - `onSuccess()`
  - `ArrayList()`
  - `OooO0O0()`
  - `onError()`
  - `onSuccess()`
  - `ArrayList()`
  - `o000O0o()`
  - `RuntimeException()`
  - *(... and 47 more)*

**Notable Strings**:
  - `"iThingBlueMeshPlugin == null"`
  - `"iThingBlueMeshPlugin == null"`

---

### o00O000 [CRITICAL]


- **Full Name**: `com.thingclips.sdk.home.o00O000`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `GroupUpdateEvent, DeviceUpdateEvent, OooOOO, IDeviceMqttProtocolListener, IMqttServerStatusCallback, IThingDeviceDpChangeListener, IThingDeviceInfoChangeListener, IThingDeviceOnlineStatusListener, IThingMqttRetainChannelListener`
- **Methods**: 100
- **Fields**: 182
- **Source**: `thingclips\sdk\home\o00O000.java`

**Key Methods**:
  - `OooO00o()`
  - `OooO0O0()`
  - `OooO()`
  - `onSuccess()`
  - `if()`
  - `onError()`
  - `OooO00o()`
  - `onSuccess()`
  - `onError()`
  - `OooO0O0()`
  - *(... and 90 more)*

**Notable Strings**:
  - `"mesh homeId: "`

---

### oo000o [CRITICAL]


- **Full Name**: `com.thingclips.sdk.home.oo000o`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `Business`
- **Implements**: `Business.ResultListener<ArrayList<DeviceRespBean>>`
- **Methods**: 113
- **Fields**: 149
- **Source**: `thingclips\sdk\home\oo000o.java`

**Key Methods**:
  - `OooOO0()`
  - `onFailure()`
  - `onSuccess()`
  - `oo000o()`
  - `OooO0Oo()`
  - `ArrayList()`
  - `OooO()`
  - `OooO0o()`
  - `ApiParams()`
  - `ApiBean()`
  - *(... and 103 more)*

**Notable Strings**:
  - `"m.life.my.group.mesh.list"`
  - `"thing.m.device.sig.mesh.list"`

---

### OooO00o [CRITICAL]


- **Full Name**: `com.thingclips.sdk.home.OooO00o`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `Runnable`
- **Methods**: 46
- **Fields**: 78
- **Source**: `thingclips\sdk\home\OooO00o.java`

**Key Methods**:
  - `OooO()`
  - `run()`
  - `ArrayList()`
  - `ArrayList()`
  - `RunnableC0349OooO00o()`
  - `run()`
  - `ArrayList()`
  - `ArrayList()`
  - `OooO0O0()`
  - `run()`
  - *(... and 36 more)*

**Notable Strings**:
  - `"meshId"`
  - `"mesh_relation_group"`
  - `"mesh_relation_group"`

---

### OooO0O0 [CRITICAL]


- **Full Name**: `com.thingclips.sdk.home.OooO0O0`
- **Package**: `com.thingclips.sdk.home`
- **Methods**: 12
- **Fields**: 42
- **Source**: `thingclips\sdk\home\OooO0O0.java`

**Key Methods**:
  - `OooO0O0()`
  - `OooO0Oo()`
  - `OooO0o()`
  - `StringBuilder()`
  - `StringBuilder()`
  - `OooO0o0()`
  - `OooO00o()`
  - `RunnableC0298a()`
  - `OooO0O0()`
  - `RunnableC0298a()`
  - *(... and 2 more)*

**Notable Strings**:
  - `"mesh_relation_group"`
  - `"mesh_relation_group"`

---

### OooOOO0 [CRITICAL]


- **Full Name**: `com.thingclips.sdk.home.OooOOO0`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `BaseModel`
- **Implements**: `Runnable`
- **Methods**: 115
- **Fields**: 158
- **Source**: `thingclips\sdk\home\OooOOO0.java`

**Key Methods**:
  - `OooO()`
  - `OooO0O0()`
  - `onFailure()`
  - `OooO00o()`
  - `run()`
  - `OooO0O0()`
  - `onSuccess()`
  - `onFailure()`
  - `OooO0OO()`
  - `onFailure()`
  - *(... and 105 more)*

**Notable Strings**:
  - `"meshId"`

---

### OooOOOO [CRITICAL]


- **Full Name**: `com.thingclips.sdk.home.OooOOOO`
- **Package**: `com.thingclips.sdk.home`
- **Methods**: 0
- **Fields**: 19
- **Source**: `thingclips\sdk\home\OooOOOO.java`

**Notable Strings**:
  - `"home_relation_mesh"`
  - `"s_home_data_sigmesh_list"`
  - `"s_home_data_blemesh_list"`
  - `"mesh_relation_group"`
  - `"mesh_relation_group"`

---

### ThingHomePlugin [CRITICAL]


- **Full Name**: `com.thingclips.sdk.home.ThingHomePlugin`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingHomePlugin`
- **Methods**: 22
- **Fields**: 3
- **Source**: `thingclips\sdk\home\ThingHomePlugin.java`

**Key Methods**:
  - `dependencies()`
  - `getCacheInstance()`
  - `getDataInstance()`
  - `getDeviceMultiControlInstance()`
  - `getHomeManagerInstance()`
  - `getMemberInstance()`
  - `getRelationInstance()`
  - `getSpeechInstance()`
  - `init()`
  - `newDeviceInstance()`
  - *(... and 12 more)*

---

### MeshListResponseBean [CRITICAL]


- **Full Name**: `com.thingclips.sdk.home.bean.MeshListResponseBean`
- **Package**: `com.thingclips.sdk.home.bean`
- **Methods**: 8
- **Fields**: 3
- **Source**: `sdk\home\bean\MeshListResponseBean.java`

**Key Methods**:
  - `getBeacon()`
  - `getBeaconMesh()`
  - `getMesh()`
  - `getSigmesh()`
  - `setBeacon()`
  - `setBeaconMesh()`
  - `setMesh()`
  - `setSigmesh()`

---

### ThingListDataBean [CRITICAL]


- **Full Name**: `com.thingclips.sdk.home.bean.ThingListDataBean`
- **Package**: `com.thingclips.sdk.home.bean`
- **Methods**: 28
- **Fields**: 14
- **Source**: `sdk\home\bean\ThingListDataBean.java`

**Key Methods**:
  - `addDevices()`
  - `ArrayList()`
  - `addProducts()`
  - `ArrayList()`
  - `getBeacons()`
  - `getDeviceRespBeen()`
  - `getDeviceRespShareList()`
  - `getDeviceSortResponseBeans()`
  - `getGroupBeen()`
  - `getGroupRespShareList()`
  - *(... and 18 more)*

---

### ThingHomeRelationCacheManager [CRITICAL]


- **Full Name**: `com.thingclips.sdk.home.cache.ThingHomeRelationCacheManager`
- **Package**: `com.thingclips.sdk.home.cache`
- **Implements**: `IHomeCacheManager`
- **Methods**: 129
- **Fields**: 256
- **Source**: `sdk\home\cache\ThingHomeRelationCacheManager.java`

**Key Methods**:
  - `ReentrantReadWriteLock()`
  - `OooO0OO()`
  - `m425to()`
  - `getType()`
  - `setType()`
  - `getKey()`
  - `OooO0OO()`
  - `ArrayList()`
  - `OooO0O0()`
  - `ThingHomeRelationCacheManager()`
  - *(... and 119 more)*

---

### Companion [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.Companion`
- **Package**: `com.savantsystems.yisdk.device`
- **Methods**: 19
- **Fields**: 0
- **Source**: `savantsystems\yisdk\device\YiDeviceManager.java`

**Key Methods**:
  - `Companion()`
  - `mo1a()`
  - `mo2b()`
  - `getF53j()`
  - `mo4d()`
  - `mo5e()`
  - `mo6f()`
  - `mo7g()`
  - `getF44a()`
  - `mo8h()`
  - *(... and 9 more)*

---

### YiDeviceManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.YiDeviceManagerImpl`
- **Package**: `com.savantsystems.yisdk.device`
- **Implements**: `YiDeviceManager`
- **Methods**: 62
- **Fields**: 60
- **Source**: `savantsystems\yisdk\device\YiDeviceManagerImpl.java`

**Key Methods**:
  - `Factory()`
  - `YiDeviceManagerImpl()`
  - `YiDeviceInfoManagerImpl()`
  - `YiPeerConnectionManagerImpl()`
  - `YiFirmwareManagerImpl()`
  - `method()`
  - `invoke()`
  - `YiPlaybackManagerImpl()`
  - `method()`
  - `invoke()`
  - *(... and 52 more)*

---

### C0002xc5264345 [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.C0002xc5264345`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function3<FlowCollector<`
- **Methods**: 7
- **Fields**: 10
- **Source**: `yisdk\device\manager\C0002xc5264345.java`

**Key Methods**:
  - `method()`
  - `C0002xc5264345()`
  - `invoke()`
  - `C0002xc5264345()`
  - `invokeSuspend()`
  - `C0004xed66f95e()`
  - `IllegalStateException()`

---

### C0003xed66f95d [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.C0003xed66f95d`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<FlowCollector<`
- **Methods**: 7
- **Fields**: 3
- **Source**: `yisdk\device\manager\C0003xed66f95d.java`

**Key Methods**:
  - `method()`
  - `C0003xed66f95d()`
  - `create()`
  - `C0003xed66f95d()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`

---

### C0004xed66f95e [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.C0004xed66f95e`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function3<FlowCollector<`
- **Methods**: 5
- **Fields**: 2
- **Source**: `yisdk\device\manager\C0004xed66f95e.java`

**Key Methods**:
  - `method()`
  - `C0004xed66f95e()`
  - `invoke()`
  - `C0004xed66f95e()`
  - `invokeSuspend()`

---

### YiDeviceInfoManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiDeviceInfoManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `YiDeviceInfoManager`
- **Methods**: 11
- **Fields**: 22
- **Source**: `yisdk\device\manager\YiDeviceInfoManagerImpl.java`

**Key Methods**:
  - `C00011()`
  - `create()`
  - `C00011()`
  - `invoke()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `YiStaticDeviceInfo()`
  - `StringBuilder()`
  - `Factory()`
  - `YiDeviceInfoManagerImpl()`
  - *(... and 1 more)*

---

### YiDeviceSubscriptionManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiDeviceSubscriptionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `CameraCloudSubscriptionStatus>>`
- **Implements**: `YiDeviceSubscriptionManager`
- **Methods**: 9
- **Fields**: 27
- **Source**: `yisdk\device\manager\YiDeviceSubscriptionManagerImpl.java`

**Key Methods**:
  - `Factory()`
  - `YiDeviceSubscriptionManagerImpl()`
  - `invoke()`
  - `C0002xc5264345()`
  - `m32b()`
  - `IllegalStateException()`
  - `NoWhenBranchMatchedException()`
  - `Err()`
  - `mo31a()`

---

### YiFirmwareManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function1<Continuation<`
- **Methods**: 8
- **Fields**: 11
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$fetchCurrentVersion$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `NoWhenBranchMatchedException()`
  - `Ok()`

---

### YiFirmwareManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 7
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$fetchFirmwareUpdateInfo$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiFirmwareManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 6
- **Fields**: 6
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$fetchFirmwareUpdateInfo$currentVersion$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`

---

### YiFirmwareManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function3<FirmwareUpdateInfo, FirmwareVersion, Continuation<`
- **Methods**: 3
- **Fields**: 8
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$observeFirmwareUpdates$1.java`

**Key Methods**:
  - `invoke()`
  - `SuspendLambda()`
  - `invokeSuspend()`

---

### YiFirmwareManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$performUpdate$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiFirmwareManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 6
- **Fields**: 9
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$performUpdate$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`

---

### YiFirmwareManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<FlowCollector<`
- **Methods**: 15
- **Fields**: 11
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$pollUpgradeProgress$1.java`

**Key Methods**:
  - `method()`
  - `C00101()`
  - `create()`
  - `C00101()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `method()`
  - `create()`
  - *(... and 5 more)*

---

### YiFirmwareManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function3<FlowCollector<`
- **Methods**: 27
- **Fields**: 43
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$pollUpgradeProgress$2.java`

**Key Methods**:
  - `AnonymousClass1()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `AnonymousClass2()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - *(... and 17 more)*

---

### YiFirmwareManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 10
- **Fields**: 17
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$setCurrentVersion$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`
  - `method()`
  - `invoke()`

---

### YiFirmwareManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<FlowCollector<`
- **Methods**: 8
- **Fields**: 14
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$startCurrentVersionFetcher$3.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `method()`
  - `invoke()`

---

### YiFirmwareManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `YiFirmwareManager`
- **Methods**: 71
- **Fields**: 163
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl.java`

**Key Methods**:
  - `C00082()`
  - `create()`
  - `C00082()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `method()`
  - `AnonymousClass1()`
  - `create()`
  - *(... and 61 more)*

---

### YiPeerConnectionManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 7
- **Fields**: 11
- **Source**: `yisdk\device\manager\YiPeerConnectionManagerImpl$initializeConnectionLock$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `SuspendLambda()`
  - `IllegalStateException()`

---

### YiPeerConnectionManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 34
- **Fields**: 31
- **Source**: `yisdk\device\manager\YiPeerConnectionManagerImpl$removeCamera$2.java`

**Key Methods**:
  - `method()`
  - `C03061()`
  - `create()`
  - `C03061()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `invoke()`
  - `IllegalStateException()`
  - `Ok()`
  - *(... and 24 more)*

---

### YiPeerConnectionManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function3<FlowCollector<`
- **Methods**: 4
- **Fields**: 14
- **Source**: `yisdk\device\manager\YiPeerConnectionManagerImpl$reportConnectionState$2.java`

**Key Methods**:
  - `method()`
  - `invoke()`
  - `invokeSuspend()`
  - `IllegalStateException()`

---

### YiPeerConnectionManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `YiPeerConnectionManager`
- **Methods**: 71
- **Fields**: 118
- **Source**: `yisdk\device\manager\YiPeerConnectionManagerImpl.java`

**Key Methods**:
  - `AnonymousClass1()`
  - `create()`
  - `invoke()`
  - `invokeSuspend()`
  - `C00171()`
  - `create()`
  - `C00171()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - *(... and 61 more)*

---

### YiDeviceIdMapper [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.mappers.YiDeviceIdMapper`
- **Package**: `com.savantsystems.yisdk.device.mappers`
- **Methods**: 9
- **Fields**: 3
- **Source**: `yisdk\device\mappers\YiDeviceIdMapper.java`

**Key Methods**:
  - `YiDeviceIdMapper()`
  - `m56a()`
  - `StandaloneDeviceId()`
  - `m57b()`
  - `YiDeviceId()`
  - `m58c()`
  - `YiDeviceId()`
  - `m59d()`
  - `YiDeviceId()`

---

### YiDeviceMapper [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.mappers.YiDeviceMapper`
- **Package**: `com.savantsystems.yisdk.device.mappers`
- **Methods**: 10
- **Fields**: 34
- **Source**: `yisdk\device\mappers\YiDeviceMapper.java`

**Key Methods**:
  - `YiDeviceMapper()`
  - `m60a()`
  - `LinkedHashSet()`
  - `if()`
  - `NoWhenBranchMatchedException()`
  - `if()`
  - `NoWhenBranchMatchedException()`
  - `ArrayList()`
  - `Device()`
  - `LinkedHashMap()`

---

### C0073x1f4519a3 [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.C0073x1f4519a3`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function3<FlowCollector<`
- **Methods**: 6
- **Fields**: 10
- **Source**: `yisdk\device\service\C0073x1f4519a3.java`

**Key Methods**:
  - `method()`
  - `C0073x1f4519a3()`
  - `invoke()`
  - `C0073x1f4519a3()`
  - `invokeSuspend()`
  - `IllegalStateException()`

---

### YiAudioController [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiAudioController`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `YiError>>`
- **Methods**: 2
- **Fields**: 0
- **Source**: `yisdk\device\service\YiAudioController.java`

**Key Methods**:
  - `mo65a()`
  - `mo66b()`

---

### YiAudioControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiAudioControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiAudioControllerImpl$isMuted$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiAudioControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiAudioControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `YiError>>`
- **Implements**: `YiAudioController`
- **Methods**: 7
- **Fields**: 11
- **Source**: `yisdk\device\service\YiAudioControllerImpl.java`

**Key Methods**:
  - `Factory()`
  - `YiAudioControllerImpl()`
  - `mo65a()`
  - `mo66b()`
  - `IllegalStateException()`
  - `Ok()`
  - `NoWhenBranchMatchedException()`

---

### YiCloudPlaybackControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiCloudPlaybackControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 6
- **Fields**: 6
- **Source**: `yisdk\device\service\YiCloudPlaybackControllerImpl$mute$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `Ok()`

---

### YiCloudPlaybackControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiCloudPlaybackControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 6
- **Fields**: 2
- **Source**: `yisdk\device\service\YiCloudPlaybackControllerImpl$pausePlayback$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `Ok()`

---

### YiCloudPlaybackControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiCloudPlaybackControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 12
- **Fields**: 10
- **Source**: `yisdk\device\service\YiCloudPlaybackControllerImpl$pauseWhenReady$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `Err()`
  - `CancellableContinuationImpl()`
  - `m74D()`
  - `m75f0()`
  - `method()`
  - *(... and 2 more)*

---

### YiCloudPlaybackControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiCloudPlaybackControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 6
- **Fields**: 2
- **Source**: `yisdk\device\service\YiCloudPlaybackControllerImpl$resumePlayback$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `Ok()`

---

### YiCloudPlaybackControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiCloudPlaybackControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 7
- **Fields**: 15
- **Source**: `yisdk\device\service\YiCloudPlaybackControllerImpl$startPlayback$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `Ok()`
  - `Err()`

---

### YiCloudPlaybackControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiCloudPlaybackControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 6
- **Fields**: 5
- **Source**: `yisdk\device\service\YiCloudPlaybackControllerImpl$stopPlayback$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `Ok()`

---

### YiCloudPlaybackControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiCloudPlaybackControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `YiError>>`
- **Implements**: `YiPlaybackController, YiAudioController`
- **Methods**: 21
- **Fields**: 29
- **Source**: `yisdk\device\service\YiCloudPlaybackControllerImpl.java`

**Key Methods**:
  - `Factory()`
  - `YiCloudPlaybackControllerImpl()`
  - `mo65a()`
  - `mo66b()`
  - `Ok()`
  - `mo67c()`
  - `mo68d()`
  - `mo69e()`
  - `mo70f()`
  - `mo71g()`
  - *(... and 11 more)*

---

### YiDeviceService [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceService`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `YiError>>`
- **Methods**: 32
- **Fields**: 0
- **Source**: `yisdk\device\service\YiDeviceService.java`

**Key Methods**:
  - `mo76A()`
  - `mo77B()`
  - `mo78C()`
  - `mo79D()`
  - `mo80E()`
  - `mo81F()`
  - `mo82G()`
  - `mo83a()`
  - `mo84b()`
  - `mo85c()`
  - *(... and 22 more)*

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 7
- **Fields**: 10
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$1$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$enableDetectionZone$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$fetchAlertAreaSettings$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$fetchAlertSettings$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$fetchAlertSettingsInternal$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$fetchBatteryStatus$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$fetchCameraInfo$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$fetchCameraSettings$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$fetchExtendedCameraSettings$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$getCameraAutoOta$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$getCameraWatermark$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$getMotionDetection$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$getPirMode$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$getRecordAudio$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$getVideoQuality$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$modifyCameraExtendSettings$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 13
- **Fields**: 37
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$modifyCameraExtendSettings$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `invoke()`
  - `NoWhenBranchMatchedException()`
  - `invoke()`
  - `method()`
  - *(... and 3 more)*

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$setCameraAutoOta$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$setCameraRecordingDuration$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$setCameraSettings$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$setCameraTimezone$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$setCameraWatermark$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$setMotionDetection$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$setMotionDetectionZone$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$setPirMode$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$setRecordAudio$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$setVideoQuality$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$startRecording$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$stopRecording$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$switchNetwork$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$takeSnapshot$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 7
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$talkToCamera$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 6
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$updateSchedules$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiDeviceServiceImpl$updateThumbnailByClip$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `YiError>>`
- **Implements**: `YiDeviceService`
- **Methods**: 147
- **Fields**: 549
- **Source**: `yisdk\device\service\YiDeviceServiceImpl.java`

**Key Methods**:
  - `Factory()`
  - `Companion()`
  - `YiDeviceServiceImpl()`
  - `File()`
  - `Err()`
  - `Ok()`
  - `Err()`
  - `mo76A()`
  - `invoke()`
  - `IllegalStateException()`
  - *(... and 137 more)*

---

### YiNotificationService [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiNotificationService`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `YiError>>`
- **Methods**: 2
- **Fields**: 0
- **Source**: `yisdk\device\service\YiNotificationService.java`

**Key Methods**:
  - `mo112a()`
  - `mo113b()`

---

### YiNotificationServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiNotificationServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiNotificationServiceImpl$fetchNotificationStatus$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiNotificationServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiNotificationServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiNotificationServiceImpl$toggleNotifications$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiNotificationServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiNotificationServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `YiError>>`
- **Implements**: `YiNotificationService`
- **Methods**: 14
- **Fields**: 41
- **Source**: `yisdk\device\service\YiNotificationServiceImpl.java`

**Key Methods**:
  - `Factory()`
  - `YiNotificationServiceImpl()`
  - `mo112a()`
  - `IllegalStateException()`
  - `Err()`
  - `NoWhenBranchMatchedException()`
  - `method()`
  - `invoke()`
  - `mo113b()`
  - `IllegalStateException()`
  - *(... and 4 more)*

---

### YiPeerService [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerService`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `YiError>>`
- **Methods**: 41
- **Fields**: 0
- **Source**: `yisdk\device\service\YiPeerService.java`

**Key Methods**:
  - `mo115A()`
  - `mo116B()`
  - `mo117C()`
  - `mo118D()`
  - `mo119E()`
  - `mo120F()`
  - `mo121G()`
  - `mo122H()`
  - `mo123I()`
  - `mo124J()`
  - *(... and 31 more)*

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 6
- **Fields**: 6
- **Source**: `yisdk\device\service\YiPeerServiceImpl$bindCameraView$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `Ok()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 8
- **Fields**: 13
- **Source**: `yisdk\device\service\YiPeerServiceImpl$deletePlaybackEvents$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 6
- **Fields**: 8
- **Source**: `yisdk\device\service\YiPeerServiceImpl$ensureStreamIsPlaying$3.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchAlertAreaSettings$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 7
- **Fields**: 12
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchAlertAreaSettings$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchBatteryStatus$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 7
- **Fields**: 12
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchBatteryStatus$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchCameraAutoOta$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 7
- **Fields**: 12
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchCameraAutoOta$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchCameraSettings$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 7
- **Fields**: 12
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchCameraSettings$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchCameraWatermark$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 7
- **Fields**: 12
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchCameraWatermark$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchFirmwareVersion$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 7
- **Fields**: 12
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchFirmwareVersion$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchListening$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 5
- **Fields**: 4
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchListening$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `Ok()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchMotionDetection$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 7
- **Fields**: 12
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchMotionDetection$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchPirMode$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 7
- **Fields**: 12
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchPirMode$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 8
- **Fields**: 13
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchPlaybackEvents$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchRecordAudio$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 7
- **Fields**: 12
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchRecordAudio$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchSdCardRecordingStatus$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 7
- **Fields**: 12
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchSdCardRecordingStatus$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchTalking$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 5
- **Fields**: 4
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchTalking$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `Ok()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 7
- **Fields**: 12
- **Source**: `yisdk\device\service\YiPeerServiceImpl$fetchVideoQuality$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$pausePlaying$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 7
- **Fields**: 12
- **Source**: `yisdk\device\service\YiPeerServiceImpl$pausePlaying$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiPeerServiceImpl$playClip$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 8
- **Fields**: 13
- **Source**: `yisdk\device\service\YiPeerServiceImpl$playClip$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiPeerServiceImpl$resetCamera$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 16
- **Fields**: 19
- **Source**: `yisdk\device\service\YiPeerServiceImpl$resetCamera$2.java`

**Key Methods**:
  - `method()`
  - `C00421()`
  - `create()`
  - `C00421()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `method()`
  - `create()`
  - *(... and 6 more)*

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$resetCameraInternal$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 7
- **Fields**: 12
- **Source**: `yisdk\device\service\YiPeerServiceImpl$resetCameraInternal$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setAlertAreaSettings$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 8
- **Fields**: 11
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setAlertAreaSettings$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setCameraAutoOta$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 8
- **Fields**: 11
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setCameraAutoOta$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setCameraSettings$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 8
- **Fields**: 9
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setCameraSettings$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setCameraWatermark$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 8
- **Fields**: 11
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setCameraWatermark$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setMotionDetection$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 8
- **Fields**: 11
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setMotionDetection$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setPirMode$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 8
- **Fields**: 11
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setPirMode$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setRecordAudio$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 8
- **Fields**: 11
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setRecordAudio$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setSdCardRecording$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 8
- **Fields**: 11
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setSdCardRecording$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setVideoQuality$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 8
- **Fields**: 11
- **Source**: `yisdk\device\service\YiPeerServiceImpl$setVideoQuality$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 9
- **Fields**: 21
- **Source**: `yisdk\device\service\YiPeerServiceImpl$startDownloadClip$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`
  - `Ok()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$startListening$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 9
- **Fields**: 11
- **Source**: `yisdk\device\service\YiPeerServiceImpl$startListening$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `Ok()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`
  - `invoke()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$startPlaying$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 12
- **Fields**: 24
- **Source**: `yisdk\device\service\YiPeerServiceImpl$startPlaying$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`
  - `onFail()`
  - `onSuccess()`
  - *(... and 2 more)*

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$startRecordingVideo$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 8
- **Fields**: 13
- **Source**: `yisdk\device\service\YiPeerServiceImpl$startRecordingVideo$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$startTalking$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 18
- **Fields**: 34
- **Source**: `yisdk\device\service\YiPeerServiceImpl$startTalking$2.java`

**Key Methods**:
  - `method()`
  - `C00581()`
  - `create()`
  - `C00581()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `Ok()`
  - `method()`
  - *(... and 8 more)*

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$stopDownloadClip$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 10
- **Fields**: 19
- **Source**: `yisdk\device\service\YiPeerServiceImpl$stopDownloadClip$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`
  - `method()`
  - `invoke()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$stopListening$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 9
- **Fields**: 11
- **Source**: `yisdk\device\service\YiPeerServiceImpl$stopListening$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `Ok()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`
  - `invoke()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$stopPlaying$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 8
- **Fields**: 10
- **Source**: `yisdk\device\service\YiPeerServiceImpl$stopPlaying$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 7
- **Fields**: 12
- **Source**: `yisdk\device\service\YiPeerServiceImpl$stopRecordingVideo$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$stopTalking$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 18
- **Fields**: 34
- **Source**: `yisdk\device\service\YiPeerServiceImpl$stopTalking$2.java`

**Key Methods**:
  - `method()`
  - `C00651()`
  - `create()`
  - `C00651()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `Ok()`
  - `method()`
  - *(... and 8 more)*

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$switchNetwork$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 8
- **Fields**: 13
- **Source**: `yisdk\device\service\YiPeerServiceImpl$switchNetwork$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiPeerServiceImpl$takeSnapshot$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 15
- **Fields**: 20
- **Source**: `yisdk\device\service\YiPeerServiceImpl$takeSnapshot$2.java`

**Key Methods**:
  - `C00671()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`
  - `method()`
  - `create()`
  - *(... and 5 more)*

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiPeerServiceImpl$unbindCameraView$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 5
- **Fields**: 1
- **Source**: `yisdk\device\service\YiPeerServiceImpl$unbindCameraView$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerServiceImpl$upgradeFirmware$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<IYiCameraP2P, Continuation<`
- **Methods**: 8
- **Fields**: 11
- **Source**: `yisdk\device\service\YiPeerServiceImpl$upgradeFirmware$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 8
- **Source**: `yisdk\device\service\YiPeerServiceImpl$withCameraP2P$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function1<Continuation<`
- **Methods**: 15
- **Fields**: 31
- **Source**: `yisdk\device\service\YiPeerServiceImpl$withCameraP2P$2.java`

**Key Methods**:
  - `method()`
  - `C00691()`
  - `create()`
  - `C00691()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `method()`
  - `create()`
  - *(... and 5 more)*

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<YiDeviceConnection, Continuation<`
- **Methods**: 4
- **Fields**: 4
- **Source**: `yisdk\device\service\YiPeerServiceImpl$withCameraP2P$cameraP2P$1$1$1.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 7
- **Fields**: 11
- **Source**: `yisdk\device\service\YiPeerServiceImpl$withCameraP2P$cameraP2P$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `SuspendLambda()`

---

### YiPeerServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `YiError>>`
- **Implements**: `YiPeerService`
- **Methods**: 147
- **Fields**: 358
- **Source**: `yisdk\device\service\YiPeerServiceImpl.java`

**Key Methods**:
  - `Factory()`
  - `Companion()`
  - `YiPeerServiceImpl()`
  - `KeyMutex()`
  - `YiCameraView()`
  - `m156P()`
  - `SuspendLambda()`
  - `IllegalStateException()`
  - `invoke()`
  - `invoke()`
  - *(... and 137 more)*

---

### YiPeerVideoControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<ProducerScope<`
- **Methods**: 18
- **Fields**: 26
- **Source**: `yisdk\device\service\YiPeerVideoControllerImpl$downloadClip$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `onFail()`
  - `onSuccess()`
  - `IllegalStateException()`
  - `method()`
  - `AnonymousClass1()`
  - *(... and 8 more)*

---

### YiPeerVideoControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiPeerVideoControllerImpl$pausePlayback$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerVideoControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiPeerVideoControllerImpl$pauseWhenReady$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerVideoControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<RetryFailure<YiError>, Continuation<`
- **Methods**: 5
- **Fields**: 3
- **Source**: `yisdk\device\service\YiPeerVideoControllerImpl$playClipInternal$$inlined$retryIf$1.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `RetryInstruction()`

---

### YiPeerVideoControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function1<Continuation<`
- **Methods**: 10
- **Fields**: 16
- **Source**: `yisdk\device\service\YiPeerVideoControllerImpl$playClipInternal$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `NoWhenBranchMatchedException()`
  - `Ok()`
  - `Err()`
  - `Err()`

---

### YiPeerVideoControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 6
- **Source**: `yisdk\device\service\YiPeerVideoControllerImpl$resumePlayback$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerVideoControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 9
- **Source**: `yisdk\device\service\YiPeerVideoControllerImpl$startDownloading$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerVideoControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 7
- **Source**: `yisdk\device\service\YiPeerVideoControllerImpl$startPlayback$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerVideoControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 7
- **Source**: `yisdk\device\service\YiPeerVideoControllerImpl$startPreview$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerVideoControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 6
- **Source**: `yisdk\device\service\YiPeerVideoControllerImpl$stopDownloading$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerVideoControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 6
- **Source**: `yisdk\device\service\YiPeerVideoControllerImpl$stopPlayback$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerVideoControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 7
- **Source**: `yisdk\device\service\YiPeerVideoControllerImpl$stopPreview$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerVideoControllerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `YiError>>`
- **Implements**: `YiPlaybackController, YiPreviewController, YiClipDownloadController`
- **Methods**: 48
- **Fields**: 275
- **Source**: `yisdk\device\service\YiPeerVideoControllerImpl.java`

**Key Methods**:
  - `Factory()`
  - `Enum()`
  - `Enum()`
  - `Enum()`
  - `Enum()`
  - `PeerVideoState()`
  - `valueOf()`
  - `values()`
  - `Companion()`
  - `YiPeerVideoControllerImpl()`
  - *(... and 38 more)*

---

### YiPlaybackController [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPlaybackController`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `YiError>>`
- **Methods**: 6
- **Fields**: 0
- **Source**: `yisdk\device\service\YiPlaybackController.java`

**Key Methods**:
  - `mo67c()`
  - `mo68d()`
  - `mo69e()`
  - `mo70f()`
  - `mo71g()`
  - `mo72h()`

---

### DefaultImpls [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.DefaultImpls`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `YiError>>`
- **Methods**: 2
- **Fields**: 0
- **Source**: `yisdk\device\service\YiPreviewController.java`

**Key Methods**:
  - `mo163b()`
  - `mo164i()`

---

### YiPreviewService [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPreviewService`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `YiError>>`
- **Methods**: 3
- **Fields**: 0
- **Source**: `yisdk\device\service\YiPreviewService.java`

**Key Methods**:
  - `mo168a()`
  - `mo169b()`
  - `mo170e()`

---

### YiPreviewServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 6
- **Source**: `yisdk\device\service\YiPreviewServiceImpl$mute$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPreviewServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiPreviewServiceImpl$restoreMuteState$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPreviewServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiPreviewServiceImpl$restoreTalking$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPreviewServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 7
- **Fields**: 15
- **Source**: `yisdk\device\service\YiPreviewServiceImpl$saveLastTakenThumbnailSnapshot$1$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPreviewServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 8
- **Source**: `yisdk\device\service\YiPreviewServiceImpl$startPlay$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPreviewServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 7
- **Source**: `yisdk\device\service\YiPreviewServiceImpl$startPreview$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPreviewServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<Long, Continuation<`
- **Methods**: 6
- **Fields**: 9
- **Source**: `yisdk\device\service\YiPreviewServiceImpl$startThumbnailSnapshottingJob$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`

---

### YiPreviewServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\service\YiPreviewServiceImpl$stopPlay$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPreviewServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 6
- **Fields**: 10
- **Source**: `yisdk\device\service\YiPreviewServiceImpl$stopPlay$3.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`

---

### YiPreviewServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 6
- **Source**: `yisdk\device\service\YiPreviewServiceImpl$stopPreview$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPreviewServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `YiError>>`
- **Implements**: `YiPreviewService`
- **Methods**: 32
- **Fields**: 161
- **Source**: `yisdk\device\service\YiPreviewServiceImpl.java`

**Key Methods**:
  - `Factory()`
  - `Companion()`
  - `YiPreviewServiceImpl()`
  - `mo168a()`
  - `IllegalStateException()`
  - `method()`
  - `invoke()`
  - `mo169b()`
  - `IllegalStateException()`
  - `m172d()`
  - *(... and 22 more)*

---

### YiSdCardService [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiSdCardService`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `YiError>>`
- **Methods**: 3
- **Fields**: 0
- **Source**: `yisdk\device\service\YiSdCardService.java`

**Key Methods**:
  - `mo176a()`
  - `mo177b()`
  - `mo178e()`

---

### YiSdCardServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiSdCardServiceImpl$formatSdCard$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiSdCardServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<Long, Continuation<`
- **Methods**: 9
- **Fields**: 10
- **Source**: `yisdk\device\service\YiSdCardServiceImpl$pollFormatStatus$1$1$state$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `Ok()`
  - `if()`
  - `NoWhenBranchMatchedException()`

---

### YiSdCardServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 25
- **Fields**: 36
- **Source**: `yisdk\device\service\YiSdCardServiceImpl$pollFormatStatus$1.java`

**Key Methods**:
  - `method()`
  - `C00741()`
  - `create()`
  - `C00741()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `AnonymousClass1()`
  - `invokeSuspend()`
  - `AnonymousClass2()`
  - *(... and 15 more)*

---

### YiSdCardServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 8
- **Fields**: 10
- **Source**: `yisdk\device\service\YiSdCardServiceImpl$pollSdCardStatus$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `pattern()`
  - `invokeSuspend()`
  - `if()`
  - `IllegalStateException()`

---

### YiSdCardServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\service\YiSdCardServiceImpl$refreshSdCardSettings$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiSdCardServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<FlowCollector<`
- **Methods**: 5
- **Fields**: 3
- **Source**: `yisdk\device\service\YiSdCardServiceImpl$sdCardStatus$2$1$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`

---

### YiSdCardServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `SuspendLambda`
- **Implements**: `Function3<FlowCollector<`
- **Methods**: 3
- **Fields**: 2
- **Source**: `yisdk\device\service\YiSdCardServiceImpl$sdCardStatus$2$1$2.java`

**Key Methods**:
  - `method()`
  - `invoke()`
  - `invokeSuspend()`

---

### YiSdCardServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 6
- **Source**: `yisdk\device\service\YiSdCardServiceImpl$setSdCardRecording$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiSdCardServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `YiSdCardInfo>>`
- **Implements**: `YiSdCardService`
- **Methods**: 18
- **Fields**: 79
- **Source**: `yisdk\device\service\YiSdCardServiceImpl.java`

**Key Methods**:
  - `invoke()`
  - `C0073x1f4519a3()`
  - `Factory()`
  - `YiSdCardServiceImpl()`
  - `mo176a()`
  - `if()`
  - `IllegalStateException()`
  - `invoke()`
  - `invoke()`
  - `mo177b()`
  - *(... and 8 more)*

---

### YiSnapshotHelper [HIGH]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiSnapshotHelper`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Methods**: 27
- **Fields**: 23
- **Source**: `yisdk\device\service\YiSnapshotHelper.java`

**Key Methods**:
  - `Companion()`
  - `YiSnapshotHelper()`
  - `m182a()`
  - `File()`
  - `Ok()`
  - `Err()`
  - `Err()`
  - `m183b()`
  - `Ok()`
  - `Err()`
  - *(... and 17 more)*

---

### YiPushTokenReceiver [HIGH]


- **Full Name**: `com.savantsystems.yisdk.notifications.YiPushTokenReceiver`
- **Package**: `com.savantsystems.yisdk.notifications`
- **Extends**: `Throwable>>`
- **Implements**: `PushTokenReceiver`
- **Methods**: 6
- **Fields**: 13
- **Source**: `savantsystems\yisdk\notifications\YiPushTokenReceiver.java`

**Key Methods**:
  - `YiPushTokenReceiver()`
  - `m196a()`
  - `Ok()`
  - `IllegalStateException()`
  - `NoWhenBranchMatchedException()`
  - `Err()`

---

### YiPlaybackManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- **Package**: `com.savantsystems.yisdk.playback`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 6
- **Source**: `savantsystems\yisdk\playback\YiPlaybackManagerImpl$pause$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPlaybackManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- **Package**: `com.savantsystems.yisdk.playback`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 7
- **Fields**: 16
- **Source**: `savantsystems\yisdk\playback\YiPlaybackManagerImpl$pauseWithTimestamp$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `invoke()`

---

### YiPlaybackManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- **Package**: `com.savantsystems.yisdk.playback`
- **Extends**: `SuspendLambda`
- **Implements**: `Function1<Continuation<`
- **Methods**: 8
- **Fields**: 26
- **Source**: `savantsystems\yisdk\playback\YiPlaybackManagerImpl$playClip$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `NoWhenBranchMatchedException()`
  - `NoWhenBranchMatchedException()`

---

### YiPlaybackManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- **Package**: `com.savantsystems.yisdk.playback`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `savantsystems\yisdk\playback\YiPlaybackManagerImpl$stop$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPlaybackManagerImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- **Package**: `com.savantsystems.yisdk.playback`
- **Extends**: `YiError>>`
- **Implements**: `YiPlaybackManager`
- **Methods**: 50
- **Fields**: 174
- **Source**: `savantsystems\yisdk\playback\YiPlaybackManagerImpl.java`

**Key Methods**:
  - `Factory()`
  - `Companion()`
  - `YiPlaybackManagerImpl()`
  - `mo201a()`
  - `IllegalStateException()`
  - `Ok()`
  - `method()`
  - `invoke()`
  - `Ok()`
  - `method()`
  - *(... and 40 more)*

---

### YiUserService [HIGH]


- **Full Name**: `com.savantsystems.yisdk.user.YiUserService`
- **Package**: `com.savantsystems.yisdk.user`
- **Extends**: `YiError>>`
- **Methods**: 3
- **Fields**: 0
- **Source**: `savantsystems\yisdk\user\YiUserService.java`

**Key Methods**:
  - `mo212a()`
  - `mo213b()`
  - `mo214c()`

---

### YiUserServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.user.YiUserServiceImpl`
- **Package**: `com.savantsystems.yisdk.user`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `savantsystems\yisdk\user\YiUserServiceImpl$setUserInfo$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiUserServiceImpl [HIGH]


- **Full Name**: `com.savantsystems.yisdk.user.YiUserServiceImpl`
- **Package**: `com.savantsystems.yisdk.user`
- **Extends**: `YiError>>`
- **Implements**: `YiUserService`
- **Methods**: 12
- **Fields**: 21
- **Source**: `savantsystems\yisdk\user\YiUserServiceImpl.java`

**Key Methods**:
  - `Companion()`
  - `Factory()`
  - `mo212a()`
  - `m215d()`
  - `mo213b()`
  - `mo214c()`
  - `m215d()`
  - `method()`
  - `invoke()`
  - `IllegalStateException()`
  - *(... and 2 more)*

---

### BLEJniLib [HIGH]


- **Full Name**: `com.thingclips.ble.jni.BLEJniLib`
- **Package**: `com.thingclips.ble.jni`
- **Methods**: 62
- **Fields**: 95
- **Source**: `thingclips\ble\jni\BLEJniLib.java`

**Key Methods**:
  - `BLEJniLib()`
  - `consumePackageList()`
  - `ArrayList()`
  - `RequestPackage()`
  - `crc4otaPackage()`
  - `dpDataRecived()`
  - `NormalResponseSecretBean()`
  - `getDpResponseBean()`
  - `getDpResponseBean()`
  - `BLEDpResponseBean()`
  - *(... and 52 more)*

---

### ASN1InputStream [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1InputStream`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `FilterInputStream`
- **Implements**: `BERTags`
- **Methods**: 72
- **Fields**: 44
- **Source**: `thingclips\bouncycastle\asn1\ASN1InputStream.java`

**Key Methods**:
  - `ASN1InputStream()`
  - `createPrimitiveDERObject()`
  - `DERUTF8String()`
  - `DERBMPString()`
  - `ASN1Integer()`
  - `DEROctetString()`
  - `DERNumericString()`
  - `DERPrintableString()`
  - `DERT61String()`
  - `DERVideotexString()`
  - *(... and 62 more)*

---

### BERPrivate [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BERPrivate`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Private`
- **Methods**: 9
- **Fields**: 7
- **Source**: `thingclips\bouncycastle\asn1\BERPrivate.java`

**Key Methods**:
  - `BERPrivate()`
  - `getEncodedVector()`
  - `ByteArrayOutputStream()`
  - `ASN1ParsingException()`
  - `getEncoding()`
  - `encode()`
  - `BERPrivate()`
  - `BERPrivate()`
  - `BERPrivate()`

---

### BERTaggedObject [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BERTaggedObject`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1TaggedObject`
- **Methods**: 10
- **Fields**: 4
- **Source**: `thingclips\bouncycastle\asn1\BERTaggedObject.java`

**Key Methods**:
  - `BERTaggedObject()`
  - `encode()`
  - `BEROctetString()`
  - `if()`
  - `ASN1Exception()`
  - `encodedLength()`
  - `isConstructed()`
  - `BERTaggedObject()`
  - `BERTaggedObject()`
  - `BERSequence()`

---

### DERTaggedObject [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DERTaggedObject`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1TaggedObject`
- **Methods**: 7
- **Fields**: 5
- **Source**: `thingclips\bouncycastle\asn1\DERTaggedObject.java`

**Key Methods**:
  - `DERTaggedObject()`
  - `encode()`
  - `encodedLength()`
  - `isConstructed()`
  - `toDERObject()`
  - `toDLObject()`
  - `DERTaggedObject()`

---

### DLPrivate [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DLPrivate`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Private`
- **Methods**: 10
- **Fields**: 7
- **Source**: `thingclips\bouncycastle\asn1\DLPrivate.java`

**Key Methods**:
  - `DLPrivate()`
  - `getEncodedVector()`
  - `ByteArrayOutputStream()`
  - `ASN1ParsingException()`
  - `getEncoding()`
  - `encode()`
  - `DLPrivate()`
  - `DLPrivate()`
  - `DLPrivate()`
  - `DLPrivate()`

---

### DLTaggedObject [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DLTaggedObject`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1TaggedObject`
- **Methods**: 5
- **Fields**: 4
- **Source**: `thingclips\bouncycastle\asn1\DLTaggedObject.java`

**Key Methods**:
  - `DLTaggedObject()`
  - `encode()`
  - `encodedLength()`
  - `isConstructed()`
  - `toDLObject()`

---

### ECGOST3410NamedCurves [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves`
- **Package**: `com.thingclips.bouncycastle.asn1.cryptopro`
- **Methods**: 26
- **Fields**: 67
- **Source**: `bouncycastle\asn1\cryptopro\ECGOST3410NamedCurves.java`

**Key Methods**:
  - `Hashtable()`
  - `Hashtable()`
  - `Hashtable()`
  - `ECDomainParameters()`
  - `ECDomainParameters()`
  - `ECDomainParameters()`
  - `ECDomainParameters()`
  - `ECDomainParameters()`
  - `ECDomainParameters()`
  - `ECDomainParameters()`
  - *(... and 16 more)*

**Notable Strings**:
  - `"DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3"`

---

### X962NamedCurves [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.asn1.p002x9.X962NamedCurves`
- **Package**: `com.thingclips.bouncycastle.asn1.p002x9`
- **Methods**: 84
- **Fields**: 102
- **Source**: `bouncycastle\asn1\p002x9\X962NamedCurves.java`

**Key Methods**:
  - `X9ECParametersHolder()`
  - `createParameters()`
  - `X9ECParameters()`
  - `X9ECParametersHolder()`
  - `createParameters()`
  - `X9ECParameters()`
  - `X9ECParametersHolder()`
  - `createParameters()`
  - `X9ECParameters()`
  - `X9ECParametersHolder()`
  - *(... and 74 more)*

---

### X9Curve [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.asn1.p002x9.X9Curve`
- **Package**: `com.thingclips.bouncycastle.asn1.p002x9`
- **Extends**: `ASN1Object`
- **Implements**: `X9ObjectIdentifiers`
- **Methods**: 19
- **Fields**: 15
- **Source**: `bouncycastle\asn1\p002x9\X9Curve.java`

**Key Methods**:
  - `X9Curve()`
  - `setFieldIdentifier()`
  - `IllegalArgumentException()`
  - `getCurve()`
  - `getSeed()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - `if()`
  - `DERSequence()`
  - `X9Curve()`
  - *(... and 9 more)*

---

### X9ECParameters [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.asn1.p002x9.X9ECParameters`
- **Package**: `com.thingclips.bouncycastle.asn1.p002x9`
- **Extends**: `ASN1Object`
- **Implements**: `X9ObjectIdentifiers`
- **Methods**: 27
- **Fields**: 13
- **Source**: `bouncycastle\asn1\p002x9\X9ECParameters.java`

**Key Methods**:
  - `X9ECParameters()`
  - `X9Curve()`
  - `X9ECPoint()`
  - `IllegalArgumentException()`
  - `getInstance()`
  - `X9ECParameters()`
  - `getBaseEntry()`
  - `getCurve()`
  - `getCurveEntry()`
  - `X9Curve()`
  - *(... and 17 more)*

---

### X9FieldID [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.asn1.p002x9.X9FieldID`
- **Package**: `com.thingclips.bouncycastle.asn1.p002x9`
- **Extends**: `ASN1Object`
- **Implements**: `X9ObjectIdentifiers`
- **Methods**: 18
- **Fields**: 6
- **Source**: `bouncycastle\asn1\p002x9\X9FieldID.java`

**Key Methods**:
  - `X9FieldID()`
  - `ASN1Integer()`
  - `getInstance()`
  - `X9FieldID()`
  - `getIdentifier()`
  - `getParameters()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - `DERSequence()`
  - `X9FieldID()`
  - *(... and 8 more)*

---

### CryptoServicesRegistrar [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.crypto.CryptoServicesRegistrar`
- **Package**: `com.thingclips.bouncycastle.crypto`
- **Methods**: 49
- **Fields**: 41
- **Source**: `thingclips\bouncycastle\crypto\CryptoServicesRegistrar.java`

**Key Methods**:
  - `CryptoServicesPermission()`
  - `CryptoServicesPermission()`
  - `CryptoServicesPermission()`
  - `Object()`
  - `Property()`
  - `Property()`
  - `Property()`
  - `Property()`
  - `DSAParameters()`
  - `BigInteger()`
  - *(... and 39 more)*

**Notable Strings**:
  - `"95475cf5d93e596c3fcd1d902add02f427f5f3c7210313bb45fb4d5bb2e5fe1cbd678cd4bbdd84c9836be1f31c0777725aeb6c2fc38b85f48076fa76bcd8146cc89a6fb2f706dd719898c2083dc8d896f84062e2c9c94d137b054a8d8096adb8d51952398eeca852a0af12df83e475aa65d4ec0c38a9560d5661186ff98b9fc9eb60eee8b030376b236bc73be3acdbd74fd61c1d2475fa3077b8f080467881ff7e1ca56fee066d79506ade51edbb5443a563927dbc4ba520086746175c8885925ebc64c6147906773496990cb714ec667304e261faee33b3cbdf008e0c3fa90650d97d3909c9275bf4ac86ffcb3d03e6dfc8ada5934242dd6d3bcca2a406cb0b"`

---

### GOST3411Digest [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.GOST3411Digest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Implements**: `ExtendedDigest, Memoable`
- **Methods**: 29
- **Fields**: 85
- **Source**: `bouncycastle\crypto\digests\GOST3411Digest.java`

**Key Methods**:
  - `GOST3411Digest()`
  - `GOST28147Engine()`
  - `ParametersWithSBox()`
  - `m218A()`
  - `m219E()`
  - `KeyParameter()`
  - `m220P()`
  - `cpyBytesToShort()`
  - `cpyShortToBytes()`
  - `finish()`
  - *(... and 19 more)*

---

### SkeinEngine [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.SkeinEngine`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Implements**: `Memoable`
- **Methods**: 61
- **Fields**: 89
- **Source**: `bouncycastle\crypto\digests\SkeinEngine.java`

**Key Methods**:
  - `Hashtable()`
  - `Configuration()`
  - `getBytes()`
  - `Parameter()`
  - `getType()`
  - `getValue()`
  - `SkeinEngine()`
  - `ThreefishEngine()`
  - `UBI()`
  - `IllegalArgumentException()`
  - *(... and 51 more)*

---

### TigerDigest [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.TigerDigest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Implements**: `ExtendedDigest, Memoable`
- **Methods**: 21
- **Fields**: 82
- **Source**: `bouncycastle\crypto\digests\TigerDigest.java`

**Key Methods**:
  - `TigerDigest()`
  - `finish()`
  - `keySchedule()`
  - `processBlock()`
  - `processLength()`
  - `processWord()`
  - `roundABC()`
  - `roundBCA()`
  - `roundCAB()`
  - `copy()`
  - *(... and 11 more)*

---

### WhirlpoolDigest [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.WhirlpoolDigest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Implements**: `ExtendedDigest, Memoable`
- **Methods**: 22
- **Fields**: 105
- **Source**: `bouncycastle\crypto\digests\WhirlpoolDigest.java`

**Key Methods**:
  - `WhirlpoolDigest()`
  - `bytesToLongFromBuffer()`
  - `convertLongToByteArray()`
  - `copyBitLength()`
  - `finish()`
  - `increment()`
  - `maskWithReductionPolynomial()`
  - `packIntoLong()`
  - `processFilledBuffer()`
  - `copy()`
  - *(... and 12 more)*

---

### PKCS1Encoding [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.crypto.encodings.PKCS1Encoding`
- **Package**: `com.thingclips.bouncycastle.crypto.encodings`
- **Implements**: `AsymmetricBlockCipher`
- **Methods**: 22
- **Fields**: 48
- **Source**: `bouncycastle\crypto\encodings\PKCS1Encoding.java`

**Key Methods**:
  - `PKCS1Encoding()`
  - `checkPkcs1Encoding()`
  - `decodeBlock()`
  - `decodeBlockOrRandom()`
  - `getOutputBlockSize()`
  - `InvalidCipherTextException()`
  - `InvalidCipherTextException()`
  - `decodeBlockOrRandom()`
  - `InvalidCipherTextException()`
  - `encodeBlock()`
  - *(... and 12 more)*

---

### GOST28147Engine [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.crypto.engines.GOST28147Engine`
- **Package**: `com.thingclips.bouncycastle.crypto.engines`
- **Implements**: `BlockCipher`
- **Methods**: 22
- **Fields**: 45
- **Source**: `bouncycastle\crypto\engines\GOST28147Engine.java`

**Key Methods**:
  - `Hashtable()`
  - `GOST28147Func()`
  - `GOST28147_mainStep()`
  - `addSBox()`
  - `bytesToint()`
  - `generateWorkingKey()`
  - `IllegalArgumentException()`
  - `getSBox()`
  - `IllegalArgumentException()`
  - `getSBoxName()`
  - *(... and 12 more)*

---

### CMac [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.crypto.macs.CMac`
- **Package**: `com.thingclips.bouncycastle.crypto.macs`
- **Implements**: `Mac`
- **Methods**: 20
- **Fields**: 39
- **Source**: `bouncycastle\crypto\macs\CMac.java`

**Key Methods**:
  - `CMac()`
  - `doubleLu()`
  - `lookupPoly()`
  - `IllegalArgumentException()`
  - `shiftLeft()`
  - `doFinal()`
  - `ISO7816d4Padding()`
  - `getAlgorithmName()`
  - `getMacSize()`
  - `init()`
  - *(... and 10 more)*

---

### OpenSSHPrivateKeyUtil [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil`
- **Package**: `com.thingclips.bouncycastle.crypto.util`
- **Methods**: 33
- **Fields**: 25
- **Source**: `bouncycastle\crypto\util\OpenSSHPrivateKeyUtil.java`

**Key Methods**:
  - `OpenSSHPrivateKeyUtil()`
  - `allIntegers()`
  - `encodePrivateKey()`
  - `IllegalArgumentException()`
  - `ASN1EncodableVector()`
  - `DERSequence()`
  - `IllegalStateException()`
  - `IllegalArgumentException()`
  - `SSHBuilder()`
  - `SSHBuilder()`
  - *(... and 23 more)*

---

### BCECPrivateKey [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec`
- **Implements**: `ECPrivateKey, com.thingclips.bouncycastle.jce.interfaces.ECPrivateKey, PKCS12BagAttributeCarrier, ECPointEncoder`
- **Methods**: 41
- **Fields**: 23
- **Source**: `provider\asymmetric\ec\BCECPrivateKey.java`

**Key Methods**:
  - `BCECPrivateKey()`
  - `PKCS12BagAttributeCarrierImpl()`
  - `getPublicKeyDetails()`
  - `populateFromPrivKeyInfo()`
  - `readObject()`
  - `PKCS12BagAttributeCarrierImpl()`
  - `writeObject()`
  - `equals()`
  - `getD()`
  - `getAlgorithm()`
  - *(... and 31 more)*

---

### KeyPairGeneratorSpi [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec`
- **Extends**: `KeyPairGenerator`
- **Methods**: 44
- **Fields**: 23
- **Source**: `provider\asymmetric\ec\KeyPairGeneratorSpi.java`

**Key Methods**:
  - `ECDH()`
  - `ECDHC()`
  - `ECDSA()`
  - `ECMQV()`
  - `KeyPairGeneratorSpi()`
  - `Hashtable()`
  - `ECGenParameterSpec()`
  - `ECGenParameterSpec()`
  - `ECGenParameterSpec()`
  - `ECGenParameterSpec()`
  - *(... and 34 more)*

---

### BCRSAPrivateKey [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa`
- **Implements**: `RSAPrivateKey, PKCS12BagAttributeCarrier`
- **Methods**: 33
- **Fields**: 24
- **Source**: `provider\asymmetric\rsa\BCRSAPrivateKey.java`

**Key Methods**:
  - `BCRSAPrivateKey()`
  - `PKCS12BagAttributeCarrierImpl()`
  - `getEncoding()`
  - `readObject()`
  - `PKCS12BagAttributeCarrierImpl()`
  - `RSAKeyParameters()`
  - `writeObject()`
  - `engineGetKeyParameters()`
  - `equals()`
  - `getModulus()`
  - *(... and 23 more)*

---

### CipherSpi [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.CipherSpi`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa`
- **Extends**: `BaseCipherSpi`
- **Methods**: 77
- **Fields**: 23
- **Source**: `provider\asymmetric\rsa\CipherSpi.java`

**Key Methods**:
  - `ISO9796d1Padding()`
  - `NoPadding()`
  - `OAEPPadding()`
  - `PKCS1v1_5Padding()`
  - `PKCS1v1_5Padding_PrivateOnly()`
  - `PKCS1Encoding()`
  - `PKCS1v1_5Padding_PublicOnly()`
  - `PKCS1Encoding()`
  - `CipherSpi()`
  - `BCJcaJceHelper()`
  - *(... and 67 more)*

---

### BaseAgreementSpi [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util`
- **Extends**: `KeyAgreementSpi`
- **Methods**: 23
- **Fields**: 58
- **Source**: `provider\asymmetric\util\BaseAgreementSpi.java`

**Key Methods**:
  - `HashMap()`
  - `HashMap()`
  - `HashMap()`
  - `Hashtable()`
  - `Hashtable()`
  - `BaseAgreementSpi()`
  - `getAlgorithm()`
  - `getKeySize()`
  - `getSharedSecretBytes()`
  - `NoSuchAlgorithmException()`
  - *(... and 13 more)*

---

### EC5Util [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.EC5Util`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util`
- **Methods**: 28
- **Fields**: 34
- **Source**: `provider\asymmetric\util\EC5Util.java`

**Key Methods**:
  - `HashMap()`
  - `convertCurve()`
  - `EllipticCurve()`
  - `convertField()`
  - `ECFieldFp()`
  - `ECFieldF2m()`
  - `convertPoint()`
  - `convertPoint()`
  - `convertSpec()`
  - `ECNamedCurveSpec()`
  - *(... and 18 more)*

---

### PKCS12BagAttributeCarrierImpl [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util`
- **Implements**: `PKCS12BagAttributeCarrier`
- **Methods**: 13
- **Fields**: 9
- **Source**: `provider\asymmetric\util\PKCS12BagAttributeCarrierImpl.java`

**Key Methods**:
  - `PKCS12BagAttributeCarrierImpl()`
  - `getAttributes()`
  - `getBagAttribute()`
  - `getBagAttributeKeys()`
  - `getOrdering()`
  - `readObject()`
  - `ASN1InputStream()`
  - `setBagAttribute()`
  - `size()`
  - `writeObject()`
  - *(... and 3 more)*

---

### X509CertificateObject [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.X509CertificateObject`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509`
- **Extends**: `X509CertificateImpl`
- **Implements**: `PKCS12BagAttributeCarrier`
- **Methods**: 33
- **Fields**: 61
- **Source**: `provider\asymmetric\x509\X509CertificateObject.java`

**Key Methods**:
  - `X509CertificateEncodingException()`
  - `getCause()`
  - `X509CertificateObject()`
  - `Object()`
  - `PKCS12BagAttributeCarrierImpl()`
  - `createBasicConstraints()`
  - `CertificateParsingException()`
  - `createKeyUsage()`
  - `CertificateParsingException()`
  - `createSigAlgName()`
  - *(... and 23 more)*

---

### BaseMac [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.symmetric.util.BaseMac`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.symmetric.util`
- **Extends**: `MacSpi`
- **Implements**: `PBE`
- **Methods**: 34
- **Fields**: 21
- **Source**: `provider\symmetric\util\BaseMac.java`

**Key Methods**:
  - `BaseMac()`
  - `copyMap()`
  - `Hashtable()`
  - `engineDoFinal()`
  - `engineGetMacLength()`
  - `engineInit()`
  - `InvalidKeyException()`
  - `PBEParameterSpec()`
  - `if()`
  - `if()`
  - *(... and 24 more)*

---

### PKCS12BagAttributeCarrier [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier`
- **Package**: `com.thingclips.bouncycastle.jce.interfaces`
- **Methods**: 3
- **Fields**: 0
- **Source**: `bouncycastle\jce\interfaces\PKCS12BagAttributeCarrier.java`

**Key Methods**:
  - `getBagAttribute()`
  - `getBagAttributeKeys()`
  - `setBagAttribute()`

---

### BouncyCastleProviderConfiguration [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.jce.provider.BouncyCastleProviderConfiguration`
- **Package**: `com.thingclips.bouncycastle.jce.provider`
- **Implements**: `ProviderConfiguration`
- **Methods**: 22
- **Fields**: 23
- **Source**: `bouncycastle\jce\provider\BouncyCastleProviderConfiguration.java`

**Key Methods**:
  - `ProviderConfigurationPermission()`
  - `ProviderConfigurationPermission()`
  - `ProviderConfigurationPermission()`
  - `ProviderConfigurationPermission()`
  - `ProviderConfigurationPermission()`
  - `ProviderConfigurationPermission()`
  - `ThreadLocal()`
  - `ThreadLocal()`
  - `HashSet()`
  - `HashMap()`
  - *(... and 12 more)*

---

### Primes [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.math.Primes`
- **Package**: `com.thingclips.bouncycastle.math`
- **Methods**: 48
- **Fields**: 100
- **Source**: `thingclips\bouncycastle\math\Primes.java`

**Key Methods**:
  - `MROutput()`
  - `probablyPrime()`
  - `provablyCompositeNotPrimePower()`
  - `probablyPrime()`
  - `MROutput()`
  - `provablyCompositeNotPrimePower()`
  - `MROutput()`
  - `provablyCompositeWithFactor()`
  - `MROutput()`
  - `getFactor()`
  - *(... and 38 more)*

---

### ECAlgorithms [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.ECAlgorithms`
- **Package**: `com.thingclips.bouncycastle.math.ec`
- **Methods**: 44
- **Fields**: 154
- **Source**: `bouncycastle\math\ec\ECAlgorithms.java`

**Key Methods**:
  - `cleanPoint()`
  - `IllegalArgumentException()`
  - `implCheckResult()`
  - `IllegalStateException()`
  - `implShamirsTrickFixedPoint()`
  - `IllegalStateException()`
  - `FixedPointCombMultiplier()`
  - `implShamirsTrickJsf()`
  - `implShamirsTrickWNaf()`
  - `implShamirsTrickFixedPoint()`
  - *(... and 34 more)*

---

### ECCurve [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.ECCurve`
- **Package**: `com.thingclips.bouncycastle.math.ec`
- **Extends**: `ECCurve`
- **Methods**: 154
- **Fields**: 164
- **Source**: `bouncycastle\math\ec\ECCurve.java`

**Key Methods**:
  - `AbstractF2m()`
  - `buildField()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `implRandomFieldElementMult()`
  - `inverse()`
  - `LongArray()`
  - `createPoint()`
  - *(... and 144 more)*

---

### ECPoint [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.ECPoint`
- **Package**: `com.thingclips.bouncycastle.math.ec`
- **Extends**: `ECPoint`
- **Methods**: 181
- **Fields**: 382
- **Source**: `bouncycastle\math\ec\ECPoint.java`

**Key Methods**:
  - `AbstractF2m()`
  - `satisfiesCurveEquation()`
  - `IllegalStateException()`
  - `satisfiesOrder()`
  - `scaleX()`
  - `getCurve()`
  - `getCurve()`
  - `scaleXNegateY()`
  - `scaleX()`
  - `scaleY()`
  - *(... and 171 more)*

---

### LongArray [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.LongArray`
- **Package**: `com.thingclips.bouncycastle.math.ec`
- **Implements**: `Cloneable`
- **Methods**: 93
- **Fields**: 382
- **Source**: `bouncycastle\math\ec\LongArray.java`

**Key Methods**:
  - `LongArray()`
  - `add()`
  - `addBoth()`
  - `addShiftedByBitsSafe()`
  - `addShiftedDown()`
  - `addShiftedUp()`
  - `bitLength()`
  - `degreeFrom()`
  - `distribute()`
  - `flipBit()`
  - *(... and 83 more)*

---

### Ed448 [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.rfc8032.Ed448`
- **Package**: `com.thingclips.bouncycastle.math.ec.rfc8032`
- **Extends**: `X448Field`
- **Methods**: 94
- **Fields**: 475
- **Source**: `math\ec\rfc8032\Ed448.java`

**Key Methods**:
  - `Object()`
  - `C0187F()`
  - `PointExt()`
  - `PointPrecomp()`
  - `calculateS()`
  - `reduceScalar()`
  - `checkContextVar()`
  - `checkPoint()`
  - `checkPointVar()`
  - `checkScalarVar()`
  - *(... and 84 more)*

---

### FiniteFields [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.math.field.FiniteFields`
- **Package**: `com.thingclips.bouncycastle.math.field`
- **Methods**: 9
- **Fields**: 6
- **Source**: `bouncycastle\math\field\FiniteFields.java`

**Key Methods**:
  - `PrimeField()`
  - `PrimeField()`
  - `getBinaryExtensionField()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `GenericPolynomialExtensionField()`
  - `getPrimeField()`
  - `IllegalArgumentException()`
  - `PrimeField()`

---

### Fingerprint [HIGH]


- **Full Name**: `com.thingclips.bouncycastle.util.Fingerprint`
- **Package**: `com.thingclips.bouncycastle.util`
- **Methods**: 15
- **Fields**: 12
- **Source**: `thingclips\bouncycastle\util\Fingerprint.java`

**Key Methods**:
  - `Fingerprint()`
  - `calculateFingerprint()`
  - `calculateFingerprint()`
  - `calculateFingerprintSHA512_160()`
  - `SHA512tDigest()`
  - `equals()`
  - `getFingerprint()`
  - `hashCode()`
  - `toString()`
  - `StringBuffer()`
  - *(... and 5 more)*

---

### OkHttpNetworkFetcher [HIGH]


- **Full Name**: `com.thingclips.imagepipeline.okhttp3.OkHttpNetworkFetcher`
- **Package**: `com.thingclips.imagepipeline.okhttp3`
- **Extends**: `BaseNetworkFetcher<OkHttpNetworkFetchState>`
- **Methods**: 18
- **Fields**: 15
- **Source**: `thingclips\imagepipeline\okhttp3\OkHttpNetworkFetcher.java`

**Key Methods**:
  - `OkHttpNetworkFetchState()`
  - `OkHttpNetworkFetcher()`
  - `handleException()`
  - `createFetchState()`
  - `m432createFetchState()`
  - `fetchWithRequest()`
  - `onCancellationRequested()`
  - `run()`
  - `onFailure()`
  - `onResponse()`
  - *(... and 8 more)*

---

### C0196R [HIGH]


- **Full Name**: `com.thingclips.scene.core.C0196R`
- **Package**: `com.thingclips.scene.core`
- **Methods**: 19
- **Fields**: 6213
- **Source**: `thingclips\scene\core\C0196R.java`

**Key Methods**:
  - `anim()`
  - `animator()`
  - `attr()`
  - `bool()`
  - `color()`
  - `dimen()`
  - `drawable()`
  - `id()`
  - `integer()`
  - `interpolator()`
  - *(... and 9 more)*

---

### ThingOSBeacon [HIGH]


- **Full Name**: `com.thingclips.sdk.beacon.p006os.ThingOSBeacon`
- **Package**: `com.thingclips.sdk.beacon.p006os`
- **Methods**: 1
- **Fields**: 0
- **Source**: `sdk\beacon\p006os\ThingOSBeacon.java`

**Key Methods**:
  - `getBeaconManager()`

---

### ThingBlePlugin [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.ThingBlePlugin`
- **Package**: `com.thingclips.sdk.ble`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingBlePlugin`
- **Methods**: 13
- **Fields**: 1
- **Source**: `thingclips\sdk\ble\ThingBlePlugin.java`

**Key Methods**:
  - `dependencies()`
  - `getThingBeaconManager()`
  - `getThingBleAbility()`
  - `getThingBleController()`
  - `getThingBleManager()`
  - `qqqdqbb()`
  - `getThingBleOperator()`
  - `qqqqdqq()`
  - `getThingInnerScanner()`
  - `getThingLEAudioManager()`
  - *(... and 3 more)*

---

### BluetoothBondCode [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.BluetoothBondCode`
- **Package**: `com.thingclips.sdk.ble.core`
- **Methods**: 0
- **Fields**: 28
- **Source**: `sdk\ble\core\BluetoothBondCode.java`

**Notable Strings**:
  - `"BLUETOOTH_NOT_ENABLE"`

---

### BluetoothPermissionCode [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.BluetoothPermissionCode`
- **Package**: `com.thingclips.sdk.ble.core`
- **Methods**: 0
- **Fields**: 12
- **Source**: `sdk\ble\core\BluetoothPermissionCode.java`

---

### GattCode [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.GattCode`
- **Package**: `com.thingclips.sdk.ble.core`
- **Methods**: 3
- **Fields**: 332
- **Source**: `sdk\ble\core\GattCode.java`

**Key Methods**:
  - `getCodeMsg()`
  - `getOpenCode()`
  - `needRetryForBLEActivator()`

**Notable Strings**:
  - `"GattCode"`

---

### IThingBleAbility [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.ability.IThingBleAbility`
- **Package**: `com.thingclips.sdk.ble.core.ability`
- **Methods**: 21
- **Fields**: 0
- **Source**: `ble\core\ability\IThingBleAbility.java`

**Key Methods**:
  - `configMtu()`
  - `connect()`
  - `disconnect()`
  - `discoveryServices()`
  - `notify()`
  - `onlyDisconnect()`
  - `read()`
  - `readDescriptor()`
  - `readRssi()`
  - `refreshCache()`
  - *(... and 11 more)*

---

### BleGattProfileData [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.ability.model.BleGattProfileData`
- **Package**: `com.thingclips.sdk.ble.core.ability.model`
- **Implements**: `Parcelable`
- **Methods**: 14
- **Fields**: 12
- **Source**: `core\ability\model\BleGattProfileData.java`

**Key Methods**:
  - `createFromParcel()`
  - `BleGattProfileData()`
  - `newArray()`
  - `BleGattProfileData()`
  - `addServices()`
  - `containsCharacter()`
  - `describeContents()`
  - `getService()`
  - `getServices()`
  - `ArrayList()`
  - *(... and 4 more)*

---

### BleGattServiceData [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.ability.model.BleGattServiceData`
- **Package**: `com.thingclips.sdk.ble.core.ability.model`
- **Implements**: `Parcelable, Comparable`
- **Methods**: 17
- **Fields**: 12
- **Source**: `core\ability\model\BleGattServiceData.java`

**Key Methods**:
  - `createFromParcel()`
  - `BleGattServiceData()`
  - `newArray()`
  - `BleGattServiceData()`
  - `ParcelUuid()`
  - `format()`
  - `compareTo()`
  - `getUUID()`
  - `describeContents()`
  - `getCharacters()`
  - *(... and 7 more)*

---

### BleConnectParams [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.ability.options.BleConnectParams`
- **Package**: `com.thingclips.sdk.ble.core.ability.options`
- **Implements**: `Parcelable`
- **Methods**: 27
- **Fields**: 25
- **Source**: `core\ability\options\BleConnectParams.java`

**Key Methods**:
  - `createFromParcel()`
  - `BleConnectParams()`
  - `newArray()`
  - `build()`
  - `BleConnectParams()`
  - `setAutoConnect()`
  - `setConnectRetry()`
  - `setConnectTimeout()`
  - `setConnectTimeoutTimes()`
  - `setServiceDiscoverRetry()`
  - *(... and 17 more)*

---

### BluetoothStateChangedReponse [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.ability.response.BluetoothStateChangedReponse`
- **Package**: `com.thingclips.sdk.ble.core.ability.response`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\ability\response\BluetoothStateChangedReponse.java`

**Key Methods**:
  - `onBluetoothStateChanged()`

---

### bdpdqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.analysis.bdpdqbp`
- **Package**: `com.thingclips.sdk.ble.core.analysis`
- **Methods**: 8
- **Fields**: 10
- **Source**: `ble\core\analysis\bdpdqbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `if()`
  - `if()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### BLEDevInfoBean [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.BLEDevInfoBean`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Implements**: `Serializable`
- **Methods**: 24
- **Fields**: 19
- **Source**: `ble\core\bean\BLEDevInfoBean.java`

**Key Methods**:
  - `BLEDevInfoBean()`
  - `if()`
  - `if()`
  - `if()`
  - `if()`
  - `bytesToVersion()`
  - `StringBuilder()`
  - `getAuthKey()`
  - `getAuthKeyHexString()`
  - `getAuthKeyString()`
  - *(... and 14 more)*

---

### DataParseBean [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.DataParseBean`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 11
- **Fields**: 23
- **Source**: `ble\core\bean\DataParseBean.java`

**Key Methods**:
  - `getDps()`
  - `getDpsTime()`
  - `setDps()`
  - `setDpsTime()`
  - `toString()`
  - `StringBuilder()`
  - `toString()`
  - `toString()`
  - `StringBuilder()`
  - `updateDpDesBean()`
  - *(... and 1 more)*

**Notable Strings**:
  - `", uuid='"`

---

### NormalResponseSecretBean [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.NormalResponseSecretBean`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 6
- **Fields**: 4
- **Source**: `ble\core\bean\NormalResponseSecretBean.java`

**Key Methods**:
  - `NormalResponseSecretBean()`
  - `getData()`
  - `getType()`
  - `setData()`
  - `setType()`
  - `toString()`

---

### OTA2AccessBean [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.OTA2AccessBean`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 7
- **Fields**: 8
- **Source**: `ble\core\bean\OTA2AccessBean.java`

**Key Methods**:
  - `OTA2AccessBean()`
  - `getAlreadyCrc()`
  - `getAlreadyIndex()`
  - `getMd5()`
  - `getStatus()`
  - `getType()`
  - `toString()`

---

### OTA2IndexBean [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.OTA2IndexBean`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 6
- **Fields**: 4
- **Source**: `ble\core\bean\OTA2IndexBean.java`

**Key Methods**:
  - `OTA2IndexBean()`
  - `getIndex()`
  - `getStatus()`
  - `getType()`
  - `toString()`
  - `StringBuilder()`

---

### ThingAdvertisingData [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.ThingAdvertisingData`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 13
- **Fields**: 15
- **Source**: `ble\core\bean\ThingAdvertisingData.java`

**Key Methods**:
  - `getDevUuId()`
  - `getDpEncryptedType()`
  - `getDpRaw()`
  - `getFrameControl()`
  - `getFrameCounter()`
  - `getMic()`
  - `getNonce()`
  - `setDevUuId()`
  - `setDpEncryptedType()`
  - `setDpRaw()`
  - *(... and 3 more)*

---

### TimeDpResponseBean [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.TimeDpResponseBean`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 6
- **Fields**: 18
- **Source**: `ble\core\bean\TimeDpResponseBean.java`

**Key Methods**:
  - `TimeDpResponseBean()`
  - `if()`
  - `getDpResponseBean()`
  - `BLEDpResponseBean()`
  - `BLEDpBean()`
  - `toString()`

---

### BluetoothBondManager [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.manager.BluetoothBondManager`
- **Package**: `com.thingclips.sdk.ble.core.manager`
- **Extends**: `BroadcastReceiver`
- **Implements**: `Handler.Callback`
- **Methods**: 78
- **Fields**: 104
- **Source**: `ble\core\manager\BluetoothBondManager.java`

**Key Methods**:
  - `BluetoothBondManager()`
  - `BluetoothBondReceive()`
  - `CopyOnWriteArrayList()`
  - `Handler()`
  - `bdpdqbp()`
  - `onReceive()`
  - `StringBuilder()`
  - `if()`
  - `StringBuilder()`
  - `bdpdqbp()`
  - *(... and 68 more)*

**Notable Strings**:
  - `"thingble_BluetoothBondManager"`
  - `"thingble_BluetoothBondManager"`
  - `"BluetoothBondReceive error = "`
  - `"thingble_BluetoothBondManager"`
  - `"android.bluetooth.adapter.action.STATE_CHANGED"`
  - *(... and 106 more)*

---

### bppdpdq [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.manager.bppdpdq`
- **Package**: `com.thingclips.sdk.ble.core.manager`
- **Implements**: `Runnable`
- **Methods**: 34
- **Fields**: 48
- **Source**: `ble\core\manager\bppdpdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `C0311bppdpdq()`
  - `onResponse()`
  - `if()`
  - `pdqppqb()`
  - `onResponse()`
  - `StringBuilder()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - *(... and 24 more)*

**Notable Strings**:
  - `"[onResponse] device BleGattService is NULL, mac:"`
  - `"[onResponse] device BleGattService is NO target characters , mac:"`
  - `"BluetoothAdapter is null"`
  - `"BluetoothAdapter isEnabled = "`

---

### bdpdqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.manager.bdpdqbp`
- **Package**: `com.thingclips.sdk.ble.core.manager`
- **Extends**: `BluetoothStateListener`
- **Implements**: `Runnable`
- **Methods**: 27
- **Fields**: 12
- **Source**: `ble\core\manager\NormalBleConnectManager.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `CopyOnWriteArrayList()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `onBluetoothStateChanged()`
  - `bppdpdq()`
  - `onConnectStatusChanged()`
  - `onConnectStatusChanged()`
  - `pdqppqb()`
  - *(... and 17 more)*

---

### pdqppqb [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.manager.pdqppqb`
- **Package**: `com.thingclips.sdk.ble.core.manager`
- **Implements**: `LeScanResponse`
- **Methods**: 25
- **Fields**: 25
- **Source**: `ble\core\manager\pdqppqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onDeviceFounded()`
  - `onScanCancel()`
  - `onScanStart()`
  - `onScanStop()`
  - `bdpdqbp()`
  - `C0312pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bppdpdq()`
  - *(... and 15 more)*

---

### bdpdqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.manager.bdpdqbp`
- **Package**: `com.thingclips.sdk.ble.core.manager`
- **Implements**: `Handler.Callback`
- **Methods**: 66
- **Fields**: 60
- **Source**: `ble\core\manager\ResetDeviceManager.java`

**Key Methods**:
  - `Semaphore()`
  - `pqdppqd()`
  - `bdpdqbp()`
  - `Handler()`
  - `bdpdqbp()`
  - `onNotify()`
  - `onResponse()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 56 more)*

---

### bdpdqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.manager.bdpdqbp`
- **Package**: `com.thingclips.sdk.ble.core.manager`
- **Implements**: `Business.ResultListener<ResetKeyBean>`
- **Methods**: 12
- **Fields**: 7
- **Source**: `ble\core\manager\ResetScanDeviceManager.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `StringBuilder()`
  - `CheckResultBean()`
  - `byteToString()`
  - `StringBuilder()`
  - `checkBleWifiDeviceReset()`
  - `pqdppqd()`
  - `bdpdqbp()`
  - *(... and 2 more)*

---

### bdpdqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.manager.bdpdqbp`
- **Package**: `com.thingclips.sdk.ble.core.manager`
- **Implements**: `Business.ResultListener<String>`
- **Methods**: 16
- **Fields**: 7
- **Source**: `ble\core\manager\WeatherAbility.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `getCurrentLocationWeathers()`
  - `if()`
  - `pqdppqd()`
  - `pdqppqb()`
  - *(... and 6 more)*

---

### ThingBleProtocol [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.open.ThingBleProtocol`
- **Package**: `com.thingclips.sdk.ble.core.open`
- **Methods**: 1
- **Fields**: 0
- **Source**: `ble\core\open\ThingBleProtocol.java`

**Key Methods**:
  - `newBleProtocolInstance()`

---

### AbsSubcontractReps [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AbsSubcontractReps`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 12
- **Fields**: 47
- **Source**: `core\packet\bean\AbsSubcontractReps.java`

**Key Methods**:
  - `ArrayList()`
  - `AbsSubcontractReps()`
  - `unpack()`
  - `SubcontractCacheData()`
  - `getPackageDataLength()`
  - `getReplyFrameByte()`
  - `if()`
  - `if()`
  - `parseRep()`
  - `receiveOver()`
  - *(... and 2 more)*

---

### AccessoriesDpReportRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AccessoriesDpReportRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `BaseAccessoriesDpReportRep`
- **Methods**: 5
- **Fields**: 15
- **Source**: `core\packet\bean\AccessoriesDpReportRep.java`

**Key Methods**:
  - `parseRep()`
  - `AccessoriesExtInfo()`
  - `ArrayList()`
  - `BLEDpBean()`
  - `BLEDpResponseBean()`

---

### AccessoriesDpReportTimeRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AccessoriesDpReportTimeRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `BaseAccessoriesDpReportRep`
- **Methods**: 6
- **Fields**: 19
- **Source**: `core\packet\bean\AccessoriesDpReportTimeRep.java`

**Key Methods**:
  - `parseRep()`
  - `AccessoriesExtInfo()`
  - `if()`
  - `ArrayList()`
  - `BLEDpBean()`
  - `BLEDpResponseBean()`

---

### AccessoriesExtInfo [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AccessoriesExtInfo`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Methods**: 9
- **Fields**: 13
- **Source**: `core\packet\bean\AccessoriesExtInfo.java`

**Key Methods**:
  - `AccessoriesExtInfo()`
  - `getIdLen()`
  - `getIdType()`
  - `getNodeId()`
  - `getRawData()`
  - `toString()`
  - `StringBuilder()`
  - `AccessoriesExtInfo()`
  - `ArrayList()`

---

### AccessoriesInfoRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AccessoriesInfoRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 20
- **Fields**: 47
- **Source**: `core\packet\bean\AccessoriesInfoRep.java`

**Key Methods**:
  - `ArrayList()`
  - `getBit()`
  - `getOtaExtChannelList()`
  - `ArrayList()`
  - `OtaExtChannel()`
  - `isConnected()`
  - `toString()`
  - `StringBuilder()`
  - `FirmwareInfo()`
  - `getHardVer()`
  - *(... and 10 more)*

**Notable Strings**:
  - `"AccessoriesDevInfo{uuid='"`
  - `"[parseRep] accessoriesInfo.uuidLen error!!!"`

---

### AccessoriesOTAFileInfoRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AccessoriesOTAFileInfoRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 2
- **Fields**: 12
- **Source**: `core\packet\bean\AccessoriesOTAFileInfoRep.java`

**Key Methods**:
  - `parseRep()`
  - `AccessoriesExtInfo()`

---

### AccessoriesOTAFileSendRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AccessoriesOTAFileSendRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 2
- **Fields**: 8
- **Source**: `core\packet\bean\AccessoriesOTAFileSendRep.java`

**Key Methods**:
  - `parseRep()`
  - `AccessoriesExtInfo()`

---

### AccessoriesOTAOffsetRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AccessoriesOTAOffsetRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 2
- **Fields**: 9
- **Source**: `core\packet\bean\AccessoriesOTAOffsetRep.java`

**Key Methods**:
  - `parseRep()`
  - `AccessoriesExtInfo()`

---

### AccessoriesOTARequestRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AccessoriesOTARequestRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 2
- **Fields**: 13
- **Source**: `core\packet\bean\AccessoriesOTARequestRep.java`

**Key Methods**:
  - `parseRep()`
  - `AccessoriesExtInfo()`

---

### AudioAlarmClockRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AudioAlarmClockRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 7
- **Source**: `core\packet\bean\AudioAlarmClockRep.java`

**Key Methods**:
  - `parseRep()`

---

### AudioTokenReportData [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AudioTokenReportData`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `AbsSubcontractReps`
- **Methods**: 2
- **Fields**: 9
- **Source**: `core\packet\bean\AudioTokenReportData.java`

**Key Methods**:
  - `AudioTokenReportData()`
  - `receiveOver()`

---

### AudioTokenRequireRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AudioTokenRequireRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 5
- **Source**: `core\packet\bean\AudioTokenRequireRep.java`

**Key Methods**:
  - `parseRep()`

---

### BleFittingsRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.BleFittingsRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 3
- **Fields**: 9
- **Source**: `core\packet\bean\BleFittingsRep.java`

**Key Methods**:
  - `parseRep()`
  - `ArrayList()`
  - `FittingsInfo()`

---

### BondStateRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.BondStateRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 3
- **Fields**: 10
- **Source**: `core\packet\bean\BondStateRep.java`

**Key Methods**:
  - `parseRep()`
  - `String()`
  - `toString()`

---

### DeviceInfoRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.DeviceInfoRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 17
- **Fields**: 79
- **Source**: `core\packet\bean\DeviceInfoRep.java`

**Key Methods**:
  - `parseAfter85byte()`
  - `parseAttachData()`
  - `ArrayList()`
  - `OtaExtChannel()`
  - `parseCombosFlag()`
  - `parsePacketMaxSize()`
  - `parseSecurityLevel()`
  - `version()`
  - `version2()`
  - `parseRep()`
  - *(... and 7 more)*

---

### DpsReportRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.DpsReportRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 6
- **Fields**: 20
- **Source**: `core\packet\bean\DpsReportRep.java`

**Key Methods**:
  - `DpsReportRep()`
  - `parseRep()`
  - `BLEDpResponseBean()`
  - `ArrayList()`
  - `BLEDpBean()`
  - `DpsReportRep()`

---

### DpsSendRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.DpsSendRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 3
- **Fields**: 4
- **Source**: `core\packet\bean\DpsSendRep.java`

**Key Methods**:
  - `DpsSendRep()`
  - `parseRep()`
  - `DpsSendRep()`

---

### ExpandDeviceInfoRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.ExpandDeviceInfoRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 6
- **Fields**: 18
- **Source**: `core\packet\bean\ExpandDeviceInfoRep.java`

**Key Methods**:
  - `transformData()`
  - `if()`
  - `parseRep()`
  - `StringBuilder()`
  - `toString()`
  - `StringBuilder()`

---

### FileTransferInfoRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.FileTransferInfoRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `FileTransferBaseRep`
- **Methods**: 1
- **Fields**: 11
- **Source**: `core\packet\bean\FileTransferInfoRep.java`

**Key Methods**:
  - `parseRep()`

---

### GetDevDataRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.GetDevDataRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `AbsSubcontractReps`
- **Implements**: `bdqqqdq<DeviceDataBean>`
- **Methods**: 6
- **Fields**: 14
- **Source**: `core\packet\bean\GetDevDataRep.java`

**Key Methods**:
  - `GetDevDataRep()`
  - `getReplyFrameByte()`
  - `parseRep()`
  - `receiveOver()`
  - `exchange()`
  - `DeviceDataBean()`

---

### IOTDataGetRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.IOTDataGetRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Implements**: `bdqqqdq<DevIotDataBean>`
- **Methods**: 3
- **Fields**: 8
- **Source**: `core\packet\bean\IOTDataGetRep.java`

**Key Methods**:
  - `parseRep()`
  - `exchange()`
  - `DevIotDataBean()`

---

### OTAOffsetRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.OTAOffsetRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 3
- **Source**: `core\packet\bean\OTAOffsetRep.java`

**Key Methods**:
  - `parseRep()`

---

### OTAStartRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.OTAStartRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 9
- **Source**: `core\packet\bean\OTAStartRep.java`

**Key Methods**:
  - `parseRep()`

---

### QueryFittingsRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.QueryFittingsRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 4
- **Source**: `core\packet\bean\QueryFittingsRep.java`

**Key Methods**:
  - `parseRep()`

---

### Ret [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.Ret`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Methods**: 78
- **Fields**: 101
- **Source**: `core\packet\bean\Ret.java`

**Key Methods**:
  - `Reps()`
  - `dataParse()`
  - `SimpleRep()`
  - `SimpleRep()`
  - `ExpandDeviceInfoRep()`
  - `SendExpandActivateInfoRep()`
  - `DeviceInfoRep()`
  - `PairRep()`
  - `DpsSendRep()`
  - `DeviceStatusSendRep()`
  - *(... and 68 more)*

---

### SecurityAuth1Rep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.SecurityAuth1Rep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 5
- **Source**: `core\packet\bean\SecurityAuth1Rep.java`

**Key Methods**:
  - `parseRep()`

---

### SecurityAuth2Rep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.SecurityAuth2Rep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 6
- **Source**: `core\packet\bean\SecurityAuth2Rep.java`

**Key Methods**:
  - `parseRep()`

---

### SecurityAuth3Rep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.SecurityAuth3Rep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 5
- **Source**: `core\packet\bean\SecurityAuth3Rep.java`

**Key Methods**:
  - `parseRep()`

---

### StatusDpsReportRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.StatusDpsReportRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 4
- **Fields**: 13
- **Source**: `core\packet\bean\StatusDpsReportRep.java`

**Key Methods**:
  - `parseRep()`
  - `BLEDpResponseBean()`
  - `ArrayList()`
  - `BLEDpBean()`

---

### StatusTimeDpsReportRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.StatusTimeDpsReportRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 5
- **Fields**: 18
- **Source**: `core\packet\bean\StatusTimeDpsReportRep.java`

**Key Methods**:
  - `parseRep()`
  - `if()`
  - `BLEDpResponseBean()`
  - `ArrayList()`
  - `BLEDpBean()`

---

### TimeDpsReportRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.TimeDpsReportRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 7
- **Fields**: 25
- **Source**: `core\packet\bean\TimeDpsReportRep.java`

**Key Methods**:
  - `TimeDpsReportRep()`
  - `parseRep()`
  - `if()`
  - `BLEDpResponseBean()`
  - `ArrayList()`
  - `BLEDpBean()`
  - `TimeDpsReportRep()`

---

### WiFiConfigResultRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.WiFiConfigResultRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 11
- **Source**: `core\packet\bean\WiFiConfigResultRep.java`

**Key Methods**:
  - `parseRep()`

---

### WiFiDevInfoRep [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.WiFiDevInfoRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 4
- **Fields**: 44
- **Source**: `core\packet\bean\WiFiDevInfoRep.java`

**Key Methods**:
  - `version()`
  - `version2()`
  - `parseRep()`
  - `ArrayList()`

---

### IThingBleFlow [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.IThingBleFlow`
- **Package**: `com.thingclips.sdk.ble.core.protocol`
- **Methods**: 49
- **Fields**: 3
- **Source**: `ble\core\protocol\IThingBleFlow.java`

**Key Methods**:
  - `clearBigData()`
  - `clearV4BigData()`
  - `connectDeviceAction()`
  - `disconnectDeviceAction()`
  - `fetchWifiDevInfoRet()`
  - `getBlePhyConnectStatus()`
  - `getBluetoothState()`
  - `getConnectState()`
  - `getDeviceSecurityFlag()`
  - `getDeviceSecurityLevel()`
  - *(... and 39 more)*

---

### ActivateStatusReceiver [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.recevier.ActivateStatusReceiver`
- **Package**: `com.thingclips.sdk.ble.core.protocol.recevier`
- **Implements**: `pppbbbb`
- **Methods**: 14
- **Fields**: 15
- **Source**: `core\protocol\recevier\ActivateStatusReceiver.java`

**Key Methods**:
  - `Status()`
  - `getStage()`
  - `getStatus()`
  - `getType()`
  - `setStage()`
  - `setStatus()`
  - `setType()`
  - `ActivateStatusReceiver()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - *(... and 4 more)*

---

### FetchActivateStatusInstruction [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.request.FetchActivateStatusInstruction`
- **Package**: `com.thingclips.sdk.ble.core.protocol.request`
- **Extends**: `qpqddqp`
- **Methods**: 17
- **Fields**: 16
- **Source**: `core\protocol\request\FetchActivateStatusInstruction.java`

**Key Methods**:
  - `Status()`
  - `getStage()`
  - `getStatus()`
  - `getType()`
  - `setStage()`
  - `setStatus()`
  - `setType()`
  - `FetchActivateStatusInstruction()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - *(... and 7 more)*

---

### FetchWiFiListInstruction [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.request.FetchWiFiListInstruction`
- **Package**: `com.thingclips.sdk.ble.core.protocol.request`
- **Extends**: `qpqddqp`
- **Methods**: 13
- **Fields**: 17
- **Source**: `core\protocol\request\FetchWiFiListInstruction.java`

**Key Methods**:
  - `WiFiList()`
  - `getWifi_list()`
  - `setWifi_list()`
  - `FetchWiFiListInstruction()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `HashMap()`
  - `bppqppq()`
  - `qddqppb()`
  - *(... and 3 more)*

---

### BleSingleScanner [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.core.scan.BleSingleScanner`
- **Package**: `com.thingclips.sdk.ble.core.scan`
- **Implements**: `LeScanResponse`
- **Methods**: 14
- **Fields**: 17
- **Source**: `ble\core\scan\BleSingleScanner.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onDeviceFounded()`
  - `onScanCancel()`
  - `onScanStart()`
  - `onScanStop()`
  - `BleSingleScanner()`
  - `containSingleBle()`
  - `dealWithDevice()`
  - `deviceNeedDeal()`
  - `generateSearchResultId()`
  - *(... and 4 more)*

**Notable Strings**:
  - `",uuid = "`

---

### BleAccessException [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.service.exception.BleAccessException`
- **Package**: `com.thingclips.sdk.ble.service.exception`
- **Extends**: `Exception`
- **Methods**: 1
- **Fields**: 0
- **Source**: `ble\service\exception\BleAccessException.java`

**Key Methods**:
  - `BleAccessException()`

---

### BleConnectionException [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.service.exception.BleConnectionException`
- **Package**: `com.thingclips.sdk.ble.service.exception`
- **Extends**: `Exception`
- **Methods**: 1
- **Fields**: 0
- **Source**: `ble\service\exception\BleConnectionException.java`

**Key Methods**:
  - `BleConnectionException()`

---

### BleLevelException [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.service.exception.BleLevelException`
- **Package**: `com.thingclips.sdk.ble.service.exception`
- **Extends**: `Exception`
- **Methods**: 1
- **Fields**: 0
- **Source**: `ble\service\exception\BleLevelException.java`

**Key Methods**:
  - `BleLevelException()`

---

### BleParamException [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.service.exception.BleParamException`
- **Package**: `com.thingclips.sdk.ble.service.exception`
- **Extends**: `Exception`
- **Methods**: 1
- **Fields**: 0
- **Source**: `ble\service\exception\BleParamException.java`

**Key Methods**:
  - `BleParamException()`

---

### BleWriteException [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.service.exception.BleWriteException`
- **Package**: `com.thingclips.sdk.ble.service.exception`
- **Extends**: `Exception`
- **Methods**: 1
- **Fields**: 0
- **Source**: `ble\service\exception\BleWriteException.java`

**Key Methods**:
  - `BleWriteException()`

---

### BLog [HIGH]


- **Full Name**: `com.thingclips.sdk.ble.utils.BLog`
- **Package**: `com.thingclips.sdk.ble.utils`
- **Methods**: 6
- **Fields**: 6
- **Source**: `sdk\ble\utils\BLog.java`

**Key Methods**:
  - `m282d()`
  - `m283e()`
  - `m284i()`
  - `setLogPrinter()`
  - `m285v()`
  - `m286w()`

---

### BluetoothContext [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.BluetoothContext`
- **Package**: `com.thingclips.sdk.blelib`
- **Methods**: 4
- **Fields**: 1
- **Source**: `thingclips\sdk\blelib\BluetoothContext.java`

**Key Methods**:
  - `getCurrentMethodName()`
  - `post()`
  - `postDelayed()`
  - `Handler()`

---

### BluetoothService [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.BluetoothService`
- **Package**: `com.thingclips.sdk.blelib`
- **Extends**: `Service`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\blelib\BluetoothService.java`

**Key Methods**:
  - `onBind()`
  - `onCreate()`

**Notable Strings**:
  - `"BluetoothService onBind"`
  - `"BluetoothService onCreate"`

---

### Code [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.Code`
- **Package**: `com.thingclips.sdk.blelib`
- **Methods**: 1
- **Fields**: 12
- **Source**: `thingclips\sdk\blelib\Code.java`

**Key Methods**:
  - `toString()`

**Notable Strings**:
  - `"BLUETOOTH_DISABLED"`

---

### Default [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.Default`
- **Package**: `com.thingclips.sdk.blelib`
- **Extends**: `IInterface`
- **Implements**: `IBluetoothService`
- **Methods**: 15
- **Fields**: 17
- **Source**: `thingclips\sdk\blelib\IBluetoothService.java`

**Key Methods**:
  - `asBinder()`
  - `callBluetoothApi()`
  - `Proxy()`
  - `asBinder()`
  - `callBluetoothApi()`
  - `getInterfaceDescriptor()`
  - `Stub()`
  - `asInterface()`
  - `Proxy()`
  - `getDefaultImpl()`
  - *(... and 5 more)*

**Notable Strings**:
  - `"com.thingclips.sdk.blelib.IBluetoothService"`

---

### SyncOperate [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.SyncOperate`
- **Package**: `com.thingclips.sdk.blelib`
- **Methods**: 17
- **Fields**: 23
- **Source**: `thingclips\sdk\blelib\SyncOperate.java`

**Key Methods**:
  - `OperateResult()`
  - `action()`
  - `action()`
  - `actionRun()`
  - `CountDownLatch()`
  - `BleGeneralResponse()`
  - `onResponse()`
  - `showAction()`
  - `run()`
  - `IllegalArgumentException()`
  - *(... and 7 more)*

---

### Channel [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.channel.Channel`
- **Package**: `com.thingclips.sdk.blelib.channel`
- **Implements**: `IChannel, ProxyInterceptor`
- **Methods**: 82
- **Fields**: 68
- **Source**: `sdk\blelib\channel\Channel.java`

**Key Methods**:
  - `RecvCallback()`
  - `run()`
  - `WriteCallback()`
  - `onCallback()`
  - `Channel()`
  - `IChannelStateHandler()`
  - `handleState()`
  - `IChannelStateHandler()`
  - `handleState()`
  - `if()`
  - *(... and 72 more)*

---

### CRC16 [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.channel.CRC16`
- **Package**: `com.thingclips.sdk.blelib.channel`
- **Methods**: 1
- **Fields**: 2
- **Source**: `sdk\blelib\channel\CRC16.java`

**Key Methods**:
  - `get()`

---

### Timer [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.channel.Timer`
- **Package**: `com.thingclips.sdk.blelib.channel`
- **Implements**: `Runnable`
- **Methods**: 10
- **Fields**: 12
- **Source**: `sdk\blelib\channel\Timer.java`

**Key Methods**:
  - `Handler()`
  - `TimerCallback()`
  - `getName()`
  - `onTimerCallback()`
  - `run()`
  - `getName()`
  - `isRunning()`
  - `start()`
  - `Handler()`
  - `stop()`

---

### Packet [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.channel.packet.Packet`
- **Package**: `com.thingclips.sdk.blelib.channel.packet`
- **Methods**: 15
- **Fields**: 23
- **Source**: `blelib\channel\packet\Packet.java`

**Key Methods**:
  - `Bytes()`
  - `getSize()`
  - `Bytes()`
  - `Header()`
  - `getDataPacket()`
  - `DataPacket()`
  - `getFlowPacket()`
  - `InvalidPacket()`
  - `ACKPacket()`
  - `CTRPacket()`
  - *(... and 5 more)*

---

### IBleConnectWorker [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.IBleConnectWorker`
- **Package**: `com.thingclips.sdk.blelib.connect`
- **Methods**: 20
- **Fields**: 0
- **Source**: `sdk\blelib\connect\IBleConnectWorker.java`

**Key Methods**:
  - `clearGattResponseListener()`
  - `closeGatt()`
  - `disconnect()`
  - `discoverService()`
  - `getCurrentStatus()`
  - `getGattProfile()`
  - `onBluetoothClosedDelay()`
  - `openGatt()`
  - `readCharacteristic()`
  - `readDescriptor()`
  - *(... and 10 more)*

---

### BleConnectStatusListener [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.listener.BleConnectStatusListener`
- **Package**: `com.thingclips.sdk.blelib.connect.listener`
- **Extends**: `BluetoothClientListener`
- **Methods**: 2
- **Fields**: 0
- **Source**: `blelib\connect\listener\BleConnectStatusListener.java`

**Key Methods**:
  - `onConnectStatusChanged()`
  - `onSyncInvoke()`

---

### BluetoothStateListener [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.listener.BluetoothStateListener`
- **Package**: `com.thingclips.sdk.blelib.connect.listener`
- **Extends**: `BluetoothClientListener`
- **Methods**: 2
- **Fields**: 0
- **Source**: `blelib\connect\listener\BluetoothStateListener.java`

**Key Methods**:
  - `onBluetoothStateChanged()`
  - `onSyncInvoke()`

---

### DisconnectListener [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.listener.DisconnectListener`
- **Package**: `com.thingclips.sdk.blelib.connect.listener`
- **Extends**: `GattResponseListener`
- **Methods**: 1
- **Fields**: 0
- **Source**: `blelib\connect\listener\DisconnectListener.java`

**Key Methods**:
  - `onDisconnected()`

---

### GattResponseListener [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.listener.GattResponseListener`
- **Package**: `com.thingclips.sdk.blelib.connect.listener`
- **Methods**: 1
- **Fields**: 6
- **Source**: `blelib\connect\listener\GattResponseListener.java`

**Key Methods**:
  - `onConnectStatusChanged()`

---

### ReadRssiListener [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.listener.ReadRssiListener`
- **Package**: `com.thingclips.sdk.blelib.connect.listener`
- **Extends**: `GattResponseListener`
- **Methods**: 1
- **Fields**: 0
- **Source**: `blelib\connect\listener\ReadRssiListener.java`

**Key Methods**:
  - `onReadRemoteRssi()`

---

### RequestMtuListener [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.listener.RequestMtuListener`
- **Package**: `com.thingclips.sdk.blelib.connect.listener`
- **Extends**: `GattResponseListener`
- **Methods**: 1
- **Fields**: 0
- **Source**: `blelib\connect\listener\RequestMtuListener.java`

**Key Methods**:
  - `onMtuChanged()`

---

### ServiceDiscoverListener [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.listener.ServiceDiscoverListener`
- **Package**: `com.thingclips.sdk.blelib.connect.listener`
- **Extends**: `GattResponseListener`
- **Methods**: 1
- **Fields**: 0
- **Source**: `blelib\connect\listener\ServiceDiscoverListener.java`

**Key Methods**:
  - `onServicesDiscovered()`

---

### BleConnectOptions [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.options.BleConnectOptions`
- **Package**: `com.thingclips.sdk.blelib.connect.options`
- **Implements**: `Parcelable`
- **Methods**: 27
- **Fields**: 25
- **Source**: `blelib\connect\options\BleConnectOptions.java`

**Key Methods**:
  - `createFromParcel()`
  - `BleConnectOptions()`
  - `newArray()`
  - `build()`
  - `BleConnectOptions()`
  - `setAutoConnect()`
  - `setConnectRetry()`
  - `setConnectTimeout()`
  - `setConnectTimeoutTimes()`
  - `setServiceDiscoverRetry()`
  - *(... and 17 more)*

---

### BleConnectRequest [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.BleConnectRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Extends**: `BleRequest`
- **Implements**: `ServiceDiscoverListener`
- **Methods**: 25
- **Fields**: 12
- **Source**: `blelib\connect\request\BleConnectRequest.java`

**Key Methods**:
  - `BleConnectRequest()`
  - `doDiscoverService()`
  - `discoverService()`
  - `doOpenNewGatt()`
  - `openGatt()`
  - `onConnectSuccess()`
  - `onServiceDiscoverFailed()`
  - `processConnect()`
  - `processConnectTimeout()`
  - `processDiscoverService()`
  - *(... and 15 more)*

---

### BleDiscoveryServiceRequest [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.BleDiscoveryServiceRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Extends**: `BleRequest`
- **Implements**: `ServiceDiscoverListener`
- **Methods**: 6
- **Fields**: 2
- **Source**: `blelib\connect\request\BleDiscoveryServiceRequest.java`

**Key Methods**:
  - `BleDiscoveryServiceRequest()`
  - `onConnectSuccess()`
  - `startDiscovery()`
  - `onServicesDiscovered()`
  - `processRequest()`
  - `if()`

---

### BleReadRssiRequest [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.BleReadRssiRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Extends**: `BleRequest`
- **Implements**: `ReadRssiListener`
- **Methods**: 7
- **Fields**: 3
- **Source**: `blelib\connect\request\BleReadRssiRequest.java`

**Key Methods**:
  - `BleReadRssiRequest()`
  - `startReadRssi()`
  - `getTimeoutInMillis()`
  - `handleMessage()`
  - `onReadRemoteRssi()`
  - `processRequest()`
  - `if()`

---

### BleRefreshCacheRequest [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.BleRefreshCacheRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Extends**: `BleRequest`
- **Methods**: 3
- **Fields**: 0
- **Source**: `blelib\connect\request\BleRefreshCacheRequest.java`

**Key Methods**:
  - `BleRefreshCacheRequest()`
  - `processRequest()`
  - `run()`

---

### BleRequest [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.BleRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Implements**: `IBleConnectWorker, IBleRequest, Handler.Callback, GattResponseListener, RuntimeChecker`
- **Methods**: 49
- **Fields**: 15
- **Source**: `blelib\connect\request\BleRequest.java`

**Key Methods**:
  - `Bundle()`
  - `Handler()`
  - `Handler()`
  - `BleRequest()`
  - `cancel()`
  - `checkRuntime()`
  - `clearGattResponseListener()`
  - `closeGatt()`
  - `disconnect()`
  - `discoverService()`
  - *(... and 39 more)*

**Notable Strings**:
  - `"close gatt"`
  - `"disconnect gatt"`

---

### BleStateChangeRequest [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.BleStateChangeRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Extends**: `BleRequest`
- **Methods**: 3
- **Fields**: 2
- **Source**: `blelib\connect\request\BleStateChangeRequest.java`

**Key Methods**:
  - `BleStateChangeRequest()`
  - `handleMessage()`
  - `processRequest()`

---

### BleConnectResponse [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.response.BleConnectResponse`
- **Package**: `com.thingclips.sdk.blelib.connect.response`
- **Extends**: `BleTResponse<BleGattProfile>`
- **Methods**: 0
- **Fields**: 0
- **Source**: `blelib\connect\response\BleConnectResponse.java`

---

### BluetoothResponse [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.connect.response.BluetoothResponse`
- **Package**: `com.thingclips.sdk.blelib.connect.response`
- **Extends**: `IResponse.Stub`
- **Implements**: `Handler.Callback`
- **Methods**: 6
- **Fields**: 3
- **Source**: `blelib\connect\response\BluetoothResponse.java`

**Key Methods**:
  - `BluetoothResponse()`
  - `RuntimeException()`
  - `Handler()`
  - `handleMessage()`
  - `onAsyncResponse()`
  - `onResponse()`

---

### AbsBluetoothReceiver [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.AbsBluetoothReceiver`
- **Package**: `com.thingclips.sdk.blelib.receiver`
- **Methods**: 6
- **Fields**: 6
- **Source**: `sdk\blelib\receiver\AbsBluetoothReceiver.java`

**Key Methods**:
  - `Handler()`
  - `AbsBluetoothReceiver()`
  - `containsAction()`
  - `getActions()`
  - `getListeners()`
  - `onReceive()`

---

### BleCharacterChangeReceiver [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.BleCharacterChangeReceiver`
- **Package**: `com.thingclips.sdk.blelib.receiver`
- **Extends**: `AbsBluetoothReceiver`
- **Methods**: 6
- **Fields**: 3
- **Source**: `sdk\blelib\receiver\BleCharacterChangeReceiver.java`

**Key Methods**:
  - `BleCharacterChangeReceiver()`
  - `newInstance()`
  - `BleCharacterChangeReceiver()`
  - `onCharacterChanged()`
  - `getActions()`
  - `onReceive()`

---

### BleConnectStatusChangeReceiver [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.BleConnectStatusChangeReceiver`
- **Package**: `com.thingclips.sdk.blelib.receiver`
- **Extends**: `AbsBluetoothReceiver`
- **Methods**: 6
- **Fields**: 5
- **Source**: `sdk\blelib\receiver\BleConnectStatusChangeReceiver.java`

**Key Methods**:
  - `BleConnectStatusChangeReceiver()`
  - `newInstance()`
  - `BleConnectStatusChangeReceiver()`
  - `onConnectStatusChanged()`
  - `getActions()`
  - `onReceive()`

---

### BluetoothBondReceiver [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.BluetoothBondReceiver`
- **Package**: `com.thingclips.sdk.blelib.receiver`
- **Extends**: `AbsBluetoothReceiver`
- **Methods**: 6
- **Fields**: 6
- **Source**: `sdk\blelib\receiver\BluetoothBondReceiver.java`

**Key Methods**:
  - `BluetoothBondReceiver()`
  - `newInstance()`
  - `BluetoothBondReceiver()`
  - `onBondStateChanged()`
  - `getActions()`
  - `onReceive()`

**Notable Strings**:
  - `"android.bluetooth.device.action.BOND_STATE_CHANGED"`
  - `"android.bluetooth.device.extra.DEVICE"`
  - `"android.bluetooth.device.extra.BOND_STATE"`

---

### BluetoothConnectStateReceiver [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.BluetoothConnectStateReceiver`
- **Package**: `com.thingclips.sdk.blelib.receiver`
- **Extends**: `AbsBluetoothReceiver`
- **Methods**: 6
- **Fields**: 7
- **Source**: `sdk\blelib\receiver\BluetoothConnectStateReceiver.java`

**Key Methods**:
  - `BluetoothConnectStateReceiver()`
  - `newInstance()`
  - `BluetoothConnectStateReceiver()`
  - `onConnectStateChanged()`
  - `getActions()`
  - `onReceive()`

**Notable Strings**:
  - `"android.bluetooth.device.action.ACL_CONNECTED"`
  - `"android.bluetooth.device.action.ACL_DISCONNECTED"`
  - `"android.bluetooth.device.extra.DEVICE"`
  - `"android.bluetooth.device.action.ACL_CONNECTED"`
  - `"android.bluetooth.device.action.ACL_DISCONNECTED"`

---

### BluetoothReceiver [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.BluetoothReceiver`
- **Package**: `com.thingclips.sdk.blelib.receiver`
- **Extends**: `BroadcastReceiver`
- **Implements**: `IBluetoothReceiver, Handler.Callback`
- **Methods**: 13
- **Fields**: 14
- **Source**: `sdk\blelib\receiver\BluetoothReceiver.java`

**Key Methods**:
  - `BluetoothReceiver()`
  - `IReceiverDispatcher()`
  - `getListeners()`
  - `HashMap()`
  - `Handler()`
  - `getInstance()`
  - `BluetoothReceiver()`
  - `getIntentFilter()`
  - `IntentFilter()`
  - `registerInner()`
  - *(... and 3 more)*

**Notable Strings**:
  - `"BluetoothReceiver onReceive: %s"`

---

### BluetoothStateReceiver [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.BluetoothStateReceiver`
- **Package**: `com.thingclips.sdk.blelib.receiver`
- **Extends**: `AbsBluetoothReceiver`
- **Methods**: 8
- **Fields**: 8
- **Source**: `sdk\blelib\receiver\BluetoothStateReceiver.java`

**Key Methods**:
  - `BluetoothStateReceiver()`
  - `getStateString()`
  - `newInstance()`
  - `BluetoothStateReceiver()`
  - `onBluetoothStateChanged()`
  - `getActions()`
  - `onReceive()`
  - `Intent()`

**Notable Strings**:
  - `"android.bluetooth.adapter.action.STATE_CHANGED"`
  - `"com.thingclips.smart.bluetooth.received"`
  - `"android.bluetooth.adapter.extra.STATE"`
  - `"android.bluetooth.adapter.extra.PREVIOUS_STATE"`

---

### IBluetoothReceiver [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.IBluetoothReceiver`
- **Package**: `com.thingclips.sdk.blelib.receiver`
- **Methods**: 1
- **Fields**: 0
- **Source**: `sdk\blelib\receiver\IBluetoothReceiver.java`

**Key Methods**:
  - `register()`

---

### IReceiverDispatcher [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.IReceiverDispatcher`
- **Package**: `com.thingclips.sdk.blelib.receiver`
- **Methods**: 1
- **Fields**: 0
- **Source**: `sdk\blelib\receiver\IReceiverDispatcher.java`

**Key Methods**:
  - `getListeners()`

---

### AbsBluetoothListener [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.listener.AbsBluetoothListener`
- **Package**: `com.thingclips.sdk.blelib.receiver.listener`
- **Implements**: `Handler.Callback`
- **Methods**: 10
- **Fields**: 7
- **Source**: `blelib\receiver\listener\AbsBluetoothListener.java`

**Key Methods**:
  - `AbsBluetoothListener()`
  - `IllegalStateException()`
  - `Handler()`
  - `Handler()`
  - `handleMessage()`
  - `if()`
  - `invoke()`
  - `invokeSync()`
  - `onInvoke()`
  - `onSyncInvoke()`

---

### BleCharacterChangeListener [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.listener.BleCharacterChangeListener`
- **Package**: `com.thingclips.sdk.blelib.receiver.listener`
- **Extends**: `BluetoothReceiverListener`
- **Methods**: 3
- **Fields**: 0
- **Source**: `blelib\receiver\listener\BleCharacterChangeListener.java`

**Key Methods**:
  - `getName()`
  - `onCharacterChanged()`
  - `onInvoke()`

---

### BleConnectStatusChangeListener [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.listener.BleConnectStatusChangeListener`
- **Package**: `com.thingclips.sdk.blelib.receiver.listener`
- **Extends**: `BluetoothReceiverListener`
- **Methods**: 3
- **Fields**: 0
- **Source**: `blelib\receiver\listener\BleConnectStatusChangeListener.java`

**Key Methods**:
  - `getName()`
  - `onConnectStatusChanged()`
  - `onInvoke()`

---

### BleSystemConnectStatusListener [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.listener.BleSystemConnectStatusListener`
- **Package**: `com.thingclips.sdk.blelib.receiver.listener`
- **Extends**: `BluetoothReceiverListener`
- **Methods**: 3
- **Fields**: 0
- **Source**: `blelib\receiver\listener\BleSystemConnectStatusListener.java`

**Key Methods**:
  - `getName()`
  - `onConnectStatusChanged()`
  - `onInvoke()`

---

### BluetoothBondListener [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.listener.BluetoothBondListener`
- **Package**: `com.thingclips.sdk.blelib.receiver.listener`
- **Extends**: `BluetoothClientListener`
- **Methods**: 2
- **Fields**: 0
- **Source**: `blelib\receiver\listener\BluetoothBondListener.java`

**Key Methods**:
  - `onBondStateChanged()`
  - `onSyncInvoke()`

---

### BluetoothBondStateChangeListener [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.listener.BluetoothBondStateChangeListener`
- **Package**: `com.thingclips.sdk.blelib.receiver.listener`
- **Extends**: `BluetoothReceiverListener`
- **Methods**: 3
- **Fields**: 0
- **Source**: `blelib\receiver\listener\BluetoothBondStateChangeListener.java`

**Key Methods**:
  - `getName()`
  - `onBondStateChanged()`
  - `onInvoke()`

**Notable Strings**:
  - `"BluetoothBondStateChangeListener"`

---

### BluetoothClientListener [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.listener.BluetoothClientListener`
- **Package**: `com.thingclips.sdk.blelib.receiver.listener`
- **Extends**: `AbsBluetoothListener`
- **Methods**: 2
- **Fields**: 0
- **Source**: `blelib\receiver\listener\BluetoothClientListener.java`

**Key Methods**:
  - `onInvoke()`
  - `UnsupportedOperationException()`

---

### BluetoothReceiverListener [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.listener.BluetoothReceiverListener`
- **Package**: `com.thingclips.sdk.blelib.receiver.listener`
- **Extends**: `AbsBluetoothListener`
- **Methods**: 3
- **Fields**: 0
- **Source**: `blelib\receiver\listener\BluetoothReceiverListener.java`

**Key Methods**:
  - `getName()`
  - `onSyncInvoke()`
  - `UnsupportedOperationException()`

---

### BluetoothStateChangeListener [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.receiver.listener.BluetoothStateChangeListener`
- **Package**: `com.thingclips.sdk.blelib.receiver.listener`
- **Extends**: `BluetoothReceiverListener`
- **Methods**: 3
- **Fields**: 2
- **Source**: `blelib\receiver\listener\BluetoothStateChangeListener.java`

**Key Methods**:
  - `getName()`
  - `onBluetoothStateChanged()`
  - `onInvoke()`

**Notable Strings**:
  - `"BluetoothStateChangeListener"`

---

### BluetoothSearcher [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.search.BluetoothSearcher`
- **Package**: `com.thingclips.sdk.blelib.search`
- **Methods**: 9
- **Fields**: 6
- **Source**: `sdk\blelib\search\BluetoothSearcher.java`

**Key Methods**:
  - `newInstance()`
  - `IllegalStateException()`
  - `notifySearchCanceled()`
  - `notifySearchStarted()`
  - `notifySearchStopped()`
  - `cancelScanBluetooth()`
  - `notifyDeviceFounded()`
  - `startScanBluetooth()`
  - `stopScanBluetooth()`

---

### BluetoothSearchHelper [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.search.BluetoothSearchHelper`
- **Package**: `com.thingclips.sdk.blelib.search`
- **Implements**: `IBluetoothSearchHelper, ProxyInterceptor, Handler.Callback`
- **Methods**: 14
- **Fields**: 9
- **Source**: `sdk\blelib\search\BluetoothSearchHelper.java`

**Key Methods**:
  - `Handler()`
  - `BluetoothSearchResponseImpl()`
  - `onDeviceFounded()`
  - `onSearchCanceled()`
  - `onSearchStarted()`
  - `onSearchStopped()`
  - `BluetoothSearchHelper()`
  - `getInstance()`
  - `BluetoothSearchHelper()`
  - `handleMessage()`
  - *(... and 4 more)*

---

### BluetoothSearchManager [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.search.BluetoothSearchManager`
- **Package**: `com.thingclips.sdk.blelib.search`
- **Methods**: 10
- **Fields**: 3
- **Source**: `sdk\blelib\search\BluetoothSearchManager.java`

**Key Methods**:
  - `search()`
  - `BluetoothSearchResponse()`
  - `onDeviceFounded()`
  - `Bundle()`
  - `onSearchCanceled()`
  - `onSearchStarted()`
  - `onSearchStopped()`
  - `startScan()`
  - `stopScan()`
  - `stopSearch()`

---

### BluetoothSearchRequest [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.search.BluetoothSearchRequest`
- **Package**: `com.thingclips.sdk.blelib.search`
- **Implements**: `Handler.Callback`
- **Methods**: 20
- **Fields**: 27
- **Source**: `sdk\blelib\search\BluetoothSearchRequest.java`

**Key Methods**:
  - `ArrayList()`
  - `BluetoothSearchTaskResponse()`
  - `onDeviceFounded()`
  - `onSearchCanceled()`
  - `onSearchStarted()`
  - `onSearchStopped()`
  - `BluetoothSearchRequest()`
  - `Handler()`
  - `notifyBondedBluetoothClassicDevices()`
  - `notifyConnectedBluetoothDevices()`
  - *(... and 10 more)*

---

### BluetoothSearchTask [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.search.BluetoothSearchTask`
- **Package**: `com.thingclips.sdk.blelib.search`
- **Implements**: `Handler.Callback`
- **Methods**: 11
- **Fields**: 10
- **Source**: `sdk\blelib\search\BluetoothSearchTask.java`

**Key Methods**:
  - `BluetoothSearchTask()`
  - `Handler()`
  - `getBluetoothSearcher()`
  - `cancel()`
  - `handleMessage()`
  - `isBluetoothClassicSearch()`
  - `isBluetoothLeSearch()`
  - `setSearchDuration()`
  - `setSearchType()`
  - `start()`
  - *(... and 1 more)*

---

### IBluetoothSearchHelper [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.search.IBluetoothSearchHelper`
- **Package**: `com.thingclips.sdk.blelib.search`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\blelib\search\IBluetoothSearchHelper.java`

**Key Methods**:
  - `startSearch()`
  - `stopSearch()`

---

### SearchRequest [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.search.SearchRequest`
- **Package**: `com.thingclips.sdk.blelib.search`
- **Implements**: `Parcelable`
- **Methods**: 17
- **Fields**: 10
- **Source**: `sdk\blelib\search\SearchRequest.java`

**Key Methods**:
  - `createFromParcel()`
  - `SearchRequest()`
  - `newArray()`
  - `ArrayList()`
  - `build()`
  - `SearchRequest()`
  - `searchBluetoothClassicDevice()`
  - `SearchTask()`
  - `searchBluetoothLeDevice()`
  - `SearchTask()`
  - *(... and 7 more)*

---

### SearchResult [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.search.SearchResult`
- **Package**: `com.thingclips.sdk.blelib.search`
- **Implements**: `Parcelable`
- **Methods**: 14
- **Fields**: 8
- **Source**: `sdk\blelib\search\SearchResult.java`

**Key Methods**:
  - `createFromParcel()`
  - `SearchResult()`
  - `newArray()`
  - `SearchResult()`
  - `describeContents()`
  - `equals()`
  - `getAddress()`
  - `getName()`
  - `hashCode()`
  - `toString()`
  - *(... and 4 more)*

---

### BluetoothClassicSearcher [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.search.classic.BluetoothClassicSearcher`
- **Package**: `com.thingclips.sdk.blelib.search.classic`
- **Extends**: `BluetoothSearcher`
- **Methods**: 13
- **Fields**: 4
- **Source**: `blelib\search\classic\BluetoothClassicSearcher.java`

**Key Methods**:
  - `BluetoothClassicSearcher()`
  - `BluetoothClassicSearcherHolder()`
  - `BluetoothSearchReceiver()`
  - `onReceive()`
  - `getInstance()`
  - `registerReceiver()`
  - `BluetoothSearchReceiver()`
  - `IntentFilter()`
  - `unregisterReceiver()`
  - `cancelScanBluetooth()`
  - *(... and 3 more)*

**Notable Strings**:
  - `"android.bluetooth.device.action.FOUND"`
  - `"android.bluetooth.device.extra.DEVICE"`
  - `"android.bluetooth.device.extra.RSSI"`
  - `"android.bluetooth.device.action.FOUND"`

---

### BluetoothLESearcher [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.search.p007le.BluetoothLESearcher`
- **Package**: `com.thingclips.sdk.blelib.search.p007le`
- **Extends**: `BluetoothSearcher`
- **Methods**: 16
- **Fields**: 6
- **Source**: `blelib\search\p007le\BluetoothLESearcher.java`

**Key Methods**:
  - `BluetoothLESearcher()`
  - `BluetoothLESearcherHolder()`
  - `createNewScanCallback()`
  - `ScanCallback()`
  - `onScanFailed()`
  - `onScanResult()`
  - `getInstance()`
  - `startLEScan()`
  - `stopLEScan()`
  - `cancelScanBluetooth()`
  - *(... and 6 more)*

**Notable Strings**:
  - `"startScanBluetooth fail: "`
  - `"BluetoothLESearcher, stopScan error :"`
  - `"BluetoothLESearcher, cancelScanBluetooth error :"`

---

### BluetoothSearchResponse [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.search.response.BluetoothSearchResponse`
- **Package**: `com.thingclips.sdk.blelib.search.response`
- **Methods**: 4
- **Fields**: 0
- **Source**: `blelib\search\response\BluetoothSearchResponse.java`

**Key Methods**:
  - `onDeviceFounded()`
  - `onSearchCanceled()`
  - `onSearchStarted()`
  - `onSearchStopped()`

---

### BleConnectStatusHelper [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.utils.BleConnectStatusHelper`
- **Package**: `com.thingclips.sdk.blelib.utils`
- **Implements**: `Handler.Callback`
- **Methods**: 11
- **Fields**: 11
- **Source**: `sdk\blelib\utils\BleConnectStatusHelper.java`

**Key Methods**:
  - `HashSet()`
  - `BleConnectStatusHelper()`
  - `Handler()`
  - `init()`
  - `onConnectStatusChanged()`
  - `if()`
  - `onBluetoothStateChanged()`
  - `newInstance()`
  - `BleConnectStatusHelper()`
  - `getConnectStatus()`
  - *(... and 1 more)*

---

### BluetoothLog [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.utils.BluetoothLog`
- **Package**: `com.thingclips.sdk.blelib.utils`
- **Methods**: 10
- **Fields**: 11
- **Source**: `sdk\blelib\utils\BluetoothLog.java`

**Key Methods**:
  - `m287e()`
  - `getThrowableString()`
  - `StringWriter()`
  - `PrintWriter()`
  - `m289i()`
  - `setLogLevel()`
  - `setLogPrinter()`
  - `m290v()`
  - `m291w()`
  - `m288e()`

**Notable Strings**:
  - `"bluetooth"`

---

### BluetoothHooker [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.utils.hook.BluetoothHooker`
- **Package**: `com.thingclips.sdk.blelib.utils.hook`
- **Methods**: 2
- **Fields**: 2
- **Source**: `blelib\utils\hook\BluetoothHooker.java`

**Key Methods**:
  - `hook()`
  - `BluetoothManagerBinderProxyHandler()`

**Notable Strings**:
  - `"bluetooth_manager"`

---

### BluetoothManagerBinderProxyHandler [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.utils.hook.BluetoothManagerBinderProxyHandler`
- **Package**: `com.thingclips.sdk.blelib.utils.hook`
- **Implements**: `InvocationHandler`
- **Methods**: 3
- **Fields**: 2
- **Source**: `blelib\utils\hook\BluetoothManagerBinderProxyHandler.java`

**Key Methods**:
  - `BluetoothManagerBinderProxyHandler()`
  - `invoke()`
  - `BluetoothManagerProxyHandler()`

**Notable Strings**:
  - `"android.bluetooth.IBluetoothManager"`
  - `"android.bluetooth.IBluetoothManager$Stub"`

---

### ServiceManagerCompat [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.utils.hook.compat.ServiceManagerCompat`
- **Package**: `com.thingclips.sdk.blelib.utils.hook.compat`
- **Methods**: 3
- **Fields**: 6
- **Source**: `utils\hook\compat\ServiceManagerCompat.java`

**Key Methods**:
  - `getCacheField()`
  - `getCacheValue()`
  - `getService()`

---

### ProxyBulk [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.utils.proxy.ProxyBulk`
- **Package**: `com.thingclips.sdk.blelib.utils.proxy`
- **Methods**: 3
- **Fields**: 4
- **Source**: `blelib\utils\proxy\ProxyBulk.java`

**Key Methods**:
  - `ProxyBulk()`
  - `safeInvoke()`
  - `safeInvoke()`

---

### ProxyInvocationHandler [HIGH]


- **Full Name**: `com.thingclips.sdk.blelib.utils.proxy.ProxyInvocationHandler`
- **Package**: `com.thingclips.sdk.blelib.utils.proxy`
- **Implements**: `InvocationHandler, ProxyInterceptor, Handler.Callback`
- **Methods**: 14
- **Fields**: 14
- **Source**: `blelib\utils\proxy\ProxyInvocationHandler.java`

**Key Methods**:
  - `ProxyInvocationHandler()`
  - `getObject()`
  - `WeakReference()`
  - `postSafeInvoke()`
  - `safeInvoke()`
  - `handleMessage()`
  - `invoke()`
  - `ProxyBulk()`
  - `onIntercept()`
  - `ProxyInvocationHandler()`
  - *(... and 4 more)*

---

### BleScanner [HIGH]


- **Full Name**: `com.thingclips.sdk.blescan.BleScanner`
- **Package**: `com.thingclips.sdk.blescan`
- **Methods**: 19
- **Fields**: 13
- **Source**: `thingclips\sdk\blescan\BleScanner.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `BleScanner()`
  - `BluetoothClient()`
  - `convertBean()`
  - `ScanLeBean()`
  - `printDeviceFounded()`
  - `restartLeScan()`
  - `Handler()`
  - `run()`
  - *(... and 9 more)*

---

### ScanLeBean [HIGH]


- **Full Name**: `com.thingclips.sdk.blescan.ScanLeBean`
- **Package**: `com.thingclips.sdk.blescan`
- **Methods**: 1
- **Fields**: 6
- **Source**: `thingclips\sdk\blescan\ScanLeBean.java`

**Key Methods**:
  - `toString()`

---

### ThingBleScanner [HIGH]


- **Full Name**: `com.thingclips.sdk.blescan.ThingBleScanner`
- **Package**: `com.thingclips.sdk.blescan`
- **Implements**: `Handler.Callback, LeScanResponse, IThingBleScanner`
- **Methods**: 34
- **Fields**: 40
- **Source**: `thingclips\sdk\blescan\ThingBleScanner.java`

**Key Methods**:
  - `SafeHandler()`
  - `ThingBleScanner()`
  - `BleScanner()`
  - `bleScanPermissionGranted()`
  - `cacheFilter()`
  - `checkAndStart()`
  - `clearAllRequest()`
  - `ArrayList()`
  - `filterRequestTask()`
  - `getDefaultSearchRequest()`
  - *(... and 24 more)*

---

### BluetoothHelper [HIGH]


- **Full Name**: `com.thingclips.sdk.blescan.utils.BluetoothHelper`
- **Package**: `com.thingclips.sdk.blescan.utils`
- **Methods**: 7
- **Fields**: 0
- **Source**: `sdk\blescan\utils\BluetoothHelper.java`

**Key Methods**:
  - `closeBluetooth()`
  - `getBluetoothState()`
  - `getBondState()`
  - `getConnectedBluetoothLeDevices()`
  - `isBleSupported()`
  - `isBluetoothEnabled()`
  - `openBluetooth()`

---

### bbbbppp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbbbppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Comparator<Integer>`
- **Methods**: 18
- **Fields**: 48
- **Source**: `thingclips\sdk\bluetooth\bbbbppp.java`

**Key Methods**:
  - `pdqppqb()`
  - `pdqppqb()`
  - `compare()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `SecureRandom()`
  - *(... and 8 more)*

---

### bbbqqqb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbbqqqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Implements**: `XResponse`
- **Methods**: 9
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\bbbqqqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `bbbqqqb()`
  - `dealWithResponse()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `bdpdqbp()`
  - `qddqppb()`

---

### bbdbqqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbdbqqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 46
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bbdbqqd.java`

**Key Methods**:
  - `activator()`
  - `activeValue()`
  - `clearDataChannel()`
  - `connect()`
  - `deviceFirmwareUpgrade()`
  - `disconnectDevice()`
  - `getAllDpBLEDpResponseBean()`
  - `getDeviceId()`
  - `getDeviceNetStatus()`
  - `getDeviceSecurityFlag()`
  - *(... and 36 more)*

---

### bbddpbq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbddpbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qpqddqp`
- **Methods**: 8
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\bbddpbq.java`

**Key Methods**:
  - `bbddpbq()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `bppqppq()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### bbdpqbd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbdpqbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbbppqb`
- **Methods**: 8
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\bbdpqbd.java`

**Key Methods**:
  - `bbdpqbd()`
  - `bdqqbqd()`
  - `bpbbqdb()`
  - `bpqqdpq()`
  - `pbpqqdp()`
  - `pdqppqb()`
  - `ppdpppq()`
  - `pdqppqb()`

---

### bbdqddp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbdqddp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IP4SuperSecurityAction`
- **Methods**: 20
- **Fields**: 13
- **Source**: `thingclips\sdk\bluetooth\bbdqddp.java`

**Key Methods**:
  - `pqdppqd()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 10 more)*

---

### bbdqddq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbdqddq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `qpbqpbq.pdqppqb`
- **Methods**: 20
- **Fields**: 37
- **Source**: `thingclips\sdk\bluetooth\bbdqddq.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `bdpdqbp()`
  - `run()`
  - `bbdqqbd()`
  - `bbdqddq()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `bddqpdp()`
  - `bddqpdp()`
  - *(... and 10 more)*

---

### bbpbqqb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbpbqqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\bbpbqqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ScanDeviceResult()`

---

### bbppbbd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbppbbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Thread`
- **Implements**: `ddbdpqb.bppdpdq`
- **Methods**: 39
- **Fields**: 69
- **Source**: `thingclips\sdk\bluetooth\bbppbbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onError()`
  - `bdpdqbp()`
  - `qddqppb()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pbddddb()`
  - *(... and 29 more)*

**Notable Strings**:
  - `"frame sender onBluetoothNameChange: "`

---

### bbpppdb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbpppdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Methods**: 8
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\bbpppdb.java`

**Key Methods**:
  - `bbpppdb()`
  - `dealWithResponse()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `ArrayList()`
  - `bppqppq()`
  - `qddqppb()`

---

### bbppqpb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbppqpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `XRequest`
- **Methods**: 13
- **Fields**: 24
- **Source**: `thingclips\sdk\bluetooth\bbppqpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bbppqpb()`
  - *(... and 3 more)*

---

### bbpqdqb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbpqdqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Handler`
- **Implements**: `IResultCallback`
- **Methods**: 19
- **Fields**: 15
- **Source**: `thingclips\sdk\bluetooth\bbpqdqb.java`

**Key Methods**:
  - `LinkedBlockingQueue()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `handleMessage()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - *(... and 9 more)*

---

### bbqbbdq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbqbbdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 23
- **Fields**: 40
- **Source**: `thingclips\sdk\bluetooth\bbqbbdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `ArrayList()`
  - *(... and 13 more)*

---

### bbqpbqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbqpbqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 13
- **Fields**: 22
- **Source**: `thingclips\sdk\bluetooth\bbqpbqd.java`

**Key Methods**:
  - `bbqpbqd()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `ArrayList()`
  - `pdqppqb()`
  - *(... and 3 more)*

---

### bbqqdbq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbqqdbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `LeScanResponse, dqdpdpq`
- **Methods**: 33
- **Fields**: 43
- **Source**: `thingclips\sdk\bluetooth\bbqqdbq.java`

**Key Methods**:
  - `bbqqdbq()`
  - `bdpdqbp()`
  - `onDeviceFounded()`
  - `onScanCancel()`
  - `onScanStart()`
  - `onScanStop()`
  - `pdqppqb()`
  - `bbqqdbq()`
  - `CopyOnWriteArrayList()`
  - `Handler()`
  - *(... and 23 more)*

---

### bdbbqbd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdbbqbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bpbqpqd`
- **Implements**: `pqpbpqd`
- **Methods**: 24
- **Fields**: 30
- **Source**: `thingclips\sdk\bluetooth\bdbbqbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onConnectStatusChanged()`
  - `bppdpdq()`
  - `onResponse()`
  - `pdqppqb()`
  - `onResponse()`
  - `if()`
  - `bppdpdq()`
  - `handleMessage()`
  - *(... and 14 more)*

---

### bdbdqdp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdbdqdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Implements**: `Business.ResultListener<Boolean>`
- **Methods**: 29
- **Fields**: 41
- **Source**: `thingclips\sdk\bluetooth\bdbdqdp.java`

**Key Methods**:
  - `HashMap()`
  - `HashMap()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `onFailure()`
  - `StringBuilder()`
  - `onSuccess()`
  - `bdbdqdp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - *(... and 19 more)*

---

### bdbdqdq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdbdqdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 17
- **Source**: `thingclips\sdk\bluetooth\bdbdqdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `if()`
  - `pdqppqb()`

---

### bddbqbq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bddbqbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 20
- **Fields**: 12
- **Source**: `thingclips\sdk\bluetooth\bddbqbq.java`

**Key Methods**:
  - `HashMap()`
  - `bddbqbq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `HashMap()`
  - `bdpdqbp()`
  - `HashMap()`
  - `bdpdqbp()`
  - `HashMap()`
  - *(... and 10 more)*

---

### bddqqbb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bddqqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pppbppp`
- **Implements**: `Runnable`
- **Methods**: 31
- **Fields**: 18
- **Source**: `thingclips\sdk\bluetooth\bddqqbb.java`

**Key Methods**:
  - `SafeHandler()`
  - `bdpdqbp()`
  - `qppddqq()`
  - `qqdqqpd()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `method()`
  - `pdqppqb()`
  - *(... and 21 more)*

**Notable Strings**:
  - `"not support, uuid = "`
  - `"stopActivator, uuids = "`
  - `"startActivator, uuid = "`

---

### bddqqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bddqqbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Runnable`
- **Methods**: 70
- **Fields**: 126
- **Source**: `thingclips\sdk\bluetooth\bddqqbp.java`

**Key Methods**:
  - `ArrayList()`
  - `ArrayList()`
  - `AtomicBoolean()`
  - `Handler()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `onResponse()`
  - *(... and 60 more)*

---

### bdpdqpb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdpdqpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Implements**: `XResponse`
- **Methods**: 8
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\bdpdqpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `dealWithResponse()`
  - `pbbppqb()`
  - `pqdbppq()`
  - `bdpdqbp()`
  - `qddqppb()`

---

### bdpqppd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdpqppd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `dqdpbpq`
- **Methods**: 8
- **Fields**: 15
- **Source**: `thingclips\sdk\bluetooth\bdpqppd.java`

**Key Methods**:
  - `bdpqppd()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### bdqpddb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdqpddb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbbppqb`
- **Methods**: 11
- **Fields**: 12
- **Source**: `thingclips\sdk\bluetooth\bdqpddb.java`

**Key Methods**:
  - `bdqpddb()`
  - `HashSet()`
  - `StringBuilder()`
  - `bdqqbqd()`
  - `bpbbqdb()`
  - `bpqqdpq()`
  - `dqdpbbd()`
  - `pdqppqb()`
  - `ppdpppq()`
  - `pqpbpqd()`
  - *(... and 1 more)*

---

### bdqqqpq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdqqqpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 21
- **Source**: `thingclips\sdk\bluetooth\bdqqqpq.java`

---

### bpbbbpd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpbbbpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 17
- **Fields**: 14
- **Source**: `thingclips\sdk\bluetooth\bpbbbpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `BufferedInputStream()`
  - `IllegalStateException()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `IllegalStateException()`
  - *(... and 7 more)*

---

### bpbbpbp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpbbpbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingDeviceConnectManager`
- **Methods**: 8
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\bpbbpbp.java`

**Key Methods**:
  - `bpbbpbp()`
  - `getInstance()`
  - `connectDeviceWithCallback()`
  - `if()`
  - `if()`
  - `disconnectDevice()`
  - `bpbbpbp()`
  - `bqdpddb()`

---

### bpbbqdb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpbbqdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Implements**: `Business.ResultListener<Boolean>`
- **Methods**: 24
- **Fields**: 31
- **Source**: `thingclips\sdk\bluetooth\bpbbqdb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `StringBuilder()`
  - `bpbbqdb()`
  - `qdddqdp()`
  - `bdpdqbp()`
  - `HashMap()`
  - *(... and 14 more)*

---

### bpbdbdb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpbdbdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `ILogPrinter`
- **Methods**: 5
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bpbdbdb.java`

**Key Methods**:
  - `level_d()`
  - `level_e()`
  - `level_i()`
  - `level_v()`
  - `level_w()`

---

### bpbqpqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpbqpqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `qppbpqq, Handler.Callback`
- **Methods**: 2
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\bpbqpqd.java`

**Key Methods**:
  - `SafeHandler()`
  - `handleMessage()`

---

### bpddqqq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpddqqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 9
- **Source**: `thingclips\sdk\bluetooth\bpddqqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `if()`
  - `if()`
  - `bdpdqbp()`

---

### bpdpqqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpdpqqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `com.thingclips.sdk.bluetooth.pbddddb`
- **Implements**: `ActionResponse<Boolean>`
- **Methods**: 340
- **Fields**: 287
- **Source**: `thingclips\sdk\bluetooth\bpdpqqd.java`

**Key Methods**:
  - `CopyOnWriteArrayList()`
  - `CopyOnWriteArrayList()`
  - `CopyOnWriteArrayList()`
  - `CopyOnWriteArrayList()`
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `bdqqbqd()`
  - *(... and 330 more)*

**Notable Strings**:
  - `"requestAuthKey11ByCloud: isMacReplaceUuid = "`
  - `"bluetoothCapability"`
  - `"bluetoothCapability"`

---

### bppbpqq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bppbpqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dppdddb`
- **Methods**: 7
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bppbpqq.java`

**Key Methods**:
  - `addBleResponseReceiver()`
  - `destroy()`
  - `isSupportInstruction()`
  - `parseDataReceived()`
  - `processInstruction()`
  - `removeBleResponseReceiver()`
  - `updateMTU()`

---

### bppbqbb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bppbqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 20
- **Source**: `thingclips\sdk\bluetooth\bppbqbb.java`

**Notable Strings**:
  - `"00010203-0405-0607-0809-0a0b0c0d1912"`
  - `"00002adb-0000-1000-8000-00805f9b34fb"`
  - `"00002add-0000-1000-8000-00805f9b34fb"`
  - `"00002ade-0000-1000-8000-00805f9b34fb"`
  - `"00002add-0000-1000-8000-00805f9b34fb"`
  - *(... and 1 more)*

---

### bppdbpq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bppdbpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingThirdProtocolSupport`
- **Methods**: 8
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\bppdbpq.java`

**Key Methods**:
  - `bppdbpq()`
  - `getInstance()`
  - `addProtocolDelete()`
  - `getProtocolDelegateList()`
  - `getThingBleService()`
  - `removeProtocolDelete()`
  - `updateDps()`
  - `bppdbpq()`

---

### bppdddb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bppdddb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBleService`
- **Methods**: 8
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\bppdddb.java`

**Key Methods**:
  - `bppdddb()`
  - `addRequest()`
  - `connectBleDevice()`
  - `qpdbqqb()`
  - `disconnectBleDevice()`
  - `getConnectStatus()`
  - `readRemoteDeviceRssi()`
  - `if()`

---

### bppddpq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bppddpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbpdbqp`
- **Implements**: `XResponse`
- **Methods**: 66
- **Fields**: 61
- **Source**: `thingclips\sdk\bluetooth\bppddpq.java`

**Key Methods**:
  - `bddqqbp()`
  - `ppbdqbd()`
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `bppdpdq()`
  - `onCommandSuccess()`
  - `onError()`
  - `pdqppqb()`
  - `onCommandSuccess()`
  - *(... and 56 more)*

---

### bppqppq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bppqppq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `XResponse`
- **Methods**: 4
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\bppqppq.java`

**Key Methods**:
  - `bppqppq()`
  - `onCommandSuccess()`
  - `onError()`
  - `StringBuilder()`

---

### bpqbbqp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpqbbqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\bpqbbqp.java`

---

### bpqbqdd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpqbqdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 7
- **Fields**: 14
- **Source**: `thingclips\sdk\bluetooth\bpqbqdd.java`

**Key Methods**:
  - `bpqbqdd()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `ArrayList()`

---

### bpqddbq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpqddbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Implements**: `XResponse`
- **Methods**: 12
- **Fields**: 12
- **Source**: `thingclips\sdk\bluetooth\bpqddbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `bpqddbq()`
  - `dealWithResponse()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `ArrayList()`
  - `ArrayList()`
  - *(... and 2 more)*

---

### bpqqddp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpqqddp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Methods**: 7
- **Fields**: 10
- **Source**: `thingclips\sdk\bluetooth\bpqqddp.java`

**Key Methods**:
  - `bpqqddp()`
  - `bdpdqbp()`
  - `dealWithResponse()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `bppqppq()`
  - `qddqppb()`

---

### bpqqdpq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpqqdpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Methods**: 8
- **Fields**: 14
- **Source**: `thingclips\sdk\bluetooth\bpqqdpq.java`

**Key Methods**:
  - `bpqqdpq()`
  - `bdpdqbp()`
  - `dealWithResponse()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `ArrayList()`
  - `bppqppq()`
  - `qddqppb()`

**Notable Strings**:
  - `"sendAccessActiveInfo: resultBean uuid is NULL!!!"`

---

### bqbdpqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqbdpqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\bqbdpqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `LinkedHashMap()`

---

### bqbqbdd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqbqbdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\bqbqbdd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### bqbqqqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqbqqqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Methods**: 10
- **Fields**: 26
- **Source**: `thingclips\sdk\bluetooth\bqbqqqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `if()`
  - `if()`
  - `if()`
  - `if()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### bqdbdbd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqdbdbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `BeaconScanFilterReceiveListener`
- **Methods**: 22
- **Fields**: 36
- **Source**: `thingclips\sdk\bluetooth\bqdbdbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onThingDeviceFound()`
  - `bqdbdbd()`
  - `bppdpdq()`
  - `onEvent()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `pdqppqb()`
  - *(... and 12 more)*

**Notable Strings**:
  - `"bluetooth is unable "`

---

### bqdpdbq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqdpdbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 7
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bqdpdbq.java`

**Key Methods**:
  - `connect()`
  - `disconnectDevice()`
  - `getConnectStatus()`
  - `isConnected()`
  - `isConnecting()`
  - `publishDps()`
  - `release()`

---

### bqdpddb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqdpddb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pdqppqb`
- **Implements**: `Handler.Callback`
- **Methods**: 24
- **Fields**: 29
- **Source**: `thingclips\sdk\bluetooth\bqdpddb.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `bdpdqbp()`
  - `Handler()`
  - `AtomicInteger()`
  - `bdpdqbp()`
  - `onStatusChanged()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `onDevInfoUpdate()`
  - `onDpUpdate()`
  - *(... and 14 more)*

---

### bqdpddd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqdpddd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pppbppp`
- **Methods**: 6
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\bqdpddd.java`

**Key Methods**:
  - `bqdpddd()`
  - `bpbbqdb()`
  - `pdqppqb()`
  - `qpbpqpq()`
  - `qqdbbpp()`
  - `pdqppqb()`

---

### bqpbqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqpbqbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Methods**: 27
- **Fields**: 35
- **Source**: `thingclips\sdk\bluetooth\bqpbqbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `RequestPackage()`
  - `pdqppqb()`
  - `RequestPackage()`
  - `bdpdqbp()`
  - `DpsCombine()`
  - `bdpdqbp()`
  - `ArrayList()`
  - *(... and 17 more)*

---

### bqpdbqq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqpdbqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 12
- **Fields**: 38
- **Source**: `thingclips\sdk\bluetooth\bqpdbqq.java`

**Key Methods**:
  - `bqpdbqq()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `ArrayList()`
  - `if()`
  - `if()`
  - `bqpdbqq()`
  - `bdpdqbp()`
  - `ArrayList()`
  - *(... and 2 more)*

---

### bqqppqq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqqppqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bqqppqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### C0264a [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.C0264a`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Function`
- **Methods**: 35
- **Fields**: 15
- **Source**: `thingclips\sdk\bluetooth\C0264a.java`

**Key Methods**:
  - `m292A()`
  - `m293B()`
  - `m294C()`
  - `m295a()`
  - `m296b()`
  - `m297c()`
  - `m298d()`
  - `m299e()`
  - `JSONObject()`
  - `m301g()`
  - *(... and 25 more)*

---

### dbbbbqq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbbbbqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 32
- **Fields**: 197
- **Source**: `thingclips\sdk\bluetooth\dbbbbqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `ArrayList()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `BLEScanDevBean()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `if()`
  - *(... and 22 more)*

---

### dbbbppp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbbbppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBleConnectService`
- **Methods**: 7
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dbbbppp.java`

**Key Methods**:
  - `addContinuousConnectDevice()`
  - `displayDeviceList()`
  - `enterDeviceConsole()`
  - `exitDeviceConsole()`
  - `onApplicationCreate()`
  - `removeContinuousConnectDevice()`
  - `takeConnectToDevice()`

---

### dbbpbbb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbbpbbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbbppqb`
- **Methods**: 7
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\dbbpbbb.java`

**Key Methods**:
  - `dbbpbbb()`
  - `bdqqbqd()`
  - `bpbbqdb()`
  - `bpqqdpq()`
  - `pdqppqb()`
  - `ppdpppq()`
  - `pdqppqb()`

**Notable Strings**:
  - `"P2AddSub"`

---

### dbddpdp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbddpdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbpdbqp`
- **Implements**: `XResponse`
- **Methods**: 61
- **Fields**: 63
- **Source**: `thingclips\sdk\bluetooth\dbddpdp.java`

**Key Methods**:
  - `bddqqbp()`
  - `qdddbpd()`
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `StringBuilder()`
  - `bppdpdq()`
  - `onCommandSuccess()`
  - `onError()`
  - `pdqppqb()`
  - *(... and 51 more)*

---

### dbpbdpb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbpbdpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\dbpbdpb.java`

---

### dbpdbqb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbpdbqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBleController`
- **Methods**: 51
- **Fields**: 42
- **Source**: `thingclips\sdk\bluetooth\dbpdbqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `dbpdbqb()`
  - *(... and 41 more)*

**Notable Strings**:
  - `"activator no bluetooth permission"`

---

### dbpdpbp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbpdpbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\dbpdpbp.java`

**Key Methods**:
  - `BluetoothClient()`
  - `bdpdqbp()`
  - `dbpdpbp()`
  - `pdqppqb()`

---

### dbpppqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbpppqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Handler.Callback`
- **Methods**: 17
- **Fields**: 26
- **Source**: `thingclips\sdk\bluetooth\dbpppqd.java`

**Key Methods**:
  - `AtomicInteger()`
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `Handler()`
  - `dbpppqd()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `ddqqbbq()`
  - *(... and 7 more)*

---

### dbpqqpp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbpqqpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbbppqb`
- **Methods**: 7
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\dbpqqpp.java`

**Key Methods**:
  - `dbpqqpp()`
  - `bdqqbqd()`
  - `bpbbqdb()`
  - `bpqqdpq()`
  - `pdqppqb()`
  - `ppdpppq()`
  - `pdqppqb()`

---

### dbqddpd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbqddpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dbqddpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onError()`

---

### dbqqqbb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbqqqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `bppbpqq`
- **Methods**: 18
- **Fields**: 21
- **Source**: `thingclips\sdk\bluetooth\dbqqqbb.java`

**Key Methods**:
  - `HashSet()`
  - `ConcurrentHashMap()`
  - `dbqqqbb()`
  - `ppbbbpd()`
  - `dqbpqbb()`
  - `dealWithResponse()`
  - `ArrayList()`
  - `addBleResponseReceiver()`
  - `addXRequest()`
  - `destroy()`
  - *(... and 8 more)*

---

### ddbbbbq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbbbbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qpqddqp`
- **Implements**: `XResponse`
- **Methods**: 11
- **Fields**: 10
- **Source**: `thingclips\sdk\bluetooth\ddbbbbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `ddbbbbq()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `bdpdqbp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - *(... and 1 more)*

---

### ddbbpqq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbbpqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\ddbbpqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`

**Notable Strings**:
  - `"android.permission.BLUETOOTH_CONNECT"`
  - `"android.permission.BLUETOOTH_SCAN"`
  - `"android.permission.BLUETOOTH_ADVERTISE"`

---

### ddbbqqp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbbqqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Implements**: `XResponse`
- **Methods**: 9
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\ddbbqqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `ddbbqqp()`
  - `dealWithResponse()`
  - `pbbppqb()`
  - `pqdbppq()`
  - `bdpdqbp()`
  - `qddqppb()`

---

### ddbdpqb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbdpqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `AdvertiseCallback`
- **Implements**: `ddpdbpd`
- **Methods**: 25
- **Fields**: 48
- **Source**: `thingclips\sdk\bluetooth\ddbdpqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `run()`
  - `qddqppb()`
  - *(... and 15 more)*

**Notable Strings**:
  - `"Bluetooth is disable"`
  - `"Bluetooth LE Advertising is not supported on this device"`

---

### ddbdqbd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbdqbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\ddbdqbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `qbqppdb()`
  - `pbpqqdb()`

---

### ddbpqdb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbpqdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Methods**: 5
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\ddbpqdb.java`

**Key Methods**:
  - `ddbpqdb()`
  - `dealWithResponse()`
  - `pqdbppq()`
  - `bppqppq()`
  - `qddqppb()`

---

### ddbqpbp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbqpbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Business`
- **Methods**: 4
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\ddbqpbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`

---

### dddddqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dddddqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `dqdpbpq`
- **Methods**: 11
- **Fields**: 12
- **Source**: `thingclips\sdk\bluetooth\dddddqd.java`

**Key Methods**:
  - `dddddqd()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `dddddqd()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - *(... and 1 more)*

---

### dddpqpb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dddpqpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `ppbdppp`
- **Implements**: `ActionResponse<ECDHRep>`
- **Methods**: 21
- **Fields**: 15
- **Source**: `thingclips\sdk\bluetooth\dddpqpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onSuccess()`
  - `String()`
  - `onError()`
  - `dddpqpb()`
  - `replayDpsReportAck()`
  - `ArrayList()`
  - `assembleConnectBuilder()`
  - `checkSchema()`
  - `dealWithResponse()`
  - *(... and 11 more)*

---

### ddpbddq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddpbddq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBleFlow`
- **Methods**: 72
- **Fields**: 9
- **Source**: `thingclips\sdk\bluetooth\ddpbddq.java`

**Key Methods**:
  - `ddpbddq()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `clearBigData()`
  - `clearV4BigData()`
  - `connectDeviceAction()`
  - `disconnectDeviceAction()`
  - `fetchWifiDevInfoRet()`
  - `getBlePhyConnectStatus()`
  - `getBluetoothState()`
  - *(... and 62 more)*

---

### ddpbpdd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddpbpdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingLEAudioManager`
- **Methods**: 21
- **Fields**: 15
- **Source**: `thingclips\sdk\bluetooth\ddpbpdd.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `ddpbpdd()`
  - `getConnectController()`
  - `getInstance()`
  - `sendLEAudioAlarmClockRequest()`
  - `sendLEAudioCommonCommandRequest()`
  - `sendLEAudioControlRequest()`
  - `sendLEAudioTokenDelieverRequest()`
  - `sendLEAudioTokenRequireRequest()`
  - `getLEAudioAuthorizationToken()`
  - *(... and 11 more)*

---

### ddqdbbd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddqdbbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\ddqdbbd.java`

**Key Methods**:
  - `pqdppqd()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### ddqdppd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddqdppd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qpqddqp`
- **Implements**: `XResponse`
- **Methods**: 11
- **Fields**: 14
- **Source**: `thingclips\sdk\bluetooth\ddqdppd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `ddqdppd()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `bdpdqbp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - *(... and 1 more)*

---

### ddqpbqb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddqpbqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Implements**: `XResponse`
- **Methods**: 10
- **Fields**: 9
- **Source**: `thingclips\sdk\bluetooth\ddqpbqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `StringBuilder()`
  - `ddqpbqb()`
  - `dealWithResponse()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `bdpdqbp()`
  - `qddqppb()`

---

### ddqpdpp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddqpdpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\ddqpdpp.java`

---

### dpbdbpq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpbdbpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Runnable`
- **Methods**: 55
- **Fields**: 66
- **Source**: `thingclips\sdk\bluetooth\dpbdbpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `File()`
  - `FileInputStream()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `StringBuilder()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - *(... and 45 more)*

---

### dpddppb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpddppb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\dpddppb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ArrayList()`
  - `bdpdqbp()`

---

### dpdpppb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpdpppb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbpdbqp`
- **Implements**: `Runnable`
- **Methods**: 35
- **Fields**: 41
- **Source**: `thingclips\sdk\bluetooth\dpdpppb.java`

**Key Methods**:
  - `ArrayList()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `run()`
  - `pdqppqb()`
  - `onCommandSuccess()`
  - `onError()`
  - `forWhite()`
  - `getXor()`
  - *(... and 25 more)*

---

### dpdqppp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpdqppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qpqbppd`
- **Implements**: `Handler.Callback, qpqbpdp`
- **Methods**: 18
- **Fields**: 24
- **Source**: `thingclips\sdk\bluetooth\dpdqppp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `Handler()`
  - `bppdpdq()`
  - `dealWithResponse()`
  - `dpdbqdp()`
  - `handleMessage()`
  - `pbbppqb()`
  - `pbddddb()`
  - `pbpdbqp()`
  - `pbpdpdp()`
  - *(... and 8 more)*

---

### dppbbqp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dppbbqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `XRequest`
- **Methods**: 18
- **Fields**: 36
- **Source**: `thingclips\sdk\bluetooth\dppbbqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - *(... and 8 more)*

---

### dppdddb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dppdddb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dppdddb.java`

**Key Methods**:
  - `addXRequest()`

---

### dpppdpp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpppdpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 7
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\dpppdpp.java`

**Key Methods**:
  - `dpppdpp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bpbdbdb()`
  - `onEvent()`
  - `dpppdpp()`

---

### dpppqbq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpppqbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Implements**: `Runnable`
- **Methods**: 70
- **Fields**: 92
- **Source**: `thingclips\sdk\bluetooth\dpppqbq.java`

**Key Methods**:
  - `HashMap()`
  - `HashMap()`
  - `ConcurrentHashMap()`
  - `pqdppqd()`
  - `qdddqdp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `run()`
  - `ArrayList()`
  - `pbbppqb()`
  - *(... and 60 more)*

---

### dpqbbdp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpqbbdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Implements**: `XResponse`
- **Methods**: 11
- **Fields**: 10
- **Source**: `thingclips\sdk\bluetooth\dpqbbdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `dpqbbdp()`
  - `dealWithResponse()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `ArrayList()`
  - `bdpdqbp()`
  - *(... and 1 more)*

---

### dpqbbpd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpqbbpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pppbppp`
- **Methods**: 7
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\dpqbbpd.java`

**Key Methods**:
  - `dpqbbpd()`
  - `bpbbqdb()`
  - `pbpqqdp()`
  - `pdqppqb()`
  - `qpbpqpq()`
  - `qqdbbpp()`
  - `pdqppqb()`

---

### dpqqbqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpqqbqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 7
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\dpqqbqd.java`

**Key Methods**:
  - `HashMap()`
  - `StringBuilder()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`

---

### dpqqqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpqqqbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `BleScanResponse`
- **Methods**: 7
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\dpqqqbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onResult()`
  - `dpqqqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### dqbdbpp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqbdbpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `com.thingclips.sdk.bluetooth.pbpdbqp`
- **Implements**: `XResponse`
- **Methods**: 237
- **Fields**: 286
- **Source**: `thingclips\sdk\bluetooth\dqbdbpp.java`

**Key Methods**:
  - `ppbbbpd()`
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `StringBuilder()`
  - `bpbbqdb()`
  - `onCommandSuccess()`
  - `onError()`
  - `StringBuilder()`
  - `bppdpdq()`
  - *(... and 227 more)*

---

### dqbdpdd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqbdpdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 15
- **Source**: `thingclips\sdk\bluetooth\dqbdpdd.java`

---

### dqbpdbq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqbpdbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 10
- **Fields**: 23
- **Source**: `thingclips\sdk\bluetooth\dqbpdbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `HashMap()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### dqbpdqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqbpdqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBleCommRodCtrl, qqqdqdb`
- **Methods**: 33
- **Fields**: 33
- **Source**: `thingclips\sdk\bluetooth\dqbpdqd.java`

**Key Methods**:
  - `SafeHandler()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onSuccess()`
  - `onError()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - *(... and 23 more)*

**Notable Strings**:
  - `"updateSchemaMap error, Bluetooth connection is about to be disconnected!! Please check schemaJson:"`

---

### dqbpqbb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqbpqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Methods**: 19
- **Fields**: 23
- **Source**: `thingclips\sdk\bluetooth\dqbpqbb.java`

**Key Methods**:
  - `dqbpqbb()`
  - `bdpdqbp()`
  - `DeviceDataBean()`
  - `bpbbqdb()`
  - `bppdpdq()`
  - `ArrayList()`
  - `dealWithResponse()`
  - `pdqppqb()`
  - `ArrayList()`
  - `pqdbppq()`
  - *(... and 9 more)*

---

### dqdbbqp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqdbbqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbbppqb`
- **Methods**: 8
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\dqdbbqp.java`

**Key Methods**:
  - `dqdbbqp()`
  - `bdqqbqd()`
  - `bpbbqdb()`
  - `bpqqdpq()`
  - `pbpqqdp()`
  - `pdqppqb()`
  - `ppdpppq()`
  - `pdqppqb()`

---

### dqdbdpq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqdbdpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IResultCallback`
- **Methods**: 32
- **Fields**: 30
- **Source**: `thingclips\sdk\bluetooth\dqdbdpq.java`

**Key Methods**:
  - `AtomicInteger()`
  - `dbqqppp()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - *(... and 22 more)*

---

### dqdpbpq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqdpbpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\dqdpbpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`

---

### dqdpppd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqdpppd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Implements**: `XResponse`
- **Methods**: 8
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\dqdpppd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `dqdpppd()`
  - `pbbppqb()`
  - `pqdbppq()`
  - `bdpdqbp()`
  - `qddqppb()`

---

### dqdpqqp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqdpqqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `qpqbpdp`
- **Methods**: 2
- **Fields**: 10
- **Source**: `thingclips\sdk\bluetooth\dqdpqqp.java`

**Key Methods**:
  - `dqdpqqp()`
  - `dealWithResponse()`

---

### dqpddpd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqpddpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 16
- **Fields**: 45
- **Source**: `thingclips\sdk\bluetooth\dqpddpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `if()`
  - `if()`
  - `if()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `if()`
  - `if()`
  - *(... and 6 more)*

---

### dqpqppq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqpqppq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 11
- **Fields**: 46
- **Source**: `thingclips\sdk\bluetooth\dqpqppq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `if()`
  - `if()`
  - `if()`
  - `bdpdqbp()`
  - `if()`
  - `if()`
  - `if()`
  - `bdpdqbp()`
  - `HashMap()`
  - *(... and 1 more)*

---

### dqqbdqb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqqbdqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 33
- **Source**: `thingclips\sdk\bluetooth\dqqbdqb.java`

**Key Methods**:
  - `ArrayList()`
  - `bdpdqbp()`
  - `Ret()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### pbbddbd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbbddbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Implements**: `Business.ResultListener<Boolean>`
- **Methods**: 31
- **Fields**: 56
- **Source**: `thingclips\sdk\bluetooth\pbbddbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pbbddbd()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pbbddbd()`
  - *(... and 21 more)*

---

### pbbppbd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbbppbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Methods**: 5
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\pbbppbd.java`

**Key Methods**:
  - `pbbppbd()`
  - `dealWithResponse()`
  - `pqdbppq()`
  - `bppqppq()`
  - `qddqppb()`

---

### pbbppqb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbbppqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdqqqbp`
- **Methods**: 21
- **Fields**: 30
- **Source**: `thingclips\sdk\bluetooth\pbbppqb.java`

**Key Methods**:
  - `pbbppqb()`
  - `bdpdqbp()`
  - `bdqqbqd()`
  - `bpbbqdb()`
  - `bpqqdpq()`
  - `bqqppqq()`
  - `dbbpbbb()`
  - `pbbppqb()`
  - `pbddddb()`
  - `pdqppqb()`
  - *(... and 11 more)*

---

### pbbqdqp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbbqdqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 7
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\pbbqdqp.java`

**Key Methods**:
  - `Object()`
  - `pbbqdqp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pbqqbbb()`
  - `pbbqdqp()`
  - `bdpdqbp()`

---

### pbbqpqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbbqpqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Handler.Callback`
- **Methods**: 38
- **Fields**: 55
- **Source**: `thingclips\sdk\bluetooth\pbbqpqd.java`

**Key Methods**:
  - `Handler()`
  - `qqqbbqq()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `run()`
  - `pdqppqb()`
  - `pppbppp()`
  - `bppdpdq()`
  - *(... and 28 more)*

---

### pbddddb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbddddb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Implements**: `bbdbqqd, Handler.Callback`
- **Methods**: 196
- **Fields**: 159
- **Source**: `thingclips\sdk\bluetooth\pbddddb.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `HashMap()`
  - `CopyOnWriteArrayList()`
  - `pqdbppq()`
  - `qqpddqd()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `bpbbqdb()`
  - *(... and 186 more)*

---

### pbdpbqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbdpbqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbbppqb`
- **Methods**: 10
- **Fields**: 17
- **Source**: `thingclips\sdk\bluetooth\pbdpbqd.java`

**Key Methods**:
  - `pbdpbqd()`
  - `bdqqbqd()`
  - `bpbbqdb()`
  - `bpqqdpq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `ppdpppq()`
  - `qbbdpbq()`
  - `qqdbbpp()`
  - `pdqppqb()`

---

### pbdppqq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbdppqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\pbdppqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ArrayList()`
  - `bdpdqbp()`

---

### pbpbpqq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbpbpqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pppbppp`
- **Methods**: 6
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\pbpbpqq.java`

**Key Methods**:
  - `pbpbpqq()`
  - `bpbbqdb()`
  - `pdqppqb()`
  - `qpbpqpq()`
  - `qqdbbpp()`
  - `pdqppqb()`

---

### pbpdbqp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbpdbqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `pqqdpdp, dppdddb, IThingBleFlow, Handler.Callback, INotifyDelegate, OnBleConnectStatusChangeListener`
- **Methods**: 199
- **Fields**: 203
- **Source**: `thingclips\sdk\bluetooth\pbpdbqp.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `CopyOnWriteArrayList()`
  - `bppdpdq()`
  - `ConcurrentHashMap()`
  - `HashSet()`
  - `qddqppb()`
  - `Handler()`
  - `bdbqbpp()`
  - *(... and 189 more)*

**Notable Strings**:
  - `"queryBluetoothState: "`
  - `"superQueryBluetoothStateRetError() called with: code = ["`

---

### pbppppp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbppppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Methods**: 20
- **Fields**: 23
- **Source**: `thingclips\sdk\bluetooth\pbppppp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `RequestPackage()`
  - `pdqppqb()`
  - `RequestPackage()`
  - `bdpdqbp()`
  - `DpsCombine()`
  - `bdpdqbp()`
  - `ArrayList()`
  - *(... and 10 more)*

---

### pbpqqdb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbpqqdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `pdppdpp`
- **Methods**: 8
- **Fields**: 13
- **Source**: `thingclips\sdk\bluetooth\pbpqqdb.java`

**Key Methods**:
  - `pbpqqdb()`
  - `bdpdqbp()`
  - `HashMap()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onConnectStatusChanged()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pbpqqdp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbpqqdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qpqbppd`
- **Implements**: `qpqbpdp`
- **Methods**: 9
- **Fields**: 22
- **Source**: `thingclips\sdk\bluetooth\pbpqqdp.java`

**Key Methods**:
  - `pbpqqdp()`
  - `bdpdqbp()`
  - `BleDps()`
  - `dealWithResponse()`
  - `bdpdqbp()`
  - `BaseAccessoriesDpReportRep()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `bppqppq()`

---

### pbqbbpb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbqbbpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `BleConnectStatusListener`
- **Methods**: 39
- **Fields**: 40
- **Source**: `thingclips\sdk\bluetooth\pbqbbpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `pbqbbpb()`
  - `cacheMasterAllSlaveInfo()`
  - `getInstance()`
  - `removeAllMasterSlaveStatus()`
  - `cacheMasterAddSlaveInfo()`
  - `qpdqppb()`
  - `disconnectAllSlaveGatt()`
  - *(... and 29 more)*

**Notable Strings**:
  - `"bluetoothLeadFollowAttr"`
  - `"bluetoothLeadFollowAttr"`

---

### pbqdddb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbqdddb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IBleActivatorListener`
- **Methods**: 29
- **Fields**: 28
- **Source**: `thingclips\sdk\bluetooth\pbqdddb.java`

**Key Methods**:
  - `HashMap()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - *(... and 19 more)*

**Notable Strings**:
  - `"configThingBleDevice() called with: devUUId = ["`
  - `"stopConfig error, uuid = "`

---

### pbqddpp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbqddpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Implements**: `XResponse`
- **Methods**: 9
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\pbqddpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `pbqddpp()`
  - `dealWithResponse()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `bdpdqbp()`
  - `qddqppb()`

---

### pbqpdpb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbqpdpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Implements**: `XResponse`
- **Methods**: 11
- **Fields**: 18
- **Source**: `thingclips\sdk\bluetooth\pbqpdpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `StringBuilder()`
  - `pbqpdpb()`
  - `dealWithResponse()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `bdpdqbp()`
  - *(... and 1 more)*

---

### pbqpppp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbqpppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 16
- **Fields**: 29
- **Source**: `thingclips\sdk\bluetooth\pbqpppp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pppbppp()`
  - `bdpdqbp()`
  - `qddqppb()`
  - `TargetDeviceBean()`
  - `bdpdqbp()`
  - *(... and 6 more)*

---

### pdbpdqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdbpdqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 33
- **Source**: `thingclips\sdk\bluetooth\pdbpdqd.java`

**Notable Strings**:
  - `"thingble_BluetoothBondManager"`

---

### pdpbbqb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdpbbqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bpbqpqd`
- **Implements**: `qbqppdq`
- **Methods**: 9
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\pdpbbqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `if()`
  - `pdpbbqb()`
  - `handleMessage()`
  - `if()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pdpdbpd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdpdbpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pdpdbpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### pdqbdbq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdqbdbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbbppqb`
- **Methods**: 7
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\pdqbdbq.java`

**Key Methods**:
  - `pdqbdbq()`
  - `bdqqbqd()`
  - `bpbbqdb()`
  - `bpqqdpq()`
  - `pdqppqb()`
  - `ppdpppq()`
  - `pdqppqb()`

---

### pdqdbdd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdqdbdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBleFittingsManager`
- **Methods**: 31
- **Fields**: 30
- **Source**: `thingclips\sdk\bluetooth\pdqdbdd.java`

**Key Methods**:
  - `HashSet()`
  - `ddbqpbp()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `StringBuilder()`
  - `pdqppqb()`
  - *(... and 21 more)*

---

### pdqdqbd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdqdqbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 14
- **Fields**: 53
- **Source**: `thingclips\sdk\bluetooth\pdqdqbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `BLEScanDevBean()`
  - `bppdpdq()`
  - `bppppdb()`
  - `pdqppqb()`
  - `bddppbd()`
  - `String()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ppbbppb()`
  - *(... and 4 more)*

---

### pdqqqdq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdqqqdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Handler.Callback`
- **Methods**: 36
- **Fields**: 37
- **Source**: `thingclips\sdk\bluetooth\pdqqqdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `Handler()`
  - `bdpdqbp()`
  - `onMessageReceived()`
  - `bppdpdq()`
  - `onSuccess()`
  - `onError()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - *(... and 26 more)*

---

### ppbbqbb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppbbqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Implements**: `XResponse`
- **Methods**: 11
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\ppbbqbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `ppbbqbb()`
  - `bpbbqdb()`
  - `ArrayList()`
  - `dealWithResponse()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `bdpdqbp()`
  - *(... and 1 more)*

---

### ppbdppp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppbdppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `pqqdpdp, bqdpdbq, OnBleConnectStatusChangeListener, qpqbpdp`
- **Methods**: 56
- **Fields**: 47
- **Source**: `thingclips\sdk\bluetooth\ppbdppp.java`

**Key Methods**:
  - `pdqppqb()`
  - `bppdpdq()`
  - `qddqppb()`
  - `pppbppp()`
  - `pbbppqb()`
  - `qpppdqb()`
  - `bdpdqbp()`
  - `onConnectError()`
  - `onConnectSuccess()`
  - `bppdpdq()`
  - *(... and 46 more)*

**Notable Strings**:
  - `"onBluetoothConnectSuccess, mac : "`

---

### ppbdqbd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppbdqbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `ppqbqbp`
- **Methods**: 6
- **Fields**: 35
- **Source**: `thingclips\sdk\bluetooth\ppbdqbd.java`

**Key Methods**:
  - `ArrayList()`
  - `ppbdqbd()`
  - `bdpdqbp()`
  - `parseDataReceived()`
  - `pdqppqb()`
  - `bdpdqbp()`

---

### ppbqqdd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppbqqdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBleGateway`
- **Methods**: 8
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\ppbqqdd.java`

**Key Methods**:
  - `addDeviceToGateway()`
  - `checkAndSendHeartBeat()`
  - `connectDeviceByGateway()`
  - `disconnectDeviceByGateway()`
  - `getDeviceListFromGateway()`
  - `getGatewayWhiteList()`
  - `removeDeviceFromGateway()`
  - `stopHeartBeat()`

---

### pppdqbd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pppdqbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Handler.Callback, ddppddd`
- **Methods**: 84
- **Fields**: 72
- **Source**: `thingclips\sdk\bluetooth\pppdqbd.java`

**Key Methods**:
  - `pbbppqb()`
  - `Handler()`
  - `pqdppqd()`
  - `bpbbqdb()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bpbbqdb()`
  - `bppdpdq()`
  - `onSuccess()`
  - *(... and 74 more)*

**Notable Strings**:
  - `"removeSlaveInfoFromMasterByDeviceRemove() called with: slaveUuid = ["`

---

### pppppqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pppppqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 6
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\pppppqd.java`

**Key Methods**:
  - `pppppqd()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pppppqd()`
  - `bdpdqbp()`
  - `BluetoothClient()`

---

### ppqbqbb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppqbqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pqdbppq<XRequest>`
- **Methods**: 10
- **Fields**: 14
- **Source**: `thingclips\sdk\bluetooth\ppqbqbb.java`

**Key Methods**:
  - `BleAccessException()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `BleWriteException()`
  - `BleConnectionException()`
  - `BleParamException()`
  - `StringBuilder()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### ppqdbbq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppqdbbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Handler.Callback`
- **Methods**: 38
- **Fields**: 37
- **Source**: `thingclips\sdk\bluetooth\ppqdbbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `Handler()`
  - `qbqqqdp()`
  - `bdpdqbp()`
  - `onNotify()`
  - `onResponse()`
  - `bppdpdq()`
  - `onResponse()`
  - `pdqppqb()`
  - `onResponse()`
  - *(... and 28 more)*

---

### ppqdbpp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppqdbpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `BleNotifyResponse`
- **Methods**: 14
- **Fields**: 18
- **Source**: `thingclips\sdk\bluetooth\ppqdbpp.java`

**Key Methods**:
  - `HashMap()`
  - `ConcurrentHashMap()`
  - `bdpdqbp()`
  - `onNotify()`
  - `onResponse()`
  - `pdqppqb()`
  - `ppqdbpp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 4 more)*

---

### pqdbppq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqdbppq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Thread`
- **Methods**: 7
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\pqdbppq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `run()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pqdbqqq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqdbqqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 45
- **Fields**: 125
- **Source**: `thingclips\sdk\bluetooth\pqdbqqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `DataParseBean()`
  - `ArrayList()`
  - `if()`
  - `if()`
  - `if()`
  - `if()`
  - `ArrayList()`
  - `ArrayList()`
  - *(... and 35 more)*

---

### pqdppqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqdppqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Business`
- **Methods**: 50
- **Fields**: 61
- **Source**: `thingclips\sdk\bluetooth\pqdppqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ApiParams()`
  - `ApiParams()`
  - `HashMap()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pbddddb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - *(... and 40 more)*

---

### pqdqpdp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqdqpdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\pqdqpdp.java`

---

### pqdqqpq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqdqqpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Methods**: 17
- **Fields**: 32
- **Source**: `thingclips\sdk\bluetooth\pqdqqpq.java`

**Key Methods**:
  - `pqdqqpq()`
  - `bbqpbqd()`
  - `AccessoriesExtInfo()`
  - `bdpdqbp()`
  - `bppqppq()`
  - `bpbbqdb()`
  - `bppqppq()`
  - `dealWithResponse()`
  - `pdqppqb()`
  - `pqdbppq()`
  - *(... and 7 more)*

---

### pqpdqbq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqpdqbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\pqpdqbq.java`

**Key Methods**:
  - `MMKVManager()`
  - `pqpdqbq()`
  - `bdpdqbp()`

---

### pqpppqp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqpppqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pdbpddd`
- **Methods**: 9
- **Fields**: 14
- **Source**: `thingclips\sdk\bluetooth\pqpppqp.java`

**Key Methods**:
  - `pqpppqp()`
  - `bdpdqbp()`
  - `bdpqqdq()`
  - `bppdpdq()`
  - `bdpqqdq()`
  - `pdqppqb()`
  - `bdpqqdq()`
  - `pdqppqb()`
  - `bdpqqdq()`

---

### pqppqpd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqppqpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `dqqbppb`
- **Methods**: 8
- **Fields**: 12
- **Source**: `thingclips\sdk\bluetooth\pqppqpd.java`

**Key Methods**:
  - `HashMap()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pqpqqpd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqpqqpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\pqpqqpd.java`

**Key Methods**:
  - `bdpdqbp()`

---

### pqqbdqp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqqbdqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 12
- **Fields**: 17
- **Source**: `thingclips\sdk\bluetooth\pqqbdqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `SecureRandom()`
  - `bdpdqbp()`
  - `ArrayList()`
  - *(... and 2 more)*

---

### pqqdqdb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqqdqdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingInnerScanner`
- **Methods**: 19
- **Fields**: 15
- **Source**: `thingclips\sdk\bluetooth\pqqdqdb.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `bdpdqbp()`
  - `onDeviceFounded()`
  - `onScanCancel()`
  - `onScanStart()`
  - `onScanStop()`
  - `pqqdqdb()`
  - `getInstance()`
  - `pqqdqdb()`
  - `onScanDeviceFound()`
  - *(... and 9 more)*

**Notable Strings**:
  - `",uuid = "`

---

### pqqpqpq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqqpqpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dddbppd`
- **Methods**: 6
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\pqqpqpq.java`

**Key Methods**:
  - `pqqpqpq()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `if()`

---

### pqqqbbp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqqqbbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Runnable`
- **Methods**: 18
- **Fields**: 14
- **Source**: `thingclips\sdk\bluetooth\pqqqbbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `Handler()`
  - `bdpdqbp()`
  - `run()`
  - `ArrayList()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - *(... and 8 more)*

---

### pqqqddq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqqqddq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 13
- **Fields**: 13
- **Source**: `thingclips\sdk\bluetooth\pqqqddq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `qddqppb()`
  - `qpppdqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 3 more)*

---

### qbbbpdp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbbbpdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `ExtModuleStatusListener`
- **Methods**: 80
- **Fields**: 85
- **Source**: `thingclips\sdk\bluetooth\qbbbpdp.java`

**Key Methods**:
  - `CopyOnWriteArrayList()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - *(... and 70 more)*

**Notable Strings**:
  - `"bluetoothLeadFollowAttr"`
  - `" uuid "`

---

### qbbdddq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbbdddq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\qbbdddq.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `bdpdqbp()`

---

### qbbppdd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbbppdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pppbppp`
- **Methods**: 6
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\qbbppdd.java`

**Key Methods**:
  - `qbbppdd()`
  - `bpbbqdb()`
  - `pdqppqb()`
  - `qpbpqpq()`
  - `qqdbbpp()`
  - `pdqppqb()`

---

### qbbppdp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbbppdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\qbbppdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `HashMap()`
  - `bdpdqbp()`

---

### qbdbbdb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbdbbdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `com.thingclips.sdk.bluetooth.pbpdbqp`
- **Implements**: `XResponse`
- **Methods**: 119
- **Fields**: 119
- **Source**: `thingclips\sdk\bluetooth\qbdbbdb.java`

**Key Methods**:
  - `ppbbbpd()`
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `StringBuilder()`
  - `bppdpdq()`
  - `onCommandSuccess()`
  - `onError()`
  - `dpdbqdp()`
  - `onCommandSuccess()`
  - *(... and 109 more)*

---

### qbdbpbq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbdbpbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 11
- **Fields**: 22
- **Source**: `thingclips\sdk\bluetooth\qbdbpbq.java`

**Key Methods**:
  - `qbdbpbq()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `bppdpdq()`
  - `ArrayList()`
  - `pdqppqb()`
  - `qddqppb()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 1 more)*

---

### qbdppqb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbdppqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qbdppqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onError()`

---

### qbdqdbd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbdqdbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 86
- **Source**: `thingclips\sdk\bluetooth\qbdqdbd.java`

**Key Methods**:
  - `bdpdqbp()`

---

### qbdqdbq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbdqdbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\qbdqdbq.java`

**Key Methods**:
  - `bdpdqbp()`

---

### qbpbbpq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbpbbpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `qpddpqd`
- **Methods**: 5
- **Fields**: 9
- **Source**: `thingclips\sdk\bluetooth\qbpbbpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `HashMap()`
  - `bdpdqbp()`
  - `HashMap()`

---

### qbpdqpq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbpdqpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Comparator<bbdbqqd>`
- **Methods**: 142
- **Fields**: 188
- **Source**: `thingclips\sdk\bluetooth\qbpdqpq.java`

**Key Methods**:
  - `CopyOnWriteArrayList()`
  - `qddqppb()`
  - `CopyOnWriteArrayList()`
  - `pppbppp()`
  - `Handler()`
  - `pbbppqb()`
  - `qpppdqb()`
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - *(... and 132 more)*

**Notable Strings**:
  - `"]with uuid= ["`
  - `"], uuid = ["`
  - `"], uuid = ["`
  - `"directConnectDevice Bluetooth not Enabled"`

---

### qbpppdb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbpppdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `LeScanResponse`
- **Methods**: 25
- **Fields**: 22
- **Source**: `thingclips\sdk\bluetooth\qbpppdb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onDeviceFounded()`
  - `onScanCancel()`
  - `onScanStart()`
  - `onScanStop()`
  - `bdpdqbp()`
  - `onScanCancel()`
  - `onScanStart()`
  - `onScanStop()`
  - `bppdpdq()`
  - *(... and 15 more)*

---

### qbpqppd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbpqppd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `Thread`
- **Methods**: 13
- **Fields**: 20
- **Source**: `thingclips\sdk\bluetooth\qbpqppd.java`

**Key Methods**:
  - `ArrayBlockingQueue()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `qpppdqb()`
  - `run()`
  - `bdpdqbp()`
  - *(... and 3 more)*

---

### qbqpbbd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbqpbbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\qbqpbbd.java`

**Key Methods**:
  - `bdpdqbp()`

---

### qbqppdb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbqppdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Handler.Callback, pdppdpp`
- **Methods**: 30
- **Fields**: 34
- **Source**: `thingclips\sdk\bluetooth\qbqppdb.java`

**Key Methods**:
  - `SafeHandler()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `onDeviceFounded()`
  - `onScanCancel()`
  - `onScanStart()`
  - `onScanStop()`
  - `qbqppdb()`
  - `AtomicInteger()`
  - `handleMessage()`
  - *(... and 20 more)*

**Notable Strings**:
  - `"retryActivator,find the target device, uuid:"`
  - `"find uuid:"`

---

### qbqqdqb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbqqdqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pdbpddd`
- **Implements**: `BleMtuResponse`
- **Methods**: 7
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\qbqqdqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onResponse()`
  - `bdpdqbp()`
  - `onFailure()`
  - `qbqqdqb()`
  - `pdqppqb()`
  - `bdpdqbp()`

---

### qbqqpbb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbqqpbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 9
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\qbqqpbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ppddqpb()`
  - `pdqppqb()`
  - `dbqddbp()`
  - `bdpdqbp()`
  - `qbbqqdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qdbpppp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdbpppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IDevListener`
- **Methods**: 18
- **Fields**: 13
- **Source**: `thingclips\sdk\bluetooth\qdbpppp.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onDevInfoUpdate()`
  - `onDpUpdate()`
  - `onNetworkStatusChanged()`
  - `onRemoved()`
  - `onStatusChanged()`
  - `bdpdqbp()`
  - `qddqppb()`
  - *(... and 8 more)*

---

### qdddbpd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdddbpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `ppqbqbp`
- **Methods**: 6
- **Fields**: 39
- **Source**: `thingclips\sdk\bluetooth\qdddbpd.java`

**Key Methods**:
  - `ArrayList()`
  - `qdddbpd()`
  - `bdpdqbp()`
  - `parseDataReceived()`
  - `pdqppqb()`
  - `bdpdqbp()`

---

### qdddqdp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdddqdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Business.ResultListener<Boolean>`
- **Methods**: 32
- **Fields**: 42
- **Source**: `thingclips\sdk\bluetooth\qdddqdp.java`

**Key Methods**:
  - `pqdppqd()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - *(... and 22 more)*

---

### qddqbdd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qddqbdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\qddqbdd.java`

**Key Methods**:
  - `qddqbdd()`
  - `bdpdqbp()`
  - `qddqbdd()`
  - `bppdddb()`

---

### qdpppbq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdpppbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 16
- **Fields**: 88
- **Source**: `thingclips\sdk\bluetooth\qdpppbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 6 more)*

---

### qdqqppp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdqqppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 23
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qdqqppp.java`

**Key Methods**:
  - `activator()`
  - `activeValue()`
  - `bdpdqbp()`
  - `connect()`
  - `disconnectDevice()`
  - `getAllDpBLEDpResponseBean()`
  - `getDeviceId()`
  - `getDeviceType()`
  - `isInConfig()`
  - `isPaired()`
  - *(... and 13 more)*

---

### qpbqpbq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpbqpbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Runnable`
- **Methods**: 28
- **Fields**: 38
- **Source**: `thingclips\sdk\bluetooth\qpbqpbq.java`

**Key Methods**:
  - `AtomicInteger()`
  - `MMKVManager()`
  - `bdpdqbp()`
  - `run()`
  - `bdpdqbp()`
  - `pbbppqb()`
  - `StringBuilder()`
  - `pbddddb()`
  - `pppbppp()`
  - `qddqppb()`
  - *(... and 18 more)*

---

### qpdbqqb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpdbqqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `pqpbpqd`
- **Methods**: 29
- **Fields**: 22
- **Source**: `thingclips\sdk\bluetooth\qpdbqqb.java`

**Key Methods**:
  - `CopyOnWriteArrayList()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `pdqppqb()`
  - `onSuccess()`
  - `onError()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - *(... and 19 more)*

---

### qppbpdp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qppbpdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qpqddqd`
- **Implements**: `pbqbqdb.bppdpdq`
- **Methods**: 13
- **Fields**: 20
- **Source**: `thingclips\sdk\bluetooth\qppbpdp.java`

**Key Methods**:
  - `CopyOnWriteArraySet()`
  - `ConcurrentHashMap()`
  - `qppbpdp()`
  - `pbqbqdb()`
  - `getDefaultOnlineStatus()`
  - `handleMessage()`
  - `startScanBeacon()`
  - `ArrayList()`
  - `stopScanBeacon()`
  - `ArrayList()`
  - *(... and 3 more)*

---

### qppddqq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qppddqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qpppdqb`
- **Implements**: `BeaconActivatorCallback`
- **Methods**: 9
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\qppddqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `dqdbdpq()`
  - `bdpdqbp()`
  - `qddqppb()`
  - `bdpdqbp()`

---

### qpppdqb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpppdqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 22
- **Fields**: 24
- **Source**: `thingclips\sdk\bluetooth\qpppdqb.java`

**Key Methods**:
  - `SafeHandler()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `CopyOnWriteArrayList()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pppbppp()`
  - `ArrayList()`
  - `qddqppb()`
  - *(... and 12 more)*

---

### qpppdqq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpppdqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\qpppdqq.java`

**Key Methods**:
  - `bdpdqbp()`

---

### qppppbq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qppppbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IDeviceMqttProtocolListener`
- **Methods**: 5
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\qppppbq.java`

**Key Methods**:
  - `qppppbq()`
  - `IllegalArgumentException()`
  - `bdpdqbp()`
  - `onResult()`
  - `bdpdqbp()`

---

### qpppqdb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpppqdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bpbqpqd`
- **Implements**: `BleMtuResponse`
- **Methods**: 8
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\qpppqdb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onResponse()`
  - `if()`
  - `qpppqdb()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qpqbbpp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqbbpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IBeaconFilterManager`
- **Methods**: 34
- **Fields**: 33
- **Source**: `thingclips\sdk\bluetooth\qpqbbpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `qpqbbpp()`
  - `addBeaconScanFilterMonitor()`
  - `bppdpdq()`
  - `if()`
  - `pdqppqb()`
  - `qddqppb()`
  - `registerBeaconReceiveOnApplicationCreate()`
  - `removeAllFilterMonitor()`
  - *(... and 24 more)*

**Notable Strings**:
  - `"android.bluetooth.le.extra.ERROR_CODE"`
  - `"android.bluetooth.le.extra.LIST_SCAN_RESULT"`
  - `"notifyIBeaconFound: uuid = "`
  - `"getDeviceName uuid:"`

---

### qpqbpdp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqbpdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qpqbpdp.java`

**Key Methods**:
  - `dealWithResponse()`

---

### qpqbppd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqbppd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\qpqbppd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qpqddpb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqddpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `qpqbpdp`
- **Methods**: 2
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\qpqddpb.java`

**Key Methods**:
  - `qpqddpb()`
  - `dealWithResponse()`

---

### qpqddqp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqddqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Implements**: `pppbbbb`
- **Methods**: 1
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\qpqddqp.java`

**Key Methods**:
  - `bdpdqbp()`

---

### qpqqdbp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqqdbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 14
- **Source**: `thingclips\sdk\bluetooth\qpqqdbp.java`

**Notable Strings**:
  - `"00001912-0000-1000-8000-00805f9b34fb"`

---

### qqdbbpp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqdbbpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Methods**: 12
- **Fields**: 17
- **Source**: `thingclips\sdk\bluetooth\qqdbbpp.java`

**Key Methods**:
  - `qqdbbpp()`
  - `bpbbqdb()`
  - `bppqppq()`
  - `dealWithResponse()`
  - `if()`
  - `if()`
  - `if()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `ArrayList()`
  - *(... and 2 more)*

---

### qqdpqqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqdpqqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qpqddqd`
- **Implements**: `IThingBeaconManager, Handler.Callback, qpqpqbb`
- **Methods**: 75
- **Fields**: 95
- **Source**: `thingclips\sdk\bluetooth\qqdpqqd.java`

**Key Methods**:
  - `HashSet()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `ArrayList()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `onError()`
  - *(... and 65 more)*

---

### qqdqbpb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqdqbpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 10
- **Fields**: 22
- **Source**: `thingclips\sdk\bluetooth\qqdqbpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `HashMap()`
  - `bdpdqbp()`
  - `HashMap()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### qqpbdqq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpbdqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `bbdbqqd, OnThirdConnectListener`
- **Methods**: 52
- **Fields**: 30
- **Source**: `thingclips\sdk\bluetooth\qqpbdqq.java`

**Key Methods**:
  - `CopyOnWriteArrayList()`
  - `qqpbdqq()`
  - `activator()`
  - `activeValue()`
  - `clearDataChannel()`
  - `connect()`
  - `deviceFirmwareUpgrade()`
  - `disconnectDevice()`
  - `getAllDpBLEDpResponseBean()`
  - `getDeviceId()`
  - *(... and 42 more)*

---

### qqpbqpq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpbqpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qpqddqp`
- **Implements**: `XResponse`
- **Methods**: 11
- **Fields**: 14
- **Source**: `thingclips\sdk\bluetooth\qqpbqpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `qqpbqpq()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pqdbppq()`
  - `bdpdqbp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - *(... and 1 more)*

---

### qqpddqd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpddqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `ActionResponse<Boolean>`
- **Methods**: 61
- **Fields**: 46
- **Source**: `thingclips\sdk\bluetooth\qqpddqd.java`

**Key Methods**:
  - `bppdpdq()`
  - `onSuccess()`
  - `onError()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onSuccess()`
  - `onError()`
  - `pppbppp()`
  - *(... and 51 more)*

**Notable Strings**:
  - `", uuid:"`
  - `"[activeAccessoriesExecutor] start active uuid:"`
  - `"[activeAccessoriesExecutor] API :uuid:"`
  - `"[checkAccessoriesState] devInfo.uuid:"`
  - `", deviceBean.getUuid:"`

---

### qqpdpbp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpdpbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\qqpdpbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`

---

### qqpppdp [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpppdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpdqppp`
- **Implements**: `XResponse`
- **Methods**: 8
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\qqpppdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `qqpppdp()`
  - `pbbppqb()`
  - `pqdbppq()`
  - `bdpdqbp()`
  - `qddqppb()`

---

### qqpqdbd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpqdbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 12
- **Fields**: 47
- **Source**: `thingclips\sdk\bluetooth\qqpqdbd.java`

**Key Methods**:
  - `qqpqdbd()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - *(... and 2 more)*

---

### qqpqqpd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpqqpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 14
- **Fields**: 42
- **Source**: `thingclips\sdk\bluetooth\qqpqqpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ArrayList()`
  - `SparseArray()`
  - `HashMap()`
  - `if()`
  - `String()`
  - `if()`
  - `pdqppqb()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - *(... and 4 more)*

**Notable Strings**:
  - `"uuidBytes cannot be null"`
  - `"uuidBytes length invalid - "`

---

### qqqbbbd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqqbbbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\qqqbbbd.java`

**Key Methods**:
  - `qqqbbbd()`
  - `BluetoothClient()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qqqbbqq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqqbbqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Runnable`
- **Methods**: 17
- **Fields**: 12
- **Source**: `thingclips\sdk\bluetooth\qqqbbqq.java`

**Key Methods**:
  - `Handler()`
  - `CopyOnWriteArrayList()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `run()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `onDevInfoUpdate()`
  - `onDpUpdate()`
  - `onNetworkStatusChanged()`
  - *(... and 7 more)*

---

### qqqdqbb [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqqdqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBleManager`
- **Methods**: 72
- **Fields**: 20
- **Source**: `thingclips\sdk\bluetooth\qqqdqbb.java`

**Key Methods**:
  - `activeExtenModuleByBLEActived()`
  - `addScanLinkTaskIds()`
  - `bindSlaveDeviceToMaster()`
  - `cancelBleOta()`
  - `checkBleWifiDeviceReset()`
  - `clearBigDataChannelData()`
  - `clearBleDataCache()`
  - `connectBleDevice()`
  - `directConnectBleDevice()`
  - `disconnectBleDevice()`
  - *(... and 62 more)*

**Notable Strings**:
  - `"getBluetoothState no connect permission"`

---

### qqqqdbd [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqqqdbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\qqqqdbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`

---

### qqqqdqq [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqqqdqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `IThingBleOperator`
- **Methods**: 33
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\qqqqdqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onResponse()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `onScanCancel()`
  - `onScanStart()`
  - `onScanStop()`
  - `addConnectHidListener()`
  - `clearLeCache()`
  - `closeBluetooth()`
  - *(... and 23 more)*

**Notable Strings**:
  - `"startScanBindDevice onSuccess uuid :"`
  - `"closeBluetooth no connect permission"`
  - `"openBluetooth no connect permission"`
  - `"readBluetoothRssi no connect permission"`

---

### RunnableC0268e [HIGH]


- **Full Name**: `com.thingclips.sdk.bluetooth.RunnableC0268e`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\RunnableC0268e.java`

**Key Methods**:
  - `run()`

---

### UserConfigSessionLogoutManager [HIGH]


- **Full Name**: `com.thingclips.sdk.config.UserConfigSessionLogoutManager`
- **Package**: `com.thingclips.sdk.config`
- **Methods**: 19
- **Fields**: 17
- **Source**: `thingclips\sdk\config\UserConfigSessionLogoutManager.java`

**Key Methods**:
  - `clearUserConfig()`
  - `init()`
  - `initMqttSessionLogout()`
  - `onNeedLogin()`
  - `Handler()`
  - `run()`
  - `LoginOutBean()`
  - `initUserConfig()`
  - `logoutSuccess()`
  - `onCancelAccountSuccess()`
  - *(... and 9 more)*

---

### TaskQueue [HIGH]


- **Full Name**: `com.thingclips.sdk.config.service.activator.parallel.task.TaskQueue`
- **Package**: `com.thingclips.sdk.config.service.activator.parallel.task`
- **Implements**: `Runnable`
- **Methods**: 14
- **Fields**: 15
- **Source**: `activator\parallel\task\TaskQueue.java`

**Key Methods**:
  - `AtomicInteger()`
  - `LinkedBlockingQueue()`
  - `CopyOnWriteArrayList()`
  - `ThreadPoolExecutor()`
  - `bdpdqbp()`
  - `run()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - *(... and 4 more)*

---

### C0278a [HIGH]


- **Full Name**: `com.thingclips.sdk.core.C0278a`
- **Package**: `com.thingclips.sdk.core`
- **Implements**: `Iterable<S>`
- **Methods**: 32
- **Fields**: 36
- **Source**: `thingclips\sdk\core\C0278a.java`

**Key Methods**:
  - `a()`
  - `hasNext()`
  - `next()`
  - `remove()`
  - `UnsupportedOperationException()`
  - `b()`
  - `m358a()`
  - `m359b()`
  - `NoSuchElementException()`
  - `ClassCastException()`
  - *(... and 22 more)*

---

### bdbdqdq [HIGH]


- **Full Name**: `com.thingclips.sdk.device.bdbdqdq`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `ppbqqdd`
- **Implements**: `IResultCallback`
- **Methods**: 10
- **Fields**: 7
- **Source**: `thingclips\sdk\device\bdbdqdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bdbdqdq()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### bdpqppd [HIGH]


- **Full Name**: `com.thingclips.sdk.device.bdpqppd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `ppbqqdd`
- **Methods**: 5
- **Fields**: 2
- **Source**: `thingclips\sdk\device\bdpqppd.java`

**Key Methods**:
  - `bdpqppd()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pdqppqb()`

---

### bdqqbqd [HIGH]


- **Full Name**: `com.thingclips.sdk.device.bdqqbqd`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `ITemporaryCallBack`
- **Methods**: 15
- **Fields**: 35
- **Source**: `thingclips\sdk\device\bdqqbqd.java`

**Key Methods**:
  - `onHandler()`
  - `ArrayList()`
  - `HashMap()`
  - `bdpdqbp()`
  - `HashMap()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - *(... and 5 more)*

---

### bpbqpqd [HIGH]


- **Full Name**: `com.thingclips.sdk.device.bpbqpqd`
- **Package**: `com.thingclips.sdk.device`
- **Methods**: 5
- **Fields**: 30
- **Source**: `thingclips\sdk\device\bpbqpqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `HashMap()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `JSONObject()`

---

### bpdpqqd [HIGH]


- **Full Name**: `com.thingclips.sdk.device.bpdpqqd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `qpdbdpd`
- **Implements**: `IDeviceMqttProtocolListener<MQ_203_AddZigbeeGroupBean>`
- **Methods**: 44
- **Fields**: 72
- **Source**: `thingclips\sdk\device\bpdpqqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `handleMessage()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - `pppbppp()`
  - `onError()`
  - *(... and 34 more)*

---

### C0280R [HIGH]


- **Full Name**: `com.thingclips.sdk.device.C0280R`
- **Package**: `com.thingclips.sdk.device`
- **Methods**: 19
- **Fields**: 6213
- **Source**: `thingclips\sdk\device\C0280R.java`

**Key Methods**:
  - `anim()`
  - `animator()`
  - `attr()`
  - `bool()`
  - `color()`
  - `dimen()`
  - `drawable()`
  - `id()`
  - `integer()`
  - `interpolator()`
  - *(... and 9 more)*

---

### dbbpdqp [HIGH]


- **Full Name**: `com.thingclips.sdk.device.dbbpdqp`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `ppqpqpd`
- **Implements**: `Handler.Callback`
- **Methods**: 44
- **Fields**: 48
- **Source**: `thingclips\sdk\device\dbbpdqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSignalValueFind()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `StringBuilder()`
  - *(... and 34 more)*

---

### ddbdqbd [HIGH]


- **Full Name**: `com.thingclips.sdk.device.ddbdqbd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `Business`
- **Implements**: `Business.ResultListener<StorageSign>`
- **Methods**: 47
- **Fields**: 70
- **Source**: `thingclips\sdk\device\ddbdqbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onResponse()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - *(... and 37 more)*

---

### dddbppd [HIGH]


- **Full Name**: `com.thingclips.sdk.device.dddbppd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `Business`
- **Methods**: 14
- **Fields**: 18
- **Source**: `thingclips\sdk\device\dddbppd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - *(... and 4 more)*

---

### dppdpbd [HIGH]


- **Full Name**: `com.thingclips.sdk.device.dppdpbd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `TypeReference<Map<String`
- **Methods**: 15
- **Fields**: 51
- **Source**: `thingclips\sdk\device\dppdpbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `JSONObject()`
  - `HashMap()`
  - `HashMap()`
  - `StringBuilder()`
  - `pdqppqb()`
  - `HashMap()`
  - `pdqppqb()`
  - `JSONObject()`
  - `bdpdqbp()`
  - *(... and 5 more)*

---

### dpqqpqq [HIGH]


- **Full Name**: `com.thingclips.sdk.device.dpqqpqq`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `TypeReference<Map<String`
- **Implements**: `IThingWifiBase`
- **Methods**: 27
- **Fields**: 39
- **Source**: `thingclips\sdk\device\dpqqpqq.java`

**Key Methods**:
  - `HashSet()`
  - `bdpdqbp()`
  - `onMessageReceived()`
  - `if()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - `dpqqpqq()`
  - `bdpdqbp()`
  - *(... and 17 more)*

---

### pbbppqb [HIGH]


- **Full Name**: `com.thingclips.sdk.device.pbbppqb`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `bpqqdpq`
- **Methods**: 9
- **Fields**: 16
- **Source**: `thingclips\sdk\device\pbbppqb.java`

**Key Methods**:
  - `pbbppqb()`
  - `bdpdqbp()`
  - `qddqppb()`
  - `bppdpdq()`
  - `onStatusChanged()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `bdpdqbp()`

---

### pdqppqb [HIGH]


- **Full Name**: `com.thingclips.sdk.device.pdqppqb`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `bpqqdpq`
- **Methods**: 3
- **Fields**: 2
- **Source**: `thingclips\sdk\device\pdqppqb.java`

**Key Methods**:
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pdqqqdq [HIGH]


- **Full Name**: `com.thingclips.sdk.device.pdqqqdq`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `IExtDevListener`
- **Implements**: `DeviceOnlineStatusEvent, DeviceDpsUpdateEvent`
- **Methods**: 17
- **Fields**: 33
- **Source**: `thingclips\sdk\device\pdqqqdq.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onDevInfoUpdate()`
  - `onDpUpdate()`
  - `onNetworkStatusChanged()`
  - `onRemoved()`
  - `onStatusChanged()`
  - `ArrayList()`
  - `pdqqqdq()`
  - *(... and 7 more)*

---

### ppdpppq [HIGH]


- **Full Name**: `com.thingclips.sdk.device.ppdpppq`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `SafeHandler`
- **Implements**: `qqdqqpd, IDeviceHardwareResponseListener`
- **Methods**: 33
- **Fields**: 39
- **Source**: `thingclips\sdk\device\ppdpppq.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - *(... and 23 more)*

---

### qbbbpdp [HIGH]


- **Full Name**: `com.thingclips.sdk.device.qbbbpdp`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `ppbqqdd`
- **Methods**: 5
- **Fields**: 2
- **Source**: `thingclips\sdk\device\qbbbpdp.java`

**Key Methods**:
  - `qbbbpdp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pdqppqb()`

---

### qbqqdqq [HIGH]


- **Full Name**: `com.thingclips.sdk.device.qbqqdqq`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IDevListener`
- **Methods**: 17
- **Fields**: 13
- **Source**: `thingclips\sdk\device\qbqqdqq.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onDevInfoUpdate()`
  - `onDpUpdate()`
  - `onNetworkStatusChanged()`
  - `onRemoved()`
  - `onStatusChanged()`
  - `bdpdqbp()`
  - `qddqppb()`
  - *(... and 7 more)*

---

### qpbdppq [HIGH]


- **Full Name**: `com.thingclips.sdk.device.qpbdppq`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IResultCallback`
- **Methods**: 26
- **Fields**: 20
- **Source**: `thingclips\sdk\device\qpbdppq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `MqttControlBuilder()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `JSONObject()`
  - *(... and 16 more)*

---

### qpppdqb [HIGH]


- **Full Name**: `com.thingclips.sdk.device.qpppdqb`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IResultCallback`
- **Methods**: 15
- **Fields**: 20
- **Source**: `thingclips\sdk\device\qpppdqb.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 5 more)*

**Notable Strings**:
  - `"BluetoothUtils"`

---

### qqppqqd [HIGH]


- **Full Name**: `com.thingclips.sdk.device.qqppqqd`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IDeviceMqttProtocolListener<MQ_203_AddZigbeeGroupBean>`
- **Methods**: 48
- **Fields**: 52
- **Source**: `thingclips\sdk\device\qqppqqd.java`

**Key Methods**:
  - `Handler()`
  - `qddqppb()`
  - `C0337bdpdqbp()`
  - `onSuccess()`
  - `GroupUpdateEventModel()`
  - `onError()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `C0337bdpdqbp()`
  - *(... and 38 more)*

---

### qqqbbbd [HIGH]


- **Full Name**: `com.thingclips.sdk.device.qqqbbbd`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingGroupCache`
- **Methods**: 20
- **Fields**: 22
- **Source**: `thingclips\sdk\device\qqqbbbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `qqqbbbd()`
  - `addGroup()`
  - `addGroupList()`
  - `getDeviceBeanList()`
  - `ArrayList()`
  - `ArrayList()`
  - `getGroupBean()`
  - `getGroupList()`
  - `ArrayList()`
  - *(... and 10 more)*

---

### ThingDevicePlugin [HIGH]


- **Full Name**: `com.thingclips.sdk.device.ThingDevicePlugin`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingDevicePlugin`
- **Methods**: 55
- **Fields**: 16
- **Source**: `thingclips\sdk\device\ThingDevicePlugin.java`

**Key Methods**:
  - `bdpdqbp()`
  - `logoutSuccess()`
  - `pdqppqb()`
  - `onCancelAccountSuccess()`
  - `dependencies()`
  - `getBatchExecutionManager()`
  - `getDataInstance()`
  - `getDevListCacheManager()`
  - `getDevModel()`
  - `dpdqppp()`
  - *(... and 45 more)*

---

### bdpdqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.device.presenter.bdpdqbp`
- **Package**: `com.thingclips.sdk.device.presenter`
- **Extends**: `AbsThingDevice`
- **Implements**: `IResultCallback`
- **Methods**: 28
- **Fields**: 23
- **Source**: `sdk\device\presenter\bdpdqbp.java`

**Key Methods**:
  - `C0331bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `C0330bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `C0331bdpdqbp()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - *(... and 18 more)*

---

### bppdpdq [HIGH]


- **Full Name**: `com.thingclips.sdk.device.presenter.bppdpdq`
- **Package**: `com.thingclips.sdk.device.presenter`
- **Extends**: `AbsThingDevice`
- **Implements**: `IResultCallback`
- **Methods**: 28
- **Fields**: 20
- **Source**: `sdk\device\presenter\bppdpdq.java`

**Key Methods**:
  - `C0333bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `C0333bdpdqbp()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - *(... and 18 more)*

---

### pdqppqb [HIGH]


- **Full Name**: `com.thingclips.sdk.device.presenter.pdqppqb`
- **Package**: `com.thingclips.sdk.device.presenter`
- **Extends**: `AbsThingDevice`
- **Implements**: `IResultCallback`
- **Methods**: 29
- **Fields**: 19
- **Source**: `sdk\device\presenter\pdqppqb.java`

**Key Methods**:
  - `C0334bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `C0334bdpdqbp()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - *(... and 19 more)*

---

### qddqppb [HIGH]


- **Full Name**: `com.thingclips.sdk.device.presenter.qddqppb`
- **Package**: `com.thingclips.sdk.device.presenter`
- **Extends**: `qbqppdq`
- **Implements**: `IResultCallback`
- **Methods**: 23
- **Fields**: 15
- **Source**: `sdk\device\presenter\qddqppb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - `qddqppb()`
  - *(... and 13 more)*

---

### ThingGroupManager [HIGH]


- **Full Name**: `com.thingclips.sdk.device.presenter.ThingGroupManager`
- **Package**: `com.thingclips.sdk.device.presenter`
- **Implements**: `IThingGroup`
- **Methods**: 21
- **Fields**: 20
- **Source**: `sdk\device\presenter\ThingGroupManager.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - `ThingGroupManager()`
  - `initThingGroup()`
  - `addDevice()`
  - `bdpdqbp()`
  - *(... and 11 more)*

---

### C0283R [HIGH]


- **Full Name**: `com.thingclips.sdk.device.share.C0283R`
- **Package**: `com.thingclips.sdk.device.share`
- **Methods**: 18
- **Fields**: 2847
- **Source**: `sdk\device\share\C0283R.java`

**Key Methods**:
  - `anim()`
  - `animator()`
  - `attr()`
  - `bool()`
  - `color()`
  - `dimen()`
  - `drawable()`
  - `id()`
  - `integer()`
  - `interpolator()`
  - *(... and 8 more)*

---

### C0284R [HIGH]


- **Full Name**: `com.thingclips.sdk.device.share.api.C0284R`
- **Package**: `com.thingclips.sdk.device.share.api`
- **Methods**: 15
- **Fields**: 1751
- **Source**: `device\share\api\C0284R.java`

**Key Methods**:
  - `anim()`
  - `attr()`
  - `bool()`
  - `color()`
  - `dimen()`
  - `drawable()`
  - `id()`
  - `integer()`
  - `interpolator()`
  - `layout()`
  - *(... and 5 more)*

---

### AsyncPoster [HIGH]


- **Full Name**: `com.thingclips.sdk.eventbus.AsyncPoster`
- **Package**: `com.thingclips.sdk.eventbus`
- **Implements**: `Runnable`
- **Methods**: 5
- **Fields**: 3
- **Source**: `thingclips\sdk\eventbus\AsyncPoster.java`

**Key Methods**:
  - `PendingPostQueue()`
  - `AsyncPoster()`
  - `enqueue()`
  - `run()`
  - `IllegalStateException()`

---

### BackgroundPoster [HIGH]


- **Full Name**: `com.thingclips.sdk.eventbus.BackgroundPoster`
- **Package**: `com.thingclips.sdk.eventbus`
- **Implements**: `Runnable`
- **Methods**: 4
- **Fields**: 7
- **Source**: `thingclips\sdk\eventbus\BackgroundPoster.java`

**Key Methods**:
  - `PendingPostQueue()`
  - `BackgroundPoster()`
  - `enqueue()`
  - `run()`

---

### EventBus [HIGH]


- **Full Name**: `com.thingclips.sdk.eventbus.EventBus`
- **Package**: `com.thingclips.sdk.eventbus`
- **Methods**: 57
- **Fields**: 66
- **Source**: `thingclips\sdk\eventbus\EventBus.java`

**Key Methods**:
  - `EventBusBuilder()`
  - `HashMap()`
  - `onPostCompleted()`
  - `ArrayList()`
  - `EventBus()`
  - `addInterfaces()`
  - `builder()`
  - `EventBusBuilder()`
  - `clearCaches()`
  - `getDefault()`
  - *(... and 47 more)*

---

### EventBusBuilder [HIGH]


- **Full Name**: `com.thingclips.sdk.eventbus.EventBusBuilder`
- **Package**: `com.thingclips.sdk.eventbus`
- **Methods**: 13
- **Fields**: 19
- **Source**: `thingclips\sdk\eventbus\EventBusBuilder.java`

**Key Methods**:
  - `build()`
  - `EventBus()`
  - `eventInheritance()`
  - `executorService()`
  - `installDefaultEventBus()`
  - `EventBusException()`
  - `logNoSubscriberMessages()`
  - `logSubscriberExceptions()`
  - `sendNoSubscriberEvent()`
  - `sendSubscriberExceptionEvent()`
  - *(... and 3 more)*

---

### bdbdqdq [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.bdbdqdq`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `BasePresenter`
- **Implements**: `IThingLightningActivator, IDeviceMqttProtocolListener, ICheckDevActiveStatusByTokenListener`
- **Methods**: 69
- **Fields**: 68
- **Source**: `thingclips\sdk\hardware\bdbdqdq.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `Handler()`
  - `qpppdqb()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pbbppqb()`
  - *(... and 59 more)*

**Notable Strings**:
  - `"[startActive]input slRelMap,uuid:"`

---

### bddqdbd [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.bddqdbd`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `dqdbbqp`
- **Implements**: `IApConnectListener, IConfig`
- **Methods**: 52
- **Fields**: 72
- **Source**: `thingclips\sdk\hardware\bddqdbd.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `bdpdqbp()`
  - `onActiveError()`
  - `onActiveSuccess()`
  - `onConfigEnd()`
  - `onConfigStart()`
  - `onDeviceBindSuccess()`
  - `onDeviceFind()`
  - *(... and 42 more)*

---

### bddqpdp [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.bddqpdp`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `SafeHandler`
- **Implements**: `IApActivatorConfigListener`
- **Methods**: 78
- **Fields**: 71
- **Source**: `thingclips\sdk\hardware\bddqpdp.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `handleMessage()`
  - `pbbppqb()`
  - `onDeviceFind()`
  - `pbddddb()`
  - *(... and 68 more)*

**Notable Strings**:
  - `"find device uuid = "`

---

### bdpqppd [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.bdpqppd`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `IMultiModeActivator`
- **Methods**: 55
- **Fields**: 31
- **Source**: `thingclips\sdk\hardware\bdpqppd.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `qbbbpdp()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onActivatorStatePauseCallback()`
  - *(... and 45 more)*

**Notable Strings**:
  - `"activate device error, uuid:"`
  - `"activate success, uuid:"`
  - `"activate device error, uuid:"`
  - `"activate success, uuid:"`
  - `"activate device error, uuid:"`
  - *(... and 6 more)*

---

### bpdpqqd [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.bpdpqqd`
- **Package**: `com.thingclips.sdk.hardware`
- **Methods**: 63
- **Fields**: 100
- **Source**: `thingclips\sdk\hardware\bpdpqqd.java`

**Key Methods**:
  - `HashMap()`
  - `bpdpqqd()`
  - `pbbppqb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `HashMap()`
  - `pbddddb()`
  - `pbpdbqp()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - *(... and 53 more)*

**Notable Strings**:
  - `"[configBatchErrorRecord] uuid is NULL!!!"`
  - `"[getBatchPairLogBean] uuid is NULL!!!"`
  - `",uuid:"`
  - `",uuid:"`
  - `"[configBatchCancelRecord] uuid is NULL!!!"`
  - *(... and 3 more)*

---

### bqbdbqb [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.bqbdbqb`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `BasePresenter`
- **Implements**: `ICheckDevAcitveStatusByToken`
- **Methods**: 22
- **Fields**: 23
- **Source**: `thingclips\sdk\hardware\bqbdbqb.java`

**Key Methods**:
  - `bqbdbqb()`
  - `ActiveTokenBean()`
  - `dqqbdqb()`
  - `HashMap()`
  - `HashMap()`
  - `pqpbpqd()`
  - `HashMap()`
  - `HashMap()`
  - `activeMatterDev()`
  - `bdpdqbp()`
  - *(... and 12 more)*

---

### bqddqpq [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.bqddqpq`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `IThingHardware, qpbdppq, bbpqdqb, bqpqpqb, dqddqdp, pqqpqpq`
- **Methods**: 91
- **Fields**: 76
- **Source**: `thingclips\sdk\hardware\bqddqpq.java`

**Key Methods**:
  - `ReentrantReadWriteLock()`
  - `ArrayList()`
  - `ArrayList()`
  - `ReentrantReadWriteLock()`
  - `C0342bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `String()`
  - *(... and 81 more)*

---

### bqpbddq [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.bqpbddq`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `dqdbbqp`
- **Implements**: `IConfig, IConnectListener`
- **Methods**: 29
- **Fields**: 54
- **Source**: `thingclips\sdk\hardware\bqpbddq.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `bqpbddq()`
  - `bppdpdq()`
  - `cancel()`
  - `onActiveError()`
  - `if()`
  - `HashMap()`
  - `if()`
  - *(... and 19 more)*

---

### bqqbpqb [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.bqqbpqb`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `IConfig`
- **Methods**: 46
- **Fields**: 50
- **Source**: `thingclips\sdk\hardware\bqqbpqb.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `bdpdqbp()`
  - `onActiveError()`
  - `onActiveSuccess()`
  - `onConfigEnd()`
  - `onConfigStart()`
  - `onDeviceBindSuccess()`
  - `onDeviceFind()`
  - `onWifiError()`
  - *(... and 36 more)*

---

### C0290R [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.C0290R`
- **Package**: `com.thingclips.sdk.hardware`
- **Methods**: 19
- **Fields**: 6213
- **Source**: `thingclips\sdk\hardware\C0290R.java`

**Key Methods**:
  - `anim()`
  - `animator()`
  - `attr()`
  - `bool()`
  - `color()`
  - `dimen()`
  - `drawable()`
  - `id()`
  - `integer()`
  - `interpolator()`
  - *(... and 9 more)*

---

### dbbpdqp [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.dbbpdqp`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `SafeHandler`
- **Implements**: `IThingRouterConfigListener`
- **Methods**: 15
- **Fields**: 15
- **Source**: `thingclips\sdk\hardware\dbbpdqp.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bdpdqbp()`
  - `dbbpdqp()`
  - `bppdpdq()`
  - `onDevOnline()`
  - `onDevResponse()`
  - `StringBuilder()`
  - *(... and 5 more)*

---

### dbpdpbp [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.dbpdpbp`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `BasePresenter`
- **Implements**: `IResultCallback`
- **Methods**: 28
- **Fields**: 34
- **Source**: `thingclips\sdk\hardware\dbpdpbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onSuccess()`
  - `onError()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - `dbpdpbp()`
  - *(... and 18 more)*

---

### dddbqdq [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.dddbqdq`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `bqddqpq`
- **Implements**: `IHardwareLogEventListener`
- **Methods**: 27
- **Fields**: 19
- **Source**: `thingclips\sdk\hardware\dddbqdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `hardwareLogCallback()`
  - `messageReceivedLogCallback()`
  - `messageSendLogCallback()`
  - `recordLogCallback()`
  - `hardwareLogCallback()`
  - `bppdpdq()`
  - `onHandler()`
  - `ArrayList()`
  - `HashMap()`
  - *(... and 17 more)*

---

### ddqpdpp [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.ddqpdpp`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `BasePresenter`
- **Implements**: `IThingActivator, ICheckDevActiveStatusByTokenListener`
- **Methods**: 23
- **Fields**: 42
- **Source**: `thingclips\sdk\hardware\ddqpdpp.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - *(... and 13 more)*

---

### dpdbddb [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.dpdbddb`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `pppppqd.pdqppqb`
- **Implements**: `IMultiModeParallelActivator`
- **Methods**: 39
- **Fields**: 36
- **Source**: `thingclips\sdk\hardware\dpdbddb.java`

**Key Methods**:
  - `SafeHandler()`
  - `AtomicBoolean()`
  - `qbbbpdp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `dpdbddb()`
  - `pdqppqb()`
  - *(... and 29 more)*

**Notable Strings**:
  - `"onError uuid =  "`
  - `"uuid = "`

---

### dqdpbbd [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.dqdpbbd`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `IBleActivator`
- **Methods**: 8
- **Fields**: 8
- **Source**: `thingclips\sdk\hardware\dqdpbbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onConfigSuccess()`
  - `onError()`
  - `startActivator()`
  - `BleControllerBean()`
  - `bdpdqbp()`
  - `startBeaconActivator()`
  - `stopActivator()`

**Notable Strings**:
  - `"[checkActivatorParam] 'uuid' cannot be empty."`
  - `"[stopActivator] uuid is empty."`

---

### pbbppqb [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.pbbppqb`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `pppppqd.pdqppqb`
- **Implements**: `IParallelActivator`
- **Methods**: 40
- **Fields**: 39
- **Source**: `thingclips\sdk\hardware\pbbppqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `SafeHandler()`
  - `AtomicBoolean()`
  - `qqpppdp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - *(... and 30 more)*

**Notable Strings**:
  - `"startActivator, uuid ="`
  - `"[stopActivator] uuid is empty."`
  - `"[checkParam] 'uuid' cannot be empty."`

---

### pbddddb [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.pbddddb`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `BasePresenter`
- **Implements**: `IPollDevByToken`
- **Methods**: 15
- **Fields**: 7
- **Source**: `thingclips\sdk\hardware\pbddddb.java`

**Key Methods**:
  - `pbddddb()`
  - `ActiveTokenBean()`
  - `dqqbdqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `handleMessage()`
  - `if()`
  - `if()`
  - *(... and 5 more)*

---

### pdbpddd [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.pdbpddd`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `BasePresenter`
- **Implements**: `IThingActivator, ICheckDevActiveStatusByTokenListener`
- **Methods**: 23
- **Fields**: 41
- **Source**: `thingclips\sdk\hardware\pdbpddd.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - *(... and 13 more)*

---

### pdqppqb [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.pdqppqb`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `dpdqppp`
- **Implements**: `NetWorkStatusEvent, IDeviceHardwareConfigListener, IDeviceActivatorConfigListener`
- **Methods**: 38
- **Fields**: 57
- **Source**: `thingclips\sdk\hardware\pdqppqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `run()`
  - `RunnableC0346pdqppqb()`
  - `run()`
  - `qddqppb()`
  - `run()`
  - `pdqppqb()`
  - `dqqbdqb()`
  - `bdpdqbp()`
  - *(... and 28 more)*

---

### pdqqqdq [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.pdqqqdq`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `qpppdqb`
- **Implements**: `IThingDataCallback<DeviceBean>`
- **Methods**: 11
- **Fields**: 19
- **Source**: `thingclips\sdk\hardware\pdqqqdq.java`

**Key Methods**:
  - `qqpppdp()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `pdqqqdq()`
  - `ArrayList()`
  - `pdqppqb()`
  - `qddqppb()`
  - `CountDownLatch()`
  - `ArrayList()`
  - *(... and 1 more)*

---

### ppbqqdd [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.ppbqqdd`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `qpppdqb`
- **Implements**: `IThingDataCallback<DeviceBean>`
- **Methods**: 10
- **Fields**: 23
- **Source**: `thingclips\sdk\hardware\ppbqqdd.java`

**Key Methods**:
  - `qqpppdp()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `ppbqqdd()`
  - `pdqppqb()`
  - `qddqppb()`
  - `CountDownLatch()`
  - `ArrayList()`
  - `bdpdqbp()`

---

### pppbppp [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.pppbppp`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `pppppqd.pdqppqb`
- **Implements**: `IMultiModeActivator, OnBleConnectStatusListener`
- **Methods**: 139
- **Fields**: 150
- **Source**: `thingclips\sdk\hardware\pppbppp.java`

**Key Methods**:
  - `SafeHandler()`
  - `qddqppb()`
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `SafeHandler()`
  - `AtomicInteger()`
  - `AtomicBoolean()`
  - `qqpppdp()`
  - *(... and 129 more)*

**Notable Strings**:
  - `"retryActivator,find the target device, uuid:"`
  - `"uuid:"`
  - `"uuid:"`
  - `"startActivator, uuid ="`
  - `"[stopActivator] uuid is empty."`
  - *(... and 6 more)*

---

### ppqpqpd [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.ppqpqpd`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `BasePresenter`
- **Implements**: `ICheckDevActiveStatusByTokenListener, IThingActivator`
- **Methods**: 25
- **Fields**: 37
- **Source**: `thingclips\sdk\hardware\ppqpqpd.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `qqpppdp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bppdpdq()`
  - `onSuccess()`
  - `onError()`
  - `pdqppqb()`
  - `onFailure()`
  - *(... and 15 more)*

---

### ppqqqpb [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.ppqqqpb`
- **Package**: `com.thingclips.sdk.hardware`
- **Methods**: 14
- **Fields**: 16
- **Source**: `thingclips\sdk\hardware\ppqqqpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `ActiveBean()`
  - `bdpdqbp()`
  - `ThingLocalNormalControlBean()`
  - `bdpdqbp()`
  - `APConfigBean()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 4 more)*

---

### qbbbpdp [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.qbbbpdp`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `Business.ResultListener<ConfigProductInfoBean>`
- **Methods**: 18
- **Fields**: 27
- **Source**: `thingclips\sdk\hardware\qbbbpdp.java`

**Key Methods**:
  - `qqpppdp()`
  - `ConcurrentHashMap()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - *(... and 8 more)*

---

### qbdppbq [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.qbdppbq`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `SafeHandler`
- **Implements**: `NetWorkStatusEvent`
- **Methods**: 91
- **Fields**: 83
- **Source**: `thingclips\sdk\hardware\qbdppbq.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `AtomicInteger()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `handleMessage()`
  - `bdpdqbp()`
  - `onAvailable()`
  - *(... and 81 more)*

**Notable Strings**:
  - `"device uuid is null"`

---

### qdbdddp [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.qdbdddp`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `IThingActivator`
- **Methods**: 24
- **Fields**: 51
- **Source**: `thingclips\sdk\hardware\qdbdddp.java`

**Key Methods**:
  - `Handler()`
  - `pdqppqb()`
  - `ddpdbbp()`
  - `qqddbpb()`
  - `bdpdqbp()`
  - `onDevOnline()`
  - `HashMap()`
  - `onFind()`
  - `onFindErrorList()`
  - `HashMap()`
  - *(... and 14 more)*

---

### qdpppbq [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.qdpppbq`
- **Package**: `com.thingclips.sdk.hardware`
- **Methods**: 3
- **Fields**: 39
- **Source**: `thingclips\sdk\hardware\qdpppbq.java`

**Key Methods**:
  - `HashMap()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qdqbdbd [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.qdqbdbd`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `pppppqd.pdqppqb`
- **Implements**: `Business.ResultListener<UpdateSecretKeyBean>`
- **Methods**: 17
- **Fields**: 19
- **Source**: `thingclips\sdk\hardware\qdqbdbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `qqpppdp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqqqdq()`
  - *(... and 7 more)*

---

### qpbpqpq [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.qpbpqpq`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `com.thingclips.sdk.hardware.pppbppp`
- **Implements**: `IThingResultCallback<byte`
- **Methods**: 49
- **Fields**: 34
- **Source**: `thingclips\sdk\hardware\qpbpqpq.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onActivatorStatusChanged()`
  - `bppdpdq()`
  - `onSuccess()`
  - `onError()`
  - `pdqppqb()`
  - *(... and 39 more)*

**Notable Strings**:
  - `"uuid:"`
  - `"uuid:"`

---

### qpdbdpd [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.qpdbdpd`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `SafeHandler`
- **Implements**: `IThingRouterConfigListener`
- **Methods**: 17
- **Fields**: 22
- **Source**: `thingclips\sdk\hardware\qpdbdpd.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bdpdqbp()`
  - `qpdbdpd()`
  - `bppdpdq()`
  - `onDevOnline()`
  - `onDevResponse()`
  - `onError()`
  - *(... and 7 more)*

---

### qppddqq [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.qppddqq`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `dpdqppp`
- **Implements**: `IDeviceHardwareFindListener, IThingHardwareOnlineStatusListener`
- **Methods**: 13
- **Fields**: 16
- **Source**: `thingclips\sdk\hardware\qppddqq.java`

**Key Methods**:
  - `qppddqq()`
  - `pqpbpqd()`
  - `HashMap()`
  - `HashMap()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `onDestroy()`
  - `onDeviceOnlineStatusUpdate()`
  - `onFind()`
  - `pdqppqb()`
  - *(... and 3 more)*

---

### qpppdbb [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.qpppdbb`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `SafeHandler`
- **Implements**: `bbpqdqb, qpbdppq, IThingWifiGetLogConfig`
- **Methods**: 54
- **Fields**: 38
- **Source**: `thingclips\sdk\hardware\qpppdbb.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `AtomicInteger()`
  - `AtomicInteger()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `qpppdbb()`
  - *(... and 44 more)*

**Notable Strings**:
  - `"fetch uuid == "`

---

### qpppqdb [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.qpppqdb`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `BasePresenter`
- **Implements**: `ICheckDevActiveStatusByTokenListener, IThingCameraDevActivator`
- **Methods**: 19
- **Fields**: 36
- **Source**: `thingclips\sdk\hardware\qpppqdb.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `pdqppqb()`
  - `onSuccess()`
  - `onError()`
  - `qpppqdb()`
  - `bqbdbqb()`
  - `bdpdqbp()`
  - *(... and 9 more)*

---

### qpqddpb [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.qpqddpb`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `qpbpqpq`
- **Implements**: `IThingResultCallback<byte`
- **Methods**: 37
- **Fields**: 36
- **Source**: `thingclips\sdk\hardware\qpqddpb.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `pdqppqb()`
  - `onSuccess()`
  - `StringBuilder()`
  - `onError()`
  - `dqdbbqp()`
  - `bdpdqbp()`
  - *(... and 27 more)*

---

### qqpddqd [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.qqpddqd`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `TimerTask`
- **Implements**: `IDeviceHardwareResponseListener, Handler.Callback, IConfig, IDeviceHardwareFindListener, IThingHardwareOnlineStatusListener`
- **Methods**: 40
- **Fields**: 42
- **Source**: `thingclips\sdk\hardware\qqpddqd.java`

**Key Methods**:
  - `Timer()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - `run()`
  - `pppbppp()`
  - `run()`
  - *(... and 30 more)*

---

### GwBroadcastMonitorModel [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.model.GwBroadcastMonitorModel`
- **Package**: `com.thingclips.sdk.hardware.model`
- **Extends**: `TimerTask`
- **Implements**: `ServiceConnection`
- **Methods**: 46
- **Fields**: 52
- **Source**: `sdk\hardware\model\GwBroadcastMonitorModel.java`

**Key Methods**:
  - `bdpdqbp()`
  - `closeService()`
  - `getAppId()`
  - `onConfigResult()`
  - `update()`
  - `Handler()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `onServiceConnected()`
  - `onServiceDisconnected()`
  - *(... and 36 more)*

---

### GwTransferModel [HIGH]


- **Full Name**: `com.thingclips.sdk.hardware.model.GwTransferModel`
- **Package**: `com.thingclips.sdk.hardware.model`
- **Implements**: `ddqqbbq, qpbdppq, Handler.Callback`
- **Methods**: 48
- **Fields**: 70
- **Source**: `sdk\hardware\model\GwTransferModel.java`

**Key Methods**:
  - `SafeHandler()`
  - `bdpdqbp()`
  - `closeService()`
  - `getAppId()`
  - `gwOff()`
  - `gwOn()`
  - `hardwareLog()`
  - `parsePkgFrameProgress()`
  - `responseByBinary()`
  - `HResponse()`
  - *(... and 38 more)*

---

### C0297R [HIGH]


- **Full Name**: `com.thingclips.sdk.home.C0297R`
- **Package**: `com.thingclips.sdk.home`
- **Methods**: 19
- **Fields**: 6213
- **Source**: `thingclips\sdk\home\C0297R.java`

**Key Methods**:
  - `anim()`
  - `animator()`
  - `attr()`
  - `bool()`
  - `color()`
  - `dimen()`
  - `drawable()`
  - `id()`
  - `integer()`
  - `interpolator()`
  - *(... and 9 more)*

---

### o000000O [HIGH]


- **Full Name**: `com.thingclips.sdk.home.o000000O`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `Business`
- **Methods**: 45
- **Fields**: 52
- **Source**: `thingclips\sdk\home\o000000O.java`

**Key Methods**:
  - `OooO00o()`
  - `ApiParams()`
  - `OooO0O0()`
  - `ApiParams()`
  - `OooO0OO()`
  - `ApiParams()`
  - `OooO0Oo()`
  - `OooO0o()`
  - `ApiParams()`
  - `OooO0o0()`
  - *(... and 35 more)*

---

### o00000O [HIGH]


- **Full Name**: `com.thingclips.sdk.home.o00000O`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `Business`
- **Methods**: 7
- **Fields**: 8
- **Source**: `thingclips\sdk\home\o00000O.java`

**Key Methods**:
  - `OooO00o()`
  - `OooO0O0()`
  - `OooO0OO()`
  - `OooO00o()`
  - `OooO0O0()`
  - `OooO0OO()`
  - `OooO00o()`

---

### o00000O0 [HIGH]


- **Full Name**: `com.thingclips.sdk.home.o00000O0`
- **Package**: `com.thingclips.sdk.home`
- **Methods**: 11
- **Fields**: 11
- **Source**: `thingclips\sdk\home\o00000O0.java`

**Key Methods**:
  - `o00000O0()`
  - `OooO00o()`
  - `LinkedBlockingQueue()`
  - `OooO0O0()`
  - `o00000O0()`
  - `LinkedBlockingQueue()`
  - `ThreadPoolExecutor()`
  - `OooO00o()`
  - `OooO00o()`
  - `OooO00o()`
  - *(... and 1 more)*

---

### o0000O0 [HIGH]


- **Full Name**: `com.thingclips.sdk.home.o0000O0`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `BaseModel`
- **Implements**: `o000000`
- **Methods**: 81
- **Fields**: 71
- **Source**: `thingclips\sdk\home\o0000O0.java`

**Key Methods**:
  - `OooO()`
  - `onFailure()`
  - `onSuccess()`
  - `OooO00o()`
  - `onFailure()`
  - `onSuccess()`
  - `if()`
  - `OooO0O0()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 71 more)*

---

### o0000O00 [HIGH]


- **Full Name**: `com.thingclips.sdk.home.o0000O00`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `IThingDataCallback<List<ProductPanelInfoBean>>`
- **Methods**: 27
- **Fields**: 43
- **Source**: `thingclips\sdk\home\o0000O00.java`

**Key Methods**:
  - `oo000o()`
  - `OooO00o()`
  - `onSuccess()`
  - `onError()`
  - `OooO0O0()`
  - `onSuccess()`
  - `onError()`
  - `OooO0OO()`
  - `onSuccess()`
  - `onError()`
  - *(... and 17 more)*

---

### o0000O0O [HIGH]


- **Full Name**: `com.thingclips.sdk.home.o0000O0O`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `OooO0OO`
- **Implements**: `Runnable, Supplier<ThingSecondaryListDataBean>`
- **Methods**: 10
- **Fields**: 6
- **Source**: `thingclips\sdk\home\o0000O0O.java`

**Key Methods**:
  - `OooO00o()`
  - `onSuccess()`
  - `onFailure()`
  - `o0000O0O()`
  - `OooO0Oo()`
  - `OooO0o0()`
  - `run()`
  - `OooO00o()`
  - `get()`
  - `OooO0OO()`

---

### o000OOo0 [HIGH]


- **Full Name**: `com.thingclips.sdk.home.o000OOo0`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `IHomePatchCacheManager`
- **Methods**: 18
- **Fields**: 27
- **Source**: `thingclips\sdk\home\o000OOo0.java`

**Key Methods**:
  - `o000OOo0()`
  - `OooO00o()`
  - `o000OOo0()`
  - `clear()`
  - `getDeviceBizPropBean()`
  - `getDeviceBizPropBean()`
  - `getDeviceBizPropBeanList()`
  - `ArrayList()`
  - `ArrayList()`
  - `getDeviceBizPropBeanListFromLocal()`
  - *(... and 8 more)*

---

### o00O0O [HIGH]


- **Full Name**: `com.thingclips.sdk.home.o00O0O`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `BaseModel`
- **Implements**: `oo0o0Oo`
- **Methods**: 109
- **Fields**: 92
- **Source**: `thingclips\sdk\home\o00O0O.java`

**Key Methods**:
  - `OooO()`
  - `onFailure()`
  - `onSuccess()`
  - `OooO00o()`
  - `compare()`
  - `OooO0O0()`
  - `run()`
  - `OooO0OO()`
  - `OooO0O0()`
  - `onFailure()`
  - *(... and 99 more)*

---

### o0OoOo0 [HIGH]


- **Full Name**: `com.thingclips.sdk.home.o0OoOo0`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `Business`
- **Implements**: `Business.ResultListener<String>`
- **Methods**: 26
- **Fields**: 21
- **Source**: `thingclips\sdk\home\o0OoOo0.java`

**Key Methods**:
  - `OooO00o()`
  - `onFailure()`
  - `HomeResponseBean()`
  - `onSuccess()`
  - `OooO00o()`
  - `OooO0O0()`
  - `ApiParams()`
  - `OooO00o()`
  - `ApiParams()`
  - `OooO00o()`
  - *(... and 16 more)*

---

### OooOo00 [HIGH]


- **Full Name**: `com.thingclips.sdk.home.OooOo00`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `Runnable`
- **Methods**: 22
- **Fields**: 24
- **Source**: `thingclips\sdk\home\OooOo00.java`

**Key Methods**:
  - `OooO00o()`
  - `onSuccess()`
  - `onError()`
  - `run()`
  - `o0000O00()`
  - `OooO00o()`
  - `OooOo00()`
  - `Handler()`
  - `Handler()`
  - `OooO00o()`
  - *(... and 12 more)*

---

### RunnableC0300c [HIGH]


- **Full Name**: `com.thingclips.sdk.home.RunnableC0300c`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 6
- **Source**: `thingclips\sdk\home\RunnableC0300c.java`

**Key Methods**:
  - `run()`

---

### C0302R [HIGH]


- **Full Name**: `com.thingclips.sdk.log.C0302R`
- **Package**: `com.thingclips.sdk.log`
- **Methods**: 15
- **Fields**: 1751
- **Source**: `thingclips\sdk\log\C0302R.java`

**Key Methods**:
  - `anim()`
  - `attr()`
  - `bool()`
  - `color()`
  - `dimen()`
  - `drawable()`
  - `id()`
  - `integer()`
  - `interpolator()`
  - `layout()`
  - *(... and 5 more)*

---

### ThingLogPlugin [HIGH]


- **Full Name**: `com.thingclips.sdk.log.ThingLogPlugin`
- **Package**: `com.thingclips.sdk.log`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingLogPlugin`
- **Methods**: 14
- **Fields**: 12
- **Source**: `thingclips\sdk\log\ThingLogPlugin.java`

**Key Methods**:
  - `ThingLogPlugin()`
  - `ThingLogSdk()`
  - `hasAnalysisManager()`
  - `beginEvent()`
  - `dependencies()`
  - `endEvent()`
  - `event()`
  - `eventOnDebugTool()`
  - `flush()`
  - `init()`
  - *(... and 4 more)*

---

### YiAlertAreaSettings [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.YiAlertAreaSettings`
- **Package**: `com.savantsystems.yisdk.device`
- **Methods**: 5
- **Fields**: 9
- **Source**: `savantsystems\yisdk\device\YiAlertAreaSettings.java`

**Key Methods**:
  - `YiAlertAreaSettings()`
  - `equals()`
  - `hashCode()`
  - `toString()`
  - `StringBuilder()`

---

### YiBatteryStatus [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.YiBatteryStatus`
- **Package**: `com.savantsystems.yisdk.device`
- **Methods**: 4
- **Fields**: 5
- **Source**: `savantsystems\yisdk\device\YiBatteryStatus.java`

**Key Methods**:
  - `YiBatteryStatus()`
  - `equals()`
  - `hashCode()`
  - `toString()`

---

### YiCameraScheduleTimerId [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.YiCameraScheduleTimerId`
- **Package**: `com.savantsystems.yisdk.device`
- **Implements**: `CameraScheduleTimerId`
- **Methods**: 4
- **Fields**: 2
- **Source**: `savantsystems\yisdk\device\YiCameraScheduleTimerId.java`

**Key Methods**:
  - `YiCameraScheduleTimerId()`
  - `equals()`
  - `hashCode()`
  - `toString()`

---

### YiCameraSettingCommand [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.YiCameraSettingCommand`
- **Package**: `com.savantsystems.yisdk.device`
- **Extends**: `YiCameraSettingCommand<Boolean>`
- **Methods**: 36
- **Fields**: 21
- **Source**: `savantsystems\yisdk\device\YiCameraSettingCommand.java`

**Key Methods**:
  - `FlipVideoCommand()`
  - `mo0a()`
  - `equals()`
  - `hashCode()`
  - `toString()`
  - `FormatSdCardCommand()`
  - `FormatSdCardCommand()`
  - `mo0a()`
  - `method()`
  - `NightVisionCommand()`
  - *(... and 26 more)*

---

### YiCameraSettings [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.YiCameraSettings`
- **Package**: `com.savantsystems.yisdk.device`
- **Methods**: 4
- **Fields**: 12
- **Source**: `savantsystems\yisdk\device\YiCameraSettings.java`

**Key Methods**:
  - `YiCameraSettings()`
  - `equals()`
  - `hashCode()`
  - `toString()`

---

### YiDeviceState [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.YiDeviceState`
- **Package**: `com.savantsystems.yisdk.device`
- **Extends**: `YiDeviceStatePart>`
- **Methods**: 13
- **Fields**: 9
- **Source**: `savantsystems\yisdk\device\YiDeviceState.java`

**Key Methods**:
  - `Companion()`
  - `YiDeviceState()`
  - `YiDeviceState()`
  - `m18a()`
  - `m19b()`
  - `HashMap()`
  - `YiDeviceState()`
  - `m20c()`
  - `HashMap()`
  - `YiDeviceState()`
  - *(... and 3 more)*

---

### YiDeviceStatePart [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.YiDeviceStatePart`
- **Package**: `com.savantsystems.yisdk.device`
- **Extends**: `YiDeviceStatePart`
- **Implements**: `YiDeviceStatePartKey<AudioTalk>`
- **Methods**: 65
- **Fields**: 46
- **Source**: `savantsystems\yisdk\device\YiDeviceStatePart.java`

**Key Methods**:
  - `Key()`
  - `AudioTalk()`
  - `mo21a()`
  - `equals()`
  - `hashCode()`
  - `toString()`
  - `Key()`
  - `CameraStream()`
  - `mo21a()`
  - `equals()`
  - *(... and 55 more)*

---

### YiExtendedCameraSettings [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.YiExtendedCameraSettings`
- **Package**: `com.savantsystems.yisdk.device`
- **Methods**: 4
- **Fields**: 2
- **Source**: `savantsystems\yisdk\device\YiExtendedCameraSettings.java`

**Key Methods**:
  - `YiExtendedCameraSettings()`
  - `equals()`
  - `hashCode()`
  - `toString()`

---

### YiPlaybackState [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.YiPlaybackState`
- **Package**: `com.savantsystems.yisdk.device`
- **Extends**: `YiPlaybackState`
- **Methods**: 14
- **Fields**: 14
- **Source**: `savantsystems\yisdk\device\YiPlaybackState.java`

**Key Methods**:
  - `Companion()`
  - `Error()`
  - `equals()`
  - `hashCode()`
  - `toString()`
  - `Idle()`
  - `Paused()`
  - `equals()`
  - `hashCode()`
  - `toString()`
  - *(... and 4 more)*

---

### YiSdCardInfo [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.YiSdCardInfo`
- **Package**: `com.savantsystems.yisdk.device`
- **Methods**: 5
- **Fields**: 8
- **Source**: `savantsystems\yisdk\device\YiSdCardInfo.java`

**Key Methods**:
  - `YiSdCardInfo()`
  - `equals()`
  - `hashCode()`
  - `toString()`
  - `StringBuilder()`

---

### YiStaticDeviceInfo [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.YiStaticDeviceInfo`
- **Package**: `com.savantsystems.yisdk.device`
- **Methods**: 4
- **Fields**: 2
- **Source**: `savantsystems\yisdk\device\YiStaticDeviceInfo.java`

**Key Methods**:
  - `YiStaticDeviceInfo()`
  - `equals()`
  - `hashCode()`
  - `toString()`

---

### YiThumbnailImage [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.YiThumbnailImage`
- **Package**: `com.savantsystems.yisdk.device`
- **Methods**: 4
- **Fields**: 5
- **Source**: `savantsystems\yisdk\device\YiThumbnailImage.java`

**Key Methods**:
  - `YiThumbnailImage()`
  - `equals()`
  - `hashCode()`
  - `toString()`

---

### C0015xa7c3fb91 [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.C0015xa7c3fb91`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function3<FlowCollector<`
- **Methods**: 6
- **Fields**: 11
- **Source**: `yisdk\device\manager\C0015xa7c3fb91.java`

**Key Methods**:
  - `method()`
  - `C0015xa7c3fb91()`
  - `invoke()`
  - `C0015xa7c3fb91()`
  - `invokeSuspend()`
  - `IllegalStateException()`

---

### YiConnectionLockManager [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiConnectionLockManager`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `YiConnectionLock`
- **Methods**: 5
- **Fields**: 11
- **Source**: `yisdk\device\manager\YiConnectionLockManager.java`

**Key Methods**:
  - `YiConnectionLockImpl()`
  - `getF196b()`
  - `mo25c()`
  - `mo26d()`
  - `YiConnectionLockManager()`

---

### YiDeviceSubscriptionManager [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiDeviceSubscriptionManager`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Methods**: 1
- **Fields**: 0
- **Source**: `yisdk\device\manager\YiDeviceSubscriptionManager.java`

**Key Methods**:
  - `mo31a()`

---

### YiDeviceSubscriptionManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiDeviceSubscriptionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\manager\YiDeviceSubscriptionManagerImpl$checkSubscriptionStatus$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiDeviceSubscriptionManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiDeviceSubscriptionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 18
- **Fields**: 18
- **Source**: `yisdk\device\manager\YiDeviceSubscriptionManagerImpl$pollSubscriptionStatus$1.java`

**Key Methods**:
  - `method()`
  - `C00051()`
  - `create()`
  - `C00051()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `method()`
  - `create()`
  - *(... and 8 more)*

---

### YiFirmwareManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<RetryFailure<YiError>, Continuation<`
- **Methods**: 5
- **Fields**: 4
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$fetchCurrentVersion$$inlined$retryIf$1.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `RetryInstruction()`

---

### YiFirmwareManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 4
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$fetchCurrentVersion$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiFirmwareManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$fetchFirmwareUpdates$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiFirmwareManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `ContinuationImpl`
- **Implements**: `Flow<String>`
- **Methods**: 6
- **Fields**: 9
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$observeCurrentVersion$$inlined$map$1.java`

**Key Methods**:
  - `AnonymousClass1()`
  - `invokeSuspend()`
  - `emit()`
  - `IllegalStateException()`
  - `AnonymousClass1()`
  - `m41e()`

---

### YiFirmwareManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<FlowCollector<`
- **Methods**: 4
- **Fields**: 2
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$performUpdate$3$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `invokeSuspend()`

---

### YiFirmwareManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<FirmwareUpdate.ProgressState, Continuation<`
- **Methods**: 5
- **Fields**: 3
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$performUpdate$5.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`

---

### YiFirmwareManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<FlowCollector<`
- **Methods**: 5
- **Fields**: 2
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$performUpdate$updateInfo$1.java`

**Key Methods**:
  - `create()`
  - `SuspendLambda()`
  - `invoke()`
  - `invokeSuspend()`
  - `IllegalStateException()`

---

### YiFirmwareManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function3<FlowCollector<`
- **Methods**: 4
- **Fields**: 8
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$special$$inlined$flatMapLatest$1.java`

**Key Methods**:
  - `invoke()`
  - `SuspendLambda()`
  - `invokeSuspend()`
  - `IllegalStateException()`

---

### YiFirmwareManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<Boolean, Continuation<`
- **Methods**: 5
- **Fields**: 7
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$startCurrentVersionFetcher$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `invokeSuspend()`
  - `IllegalStateException()`

---

### YiFirmwareManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$updateAutoOtaEnabled$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiFirmwareManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<YiDeviceConnection, Continuation<`
- **Methods**: 4
- **Fields**: 4
- **Source**: `yisdk\device\manager\YiFirmwareManagerImpl$updateAutoOtaEnabled$2.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`

---

### YiPeerConnectionManager [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManager`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `YiError>>`
- **Methods**: 3
- **Fields**: 0
- **Source**: `yisdk\device\manager\YiPeerConnectionManager.java`

**Key Methods**:
  - `mo43a()`
  - `mo44b()`
  - `mo45c()`

---

### YiPeerConnectionManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\manager\YiPeerConnectionManagerImpl$connect$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerConnectionManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 14
- **Fields**: 15
- **Source**: `yisdk\device\manager\YiPeerConnectionManagerImpl$connect$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `invoke()`
  - `IllegalStateException()`
  - `invoke()`
  - `invoke()`
  - `NoWhenBranchMatchedException()`
  - *(... and 4 more)*

---

### YiPeerConnectionManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<YiDeviceConnection, Continuation<`
- **Methods**: 4
- **Fields**: 4
- **Source**: `yisdk\device\manager\YiPeerConnectionManagerImpl$initializeConnectionLock$1$1$1.java`

**Key Methods**:
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`

---

### YiPeerConnectionManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function5<IYiCameraP2P, Boolean, Boolean, Boolean, Continuation<`
- **Methods**: 3
- **Fields**: 13
- **Source**: `yisdk\device\manager\YiPeerConnectionManagerImpl$monitorConnection$3.java`

**Key Methods**:
  - `method()`
  - `invoke()`
  - `invokeSuspend()`

---

### YiPeerConnectionManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function3<FlowCollector<`
- **Methods**: 16
- **Fields**: 31
- **Source**: `yisdk\device\manager\YiPeerConnectionManagerImpl$monitorConnection$4.java`

**Key Methods**:
  - `method()`
  - `C00221()`
  - `create()`
  - `C00221()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `method()`
  - `invoke()`
  - *(... and 6 more)*

---

### YiPeerConnectionManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<YiDeviceConnection, Continuation<`
- **Methods**: 5
- **Fields**: 2
- **Source**: `yisdk\device\manager\YiPeerConnectionManagerImpl$monitorConnection$5.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`

---

### YiPeerConnectionManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `yisdk\device\manager\YiPeerConnectionManagerImpl$removeCamera$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPeerConnectionManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<YiDeviceConnection, Continuation<`
- **Methods**: 7
- **Fields**: 10
- **Source**: `yisdk\device\manager\YiPeerConnectionManagerImpl$reportConnectionState$3.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPeerConnectionManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 5
- **Fields**: 6
- **Source**: `yisdk\device\manager\YiPeerConnectionManagerImpl$resetConnection$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`

---

### YiPeerConnectionManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<Long, Continuation<`
- **Methods**: 6
- **Fields**: 9
- **Source**: `yisdk\device\manager\YiPeerConnectionManagerImpl$startKeepAlive$2$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`

---

### YiPeerConnectionManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<FlowCollector<`
- **Methods**: 5
- **Fields**: 1
- **Source**: `yisdk\device\manager\YiPeerConnectionManagerImpl$startKeepAlive$2$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`

---

### YiPeerConnectionManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- **Package**: `com.savantsystems.yisdk.device.manager`
- **Extends**: `SuspendLambda`
- **Implements**: `Function3<FlowCollector<`
- **Methods**: 3
- **Fields**: 1
- **Source**: `yisdk\device\manager\YiPeerConnectionManagerImpl$startKeepAlive$2$3.java`

**Key Methods**:
  - `method()`
  - `invoke()`
  - `invokeSuspend()`

---

### CloudClipEventTypeToDetectionType [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.mappers.CloudClipEventTypeToDetectionType`
- **Package**: `com.savantsystems.yisdk.device.mappers`
- **Methods**: 1
- **Fields**: 23
- **Source**: `yisdk\device\mappers\CloudClipEventTypeToDetectionType.java`

**Key Methods**:
  - `CloudClipEventTypeToDetectionType()`

---

### YiAlertTimePeriodsMapper [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.mappers.YiAlertTimePeriodsMapper`
- **Package**: `com.savantsystems.yisdk.device.mappers`
- **Methods**: 4
- **Fields**: 3
- **Source**: `yisdk\device\mappers\YiAlertTimePeriodsMapper.java`

**Key Methods**:
  - `YiAlertTimePeriodsMapper()`
  - `m55a()`
  - `YIAlertTimePeriodsInfo()`
  - `invoke()`

---

### C0076a [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.service.C0076a`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Implements**: `FileFilter`
- **Methods**: 1
- **Fields**: 4
- **Source**: `yisdk\device\service\C0076a.java`

**Key Methods**:
  - `accept()`

---

### removed [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.service.removed`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Methods**: 44
- **Fields**: 45
- **Source**: `yisdk\device\service\PeerRequestType.java`

**Key Methods**:
  - `Enum()`
  - `Enum()`
  - `Enum()`
  - `Enum()`
  - `Enum()`
  - `Enum()`
  - `Enum()`
  - `Enum()`
  - `Enum()`
  - `Enum()`
  - *(... and 34 more)*

---

### YiAudioControllerImpl_Factory_Factory [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiAudioControllerImpl_Factory_Factory`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Implements**: `Factory<YiAudioControllerImpl.Factory>`
- **Methods**: 2
- **Fields**: 0
- **Source**: `yisdk\device\service\YiAudioControllerImpl_Factory_Factory.java`

**Key Methods**:
  - `YiAudioControllerImpl_Factory_Factory()`
  - `get()`

---

### YiCloudPlaybackControllerImpl_Factory_Factory [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiCloudPlaybackControllerImpl_Factory_Factory`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Implements**: `Factory<YiCloudPlaybackControllerImpl.Factory>`
- **Methods**: 1
- **Fields**: 1
- **Source**: `yisdk\device\service\YiCloudPlaybackControllerImpl_Factory_Factory.java`

**Key Methods**:
  - `get()`

---

### YiDeviceServiceImpl_Factory_Factory [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl_Factory_Factory`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Implements**: `Factory<YiDeviceServiceImpl.Factory>`
- **Methods**: 1
- **Fields**: 1
- **Source**: `yisdk\device\service\YiDeviceServiceImpl_Factory_Factory.java`

**Key Methods**:
  - `get()`

---

### YiNotificationServiceImpl_Factory_Factory [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiNotificationServiceImpl_Factory_Factory`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Implements**: `Factory<YiNotificationServiceImpl.Factory>`
- **Methods**: 1
- **Fields**: 1
- **Source**: `yisdk\device\service\YiNotificationServiceImpl_Factory_Factory.java`

**Key Methods**:
  - `get()`

---

### YiPeerServiceImplKt [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImplKt`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Methods**: 0
- **Fields**: 0
- **Source**: `yisdk\device\service\YiPeerServiceImplKt.java`

---

### YiPeerServiceImpl_Factory_Factory [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerServiceImpl_Factory_Factory`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Implements**: `Factory<YiPeerServiceImpl.Factory>`
- **Methods**: 1
- **Fields**: 1
- **Source**: `yisdk\device\service\YiPeerServiceImpl_Factory_Factory.java`

**Key Methods**:
  - `get()`

---

### YiPeerVideoControllerImpl_Factory_Factory [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl_Factory_Factory`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Implements**: `Factory<YiPeerVideoControllerImpl.Factory>`
- **Methods**: 2
- **Fields**: 0
- **Source**: `yisdk\device\service\YiPeerVideoControllerImpl_Factory_Factory.java`

**Key Methods**:
  - `YiPeerVideoControllerImpl_Factory_Factory()`
  - `get()`

---

### YiPreviewServiceImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Extends**: `Lambda`
- **Implements**: `Function1<YiDeviceState, YiDeviceState>`
- **Methods**: 1
- **Fields**: 1
- **Source**: `yisdk\device\service\YiPreviewServiceImpl$cleanUpPreview$2.java`

**Key Methods**:
  - `invoke()`

---

### YiPreviewServiceImpl_Factory_Factory [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl_Factory_Factory`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Implements**: `Factory<YiPreviewServiceImpl.Factory>`
- **Methods**: 1
- **Fields**: 1
- **Source**: `yisdk\device\service\YiPreviewServiceImpl_Factory_Factory.java`

**Key Methods**:
  - `get()`

---

### YiSdCardServiceImplKt [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiSdCardServiceImplKt`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Methods**: 0
- **Fields**: 5
- **Source**: `yisdk\device\service\YiSdCardServiceImplKt.java`

---

### YiSdCardServiceImpl_Factory_Factory [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl_Factory_Factory`
- **Package**: `com.savantsystems.yisdk.device.service`
- **Implements**: `Factory<YiSdCardServiceImpl.Factory>`
- **Methods**: 2
- **Fields**: 0
- **Source**: `yisdk\device\service\YiSdCardServiceImpl_Factory_Factory.java`

**Key Methods**:
  - `YiSdCardServiceImpl_Factory_Factory()`
  - `get()`

---

### CallbackExtensionsKt [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.extensions.CallbackExtensionsKt`
- **Package**: `com.savantsystems.yisdk.extensions`
- **Extends**: `ContinuationImpl`
- **Methods**: 1
- **Fields**: 3
- **Source**: `savantsystems\yisdk\extensions\CallbackExtensionsKt$awaitCompletion$1.java`

**Key Methods**:
  - `invokeSuspend()`

---

### CallbackExtensionsKt [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.extensions.CallbackExtensionsKt`
- **Package**: `com.savantsystems.yisdk.extensions`
- **Extends**: `T`
- **Methods**: 14
- **Fields**: 18
- **Source**: `savantsystems\yisdk\extensions\CallbackExtensionsKt.java`

**Key Methods**:
  - `m186a()`
  - `IllegalStateException()`
  - `ContinuationImpl()`
  - `m187b()`
  - `CancellableContinuationImpl()`
  - `onFail()`
  - `onSuccess()`
  - `m188c()`
  - `Err()`
  - `NoWhenBranchMatchedException()`
  - *(... and 4 more)*

---

### YiPushTokenReceiver [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.notifications.YiPushTokenReceiver`
- **Package**: `com.savantsystems.yisdk.notifications`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 3
- **Source**: `savantsystems\yisdk\notifications\YiPushTokenReceiver$onNewToken$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiSdkModule_ProvideYiActivationServiceFactory [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.p000di.YiSdkModule_ProvideYiActivationServiceFactory`
- **Package**: `com.savantsystems.yisdk.p000di`
- **Implements**: `Factory<YiActivationService>`
- **Methods**: 1
- **Fields**: 1
- **Source**: `savantsystems\yisdk\p000di\YiSdkModule_ProvideYiActivationServiceFactory.java`

**Key Methods**:
  - `get()`

---

### YiSdkModule_ProvideYiCameraListServiceFactory [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.p000di.YiSdkModule_ProvideYiCameraListServiceFactory`
- **Package**: `com.savantsystems.yisdk.p000di`
- **Implements**: `Factory<YiCameraListService>`
- **Methods**: 1
- **Fields**: 1
- **Source**: `savantsystems\yisdk\p000di\YiSdkModule_ProvideYiCameraListServiceFactory.java`

**Key Methods**:
  - `get()`

---

### YiSdkModule_ProvideYiCameraSettingsServiceFactory [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.p000di.YiSdkModule_ProvideYiCameraSettingsServiceFactory`
- **Package**: `com.savantsystems.yisdk.p000di`
- **Implements**: `Factory<YiCameraService>`
- **Methods**: 1
- **Fields**: 1
- **Source**: `savantsystems\yisdk\p000di\YiSdkModule_ProvideYiCameraSettingsServiceFactory.java`

**Key Methods**:
  - `get()`

---

### YiSdkModule_ProvideYiUserServiceFactory [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.p000di.YiSdkModule_ProvideYiUserServiceFactory`
- **Package**: `com.savantsystems.yisdk.p000di`
- **Implements**: `Factory<YiUserService>`
- **Methods**: 1
- **Fields**: 1
- **Source**: `savantsystems\yisdk\p000di\YiSdkModule_ProvideYiUserServiceFactory.java`

**Key Methods**:
  - `get()`

---

### YiPlaybackClip [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.playback.YiPlaybackClip`
- **Package**: `com.savantsystems.yisdk.playback`
- **Extends**: `ClipData>`
- **Methods**: 11
- **Fields**: 23
- **Source**: `savantsystems\yisdk\playback\YiPlaybackClip.java`

**Key Methods**:
  - `YiPlaybackClip()`
  - `m197a()`
  - `YiPlaybackClip()`
  - `m198b()`
  - `ArrayList()`
  - `m199c()`
  - `LinkedHashSet()`
  - `m200d()`
  - `equals()`
  - `hashCode()`
  - *(... and 1 more)*

---

### YiPlaybackManager [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.playback.YiPlaybackManager`
- **Package**: `com.savantsystems.yisdk.playback`
- **Extends**: `YiError>>`
- **Methods**: 6
- **Fields**: 0
- **Source**: `savantsystems\yisdk\playback\YiPlaybackManager.java`

**Key Methods**:
  - `mo201a()`
  - `mo202b()`
  - `mo203c()`
  - `mo204d()`
  - `mo205e()`
  - `mo206f()`

---

### YiPlaybackManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- **Package**: `com.savantsystems.yisdk.playback`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 6
- **Source**: `savantsystems\yisdk\playback\YiPlaybackManagerImpl$mute$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPlaybackManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- **Package**: `com.savantsystems.yisdk.playback`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 6
- **Source**: `savantsystems\yisdk\playback\YiPlaybackManagerImpl$pauseWithTimestamp$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPlaybackManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- **Package**: `com.savantsystems.yisdk.playback`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 7
- **Source**: `savantsystems\yisdk\playback\YiPlaybackManagerImpl$playClip$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPlaybackManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- **Package**: `com.savantsystems.yisdk.playback`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<YiPlaybackState, Continuation<`
- **Methods**: 7
- **Fields**: 10
- **Source**: `savantsystems\yisdk\playback\YiPlaybackManagerImpl$playClip$2$2$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`
  - `invoke()`
  - `IllegalStateException()`

---

### YiPlaybackManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- **Package**: `com.savantsystems.yisdk.playback`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 6
- **Source**: `savantsystems\yisdk\playback\YiPlaybackManagerImpl$resume$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPlaybackManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- **Package**: `com.savantsystems.yisdk.playback`
- **Extends**: `ContinuationImpl`
- **Methods**: 2
- **Fields**: 8
- **Source**: `savantsystems\yisdk\playback\YiPlaybackManagerImpl$startPlayback$1.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`

---

### YiPlaybackManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- **Package**: `com.savantsystems.yisdk.playback`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 5
- **Fields**: 1
- **Source**: `savantsystems\yisdk\playback\YiPlaybackManagerImpl$startPlayback$3.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`

---

### YiPlaybackManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- **Package**: `com.savantsystems.yisdk.playback`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 5
- **Fields**: 1
- **Source**: `savantsystems\yisdk\playback\YiPlaybackManagerImpl$startPlayback$4.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`

---

### YiPlaybackManagerImpl [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- **Package**: `com.savantsystems.yisdk.playback`
- **Extends**: `SuspendLambda`
- **Implements**: `Function1<Continuation<`
- **Methods**: 5
- **Fields**: 2
- **Source**: `savantsystems\yisdk\playback\YiPlaybackManagerImpl$stop$2.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invoke()`
  - `create()`
  - `invokeSuspend()`

---

### YiUserServiceImpl_Factory_Factory [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.user.YiUserServiceImpl_Factory_Factory`
- **Package**: `com.savantsystems.yisdk.user`
- **Implements**: `Factory<YiUserServiceImpl.Factory>`
- **Methods**: 2
- **Fields**: 0
- **Source**: `savantsystems\yisdk\user\YiUserServiceImpl_Factory_Factory.java`

**Key Methods**:
  - `YiUserServiceImpl_Factory_Factory()`
  - `get()`

---

### YiUserState [MEDIUM]


- **Full Name**: `com.savantsystems.yisdk.user.YiUserState`
- **Package**: `com.savantsystems.yisdk.user`
- **Methods**: 4
- **Fields**: 2
- **Source**: `savantsystems\yisdk\user\YiUserState.java`

**Key Methods**:
  - `YiUserState()`
  - `equals()`
  - `hashCode()`
  - `toString()`

---

### C0078R [MEDIUM]


- **Full Name**: `com.thing.smart.openssl.C0078R`
- **Package**: `com.thing.smart.openssl`
- **Methods**: 0
- **Fields**: 0
- **Source**: `thing\smart\openssl\C0078R.java`

---

### LICENSE [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.LICENSE`
- **Package**: `com.thingclips.bouncycastle`
- **Methods**: 2
- **Fields**: 1
- **Source**: `com\thingclips\bouncycastle\LICENSE.java`

**Key Methods**:
  - `files()`
  - `main()`

---

### ASN1ApplicationSpecificParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1ApplicationSpecificParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Encodable`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\asn1\ASN1ApplicationSpecificParser.java`

**Key Methods**:
  - `readObject()`

---

### ASN1BitString [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1BitString`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Primitive`
- **Implements**: `ASN1String`
- **Methods**: 32
- **Fields**: 43
- **Source**: `thingclips\bouncycastle\asn1\ASN1BitString.java`

**Key Methods**:
  - `ASN1BitString()`
  - `IllegalArgumentException()`
  - `fromInputStream()`
  - `IllegalArgumentException()`
  - `EOFException()`
  - `DLBitString()`
  - `DERBitString()`
  - `getBytes()`
  - `getPadBits()`
  - `asn1Equals()`
  - *(... and 22 more)*

---

### ASN1Encodable [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1Encodable`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\asn1\ASN1Encodable.java`

**Key Methods**:
  - `toASN1Primitive()`

---

### ASN1EncodableVector [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1EncodableVector`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Methods**: 15
- **Fields**: 23
- **Source**: `thingclips\bouncycastle\asn1\ASN1EncodableVector.java`

**Key Methods**:
  - `ASN1EncodableVector()`
  - `cloneElements()`
  - `reallocate()`
  - `add()`
  - `NullPointerException()`
  - `addAll()`
  - `NullPointerException()`
  - `NullPointerException()`
  - `copyElements()`
  - `get()`
  - *(... and 5 more)*

---

### ASN1Exception [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1Exception`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `IOException`
- **Methods**: 3
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\asn1\ASN1Exception.java`

**Key Methods**:
  - `ASN1Exception()`
  - `getCause()`
  - `ASN1Exception()`

---

### ASN1External [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1External`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Primitive`
- **Methods**: 27
- **Fields**: 25
- **Source**: `thingclips\bouncycastle\asn1\ASN1External.java`

**Key Methods**:
  - `ASN1External()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `getObjFromVector()`
  - `IllegalArgumentException()`
  - `setDataValueDescriptor()`
  - `setDirectReference()`
  - `setEncoding()`
  - `IllegalArgumentException()`
  - `setExternalContent()`
  - *(... and 17 more)*

---

### ASN1Object [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1Object`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Implements**: `ASN1Encodable, Encodable`
- **Methods**: 12
- **Fields**: 4
- **Source**: `thingclips\bouncycastle\asn1\ASN1Object.java`

**Key Methods**:
  - `hasEncodedTagValue()`
  - `encodeTo()`
  - `equals()`
  - `toASN1Primitive()`
  - `getEncoded()`
  - `ByteArrayOutputStream()`
  - `hashCode()`
  - `toASN1Primitive()`
  - `toASN1Primitive()`
  - `encodeTo()`
  - *(... and 2 more)*

---

### ASN1ObjectIdentifier [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1ObjectIdentifier`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Primitive`
- **Methods**: 44
- **Fields**: 52
- **Source**: `thingclips\bouncycastle\asn1\ASN1ObjectIdentifier.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `OidHandle()`
  - `equals()`
  - `hashCode()`
  - `ASN1ObjectIdentifier()`
  - `StringBuffer()`
  - `if()`
  - `doOutput()`
  - `OIDTokenizer()`
  - `BigInteger()`
  - *(... and 34 more)*

---

### ASN1OctetString [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1OctetString`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Primitive`
- **Implements**: `ASN1OctetStringParser`
- **Methods**: 26
- **Fields**: 8
- **Source**: `thingclips\bouncycastle\asn1\ASN1OctetString.java`

**Key Methods**:
  - `ASN1OctetString()`
  - `NullPointerException()`
  - `getInstance()`
  - `getInstance()`
  - `IllegalArgumentException()`
  - `BEROctetString()`
  - `BEROctetString()`
  - `IllegalArgumentException()`
  - `asn1Equals()`
  - `encode()`
  - *(... and 16 more)*

---

### ASN1OctetStringParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1OctetStringParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Encodable`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\asn1\ASN1OctetStringParser.java`

**Key Methods**:
  - `getOctetStream()`

---

### ASN1OutputStream [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1OutputStream`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Methods**: 34
- **Fields**: 5
- **Source**: `thingclips\bouncycastle\asn1\ASN1OutputStream.java`

**Key Methods**:
  - `ASN1OutputStream()`
  - `create()`
  - `ASN1OutputStream()`
  - `close()`
  - `flush()`
  - `flushInternal()`
  - `getDERSubStream()`
  - `DEROutputStream()`
  - `getDLSubStream()`
  - `DLOutputStream()`
  - *(... and 24 more)*

---

### ASN1ParsingException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1ParsingException`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `IllegalStateException`
- **Methods**: 3
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\asn1\ASN1ParsingException.java`

**Key Methods**:
  - `ASN1ParsingException()`
  - `getCause()`
  - `ASN1ParsingException()`

---

### ASN1Primitive [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1Primitive`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Object`
- **Methods**: 17
- **Fields**: 9
- **Source**: `thingclips\bouncycastle\asn1\ASN1Primitive.java`

**Key Methods**:
  - `fromByteArray()`
  - `ASN1InputStream()`
  - `IOException()`
  - `IOException()`
  - `asn1Equals()`
  - `encode()`
  - `encodeTo()`
  - `encodedLength()`
  - `equals()`
  - `hashCode()`
  - *(... and 7 more)*

---

### ASN1Private [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1Private`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Primitive`
- **Methods**: 21
- **Fields**: 19
- **Source**: `thingclips\bouncycastle\asn1\ASN1Private.java`

**Key Methods**:
  - `ASN1Private()`
  - `getInstance()`
  - `IllegalArgumentException()`
  - `getInstance()`
  - `IllegalArgumentException()`
  - `getLengthOfHeader()`
  - `IllegalStateException()`
  - `replaceTagNumber()`
  - `IOException()`
  - `asn1Equals()`
  - *(... and 11 more)*

---

### ASN1PrivateParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1PrivateParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Encodable`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\asn1\ASN1PrivateParser.java`

**Key Methods**:
  - `readObject()`

---

### ASN1Sequence [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1Sequence`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Primitive`
- **Implements**: `Iterable<ASN1Encodable>`
- **Methods**: 44
- **Fields**: 30
- **Source**: `thingclips\bouncycastle\asn1\ASN1Sequence.java`

**Key Methods**:
  - `ASN1Sequence()`
  - `getInstance()`
  - `getInstance()`
  - `getInstance()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `asn1Equals()`
  - `encode()`
  - `getObjectAt()`
  - `getObjects()`
  - *(... and 34 more)*

---

### ASN1SequenceParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1SequenceParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Encodable`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\asn1\ASN1SequenceParser.java`

**Key Methods**:
  - `readObject()`

---

### ASN1Set [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1Set`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Primitive`
- **Implements**: `Iterable<ASN1Encodable>`
- **Methods**: 50
- **Fields**: 58
- **Source**: `thingclips\bouncycastle\asn1\ASN1Set.java`

**Key Methods**:
  - `ASN1Set()`
  - `getDEREncoded()`
  - `IllegalArgumentException()`
  - `getInstance()`
  - `getInstance()`
  - `getInstance()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `lessThanOrEqual()`
  - `sort()`
  - *(... and 40 more)*

---

### ASN1SetParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1SetParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Encodable`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\asn1\ASN1SetParser.java`

**Key Methods**:
  - `readObject()`

---

### ASN1StreamParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1StreamParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Methods**: 46
- **Fields**: 16
- **Source**: `thingclips\bouncycastle\asn1\ASN1StreamParser.java`

**Key Methods**:
  - `ASN1StreamParser()`
  - `set00Check()`
  - `readImplicit()`
  - `readIndef()`
  - `IOException()`
  - `BEROctetStringParser()`
  - `DLSequenceParser()`
  - `DLSetParser()`
  - `DEROctetStringParser()`
  - `ASN1Exception()`
  - *(... and 36 more)*

---

### ASN1TaggedObject [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1TaggedObject`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Primitive`
- **Implements**: `ASN1TaggedObjectParser`
- **Methods**: 25
- **Fields**: 9
- **Source**: `thingclips\bouncycastle\asn1\ASN1TaggedObject.java`

**Key Methods**:
  - `ASN1TaggedObject()`
  - `NullPointerException()`
  - `getInstance()`
  - `getInstance()`
  - `IllegalArgumentException()`
  - `asn1Equals()`
  - `encode()`
  - `getLoadedObject()`
  - `toASN1Primitive()`
  - `getObject()`
  - *(... and 15 more)*

---

### ASN1TaggedObjectParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ASN1TaggedObjectParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Encodable`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\asn1\ASN1TaggedObjectParser.java`

**Key Methods**:
  - `getObjectParser()`
  - `getTagNo()`

---

### BERApplicationSpecific [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BERApplicationSpecific`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1ApplicationSpecific`
- **Methods**: 9
- **Fields**: 7
- **Source**: `thingclips\bouncycastle\asn1\BERApplicationSpecific.java`

**Key Methods**:
  - `BERApplicationSpecific()`
  - `getEncodedVector()`
  - `ByteArrayOutputStream()`
  - `ASN1ParsingException()`
  - `getEncoding()`
  - `encode()`
  - `BERApplicationSpecific()`
  - `BERApplicationSpecific()`
  - `BERApplicationSpecific()`

---

### BERApplicationSpecificParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BERApplicationSpecificParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Implements**: `ASN1ApplicationSpecificParser`
- **Methods**: 7
- **Fields**: 2
- **Source**: `thingclips\bouncycastle\asn1\BERApplicationSpecificParser.java`

**Key Methods**:
  - `BERApplicationSpecificParser()`
  - `getLoadedObject()`
  - `BERApplicationSpecific()`
  - `readObject()`
  - `toASN1Primitive()`
  - `getLoadedObject()`
  - `ASN1ParsingException()`

---

### BERConstructedOctetString [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BERConstructedOctetString`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `BEROctetString`
- **Methods**: 17
- **Fields**: 14
- **Source**: `thingclips\bouncycastle\asn1\BERConstructedOctetString.java`

**Key Methods**:
  - `BERConstructedOctetString()`
  - `fromSequence()`
  - `Vector()`
  - `BERConstructedOctetString()`
  - `generateOcts()`
  - `Vector()`
  - `toByteArray()`
  - `IllegalArgumentException()`
  - `toBytes()`
  - `ByteArrayOutputStream()`
  - *(... and 7 more)*

---

### BERFactory [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BERFactory`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Methods**: 6
- **Fields**: 2
- **Source**: `thingclips\bouncycastle\asn1\BERFactory.java`

**Key Methods**:
  - `BERSequence()`
  - `BERSet()`
  - `createSequence()`
  - `BERSequence()`
  - `createSet()`
  - `BERSet()`

---

### BERGenerator [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BERGenerator`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Generator`
- **Methods**: 7
- **Fields**: 5
- **Source**: `thingclips\bouncycastle\asn1\BERGenerator.java`

**Key Methods**:
  - `BERGenerator()`
  - `writeHdr()`
  - `getRawOutputStream()`
  - `writeBEREnd()`
  - `writeBERHeader()`
  - `if()`
  - `BERGenerator()`

---

### BEROctetString [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BEROctetString`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1OctetString`
- **Methods**: 23
- **Fields**: 19
- **Source**: `thingclips\bouncycastle\asn1\BEROctetString.java`

**Key Methods**:
  - `BEROctetString()`
  - `fromSequence()`
  - `BEROctetString()`
  - `toBytes()`
  - `ByteArrayOutputStream()`
  - `IllegalArgumentException()`
  - `encode()`
  - `encodedLength()`
  - `getObjects()`
  - `Enumeration()`
  - *(... and 13 more)*

---

### BEROctetStringGenerator [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BEROctetStringGenerator`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `BERGenerator`
- **Methods**: 11
- **Fields**: 10
- **Source**: `thingclips\bouncycastle\asn1\BEROctetStringGenerator.java`

**Key Methods**:
  - `BEROctetStringGenerator()`
  - `getOctetOutputStream()`
  - `getOctetOutputStream()`
  - `getOctetOutputStream()`
  - `BufferedBEROctetStream()`
  - `BEROctetStringGenerator()`
  - `BufferedBEROctetStream()`
  - `DEROutputStream()`
  - `close()`
  - `write()`
  - *(... and 1 more)*

---

### BEROctetStringParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BEROctetStringParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Implements**: `ASN1OctetStringParser`
- **Methods**: 8
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\asn1\BEROctetStringParser.java`

**Key Methods**:
  - `BEROctetStringParser()`
  - `getLoadedObject()`
  - `BEROctetString()`
  - `getOctetStream()`
  - `ConstructedOctetStream()`
  - `toASN1Primitive()`
  - `getLoadedObject()`
  - `ASN1ParsingException()`

---

### BERPrivateParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BERPrivateParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Implements**: `ASN1PrivateParser`
- **Methods**: 7
- **Fields**: 2
- **Source**: `thingclips\bouncycastle\asn1\BERPrivateParser.java`

**Key Methods**:
  - `BERPrivateParser()`
  - `getLoadedObject()`
  - `BERPrivate()`
  - `readObject()`
  - `toASN1Primitive()`
  - `getLoadedObject()`
  - `ASN1ParsingException()`

---

### BERSequence [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BERSequence`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Sequence`
- **Methods**: 6
- **Fields**: 3
- **Source**: `thingclips\bouncycastle\asn1\BERSequence.java`

**Key Methods**:
  - `BERSequence()`
  - `encode()`
  - `encodedLength()`
  - `BERSequence()`
  - `BERSequence()`
  - `BERSequence()`

---

### BERSequenceGenerator [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BERSequenceGenerator`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `BERGenerator`
- **Methods**: 4
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\asn1\BERSequenceGenerator.java`

**Key Methods**:
  - `BERSequenceGenerator()`
  - `addObject()`
  - `close()`
  - `BERSequenceGenerator()`

---

### BERSequenceParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BERSequenceParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Implements**: `ASN1SequenceParser`
- **Methods**: 7
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\asn1\BERSequenceParser.java`

**Key Methods**:
  - `BERSequenceParser()`
  - `getLoadedObject()`
  - `BERSequence()`
  - `readObject()`
  - `toASN1Primitive()`
  - `getLoadedObject()`
  - `IllegalStateException()`

---

### BERSet [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BERSet`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Set`
- **Methods**: 7
- **Fields**: 3
- **Source**: `thingclips\bouncycastle\asn1\BERSet.java`

**Key Methods**:
  - `BERSet()`
  - `encode()`
  - `encodedLength()`
  - `BERSet()`
  - `BERSet()`
  - `BERSet()`
  - `BERSet()`

---

### BERSetParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BERSetParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Implements**: `ASN1SetParser`
- **Methods**: 7
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\asn1\BERSetParser.java`

**Key Methods**:
  - `BERSetParser()`
  - `getLoadedObject()`
  - `BERSet()`
  - `readObject()`
  - `toASN1Primitive()`
  - `getLoadedObject()`
  - `ASN1ParsingException()`

---

### BERTaggedObjectParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BERTaggedObjectParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Implements**: `ASN1TaggedObjectParser`
- **Methods**: 9
- **Fields**: 3
- **Source**: `thingclips\bouncycastle\asn1\BERTaggedObjectParser.java`

**Key Methods**:
  - `BERTaggedObjectParser()`
  - `getLoadedObject()`
  - `getObjectParser()`
  - `IOException()`
  - `getTagNo()`
  - `isConstructed()`
  - `toASN1Primitive()`
  - `getLoadedObject()`
  - `ASN1ParsingException()`

---

### BERTags [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.BERTags`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Methods**: 0
- **Fields**: 29
- **Source**: `thingclips\bouncycastle\asn1\BERTags.java`

---

### ConstructedOctetStream [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.ConstructedOctetStream`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `InputStream`
- **Methods**: 5
- **Fields**: 15
- **Source**: `thingclips\bouncycastle\asn1\ConstructedOctetStream.java`

**Key Methods**:
  - `ConstructedOctetStream()`
  - `getNextParser()`
  - `IOException()`
  - `read()`
  - `read()`

---

### DateUtil [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DateUtil`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Methods**: 6
- **Fields**: 11
- **Source**: `thingclips\bouncycastle\asn1\DateUtil.java`

**Key Methods**:
  - `HashMap()`
  - `epochAdjust()`
  - `SimpleDateFormat()`
  - `Date()`
  - `forEN()`
  - `longValueOf()`

---

### DERApplicationSpecific [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DERApplicationSpecific`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1ApplicationSpecific`
- **Methods**: 10
- **Fields**: 7
- **Source**: `thingclips\bouncycastle\asn1\DERApplicationSpecific.java`

**Key Methods**:
  - `DERApplicationSpecific()`
  - `getEncodedVector()`
  - `ByteArrayOutputStream()`
  - `ASN1ParsingException()`
  - `getEncoding()`
  - `encode()`
  - `DERApplicationSpecific()`
  - `DERApplicationSpecific()`
  - `DERApplicationSpecific()`
  - `DERApplicationSpecific()`

---

### DERBitString [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DERBitString`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1BitString`
- **Methods**: 20
- **Fields**: 14
- **Source**: `thingclips\bouncycastle\asn1\DERBitString.java`

**Key Methods**:
  - `DERBitString()`
  - `fromOctetString()`
  - `IllegalArgumentException()`
  - `DERBitString()`
  - `getInstance()`
  - `DERBitString()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `encode()`
  - `encodedLength()`
  - *(... and 10 more)*

---

### DEREncodableVector [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DEREncodableVector`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1EncodableVector`
- **Methods**: 0
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\asn1\DEREncodableVector.java`

---

### DERExternal [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DERExternal`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1External`
- **Methods**: 9
- **Fields**: 6
- **Source**: `thingclips\bouncycastle\asn1\DERExternal.java`

**Key Methods**:
  - `DERExternal()`
  - `encode()`
  - `ByteArrayOutputStream()`
  - `encodedLength()`
  - `getEncoded()`
  - `toDERObject()`
  - `toDLObject()`
  - `DERExternal()`
  - `DERExternal()`

---

### DERExternalParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DERExternalParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Implements**: `ASN1Encodable, InMemoryRepresentable`
- **Methods**: 9
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\asn1\DERExternalParser.java`

**Key Methods**:
  - `DERExternalParser()`
  - `getLoadedObject()`
  - `DLExternal()`
  - `ASN1Exception()`
  - `readObject()`
  - `toASN1Primitive()`
  - `getLoadedObject()`
  - `ASN1ParsingException()`
  - `ASN1ParsingException()`

---

### DERFactory [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DERFactory`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Methods**: 6
- **Fields**: 2
- **Source**: `thingclips\bouncycastle\asn1\DERFactory.java`

**Key Methods**:
  - `DERSequence()`
  - `DERSet()`
  - `createSequence()`
  - `DERSequence()`
  - `createSet()`
  - `DERSet()`

---

### DERGenerator [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DERGenerator`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Generator`
- **Methods**: 6
- **Fields**: 9
- **Source**: `thingclips\bouncycastle\asn1\DERGenerator.java`

**Key Methods**:
  - `DERGenerator()`
  - `writeLength()`
  - `writeDEREncoded()`
  - `DERGenerator()`
  - `writeDEREncoded()`
  - `ByteArrayOutputStream()`

---

### DEROctetString [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DEROctetString`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1OctetString`
- **Methods**: 8
- **Fields**: 3
- **Source**: `thingclips\bouncycastle\asn1\DEROctetString.java`

**Key Methods**:
  - `DEROctetString()`
  - `encode()`
  - `encodedLength()`
  - `isConstructed()`
  - `toDERObject()`
  - `toDLObject()`
  - `DEROctetString()`
  - `encode()`

---

### DEROctetStringParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DEROctetStringParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Implements**: `ASN1OctetStringParser`
- **Methods**: 7
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\asn1\DEROctetStringParser.java`

**Key Methods**:
  - `DEROctetStringParser()`
  - `getLoadedObject()`
  - `DEROctetString()`
  - `getOctetStream()`
  - `toASN1Primitive()`
  - `getLoadedObject()`
  - `ASN1ParsingException()`

---

### DERPrintableString [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DERPrintableString`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Primitive`
- **Implements**: `ASN1String`
- **Methods**: 20
- **Fields**: 8
- **Source**: `thingclips\bouncycastle\asn1\DERPrintableString.java`

**Key Methods**:
  - `DERPrintableString()`
  - `getInstance()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `isPrintableString()`
  - `asn1Equals()`
  - `encode()`
  - `encodedLength()`
  - `getOctets()`
  - `getString()`
  - *(... and 10 more)*

---

### DERSequence [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DERSequence`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Sequence`
- **Methods**: 11
- **Fields**: 14
- **Source**: `thingclips\bouncycastle\asn1\DERSequence.java`

**Key Methods**:
  - `DERSequence()`
  - `convert()`
  - `getBodyLength()`
  - `encode()`
  - `encodedLength()`
  - `toDERObject()`
  - `toDLObject()`
  - `DERSequence()`
  - `DERSequence()`
  - `DERSequence()`
  - *(... and 1 more)*

---

### DERSequenceGenerator [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DERSequenceGenerator`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `DERGenerator`
- **Methods**: 7
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\asn1\DERSequenceGenerator.java`

**Key Methods**:
  - `DERSequenceGenerator()`
  - `ByteArrayOutputStream()`
  - `addObject()`
  - `close()`
  - `getRawOutputStream()`
  - `DERSequenceGenerator()`
  - `ByteArrayOutputStream()`

---

### DERSequenceParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DERSequenceParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Implements**: `ASN1SequenceParser`
- **Methods**: 7
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\asn1\DERSequenceParser.java`

**Key Methods**:
  - `DERSequenceParser()`
  - `getLoadedObject()`
  - `DERSequence()`
  - `readObject()`
  - `toASN1Primitive()`
  - `getLoadedObject()`
  - `IllegalStateException()`

---

### DERSet [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DERSet`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Set`
- **Methods**: 13
- **Fields**: 14
- **Source**: `thingclips\bouncycastle\asn1\DERSet.java`

**Key Methods**:
  - `DERSet()`
  - `checkSorted()`
  - `IllegalStateException()`
  - `convert()`
  - `getBodyLength()`
  - `encode()`
  - `encodedLength()`
  - `toDERObject()`
  - `toDLObject()`
  - `DERSet()`
  - *(... and 3 more)*

---

### DERUniversalString [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DERUniversalString`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Primitive`
- **Implements**: `ASN1String`
- **Methods**: 18
- **Fields**: 8
- **Source**: `thingclips\bouncycastle\asn1\DERUniversalString.java`

**Key Methods**:
  - `DERUniversalString()`
  - `getInstance()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `asn1Equals()`
  - `encode()`
  - `encodedLength()`
  - `getOctets()`
  - `getString()`
  - `StringBuffer()`
  - *(... and 8 more)*

---

### DERVisibleString [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DERVisibleString`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Primitive`
- **Implements**: `ASN1String`
- **Methods**: 17
- **Fields**: 4
- **Source**: `thingclips\bouncycastle\asn1\DERVisibleString.java`

**Key Methods**:
  - `DERVisibleString()`
  - `getInstance()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `asn1Equals()`
  - `encode()`
  - `encodedLength()`
  - `getOctets()`
  - `getString()`
  - `hashCode()`
  - *(... and 7 more)*

---

### DLApplicationSpecific [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DLApplicationSpecific`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1ApplicationSpecific`
- **Methods**: 10
- **Fields**: 7
- **Source**: `thingclips\bouncycastle\asn1\DLApplicationSpecific.java`

**Key Methods**:
  - `DLApplicationSpecific()`
  - `getEncodedVector()`
  - `ByteArrayOutputStream()`
  - `ASN1ParsingException()`
  - `getEncoding()`
  - `encode()`
  - `DLApplicationSpecific()`
  - `DLApplicationSpecific()`
  - `DLApplicationSpecific()`
  - `DLApplicationSpecific()`

---

### DLBitString [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DLBitString`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1BitString`
- **Methods**: 18
- **Fields**: 6
- **Source**: `thingclips\bouncycastle\asn1\DLBitString.java`

**Key Methods**:
  - `DLBitString()`
  - `fromOctetString()`
  - `IllegalArgumentException()`
  - `DLBitString()`
  - `getInstance()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `encode()`
  - `encodedLength()`
  - `isConstructed()`
  - *(... and 8 more)*

---

### DLExternal [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DLExternal`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1External`
- **Methods**: 8
- **Fields**: 5
- **Source**: `thingclips\bouncycastle\asn1\DLExternal.java`

**Key Methods**:
  - `DLExternal()`
  - `encode()`
  - `ByteArrayOutputStream()`
  - `encodedLength()`
  - `getEncoded()`
  - `toDLObject()`
  - `DLExternal()`
  - `DLExternal()`

---

### DLFactory [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DLFactory`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Methods**: 6
- **Fields**: 2
- **Source**: `thingclips\bouncycastle\asn1\DLFactory.java`

**Key Methods**:
  - `DLSequence()`
  - `DLSet()`
  - `createSequence()`
  - `DLSequence()`
  - `createSet()`
  - `DLSet()`

---

### DLSequence [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DLSequence`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Sequence`
- **Methods**: 9
- **Fields**: 13
- **Source**: `thingclips\bouncycastle\asn1\DLSequence.java`

**Key Methods**:
  - `DLSequence()`
  - `getBodyLength()`
  - `encode()`
  - `encodedLength()`
  - `toDLObject()`
  - `DLSequence()`
  - `DLSequence()`
  - `DLSequence()`
  - `DLSequence()`

---

### DLSequenceParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DLSequenceParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Implements**: `ASN1SequenceParser`
- **Methods**: 7
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\asn1\DLSequenceParser.java`

**Key Methods**:
  - `DLSequenceParser()`
  - `getLoadedObject()`
  - `DLSequence()`
  - `readObject()`
  - `toASN1Primitive()`
  - `getLoadedObject()`
  - `IllegalStateException()`

---

### DLSet [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DLSet`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Set`
- **Methods**: 9
- **Fields**: 13
- **Source**: `thingclips\bouncycastle\asn1\DLSet.java`

**Key Methods**:
  - `DLSet()`
  - `getBodyLength()`
  - `encode()`
  - `encodedLength()`
  - `toDLObject()`
  - `DLSet()`
  - `DLSet()`
  - `DLSet()`
  - `DLSet()`

---

### DLSetParser [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.DLSetParser`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Implements**: `ASN1SetParser`
- **Methods**: 7
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\asn1\DLSetParser.java`

**Key Methods**:
  - `DLSetParser()`
  - `getLoadedObject()`
  - `DLSet()`
  - `readObject()`
  - `toASN1Primitive()`
  - `getLoadedObject()`
  - `ASN1ParsingException()`

---

### InMemoryRepresentable [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.InMemoryRepresentable`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\asn1\InMemoryRepresentable.java`

**Key Methods**:
  - `getLoadedObject()`

---

### LazyEncodedSequence [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.LazyEncodedSequence`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Extends**: `ASN1Sequence`
- **Methods**: 16
- **Fields**: 7
- **Source**: `thingclips\bouncycastle\asn1\LazyEncodedSequence.java`

**Key Methods**:
  - `LazyEncodedSequence()`
  - `force()`
  - `ASN1EncodableVector()`
  - `LazyConstructionEnumeration()`
  - `encode()`
  - `encodedLength()`
  - `getObjectAt()`
  - `getObjects()`
  - `LazyConstructionEnumeration()`
  - `hashCode()`
  - *(... and 6 more)*

---

### StreamUtil [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.StreamUtil`
- **Package**: `com.thingclips.bouncycastle.asn1`
- **Methods**: 3
- **Fields**: 11
- **Source**: `thingclips\bouncycastle\asn1\StreamUtil.java`

**Key Methods**:
  - `calculateBodyLength()`
  - `calculateTagLength()`
  - `findLimit()`

---

### ANSSINamedCurves [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.anssi.ANSSINamedCurves`
- **Package**: `com.thingclips.bouncycastle.asn1.anssi`
- **Methods**: 18
- **Fields**: 17
- **Source**: `bouncycastle\asn1\anssi\ANSSINamedCurves.java`

**Key Methods**:
  - `X9ECParametersHolder()`
  - `createParameters()`
  - `X9ECParameters()`
  - `Hashtable()`
  - `Hashtable()`
  - `Hashtable()`
  - `configureBasepoint()`
  - `X9ECPoint()`
  - `configureCurve()`
  - `defineCurve()`
  - *(... and 8 more)*

---

### GCMParameters [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.cms.GCMParameters`
- **Package**: `com.thingclips.bouncycastle.asn1.cms`
- **Extends**: `ASN1Object`
- **Methods**: 9
- **Fields**: 5
- **Source**: `bouncycastle\asn1\cms\GCMParameters.java`

**Key Methods**:
  - `GCMParameters()`
  - `getInstance()`
  - `GCMParameters()`
  - `getIcvLen()`
  - `getNonce()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - `DERSequence()`
  - `GCMParameters()`

---

### GOST3410PublicKeyAlgParameters [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters`
- **Package**: `com.thingclips.bouncycastle.asn1.cryptopro`
- **Extends**: `ASN1Object`
- **Methods**: 13
- **Fields**: 6
- **Source**: `bouncycastle\asn1\cryptopro\GOST3410PublicKeyAlgParameters.java`

**Key Methods**:
  - `GOST3410PublicKeyAlgParameters()`
  - `getInstance()`
  - `getInstance()`
  - `getDigestParamSet()`
  - `getEncryptionParamSet()`
  - `getPublicKeyParamSet()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - `DERSequence()`
  - `getInstance()`
  - *(... and 3 more)*

---

### EdECObjectIdentifiers [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.edec.EdECObjectIdentifiers`
- **Package**: `com.thingclips.bouncycastle.asn1.edec`
- **Methods**: 1
- **Fields**: 6
- **Source**: `bouncycastle\asn1\edec\EdECObjectIdentifiers.java`

**Key Methods**:
  - `ASN1ObjectIdentifier()`

---

### ISOIECObjectIdentifiers [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.iso.ISOIECObjectIdentifiers`
- **Package**: `com.thingclips.bouncycastle.asn1.iso`
- **Methods**: 2
- **Fields**: 11
- **Source**: `bouncycastle\asn1\iso\ISOIECObjectIdentifiers.java`

**Key Methods**:
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`

---

### NISTNamedCurves [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.nist.NISTNamedCurves`
- **Package**: `com.thingclips.bouncycastle.asn1.nist`
- **Methods**: 9
- **Fields**: 4
- **Source**: `bouncycastle\asn1\nist\NISTNamedCurves.java`

**Key Methods**:
  - `Hashtable()`
  - `Hashtable()`
  - `defineCurve()`
  - `getByName()`
  - `getByOID()`
  - `getByOID()`
  - `getName()`
  - `getNames()`
  - `getOID()`

---

### NISTObjectIdentifiers [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.nist.NISTObjectIdentifiers`
- **Package**: `com.thingclips.bouncycastle.asn1.nist`
- **Methods**: 1
- **Fields**: 67
- **Source**: `bouncycastle\asn1\nist\NISTObjectIdentifiers.java`

**Key Methods**:
  - `ASN1ObjectIdentifier()`

---

### ElGamalParameter [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.oiw.ElGamalParameter`
- **Package**: `com.thingclips.bouncycastle.asn1.oiw`
- **Extends**: `ASN1Object`
- **Methods**: 11
- **Fields**: 5
- **Source**: `bouncycastle\asn1\oiw\ElGamalParameter.java`

**Key Methods**:
  - `ElGamalParameter()`
  - `ASN1Integer()`
  - `ASN1Integer()`
  - `getInstance()`
  - `ElGamalParameter()`
  - `getG()`
  - `getP()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - `DERSequence()`
  - *(... and 1 more)*

---

### ECNamedCurveTable [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.p002x9.ECNamedCurveTable`
- **Package**: `com.thingclips.bouncycastle.asn1.p002x9`
- **Methods**: 7
- **Fields**: 9
- **Source**: `bouncycastle\asn1\p002x9\ECNamedCurveTable.java`

**Key Methods**:
  - `addEnumeration()`
  - `getByName()`
  - `getByOID()`
  - `getName()`
  - `getNames()`
  - `Vector()`
  - `getOID()`

---

### X962Parameters [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.p002x9.X962Parameters`
- **Package**: `com.thingclips.bouncycastle.asn1.p002x9`
- **Extends**: `ASN1Object`
- **Implements**: `ASN1Choice`
- **Methods**: 15
- **Fields**: 3
- **Source**: `bouncycastle\asn1\p002x9\X962Parameters.java`

**Key Methods**:
  - `X962Parameters()`
  - `getInstance()`
  - `X962Parameters()`
  - `X962Parameters()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `getParameters()`
  - `isImplicitlyCA()`
  - `isNamedCurve()`
  - `toASN1Primitive()`
  - *(... and 5 more)*

---

### X9ECParametersHolder [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.p002x9.X9ECParametersHolder`
- **Package**: `com.thingclips.bouncycastle.asn1.p002x9`
- **Methods**: 2
- **Fields**: 2
- **Source**: `bouncycastle\asn1\p002x9\X9ECParametersHolder.java`

**Key Methods**:
  - `createParameters()`
  - `getParameters()`

---

### X9ECPoint [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.p002x9.X9ECPoint`
- **Package**: `com.thingclips.bouncycastle.asn1.p002x9`
- **Extends**: `ASN1Object`
- **Methods**: 9
- **Fields**: 8
- **Source**: `bouncycastle\asn1\p002x9\X9ECPoint.java`

**Key Methods**:
  - `X9ECPoint()`
  - `DEROctetString()`
  - `getPoint()`
  - `getPointEncoding()`
  - `isPointCompressed()`
  - `toASN1Primitive()`
  - `X9ECPoint()`
  - `DEROctetString()`
  - `X9ECPoint()`

---

### X9FieldElement [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.p002x9.X9FieldElement`
- **Package**: `com.thingclips.bouncycastle.asn1.p002x9`
- **Extends**: `ASN1Object`
- **Methods**: 9
- **Fields**: 2
- **Source**: `bouncycastle\asn1\p002x9\X9FieldElement.java`

**Key Methods**:
  - `X9IntegerConverter()`
  - `X9FieldElement()`
  - `getValue()`
  - `toASN1Primitive()`
  - `DEROctetString()`
  - `X9FieldElement()`
  - `BigInteger()`
  - `X9FieldElement()`
  - `BigInteger()`

---

### X9ObjectIdentifiers [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.p002x9.X9ObjectIdentifiers`
- **Package**: `com.thingclips.bouncycastle.asn1.p002x9`
- **Methods**: 6
- **Fields**: 81
- **Source**: `bouncycastle\asn1\p002x9\X9ObjectIdentifiers.java`

**Key Methods**:
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`

---

### Attribute [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.pkcs.Attribute`
- **Package**: `com.thingclips.bouncycastle.asn1.pkcs`
- **Extends**: `ASN1Object`
- **Methods**: 11
- **Fields**: 3
- **Source**: `bouncycastle\asn1\pkcs\Attribute.java`

**Key Methods**:
  - `Attribute()`
  - `getInstance()`
  - `Attribute()`
  - `IllegalArgumentException()`
  - `getAttrType()`
  - `getAttrValues()`
  - `getAttributeValues()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - `DERSequence()`
  - *(... and 1 more)*

---

### CertificationRequest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.pkcs.CertificationRequest`
- **Package**: `com.thingclips.bouncycastle.asn1.pkcs`
- **Extends**: `ASN1Object`
- **Methods**: 11
- **Fields**: 5
- **Source**: `bouncycastle\asn1\pkcs\CertificationRequest.java`

**Key Methods**:
  - `CertificationRequest()`
  - `getInstance()`
  - `CertificationRequest()`
  - `getCertificationRequestInfo()`
  - `getSignature()`
  - `getSignatureAlgorithm()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - `DERSequence()`
  - `CertificationRequest()`
  - *(... and 1 more)*

---

### CertificationRequestInfo [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.pkcs.CertificationRequestInfo`
- **Package**: `com.thingclips.bouncycastle.asn1.pkcs`
- **Extends**: `ASN1Object`
- **Methods**: 18
- **Fields**: 9
- **Source**: `bouncycastle\asn1\pkcs\CertificationRequestInfo.java`

**Key Methods**:
  - `CertificationRequestInfo()`
  - `ASN1Integer()`
  - `IllegalArgumentException()`
  - `getInstance()`
  - `CertificationRequestInfo()`
  - `validateAttributes()`
  - `IllegalArgumentException()`
  - `getAttributes()`
  - `getSubject()`
  - `getSubjectPublicKeyInfo()`
  - *(... and 8 more)*

---

### ContentInfo [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.pkcs.ContentInfo`
- **Package**: `com.thingclips.bouncycastle.asn1.pkcs`
- **Extends**: `ASN1Object`
- **Implements**: `PKCSObjectIdentifiers`
- **Methods**: 10
- **Fields**: 8
- **Source**: `bouncycastle\asn1\pkcs\ContentInfo.java`

**Key Methods**:
  - `ContentInfo()`
  - `getInstance()`
  - `ContentInfo()`
  - `getContent()`
  - `getContentType()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - `BERSequence()`
  - `DLSequence()`
  - `ContentInfo()`

---

### PKCSObjectIdentifiers [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers`
- **Package**: `com.thingclips.bouncycastle.asn1.pkcs`
- **Methods**: 16
- **Fields**: 166
- **Source**: `bouncycastle\asn1\pkcs\PKCSObjectIdentifiers.java`

**Key Methods**:
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - *(... and 6 more)*

---

### PrivateKeyInfo [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.pkcs.PrivateKeyInfo`
- **Package**: `com.thingclips.bouncycastle.asn1.pkcs`
- **Extends**: `ASN1Object`
- **Methods**: 28
- **Fields**: 19
- **Source**: `bouncycastle\asn1\pkcs\PrivateKeyInfo.java`

**Key Methods**:
  - `PrivateKeyInfo()`
  - `getInstance()`
  - `getInstance()`
  - `getVersionValue()`
  - `IllegalArgumentException()`
  - `getAttributes()`
  - `getPrivateKey()`
  - `DEROctetString()`
  - `getPrivateKeyAlgorithm()`
  - `getPublicKeyData()`
  - *(... and 18 more)*

---

### RSAESOAEPparams [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.pkcs.RSAESOAEPparams`
- **Package**: `com.thingclips.bouncycastle.asn1.pkcs`
- **Extends**: `ASN1Object`
- **Methods**: 17
- **Fields**: 11
- **Source**: `bouncycastle\asn1\pkcs\RSAESOAEPparams.java`

**Key Methods**:
  - `AlgorithmIdentifier()`
  - `AlgorithmIdentifier()`
  - `AlgorithmIdentifier()`
  - `RSAESOAEPparams()`
  - `getInstance()`
  - `RSAESOAEPparams()`
  - `getHashAlgorithm()`
  - `getMaskGenAlgorithm()`
  - `getPSourceAlgorithm()`
  - `toASN1Primitive()`
  - *(... and 7 more)*

---

### RSAPrivateKey [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.pkcs.RSAPrivateKey`
- **Package**: `com.thingclips.bouncycastle.asn1.pkcs`
- **Extends**: `ASN1Object`
- **Methods**: 19
- **Fields**: 16
- **Source**: `bouncycastle\asn1\pkcs\RSAPrivateKey.java`

**Key Methods**:
  - `RSAPrivateKey()`
  - `getInstance()`
  - `getInstance()`
  - `getCoefficient()`
  - `getExponent1()`
  - `getExponent2()`
  - `getModulus()`
  - `getPrime1()`
  - `getPrime2()`
  - `getPrivateExponent()`
  - *(... and 9 more)*

---

### RSAPublicKey [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.pkcs.RSAPublicKey`
- **Package**: `com.thingclips.bouncycastle.asn1.pkcs`
- **Extends**: `ASN1Object`
- **Methods**: 12
- **Fields**: 5
- **Source**: `bouncycastle\asn1\pkcs\RSAPublicKey.java`

**Key Methods**:
  - `RSAPublicKey()`
  - `getInstance()`
  - `getInstance()`
  - `getModulus()`
  - `getPublicExponent()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - `DERSequence()`
  - `getInstance()`
  - `RSAPublicKey()`
  - *(... and 2 more)*

---

### RSASSAPSSparams [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.pkcs.RSASSAPSSparams`
- **Package**: `com.thingclips.bouncycastle.asn1.pkcs`
- **Extends**: `ASN1Object`
- **Methods**: 20
- **Fields**: 13
- **Source**: `bouncycastle\asn1\pkcs\RSASSAPSSparams.java`

**Key Methods**:
  - `AlgorithmIdentifier()`
  - `AlgorithmIdentifier()`
  - `ASN1Integer()`
  - `ASN1Integer()`
  - `RSASSAPSSparams()`
  - `getInstance()`
  - `RSASSAPSSparams()`
  - `getHashAlgorithm()`
  - `getMaskGenAlgorithm()`
  - `getSaltLength()`
  - *(... and 10 more)*

---

### SignedData [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.pkcs.SignedData`
- **Package**: `com.thingclips.bouncycastle.asn1.pkcs`
- **Extends**: `ASN1Object`
- **Implements**: `PKCSObjectIdentifiers`
- **Methods**: 15
- **Fields**: 14
- **Source**: `bouncycastle\asn1\pkcs\SignedData.java`

**Key Methods**:
  - `SignedData()`
  - `getInstance()`
  - `SignedData()`
  - `getCRLs()`
  - `getCertificates()`
  - `getContentInfo()`
  - `getDigestAlgorithms()`
  - `getSignerInfos()`
  - `getVersion()`
  - `toASN1Primitive()`
  - *(... and 5 more)*

---

### ECPrivateKey [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.sec.ECPrivateKey`
- **Package**: `com.thingclips.bouncycastle.asn1.sec`
- **Extends**: `ASN1Object`
- **Methods**: 20
- **Fields**: 10
- **Source**: `bouncycastle\asn1\sec\ECPrivateKey.java`

**Key Methods**:
  - `ECPrivateKey()`
  - `getInstance()`
  - `ECPrivateKey()`
  - `getObjectInTag()`
  - `getKey()`
  - `BigInteger()`
  - `getParameters()`
  - `getObjectInTag()`
  - `getPublicKey()`
  - `toASN1Primitive()`
  - *(... and 10 more)*

---

### SECNamedCurves [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.sec.SECNamedCurves`
- **Package**: `com.thingclips.bouncycastle.asn1.sec`
- **Methods**: 16
- **Fields**: 16
- **Source**: `bouncycastle\asn1\sec\SECNamedCurves.java`

**Key Methods**:
  - `X9ECParametersHolder()`
  - `createParameters()`
  - `X9ECParameters()`
  - `Hashtable()`
  - `Hashtable()`
  - `Hashtable()`
  - `configureCurve()`
  - `defineCurve()`
  - `fromHex()`
  - `BigInteger()`
  - *(... and 6 more)*

---

### TeleTrusTNamedCurves [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves`
- **Package**: `com.thingclips.bouncycastle.asn1.teletrust`
- **Methods**: 60
- **Fields**: 67
- **Source**: `bouncycastle\asn1\teletrust\TeleTrusTNamedCurves.java`

**Key Methods**:
  - `X9ECParametersHolder()`
  - `createParameters()`
  - `X9ECParameters()`
  - `X9ECParametersHolder()`
  - `createParameters()`
  - `X9ECParameters()`
  - `X9ECParametersHolder()`
  - `createParameters()`
  - `X9ECParameters()`
  - `X9ECParametersHolder()`
  - *(... and 50 more)*

---

### ASN1Dump [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.util.ASN1Dump`
- **Package**: `com.thingclips.bouncycastle.asn1.util`
- **Methods**: 17
- **Fields**: 47
- **Source**: `bouncycastle\asn1\util\ASN1Dump.java`

**Key Methods**:
  - `_dumpAsString()`
  - `if()`
  - `if()`
  - `if()`
  - `if()`
  - `StringBuilder()`
  - `calculateAscString()`
  - `StringBuffer()`
  - `dumpAsString()`
  - `dumpAsString()`
  - *(... and 7 more)*

---

### AttributeTypeAndValue [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x500.AttributeTypeAndValue`
- **Package**: `com.thingclips.bouncycastle.asn1.x500`
- **Extends**: `ASN1Object`
- **Methods**: 10
- **Fields**: 3
- **Source**: `bouncycastle\asn1\x500\AttributeTypeAndValue.java`

**Key Methods**:
  - `AttributeTypeAndValue()`
  - `getInstance()`
  - `AttributeTypeAndValue()`
  - `IllegalArgumentException()`
  - `getType()`
  - `getValue()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - `DERSequence()`
  - `AttributeTypeAndValue()`

---

### RDN [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x500.RDN`
- **Package**: `com.thingclips.bouncycastle.asn1.x500`
- **Extends**: `ASN1Object`
- **Methods**: 17
- **Fields**: 15
- **Source**: `bouncycastle\asn1\x500\RDN.java`

**Key Methods**:
  - `RDN()`
  - `getInstance()`
  - `RDN()`
  - `collectAttributeTypes()`
  - `containsAttributeType()`
  - `getFirst()`
  - `getTypesAndValues()`
  - `isMultiValued()`
  - `size()`
  - `toASN1Primitive()`
  - *(... and 7 more)*

---

### X500Name [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x500.X500Name`
- **Package**: `com.thingclips.bouncycastle.asn1.x500`
- **Extends**: `ASN1Object`
- **Implements**: `ASN1Choice`
- **Methods**: 27
- **Fields**: 37
- **Source**: `bouncycastle\asn1\x500\X500Name.java`

**Key Methods**:
  - `X500Name()`
  - `getDefaultStyle()`
  - `getInstance()`
  - `getInstance()`
  - `setDefaultStyle()`
  - `NullPointerException()`
  - `equals()`
  - `X500Name()`
  - `getAttributeTypes()`
  - `getRDNs()`
  - *(... and 17 more)*

---

### X500NameBuilder [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x500.X500NameBuilder`
- **Package**: `com.thingclips.bouncycastle.asn1.x500`
- **Methods**: 14
- **Fields**: 11
- **Source**: `bouncycastle\asn1\x500\X500NameBuilder.java`

**Key Methods**:
  - `X500NameBuilder()`
  - `addMultiValuedRDN()`
  - `addMultiValuedRDN()`
  - `addRDN()`
  - `build()`
  - `X500Name()`
  - `X500NameBuilder()`
  - `Vector()`
  - `addRDN()`
  - `addRDN()`
  - *(... and 4 more)*

---

### X500NameStyle [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x500.X500NameStyle`
- **Package**: `com.thingclips.bouncycastle.asn1.x500`
- **Methods**: 8
- **Fields**: 0
- **Source**: `bouncycastle\asn1\x500\X500NameStyle.java`

**Key Methods**:
  - `areEqual()`
  - `attrNameToOID()`
  - `calculateHashCode()`
  - `fromString()`
  - `oidToAttrNames()`
  - `oidToDisplayName()`
  - `stringToValue()`
  - `toString()`

---

### AbstractX500NameStyle [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x500.style.AbstractX500NameStyle`
- **Package**: `com.thingclips.bouncycastle.asn1.x500.style`
- **Implements**: `X500NameStyle`
- **Methods**: 12
- **Fields**: 19
- **Source**: `asn1\x500\style\AbstractX500NameStyle.java`

**Key Methods**:
  - `calcHashCode()`
  - `copyHashTable()`
  - `Hashtable()`
  - `foundMatch()`
  - `areEqual()`
  - `calculateHashCode()`
  - `encodeStringValue()`
  - `DERUTF8String()`
  - `rdnAreEqual()`
  - `stringToValue()`
  - *(... and 2 more)*

---

### BCStyle [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x500.style.BCStyle`
- **Package**: `com.thingclips.bouncycastle.asn1.x500.style`
- **Extends**: `AbstractX500NameStyle`
- **Methods**: 15
- **Fields**: 82
- **Source**: `asn1\x500\style\BCStyle.java`

**Key Methods**:
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `Hashtable()`
  - `Hashtable()`
  - `BCStyle()`
  - `attrNameToOID()`
  - `encodeStringValue()`
  - `DERIA5String()`
  - `ASN1GeneralizedTime()`
  - `DERPrintableString()`
  - *(... and 5 more)*

---

### IETFUtils [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x500.style.IETFUtils`
- **Package**: `com.thingclips.bouncycastle.asn1.x500.style`
- **Methods**: 42
- **Fields**: 72
- **Source**: `asn1\x500\style\IETFUtils.java`

**Key Methods**:
  - `appendRDN()`
  - `appendTypeAndValue()`
  - `atvAreEqual()`
  - `canonicalString()`
  - `canonicalize()`
  - `canonicalize()`
  - `stripInternalSpaces()`
  - `convertHex()`
  - `decodeAttrName()`
  - `ASN1ObjectIdentifier()`
  - *(... and 32 more)*

---

### RFC4519Style [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x500.style.RFC4519Style`
- **Package**: `com.thingclips.bouncycastle.asn1.x500.style`
- **Extends**: `AbstractX500NameStyle`
- **Methods**: 12
- **Fields**: 99
- **Source**: `asn1\x500\style\RFC4519Style.java`

**Key Methods**:
  - `Hashtable()`
  - `Hashtable()`
  - `RFC4519Style()`
  - `attrNameToOID()`
  - `encodeStringValue()`
  - `DERIA5String()`
  - `DERPrintableString()`
  - `fromString()`
  - `oidToAttrNames()`
  - `oidToDisplayName()`
  - *(... and 2 more)*

---

### AlgorithmIdentifier [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.AlgorithmIdentifier`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 13
- **Fields**: 5
- **Source**: `bouncycastle\asn1\x509\AlgorithmIdentifier.java`

**Key Methods**:
  - `AlgorithmIdentifier()`
  - `getInstance()`
  - `getInstance()`
  - `getAlgorithm()`
  - `getParameters()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - `DERSequence()`
  - `getInstance()`
  - `AlgorithmIdentifier()`
  - *(... and 3 more)*

---

### AttCertIssuer [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.AttCertIssuer`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Implements**: `ASN1Choice`
- **Methods**: 13
- **Fields**: 2
- **Source**: `bouncycastle\asn1\x509\AttCertIssuer.java`

**Key Methods**:
  - `AttCertIssuer()`
  - `getInstance()`
  - `AttCertIssuer()`
  - `AttCertIssuer()`
  - `AttCertIssuer()`
  - `AttCertIssuer()`
  - `IllegalArgumentException()`
  - `getIssuer()`
  - `toASN1Primitive()`
  - `AttCertIssuer()`
  - *(... and 3 more)*

---

### AttCertValidityPeriod [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.AttCertValidityPeriod`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 10
- **Fields**: 4
- **Source**: `bouncycastle\asn1\x509\AttCertValidityPeriod.java`

**Key Methods**:
  - `AttCertValidityPeriod()`
  - `IllegalArgumentException()`
  - `getInstance()`
  - `AttCertValidityPeriod()`
  - `getNotAfterTime()`
  - `getNotBeforeTime()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - `DERSequence()`
  - `AttCertValidityPeriod()`

---

### Attribute [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.Attribute`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 12
- **Fields**: 4
- **Source**: `bouncycastle\asn1\x509\Attribute.java`

**Key Methods**:
  - `Attribute()`
  - `IllegalArgumentException()`
  - `getInstance()`
  - `Attribute()`
  - `getAttrType()`
  - `ASN1ObjectIdentifier()`
  - `getAttrValues()`
  - `getAttributeValues()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - *(... and 2 more)*

---

### AttributeCertificate [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.AttributeCertificate`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 11
- **Fields**: 5
- **Source**: `bouncycastle\asn1\x509\AttributeCertificate.java`

**Key Methods**:
  - `AttributeCertificate()`
  - `getInstance()`
  - `AttributeCertificate()`
  - `getAcinfo()`
  - `getSignatureAlgorithm()`
  - `getSignatureValue()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - `DERSequence()`
  - `AttributeCertificate()`
  - *(... and 1 more)*

---

### AttributeCertificateInfo [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.AttributeCertificateInfo`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 20
- **Fields**: 15
- **Source**: `bouncycastle\asn1\x509\AttributeCertificateInfo.java`

**Key Methods**:
  - `AttributeCertificateInfo()`
  - `IllegalArgumentException()`
  - `ASN1Integer()`
  - `if()`
  - `getInstance()`
  - `getInstance()`
  - `getAttrCertValidityPeriod()`
  - `getAttributes()`
  - `getExtensions()`
  - `getHolder()`
  - *(... and 10 more)*

---

### BasicConstraints [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.BasicConstraints`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 18
- **Fields**: 9
- **Source**: `bouncycastle\asn1\x509\BasicConstraints.java`

**Key Methods**:
  - `BasicConstraints()`
  - `IllegalArgumentException()`
  - `fromExtensions()`
  - `getInstance()`
  - `getInstance()`
  - `getInstance()`
  - `getPathLenConstraint()`
  - `isCA()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - *(... and 8 more)*

---

### Certificate [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.Certificate`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 18
- **Fields**: 5
- **Source**: `bouncycastle\asn1\x509\Certificate.java`

**Key Methods**:
  - `Certificate()`
  - `IllegalArgumentException()`
  - `getInstance()`
  - `getInstance()`
  - `getEndDate()`
  - `getIssuer()`
  - `getSerialNumber()`
  - `getSignature()`
  - `getSignatureAlgorithm()`
  - `getStartDate()`
  - *(... and 8 more)*

---

### CertificateList [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.CertificateList`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 18
- **Fields**: 7
- **Source**: `bouncycastle\asn1\x509\CertificateList.java`

**Key Methods**:
  - `CertificateList()`
  - `IllegalArgumentException()`
  - `getInstance()`
  - `getInstance()`
  - `getIssuer()`
  - `getNextUpdate()`
  - `getRevokedCertificateEnumeration()`
  - `getSignature()`
  - `getSignatureAlgorithm()`
  - `getTBSCertList()`
  - *(... and 8 more)*

---

### CRLDistPoint [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.CRLDistPoint`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 13
- **Fields**: 7
- **Source**: `bouncycastle\asn1\x509\CRLDistPoint.java`

**Key Methods**:
  - `CRLDistPoint()`
  - `fromExtensions()`
  - `getInstance()`
  - `getInstance()`
  - `getInstance()`
  - `getDistributionPoints()`
  - `toASN1Primitive()`
  - `toString()`
  - `StringBuffer()`
  - `getInstance()`
  - *(... and 3 more)*

---

### CRLNumber [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.CRLNumber`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 8
- **Fields**: 2
- **Source**: `bouncycastle\asn1\x509\CRLNumber.java`

**Key Methods**:
  - `CRLNumber()`
  - `IllegalArgumentException()`
  - `getInstance()`
  - `CRLNumber()`
  - `getCRLNumber()`
  - `toASN1Primitive()`
  - `ASN1Integer()`
  - `toString()`

---

### CRLReason [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.CRLReason`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 11
- **Fields**: 27
- **Source**: `bouncycastle\asn1\x509\CRLReason.java`

**Key Methods**:
  - `Hashtable()`
  - `CRLReason()`
  - `IllegalArgumentException()`
  - `ASN1Enumerated()`
  - `getInstance()`
  - `lookup()`
  - `lookup()`
  - `CRLReason()`
  - `getValue()`
  - `toASN1Primitive()`
  - *(... and 1 more)*

---

### DigestInfo [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.DigestInfo`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 11
- **Fields**: 5
- **Source**: `bouncycastle\asn1\x509\DigestInfo.java`

**Key Methods**:
  - `DigestInfo()`
  - `getInstance()`
  - `getInstance()`
  - `getAlgorithmId()`
  - `getDigest()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - `DERSequence()`
  - `getInstance()`
  - `DigestInfo()`
  - *(... and 1 more)*

---

### DistributionPoint [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.DistributionPoint`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 20
- **Fields**: 14
- **Source**: `bouncycastle\asn1\x509\DistributionPoint.java`

**Key Methods**:
  - `DistributionPoint()`
  - `if()`
  - `ReasonFlags()`
  - `if()`
  - `IllegalArgumentException()`
  - `appendObject()`
  - `getInstance()`
  - `getInstance()`
  - `getCRLIssuer()`
  - `getDistributionPoint()`
  - *(... and 10 more)*

---

### DistributionPointName [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.DistributionPointName`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Implements**: `ASN1Choice`
- **Methods**: 15
- **Fields**: 7
- **Source**: `bouncycastle\asn1\x509\DistributionPointName.java`

**Key Methods**:
  - `DistributionPointName()`
  - `appendObject()`
  - `getInstance()`
  - `getInstance()`
  - `getName()`
  - `getType()`
  - `toASN1Primitive()`
  - `DERTaggedObject()`
  - `toString()`
  - `StringBuffer()`
  - *(... and 5 more)*

---

### DSAParameter [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.DSAParameter`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 16
- **Fields**: 6
- **Source**: `bouncycastle\asn1\x509\DSAParameter.java`

**Key Methods**:
  - `DSAParameter()`
  - `ASN1Integer()`
  - `ASN1Integer()`
  - `ASN1Integer()`
  - `getInstance()`
  - `getInstance()`
  - `getG()`
  - `getP()`
  - `getQ()`
  - `toASN1Primitive()`
  - *(... and 6 more)*

---

### Extension [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.Extension`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 24
- **Fields**: 39
- **Source**: `bouncycastle\asn1\x509\Extension.java`

**Key Methods**:
  - `Extension()`
  - `convertValueToObject()`
  - `IllegalArgumentException()`
  - `create()`
  - `Extension()`
  - `getInstance()`
  - `Extension()`
  - `equals()`
  - `getExtnId()`
  - `getExtnValue()`
  - *(... and 14 more)*

---

### Extensions [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.Extensions`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 33
- **Fields**: 23
- **Source**: `bouncycastle\asn1\x509\Extensions.java`

**Key Methods**:
  - `Extensions()`
  - `Hashtable()`
  - `Vector()`
  - `IllegalArgumentException()`
  - `getExtension()`
  - `getExtensionParsedValue()`
  - `getInstance()`
  - `getInstance()`
  - `toOidArray()`
  - `equivalent()`
  - *(... and 23 more)*

---

### ExtensionsGenerator [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.ExtensionsGenerator`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Methods**: 22
- **Fields**: 3
- **Source**: `bouncycastle\asn1\x509\ExtensionsGenerator.java`

**Key Methods**:
  - `Hashtable()`
  - `Vector()`
  - `addExtension()`
  - `generate()`
  - `Extensions()`
  - `getExtension()`
  - `hasExtension()`
  - `isEmpty()`
  - `removeExtension()`
  - `IllegalArgumentException()`
  - *(... and 12 more)*

---

### GeneralName [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.GeneralName`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Implements**: `ASN1Choice`
- **Methods**: 39
- **Fields**: 51
- **Source**: `bouncycastle\asn1\x509\GeneralName.java`

**Key Methods**:
  - `GeneralName()`
  - `copyInts()`
  - `getInstance()`
  - `GeneralName()`
  - `GeneralName()`
  - `GeneralName()`
  - `GeneralName()`
  - `GeneralName()`
  - `IllegalArgumentException()`
  - `getInstance()`
  - *(... and 29 more)*

---

### GeneralNames [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.GeneralNames`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 16
- **Fields**: 6
- **Source**: `bouncycastle\asn1\x509\GeneralNames.java`

**Key Methods**:
  - `GeneralNames()`
  - `copy()`
  - `fromExtensions()`
  - `getInstance()`
  - `getInstance()`
  - `GeneralNames()`
  - `getNames()`
  - `copy()`
  - `toASN1Primitive()`
  - `DERSequence()`
  - *(... and 6 more)*

---

### Holder [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.Holder`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 25
- **Fields**: 15
- **Source**: `bouncycastle\asn1\x509\Holder.java`

**Key Methods**:
  - `Holder()`
  - `if()`
  - `IllegalArgumentException()`
  - `getInstance()`
  - `Holder()`
  - `Holder()`
  - `getBaseCertificateID()`
  - `getEntityName()`
  - `getObjectDigestInfo()`
  - `getVersion()`
  - *(... and 15 more)*

---

### IssuerSerial [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.IssuerSerial`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 17
- **Fields**: 6
- **Source**: `bouncycastle\asn1\x509\IssuerSerial.java`

**Key Methods**:
  - `IssuerSerial()`
  - `IllegalArgumentException()`
  - `getInstance()`
  - `IssuerSerial()`
  - `getIssuer()`
  - `getIssuerUID()`
  - `getSerial()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - `DERSequence()`
  - *(... and 7 more)*

---

### IssuingDistributionPoint [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.IssuingDistributionPoint`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 27
- **Fields**: 19
- **Source**: `bouncycastle\asn1\x509\IssuingDistributionPoint.java`

**Key Methods**:
  - `IssuingDistributionPoint()`
  - `ASN1EncodableVector()`
  - `DERSequence()`
  - `appendObject()`
  - `booleanToString()`
  - `getInstance()`
  - `getInstance()`
  - `getDistributionPoint()`
  - `getOnlySomeReasons()`
  - `isIndirectCRL()`
  - *(... and 17 more)*

---

### KeyUsage [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.KeyUsage`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 12
- **Fields**: 12
- **Source**: `bouncycastle\asn1\x509\KeyUsage.java`

**Key Methods**:
  - `KeyUsage()`
  - `DERBitString()`
  - `fromExtensions()`
  - `getInstance()`
  - `getInstance()`
  - `KeyUsage()`
  - `getBytes()`
  - `getPadBits()`
  - `hasUsages()`
  - `toASN1Primitive()`
  - *(... and 2 more)*

---

### ObjectDigestInfo [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.ObjectDigestInfo`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 16
- **Fields**: 11
- **Source**: `bouncycastle\asn1\x509\ObjectDigestInfo.java`

**Key Methods**:
  - `ObjectDigestInfo()`
  - `ASN1Enumerated()`
  - `DERBitString()`
  - `getInstance()`
  - `ObjectDigestInfo()`
  - `getDigestAlgorithm()`
  - `getDigestedObjectType()`
  - `getObjectDigest()`
  - `getOtherObjectTypeID()`
  - `toASN1Primitive()`
  - *(... and 6 more)*

---

### SubjectPublicKeyInfo [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.SubjectPublicKeyInfo`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 18
- **Fields**: 5
- **Source**: `bouncycastle\asn1\x509\SubjectPublicKeyInfo.java`

**Key Methods**:
  - `SubjectPublicKeyInfo()`
  - `DERBitString()`
  - `getInstance()`
  - `getInstance()`
  - `getAlgorithm()`
  - `getAlgorithmId()`
  - `getPublicKey()`
  - `getPublicKeyData()`
  - `parsePublicKey()`
  - `toASN1Primitive()`
  - *(... and 8 more)*

---

### TBSCertificate [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.TBSCertificate`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 28
- **Fields**: 27
- **Source**: `bouncycastle\asn1\x509\TBSCertificate.java`

**Key Methods**:
  - `TBSCertificate()`
  - `ASN1Integer()`
  - `if()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `if()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `getInstance()`
  - `getInstance()`
  - *(... and 18 more)*

---

### TBSCertList [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.TBSCertList`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Implements**: `Enumeration`
- **Methods**: 36
- **Fields**: 29
- **Source**: `bouncycastle\asn1\x509\TBSCertList.java`

**Key Methods**:
  - `CRLEntry()`
  - `IllegalArgumentException()`
  - `getInstance()`
  - `CRLEntry()`
  - `getExtensions()`
  - `getRevocationDate()`
  - `getUserCertificate()`
  - `hasExtensions()`
  - `toASN1Primitive()`
  - `EmptyEnumeration()`
  - *(... and 26 more)*

---

### Time [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.Time`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Implements**: `ASN1Choice`
- **Methods**: 24
- **Fields**: 11
- **Source**: `bouncycastle\asn1\x509\Time.java`

**Key Methods**:
  - `Time()`
  - `IllegalArgumentException()`
  - `getInstance()`
  - `getInstance()`
  - `getDate()`
  - `IllegalStateException()`
  - `getTime()`
  - `toASN1Primitive()`
  - `toString()`
  - `getTime()`
  - *(... and 14 more)*

---

### V2Form [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.V2Form`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 18
- **Fields**: 10
- **Source**: `bouncycastle\asn1\x509\V2Form.java`

**Key Methods**:
  - `V2Form()`
  - `getInstance()`
  - `getInstance()`
  - `getBaseCertificateID()`
  - `getIssuerName()`
  - `getObjectDigestInfo()`
  - `toASN1Primitive()`
  - `ASN1EncodableVector()`
  - `DERSequence()`
  - `V2Form()`
  - *(... and 8 more)*

---

### X509DefaultEntryConverter [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.X509DefaultEntryConverter`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `X509NameEntryConverter`
- **Methods**: 7
- **Fields**: 0
- **Source**: `bouncycastle\asn1\x509\X509DefaultEntryConverter.java`

**Key Methods**:
  - `getConvertedValue()`
  - `DERIA5String()`
  - `DERGeneralizedTime()`
  - `DERPrintableString()`
  - `DERUTF8String()`
  - `convertHexEncoded()`
  - `RuntimeException()`

---

### X509Extension [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.X509Extension`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Methods**: 42
- **Fields**: 35
- **Source**: `bouncycastle\asn1\x509\X509Extension.java`

**Key Methods**:
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - *(... and 32 more)*

---

### X509Name [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.X509Name`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Extends**: `ASN1Object`
- **Methods**: 121
- **Fields**: 177
- **Source**: `bouncycastle\asn1\x509\X509Name.java`

**Key Methods**:
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`
  - *(... and 111 more)*

---

### X509NameEntryConverter [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.X509NameEntryConverter`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Methods**: 3
- **Fields**: 0
- **Source**: `bouncycastle\asn1\x509\X509NameEntryConverter.java`

**Key Methods**:
  - `canBePrintable()`
  - `convertHexEncoded()`
  - `getConvertedValue()`

---

### X509ObjectIdentifiers [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.asn1.x509.X509ObjectIdentifiers`
- **Package**: `com.thingclips.bouncycastle.asn1.x509`
- **Methods**: 2
- **Fields**: 25
- **Source**: `bouncycastle\asn1\x509\X509ObjectIdentifiers.java`

**Key Methods**:
  - `ASN1ObjectIdentifier()`
  - `ASN1ObjectIdentifier()`

---

### AttributeCertificateIssuer [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.cert.AttributeCertificateIssuer`
- **Package**: `com.thingclips.bouncycastle.cert`
- **Implements**: `Selector`
- **Methods**: 11
- **Fields**: 17
- **Source**: `thingclips\bouncycastle\cert\AttributeCertificateIssuer.java`

**Key Methods**:
  - `AttributeCertificateIssuer()`
  - `matchesDN()`
  - `clone()`
  - `AttributeCertificateIssuer()`
  - `equals()`
  - `getNames()`
  - `ArrayList()`
  - `hashCode()`
  - `match()`
  - `AttributeCertificateIssuer()`
  - *(... and 1 more)*

---

### CertException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.cert.CertException`
- **Package**: `com.thingclips.bouncycastle.cert`
- **Extends**: `Exception`
- **Methods**: 3
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\cert\CertException.java`

**Key Methods**:
  - `CertException()`
  - `getCause()`
  - `CertException()`

---

### CertIOException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.cert.CertIOException`
- **Package**: `com.thingclips.bouncycastle.cert`
- **Extends**: `IOException`
- **Methods**: 3
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\cert\CertIOException.java`

**Key Methods**:
  - `CertIOException()`
  - `getCause()`
  - `CertIOException()`

---

### CertUtils [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.cert.CertUtils`
- **Package**: `com.thingclips.bouncycastle.cert`
- **Methods**: 36
- **Fields**: 34
- **Source**: `thingclips\bouncycastle\cert\CertUtils.java`

**Key Methods**:
  - `addExtension()`
  - `CertIOException()`
  - `bitStringToBoolean()`
  - `booleanToBitString()`
  - `DERBitString()`
  - `DERBitString()`
  - `doRemoveExtension()`
  - `ExtensionsGenerator()`
  - `IllegalArgumentException()`
  - `doReplaceExtension()`
  - *(... and 26 more)*

---

### X509AttributeCertificateHolder [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.cert.X509AttributeCertificateHolder`
- **Package**: `com.thingclips.bouncycastle.cert`
- **Implements**: `Encodable, Serializable`
- **Methods**: 36
- **Fields**: 19
- **Source**: `thingclips\bouncycastle\cert\X509AttributeCertificateHolder.java`

**Key Methods**:
  - `X509AttributeCertificateHolder()`
  - `init()`
  - `parseBytes()`
  - `CertIOException()`
  - `CertIOException()`
  - `readObject()`
  - `writeObject()`
  - `equals()`
  - `getAttributes()`
  - `getCriticalExtensionOIDs()`
  - *(... and 26 more)*

---

### X509CertificateHolder [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.cert.X509CertificateHolder`
- **Package**: `com.thingclips.bouncycastle.cert`
- **Implements**: `Encodable, Serializable`
- **Methods**: 32
- **Fields**: 10
- **Source**: `thingclips\bouncycastle\cert\X509CertificateHolder.java`

**Key Methods**:
  - `X509CertificateHolder()`
  - `init()`
  - `parseBytes()`
  - `CertIOException()`
  - `CertIOException()`
  - `readObject()`
  - `writeObject()`
  - `equals()`
  - `getCriticalExtensionOIDs()`
  - `getEncoded()`
  - *(... and 22 more)*

---

### X509CRLHolder [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.cert.X509CRLHolder`
- **Package**: `com.thingclips.bouncycastle.cert`
- **Implements**: `Encodable, Serializable`
- **Methods**: 34
- **Fields**: 26
- **Source**: `thingclips\bouncycastle\cert\X509CRLHolder.java`

**Key Methods**:
  - `X509CRLHolder()`
  - `init()`
  - `GeneralNames()`
  - `isIndirectCRL()`
  - `parseStream()`
  - `ASN1InputStream()`
  - `IOException()`
  - `CertIOException()`
  - `CertIOException()`
  - `readObject()`
  - *(... and 24 more)*

---

### CMSException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.cms.CMSException`
- **Package**: `com.thingclips.bouncycastle.cms`
- **Extends**: `Exception`
- **Methods**: 4
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\cms\CMSException.java`

**Key Methods**:
  - `CMSException()`
  - `getCause()`
  - `getUnderlyingException()`
  - `CMSException()`

---

### CryptoException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.CryptoException`
- **Package**: `com.thingclips.bouncycastle.crypto`
- **Extends**: `Exception`
- **Methods**: 4
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\crypto\CryptoException.java`

**Key Methods**:
  - `CryptoException()`
  - `getCause()`
  - `CryptoException()`
  - `CryptoException()`

---

### CryptoServicesPermission [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.CryptoServicesPermission`
- **Package**: `com.thingclips.bouncycastle.crypto`
- **Extends**: `Permission`
- **Methods**: 7
- **Fields**: 7
- **Source**: `thingclips\bouncycastle\crypto\CryptoServicesPermission.java`

**Key Methods**:
  - `CryptoServicesPermission()`
  - `HashSet()`
  - `equals()`
  - `getActions()`
  - `hashCode()`
  - `implies()`
  - `getName()`

---

### InvalidCipherTextException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.InvalidCipherTextException`
- **Package**: `com.thingclips.bouncycastle.crypto`
- **Extends**: `CryptoException`
- **Methods**: 3
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\crypto\InvalidCipherTextException.java`

**Key Methods**:
  - `InvalidCipherTextException()`
  - `InvalidCipherTextException()`
  - `InvalidCipherTextException()`

---

### KeyGenerationParameters [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.KeyGenerationParameters`
- **Package**: `com.thingclips.bouncycastle.crypto`
- **Methods**: 3
- **Fields**: 2
- **Source**: `thingclips\bouncycastle\crypto\KeyGenerationParameters.java`

**Key Methods**:
  - `KeyGenerationParameters()`
  - `getRandom()`
  - `getStrength()`

---

### ECMQVBasicAgreement [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.agreement.ECMQVBasicAgreement`
- **Package**: `com.thingclips.bouncycastle.crypto.agreement`
- **Implements**: `BasicAgreement`
- **Methods**: 7
- **Fields**: 15
- **Source**: `bouncycastle\crypto\agreement\ECMQVBasicAgreement.java`

**Key Methods**:
  - `calculateMqvAgreement()`
  - `calculateAgreement()`
  - `IllegalStateException()`
  - `IllegalStateException()`
  - `IllegalStateException()`
  - `getFieldSize()`
  - `init()`

---

### DHKEKGenerator [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.agreement.kdf.DHKEKGenerator`
- **Package**: `com.thingclips.bouncycastle.crypto.agreement.kdf`
- **Implements**: `DerivationFunction`
- **Methods**: 12
- **Fields**: 24
- **Source**: `crypto\agreement\kdf\DHKEKGenerator.java`

**Key Methods**:
  - `DHKEKGenerator()`
  - `generateBytes()`
  - `OutputLengthException()`
  - `IllegalArgumentException()`
  - `ASN1EncodableVector()`
  - `ASN1EncodableVector()`
  - `DEROctetString()`
  - `DEROctetString()`
  - `DERSequence()`
  - `IllegalArgumentException()`
  - *(... and 2 more)*

---

### EncodableDigest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.EncodableDigest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Methods**: 1
- **Fields**: 0
- **Source**: `bouncycastle\crypto\digests\EncodableDigest.java`

**Key Methods**:
  - `getEncodedState()`

---

### GeneralDigest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.GeneralDigest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Implements**: `ExtendedDigest, Memoable`
- **Methods**: 13
- **Fields**: 24
- **Source**: `bouncycastle\crypto\digests\GeneralDigest.java`

**Key Methods**:
  - `GeneralDigest()`
  - `copyIn()`
  - `finish()`
  - `getByteLength()`
  - `populateState()`
  - `processBlock()`
  - `processLength()`
  - `processWord()`
  - `reset()`
  - `update()`
  - *(... and 3 more)*

---

### LongDigest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.LongDigest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Implements**: `ExtendedDigest, Memoable, EncodableDigest`
- **Methods**: 21
- **Fields**: 91
- **Source**: `bouncycastle\crypto\digests\LongDigest.java`

**Key Methods**:
  - `LongDigest()`
  - `m222Ch()`
  - `Maj()`
  - `Sigma0()`
  - `Sigma1()`
  - `Sum0()`
  - `Sum1()`
  - `adjustByteCounts()`
  - `copyIn()`
  - `finish()`
  - *(... and 11 more)*

---

### MD2Digest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.MD2Digest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Implements**: `ExtendedDigest, Memoable`
- **Methods**: 15
- **Fields**: 37
- **Source**: `bouncycastle\crypto\digests\MD2Digest.java`

**Key Methods**:
  - `MD2Digest()`
  - `copyIn()`
  - `copy()`
  - `MD2Digest()`
  - `doFinal()`
  - `getAlgorithmName()`
  - `getByteLength()`
  - `getDigestSize()`
  - `processBlock()`
  - `processCheckSum()`
  - *(... and 5 more)*

---

### MD4Digest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.MD4Digest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Extends**: `GeneralDigest`
- **Methods**: 18
- **Fields**: 82
- **Source**: `bouncycastle\crypto\digests\MD4Digest.java`

**Key Methods**:
  - `MD4Digest()`
  - `m223F()`
  - `m224G()`
  - `m225H()`
  - `copyIn()`
  - `rotateLeft()`
  - `unpackWord()`
  - `copy()`
  - `MD4Digest()`
  - `doFinal()`
  - *(... and 8 more)*

---

### MD5Digest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.MD5Digest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Extends**: `GeneralDigest`
- **Implements**: `EncodableDigest`
- **Methods**: 21
- **Fields**: 104
- **Source**: `bouncycastle\crypto\digests\MD5Digest.java`

**Key Methods**:
  - `MD5Digest()`
  - `m226F()`
  - `m227G()`
  - `m228H()`
  - `m229K()`
  - `copyIn()`
  - `rotateLeft()`
  - `unpackWord()`
  - `copy()`
  - `MD5Digest()`
  - *(... and 11 more)*

---

### RIPEMD128Digest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.RIPEMD128Digest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Extends**: `GeneralDigest`
- **Methods**: 35
- **Fields**: 151
- **Source**: `bouncycastle\crypto\digests\RIPEMD128Digest.java`

**Key Methods**:
  - `RIPEMD128Digest()`
  - `m230F1()`
  - `m234RL()`
  - `m231F2()`
  - `m234RL()`
  - `m232F3()`
  - `m234RL()`
  - `m233F4()`
  - `m234RL()`
  - `FF1()`
  - *(... and 25 more)*

---

### RIPEMD160Digest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.RIPEMD160Digest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Extends**: `GeneralDigest`
- **Methods**: 20
- **Fields**: 344
- **Source**: `bouncycastle\crypto\digests\RIPEMD160Digest.java`

**Key Methods**:
  - `RIPEMD160Digest()`
  - `m239RL()`
  - `copyIn()`
  - `m240f1()`
  - `m241f2()`
  - `m242f3()`
  - `m243f4()`
  - `m244f5()`
  - `unpackWord()`
  - `copy()`
  - *(... and 10 more)*

---

### RIPEMD256Digest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.RIPEMD256Digest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Extends**: `GeneralDigest`
- **Methods**: 35
- **Fields**: 158
- **Source**: `bouncycastle\crypto\digests\RIPEMD256Digest.java`

**Key Methods**:
  - `RIPEMD256Digest()`
  - `m245F1()`
  - `m249RL()`
  - `m246F2()`
  - `m249RL()`
  - `m247F3()`
  - `m249RL()`
  - `m248F4()`
  - `m249RL()`
  - `FF1()`
  - *(... and 25 more)*

---

### SHA1Digest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.SHA1Digest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Extends**: `GeneralDigest`
- **Implements**: `EncodableDigest`
- **Methods**: 18
- **Fields**: 62
- **Source**: `bouncycastle\crypto\digests\SHA1Digest.java`

**Key Methods**:
  - `SHA1Digest()`
  - `copyIn()`
  - `m254f()`
  - `m255g()`
  - `m256h()`
  - `copy()`
  - `SHA1Digest()`
  - `doFinal()`
  - `getAlgorithmName()`
  - `getDigestSize()`
  - *(... and 8 more)*

---

### SHA224Digest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.SHA224Digest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Extends**: `GeneralDigest`
- **Implements**: `EncodableDigest`
- **Methods**: 21
- **Fields**: 63
- **Source**: `bouncycastle\crypto\digests\SHA224Digest.java`

**Key Methods**:
  - `SHA224Digest()`
  - `m257Ch()`
  - `Maj()`
  - `Sum0()`
  - `Sum1()`
  - `Theta0()`
  - `Theta1()`
  - `doCopy()`
  - `copy()`
  - `SHA224Digest()`
  - *(... and 11 more)*

---

### SHA256Digest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.SHA256Digest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Extends**: `GeneralDigest`
- **Implements**: `EncodableDigest`
- **Methods**: 21
- **Fields**: 63
- **Source**: `bouncycastle\crypto\digests\SHA256Digest.java`

**Key Methods**:
  - `SHA256Digest()`
  - `m258Ch()`
  - `Maj()`
  - `Sum0()`
  - `Sum1()`
  - `Theta0()`
  - `Theta1()`
  - `copyIn()`
  - `copy()`
  - `SHA256Digest()`
  - *(... and 11 more)*

---

### SHA384Digest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.SHA384Digest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Extends**: `LongDigest`
- **Methods**: 11
- **Fields**: 5
- **Source**: `bouncycastle\crypto\digests\SHA384Digest.java`

**Key Methods**:
  - `SHA384Digest()`
  - `copy()`
  - `SHA384Digest()`
  - `doFinal()`
  - `getAlgorithmName()`
  - `getDigestSize()`
  - `getEncodedState()`
  - `reset()`
  - `SHA384Digest()`
  - `SHA384Digest()`
  - *(... and 1 more)*

---

### SHA512Digest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.SHA512Digest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Extends**: `LongDigest`
- **Methods**: 11
- **Fields**: 5
- **Source**: `bouncycastle\crypto\digests\SHA512Digest.java`

**Key Methods**:
  - `SHA512Digest()`
  - `copy()`
  - `SHA512Digest()`
  - `doFinal()`
  - `getAlgorithmName()`
  - `getDigestSize()`
  - `getEncodedState()`
  - `reset()`
  - `SHA512Digest()`
  - `SHA512Digest()`
  - *(... and 1 more)*

---

### SHA512tDigest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.SHA512tDigest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Extends**: `LongDigest`
- **Methods**: 20
- **Fields**: 16
- **Source**: `bouncycastle\crypto\digests\SHA512tDigest.java`

**Key Methods**:
  - `SHA512tDigest()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `intToBigEndian()`
  - `longToBigEndian()`
  - `readDigestLength()`
  - `tIvGenerate()`
  - `if()`
  - `copy()`
  - *(... and 10 more)*

---

### SkeinDigest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.SkeinDigest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Implements**: `ExtendedDigest, Memoable`
- **Methods**: 15
- **Fields**: 4
- **Source**: `bouncycastle\crypto\digests\SkeinDigest.java`

**Key Methods**:
  - `SkeinDigest()`
  - `SkeinEngine()`
  - `copy()`
  - `SkeinDigest()`
  - `doFinal()`
  - `getAlgorithmName()`
  - `getByteLength()`
  - `getDigestSize()`
  - `init()`
  - `reset()`
  - *(... and 5 more)*

---

### SM3Digest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.digests.SM3Digest`
- **Package**: `com.thingclips.bouncycastle.crypto.digests`
- **Extends**: `GeneralDigest`
- **Methods**: 19
- **Fields**: 65
- **Source**: `bouncycastle\crypto\digests\SM3Digest.java`

**Key Methods**:
  - `SM3Digest()`
  - `FF0()`
  - `FF1()`
  - `GG0()`
  - `GG1()`
  - `m259P0()`
  - `m260P1()`
  - `copyIn()`
  - `copy()`
  - `SM3Digest()`
  - *(... and 9 more)*

---

### CustomNamedCurves [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.ec.CustomNamedCurves`
- **Package**: `com.thingclips.bouncycastle.crypto.ec`
- **Methods**: 23
- **Fields**: 21
- **Source**: `bouncycastle\crypto\ec\CustomNamedCurves.java`

**Key Methods**:
  - `X9ECParametersHolder()`
  - `createParameters()`
  - `X9ECParameters()`
  - `X9ECParametersHolder()`
  - `createParameters()`
  - `X9ECParameters()`
  - `Hashtable()`
  - `Hashtable()`
  - `Hashtable()`
  - `Hashtable()`
  - *(... and 13 more)*

---

### OAEPEncoding [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.encodings.OAEPEncoding`
- **Package**: `com.thingclips.bouncycastle.crypto.encodings`
- **Implements**: `AsymmetricBlockCipher`
- **Methods**: 16
- **Fields**: 42
- **Source**: `bouncycastle\crypto\encodings\OAEPEncoding.java`

**Key Methods**:
  - `OAEPEncoding()`
  - `ItoOSP()`
  - `maskGeneratorFunction1()`
  - `decodeBlock()`
  - `InvalidCipherTextException()`
  - `encodeBlock()`
  - `getInputBlockSize()`
  - `DataLengthException()`
  - `getInputBlockSize()`
  - `getOutputBlockSize()`
  - *(... and 6 more)*

---

### AESEngine [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.engines.AESEngine`
- **Package**: `com.thingclips.bouncycastle.crypto.engines`
- **Implements**: `BlockCipher`
- **Methods**: 20
- **Fields**: 145
- **Source**: `bouncycastle\crypto\engines\AESEngine.java`

**Key Methods**:
  - `FFmulX()`
  - `FFmulX2()`
  - `decryptBlock()`
  - `encryptBlock()`
  - `generateWorkingKey()`
  - `IllegalArgumentException()`
  - `if()`
  - `IllegalStateException()`
  - `inv_mcol()`
  - `shift()`
  - *(... and 10 more)*

---

### AESLightEngine [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.engines.AESLightEngine`
- **Package**: `com.thingclips.bouncycastle.crypto.engines`
- **Implements**: `BlockCipher`
- **Methods**: 22
- **Fields**: 138
- **Source**: `bouncycastle\crypto\engines\AESLightEngine.java`

**Key Methods**:
  - `FFmulX()`
  - `FFmulX2()`
  - `decryptBlock()`
  - `encryptBlock()`
  - `generateWorkingKey()`
  - `IllegalArgumentException()`
  - `if()`
  - `IllegalStateException()`
  - `inv_mcol()`
  - `mcol()`
  - *(... and 12 more)*

---

### RSABlindedEngine [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.engines.RSABlindedEngine`
- **Package**: `com.thingclips.bouncycastle.crypto.engines`
- **Implements**: `AsymmetricBlockCipher`
- **Methods**: 7
- **Fields**: 15
- **Source**: `bouncycastle\crypto\engines\RSABlindedEngine.java`

**Key Methods**:
  - `RSACoreEngine()`
  - `getInputBlockSize()`
  - `getOutputBlockSize()`
  - `init()`
  - `processBlock()`
  - `IllegalStateException()`
  - `IllegalStateException()`

---

### ThreefishEngine [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.engines.ThreefishEngine`
- **Package**: `com.thingclips.bouncycastle.crypto.engines`
- **Extends**: `ThreefishCipher`
- **Implements**: `BlockCipher`
- **Methods**: 57
- **Fields**: 949
- **Source**: `bouncycastle\crypto\engines\ThreefishEngine.java`

**Key Methods**:
  - `Threefish1024Cipher()`
  - `decryptBlock()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `encryptBlock()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `Threefish256Cipher()`
  - `decryptBlock()`
  - `IllegalArgumentException()`
  - *(... and 47 more)*

---

### RSAKeyPairGenerator [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.generators.RSAKeyPairGenerator`
- **Package**: `com.thingclips.bouncycastle.crypto.generators`
- **Implements**: `AsymmetricCipherKeyPairGenerator`
- **Methods**: 9
- **Fields**: 40
- **Source**: `bouncycastle\crypto\generators\RSAKeyPairGenerator.java`

**Key Methods**:
  - `getNumberOfIterations()`
  - `chooseRandomPrime()`
  - `IllegalStateException()`
  - `generateKeyPair()`
  - `AsymmetricCipherKeyPair()`
  - `RSAKeyParameters()`
  - `RSAPrivateCrtKeyParameters()`
  - `init()`
  - `isProbablePrime()`

---

### HMac [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.macs.HMac`
- **Package**: `com.thingclips.bouncycastle.crypto.macs`
- **Implements**: `Mac`
- **Methods**: 14
- **Fields**: 35
- **Source**: `bouncycastle\crypto\macs\HMac.java`

**Key Methods**:
  - `Hashtable()`
  - `HMac()`
  - `getByteLength()`
  - `IllegalArgumentException()`
  - `xorPad()`
  - `doFinal()`
  - `getAlgorithmName()`
  - `getMacSize()`
  - `getUnderlyingDigest()`
  - `init()`
  - *(... and 4 more)*

---

### ECDomainParameters [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.params.ECDomainParameters`
- **Package**: `com.thingclips.bouncycastle.crypto.params`
- **Implements**: `ECConstants`
- **Methods**: 23
- **Fields**: 13
- **Source**: `bouncycastle\crypto\params\ECDomainParameters.java`

**Key Methods**:
  - `ECDomainParameters()`
  - `equals()`
  - `getCurve()`
  - `getG()`
  - `getH()`
  - `getHInv()`
  - `getN()`
  - `getSeed()`
  - `hashCode()`
  - `validatePrivateScalar()`
  - *(... and 13 more)*

---

### Ed25519PrivateKeyParameters [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.params.Ed25519PrivateKeyParameters`
- **Package**: `com.thingclips.bouncycastle.crypto.params`
- **Extends**: `AsymmetricKeyParameter`
- **Methods**: 16
- **Fields**: 13
- **Source**: `bouncycastle\crypto\params\Ed25519PrivateKeyParameters.java`

**Key Methods**:
  - `Ed25519PrivateKeyParameters()`
  - `validate()`
  - `IllegalArgumentException()`
  - `encode()`
  - `generatePublicKey()`
  - `Ed25519PublicKeyParameters()`
  - `getEncoded()`
  - `sign()`
  - `sign()`
  - `IllegalArgumentException()`
  - *(... and 6 more)*

---

### Ed448PrivateKeyParameters [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.params.Ed448PrivateKeyParameters`
- **Package**: `com.thingclips.bouncycastle.crypto.params`
- **Extends**: `AsymmetricKeyParameter`
- **Methods**: 15
- **Fields**: 13
- **Source**: `bouncycastle\crypto\params\Ed448PrivateKeyParameters.java`

**Key Methods**:
  - `Ed448PrivateKeyParameters()`
  - `validate()`
  - `IllegalArgumentException()`
  - `encode()`
  - `generatePublicKey()`
  - `Ed448PublicKeyParameters()`
  - `getEncoded()`
  - `sign()`
  - `sign()`
  - `IllegalArgumentException()`
  - *(... and 5 more)*

---

### ParametersWithRandom [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.params.ParametersWithRandom`
- **Package**: `com.thingclips.bouncycastle.crypto.params`
- **Implements**: `CipherParameters`
- **Methods**: 4
- **Fields**: 2
- **Source**: `bouncycastle\crypto\params\ParametersWithRandom.java`

**Key Methods**:
  - `ParametersWithRandom()`
  - `getParameters()`
  - `getRandom()`
  - `ParametersWithRandom()`

---

### SkeinParameters [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.params.SkeinParameters`
- **Package**: `com.thingclips.bouncycastle.crypto.params`
- **Implements**: `CipherParameters`
- **Methods**: 38
- **Fields**: 19
- **Source**: `bouncycastle\crypto\params\SkeinParameters.java`

**Key Methods**:
  - `Hashtable()`
  - `Builder()`
  - `build()`
  - `SkeinParameters()`
  - `set()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `setKey()`
  - `set()`
  - *(... and 28 more)*

---

### TweakableBlockCipherParameters [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.params.TweakableBlockCipherParameters`
- **Package**: `com.thingclips.bouncycastle.crypto.params`
- **Implements**: `CipherParameters`
- **Methods**: 3
- **Fields**: 2
- **Source**: `bouncycastle\crypto\params\TweakableBlockCipherParameters.java`

**Key Methods**:
  - `TweakableBlockCipherParameters()`
  - `getKey()`
  - `getTweak()`

---

### ECDSASigner [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.signers.ECDSASigner`
- **Package**: `com.thingclips.bouncycastle.crypto.signers`
- **Implements**: `ECConstants, DSAExt`
- **Methods**: 13
- **Fields**: 33
- **Source**: `bouncycastle\crypto\signers\ECDSASigner.java`

**Key Methods**:
  - `ECDSASigner()`
  - `RandomDSAKCalculator()`
  - `calculateE()`
  - `BigInteger()`
  - `createBasePointMultiplier()`
  - `FixedPointCombMultiplier()`
  - `generateSignature()`
  - `getDenominator()`
  - `getOrder()`
  - `init()`
  - *(... and 3 more)*

---

### ECNRSigner [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.signers.ECNRSigner`
- **Package**: `com.thingclips.bouncycastle.crypto.signers`
- **Implements**: `DSAExt`
- **Methods**: 14
- **Fields**: 21
- **Source**: `bouncycastle\crypto\signers\ECNRSigner.java`

**Key Methods**:
  - `extractT()`
  - `generateSignature()`
  - `IllegalStateException()`
  - `BigInteger()`
  - `DataLengthException()`
  - `ECKeyPairGenerator()`
  - `getOrder()`
  - `getRecoveredMessage()`
  - `IllegalStateException()`
  - `init()`
  - *(... and 4 more)*

---

### ISOTrailers [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.signers.ISOTrailers`
- **Package**: `com.thingclips.bouncycastle.crypto.signers`
- **Methods**: 3
- **Fields**: 13
- **Source**: `bouncycastle\crypto\signers\ISOTrailers.java`

**Key Methods**:
  - `HashMap()`
  - `getTrailer()`
  - `noTrailerAvailable()`

---

### PSSSigner [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.signers.PSSSigner`
- **Package**: `com.thingclips.bouncycastle.crypto.signers`
- **Implements**: `Signer`
- **Methods**: 19
- **Fields**: 89
- **Source**: `bouncycastle\crypto\signers\PSSSigner.java`

**Key Methods**:
  - `PSSSigner()`
  - `ItoOSP()`
  - `clearBlock()`
  - `maskGenerator()`
  - `maskGeneratorFunction1()`
  - `maskGeneratorFunction1()`
  - `generateSignature()`
  - `init()`
  - `IllegalArgumentException()`
  - `reset()`
  - *(... and 9 more)*

---

### DigestFactory [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.util.DigestFactory`
- **Package**: `com.thingclips.bouncycastle.crypto.util`
- **Methods**: 67
- **Fields**: 2
- **Source**: `bouncycastle\crypto\util\DigestFactory.java`

**Key Methods**:
  - `createClone()`
  - `HashMap()`
  - `Cloner()`
  - `createClone()`
  - `MD5Digest()`
  - `Cloner()`
  - `createClone()`
  - `MD5Digest()`
  - `Cloner()`
  - `createClone()`
  - *(... and 57 more)*

---

### OpenSSHPublicKeyUtil [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.util.OpenSSHPublicKeyUtil`
- **Package**: `com.thingclips.bouncycastle.crypto.util`
- **Methods**: 25
- **Fields**: 21
- **Source**: `bouncycastle\crypto\util\OpenSSHPublicKeyUtil.java`

**Key Methods**:
  - `OpenSSHPublicKeyUtil()`
  - `encodePublicKey()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `SSHBuilder()`
  - `SSHBuilder()`
  - `IllegalArgumentException()`
  - `SSHBuilder()`
  - `SSHBuilder()`
  - `IllegalArgumentException()`
  - *(... and 15 more)*

---

### SSHNamedCurves [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.crypto.util.SSHNamedCurves`
- **Package**: `com.thingclips.bouncycastle.crypto.util`
- **Methods**: 8
- **Fields**: 8
- **Source**: `bouncycastle\crypto\util\SSHNamedCurves.java`

**Key Methods**:
  - `getByName()`
  - `getName()`
  - `getNameForParameters()`
  - `getName()`
  - `getNameForParameters()`
  - `getParameters()`
  - `getParameters()`
  - `getNameForParameters()`

---

### CompositePrivateKey [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.CompositePrivateKey`
- **Package**: `com.thingclips.bouncycastle.jcajce`
- **Implements**: `PrivateKey`
- **Methods**: 13
- **Fields**: 5
- **Source**: `thingclips\bouncycastle\jcajce\CompositePrivateKey.java`

**Key Methods**:
  - `CompositePrivateKey()`
  - `IllegalArgumentException()`
  - `ArrayList()`
  - `equals()`
  - `getAlgorithm()`
  - `getEncoded()`
  - `ASN1EncodableVector()`
  - `PrivateKeyInfo()`
  - `DERSequence()`
  - `IllegalStateException()`
  - *(... and 3 more)*

---

### CompositePublicKey [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.CompositePublicKey`
- **Package**: `com.thingclips.bouncycastle.jcajce`
- **Implements**: `PublicKey`
- **Methods**: 13
- **Fields**: 5
- **Source**: `thingclips\bouncycastle\jcajce\CompositePublicKey.java`

**Key Methods**:
  - `CompositePublicKey()`
  - `IllegalArgumentException()`
  - `ArrayList()`
  - `equals()`
  - `getAlgorithm()`
  - `getEncoded()`
  - `ASN1EncodableVector()`
  - `SubjectPublicKeyInfo()`
  - `DERSequence()`
  - `IllegalStateException()`
  - *(... and 3 more)*

---

### C0146EC [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.C0146EC`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric`
- **Extends**: `AsymmetricAlgorithmProvider`
- **Methods**: 2
- **Fields**: 3
- **Source**: `jcajce\provider\asymmetric\C0146EC.java`

**Key Methods**:
  - `configure()`
  - `HashMap()`

---

### RSA [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.RSA`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric`
- **Extends**: `AsymmetricAlgorithmProvider`
- **Methods**: 9
- **Fields**: 20
- **Source**: `jcajce\provider\asymmetric\RSA.java`

**Key Methods**:
  - `HashMap()`
  - `addDigestSignature()`
  - `addISO9796Signature()`
  - `addPSSSignature()`
  - `addX931Signature()`
  - `configure()`
  - `KeyFactorySpi()`
  - `StringBuilder()`
  - `addPSSSignature()`

---

### BCECPublicKey [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec`
- **Implements**: `ECPublicKey, com.thingclips.bouncycastle.jce.interfaces.ECPublicKey, ECPointEncoder`
- **Methods**: 31
- **Fields**: 24
- **Source**: `provider\asymmetric\ec\BCECPublicKey.java`

**Key Methods**:
  - `BCECPublicKey()`
  - `createSpec()`
  - `ECParameterSpec()`
  - `populateFromPubKeyInfo()`
  - `DEROctetString()`
  - `X9IntegerConverter()`
  - `IllegalArgumentException()`
  - `ECPublicKeyParameters()`
  - `readObject()`
  - `writeObject()`
  - *(... and 21 more)*

---

### KeyAgreementSpi [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec.KeyAgreementSpi`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec`
- **Extends**: `BaseAgreementSpi`
- **Methods**: 32
- **Fields**: 35
- **Source**: `provider\asymmetric\ec\KeyAgreementSpi.java`

**Key Methods**:
  - `X9IntegerConverter()`
  - `C0148DH()`
  - `ECDHBasicAgreement()`
  - `KeyAgreementSpi()`
  - `getSimpleName()`
  - `initFromKey()`
  - `StringBuilder()`
  - `InvalidAlgorithmParameterException()`
  - `MQVPrivateParameters()`
  - `StringBuilder()`
  - *(... and 22 more)*

---

### KeyFactorySpi [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec`
- **Extends**: `BaseKeyFactorySpi`
- **Implements**: `AsymmetricKeyInfoConverter`
- **Methods**: 42
- **Fields**: 13
- **Source**: `provider\asymmetric\ec\KeyFactorySpi.java`

**Key Methods**:
  - `C0149EC()`
  - `ECDH()`
  - `ECDHC()`
  - `ECDSA()`
  - `ECGOST3410()`
  - `ECGOST3410_2012()`
  - `ECMQV()`
  - `KeyFactorySpi()`
  - `engineGeneratePrivate()`
  - `BCECPrivateKey()`
  - *(... and 32 more)*

---

### BCRSAPrivateCrtKey [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa`
- **Extends**: `BCRSAPrivateKey`
- **Implements**: `RSAPrivateCrtKey`
- **Methods**: 26
- **Fields**: 12
- **Source**: `provider\asymmetric\rsa\BCRSAPrivateCrtKey.java`

**Key Methods**:
  - `BCRSAPrivateCrtKey()`
  - `readObject()`
  - `PKCS12BagAttributeCarrierImpl()`
  - `RSAPrivateCrtKeyParameters()`
  - `writeObject()`
  - `equals()`
  - `getModulus()`
  - `getCrtCoefficient()`
  - `getEncoded()`
  - `RSAPrivateKey()`
  - *(... and 16 more)*

---

### KeyFactorySpi [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa`
- **Extends**: `BaseKeyFactorySpi`
- **Methods**: 33
- **Fields**: 7
- **Source**: `provider\asymmetric\rsa\KeyFactorySpi.java`

**Key Methods**:
  - `engineGeneratePrivate()`
  - `generatePrivate()`
  - `BCRSAPrivateCrtKey()`
  - `ExtendedInvalidKeySpecException()`
  - `BCRSAPrivateCrtKey()`
  - `BCRSAPrivateKey()`
  - `InvalidKeySpecException()`
  - `BCRSAPrivateCrtKey()`
  - `InvalidKeySpecException()`
  - `engineGeneratePublic()`
  - *(... and 23 more)*

---

### KeyPairGeneratorSpi [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa`
- **Extends**: `KeyPairGenerator`
- **Methods**: 15
- **Fields**: 11
- **Source**: `provider\asymmetric\rsa\KeyPairGeneratorSpi.java`

**Key Methods**:
  - `AlgorithmIdentifier()`
  - `AlgorithmIdentifier()`
  - `PSS()`
  - `KeyPairGeneratorSpi()`
  - `RSAKeyPairGenerator()`
  - `RSAKeyGenerationParameters()`
  - `generateKeyPair()`
  - `KeyPair()`
  - `BCRSAPrivateCrtKey()`
  - `initialize()`
  - *(... and 5 more)*

---

### BaseCipherSpi [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util`
- **Extends**: `CipherSpi`
- **Methods**: 28
- **Fields**: 19
- **Source**: `provider\asymmetric\util\BaseCipherSpi.java`

**Key Methods**:
  - `BCJcaJceHelper()`
  - `erase()`
  - `getBuf()`
  - `createParametersInstance()`
  - `engineGetBlockSize()`
  - `engineGetIV()`
  - `engineGetKeySize()`
  - `engineGetOutputSize()`
  - `engineGetParameters()`
  - `engineSetMode()`
  - *(... and 18 more)*

---

### BaseKeyFactorySpi [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util`
- **Extends**: `KeyFactorySpi`
- **Implements**: `AsymmetricKeyInfoConverter`
- **Methods**: 12
- **Fields**: 0
- **Source**: `provider\asymmetric\util\BaseKeyFactorySpi.java`

**Key Methods**:
  - `engineGeneratePrivate()`
  - `InvalidKeySpecException()`
  - `generatePrivate()`
  - `InvalidKeySpecException()`
  - `engineGeneratePublic()`
  - `InvalidKeySpecException()`
  - `generatePublic()`
  - `InvalidKeySpecException()`
  - `engineGetKeySpec()`
  - `PKCS8EncodedKeySpec()`
  - *(... and 2 more)*

---

### ECUtil [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.ECUtil`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util`
- **Methods**: 48
- **Fields**: 49
- **Source**: `provider\asymmetric\util\ECUtil.java`

**Key Methods**:
  - `convertMidTerms()`
  - `IllegalArgumentException()`
  - `generateKeyFingerprint()`
  - `Fingerprint()`
  - `Fingerprint()`
  - `generatePrivateKeyParameter()`
  - `ECPrivateKeyParameters()`
  - `ECDomainParameters()`
  - `ECPrivateKeyParameters()`
  - `ECNamedDomainParameters()`
  - *(... and 38 more)*

---

### ExtendedInvalidKeySpecException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.ExtendedInvalidKeySpecException`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util`
- **Extends**: `InvalidKeySpecException`
- **Methods**: 2
- **Fields**: 1
- **Source**: `provider\asymmetric\util\ExtendedInvalidKeySpecException.java`

**Key Methods**:
  - `ExtendedInvalidKeySpecException()`
  - `getCause()`

---

### KeyUtil [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util`
- **Methods**: 8
- **Fields**: 5
- **Source**: `provider\asymmetric\util\KeyUtil.java`

**Key Methods**:
  - `getEncodedPrivateKeyInfo()`
  - `getEncodedPrivateKeyInfo()`
  - `getEncodedSubjectPublicKeyInfo()`
  - `getEncodedSubjectPublicKeyInfo()`
  - `getEncodedSubjectPublicKeyInfo()`
  - `getEncodedSubjectPublicKeyInfo()`
  - `getEncodedPrivateKeyInfo()`
  - `getEncodedSubjectPublicKeyInfo()`

---

### CertificateFactory [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509`
- **Extends**: `CertificateFactorySpi`
- **Methods**: 55
- **Fields**: 41
- **Source**: `provider\asymmetric\x509\CertificateFactory.java`

**Key Methods**:
  - `PEMUtil()`
  - `PEMUtil()`
  - `PEMUtil()`
  - `BCJcaJceHelper()`
  - `doGenerateCRL()`
  - `if()`
  - `getCRL()`
  - `ByteArrayInputStream()`
  - `CRLException()`
  - `doGenerateCertificate()`
  - *(... and 45 more)*

---

### ExtCRLException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.ExtCRLException`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509`
- **Extends**: `CRLException`
- **Methods**: 2
- **Fields**: 1
- **Source**: `provider\asymmetric\x509\ExtCRLException.java`

**Key Methods**:
  - `ExtCRLException()`
  - `getCause()`

---

### PKIXCertPath [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.PKIXCertPath`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509`
- **Extends**: `CertPath`
- **Methods**: 38
- **Fields**: 33
- **Source**: `provider\asymmetric\x509\PKIXCertPath.java`

**Key Methods**:
  - `ArrayList()`
  - `PKIXCertPath()`
  - `BCJcaJceHelper()`
  - `sortCerts()`
  - `ArrayList()`
  - `ArrayList()`
  - `toASN1Object()`
  - `ASN1InputStream()`
  - `CertificateEncodingException()`
  - `toDEREncoded()`
  - *(... and 28 more)*

---

### X509CertificateImpl [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.X509CertificateImpl`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509`
- **Extends**: `X509Certificate`
- **Implements**: `BCX509Certificate`
- **Methods**: 82
- **Fields**: 86
- **Source**: `provider\asymmetric\x509\X509CertificateImpl.java`

**Key Methods**:
  - `X509CertificateImpl()`
  - `checkSignature()`
  - `CertificateException()`
  - `BufferedOutputStream()`
  - `SignatureException()`
  - `CertificateEncodingException()`
  - `doVerify()`
  - `InvalidKeyException()`
  - `InvalidKeyException()`
  - `InvalidKeyException()`
  - *(... and 72 more)*

---

### X509CRLImpl [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.X509CRLImpl`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509`
- **Extends**: `X509CRL`
- **Methods**: 61
- **Fields**: 65
- **Source**: `provider\asymmetric\x509\X509CRLImpl.java`

**Key Methods**:
  - `X509CRLImpl()`
  - `checkSignature()`
  - `BufferedOutputStream()`
  - `SignatureException()`
  - `CRLException()`
  - `doVerify()`
  - `CRLException()`
  - `InvalidKeyException()`
  - `SignatureException()`
  - `InvalidKeyException()`
  - *(... and 51 more)*

---

### X509CRLObject [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.X509CRLObject`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509`
- **Extends**: `X509CRLImpl`
- **Methods**: 20
- **Fields**: 21
- **Source**: `provider\asymmetric\x509\X509CRLObject.java`

**Key Methods**:
  - `X509CRLObject()`
  - `Object()`
  - `createSigAlgName()`
  - `X509CRLException()`
  - `createSigAlgParams()`
  - `CRLException()`
  - `getInternalCRL()`
  - `X509CRLException()`
  - `X509CRLInternal()`
  - `isIndirectCRL()`
  - *(... and 10 more)*

---

### X509SignatureUtil [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.X509SignatureUtil`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509`
- **Methods**: 10
- **Fields**: 21
- **Source**: `provider\asymmetric\x509\X509SignatureUtil.java`

**Key Methods**:
  - `HashMap()`
  - `findAlgName()`
  - `getDigestAlgName()`
  - `getSignatureName()`
  - `isCompositeAlgorithm()`
  - `lookupAlg()`
  - `prettyPrintSignature()`
  - `setSignatureParameters()`
  - `SignatureException()`
  - `SignatureException()`

---

### ConfigurableProvider [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.config.ConfigurableProvider`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.config`
- **Methods**: 6
- **Fields**: 6
- **Source**: `jcajce\provider\config\ConfigurableProvider.java`

**Key Methods**:
  - `addAlgorithm()`
  - `addAlgorithm()`
  - `addAttributes()`
  - `addKeyInfoConverter()`
  - `hasAlgorithm()`
  - `setParameter()`

---

### ProviderConfiguration [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.config.ProviderConfiguration`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.config`
- **Methods**: 5
- **Fields**: 0
- **Source**: `jcajce\provider\config\ProviderConfiguration.java`

**Key Methods**:
  - `getAcceptableNamedCurves()`
  - `getAdditionalECParameters()`
  - `getDHDefaultParameters()`
  - `getDSADefaultParameters()`
  - `getEcImplicitlyCa()`

---

### ProviderConfigurationPermission [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.config.ProviderConfigurationPermission`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.config`
- **Extends**: `BasicPermission`
- **Methods**: 16
- **Fields**: 26
- **Source**: `jcajce\provider\config\ProviderConfigurationPermission.java`

**Key Methods**:
  - `ProviderConfigurationPermission()`
  - `calculateMask()`
  - `StringTokenizer()`
  - `if()`
  - `if()`
  - `if()`
  - `if()`
  - `if()`
  - `if()`
  - `IllegalArgumentException()`
  - *(... and 6 more)*

---

### DigestAlgorithmProvider [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.digest.DigestAlgorithmProvider`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.digest`
- **Extends**: `AlgorithmProvider`
- **Methods**: 2
- **Fields**: 2
- **Source**: `jcajce\provider\digest\DigestAlgorithmProvider.java`

**Key Methods**:
  - `addHMACAlgorithm()`
  - `addHMACAlias()`

---

### SHA256 [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.digest.SHA256`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.digest`
- **Extends**: `BCMessageDigest`
- **Implements**: `Cloneable`
- **Methods**: 11
- **Fields**: 7
- **Source**: `jcajce\provider\digest\SHA256.java`

**Key Methods**:
  - `Digest()`
  - `clone()`
  - `SHA256Digest()`
  - `HashMac()`
  - `KeyGenerator()`
  - `CipherKeyGenerator()`
  - `configure()`
  - `StringBuilder()`
  - `StringBuilder()`
  - `PBEWithMacKeyFactory()`
  - *(... and 1 more)*

---

### BaseKeyGenerator [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.symmetric.util`
- **Extends**: `KeyGeneratorSpi`
- **Methods**: 8
- **Fields**: 5
- **Source**: `provider\symmetric\util\BaseKeyGenerator.java`

**Key Methods**:
  - `BaseKeyGenerator()`
  - `engineGenerateKey()`
  - `SecretKeySpec()`
  - `engineInit()`
  - `InvalidAlgorithmParameterException()`
  - `engineInit()`
  - `engineInit()`
  - `InvalidParameterException()`

---

### BaseSecretKeyFactory [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.symmetric.util`
- **Extends**: `SecretKeyFactorySpi`
- **Implements**: `PBE`
- **Methods**: 13
- **Fields**: 2
- **Source**: `provider\symmetric\util\BaseSecretKeyFactory.java`

**Key Methods**:
  - `BaseSecretKeyFactory()`
  - `engineGenerateSecret()`
  - `SecretKeySpec()`
  - `InvalidKeySpecException()`
  - `engineGetKeySpec()`
  - `InvalidKeySpecException()`
  - `InvalidKeySpecException()`
  - `SecretKeySpec()`
  - `InvalidKeySpecException()`
  - `engineTranslateKey()`
  - *(... and 3 more)*

---

### BCPBEKey [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.symmetric.util`
- **Implements**: `PBEKey, Destroyable`
- **Methods**: 23
- **Fields**: 18
- **Source**: `provider\symmetric\util\BCPBEKey.java`

**Key Methods**:
  - `BCPBEKey()`
  - `AtomicBoolean()`
  - `checkDestroyed()`
  - `IllegalStateException()`
  - `destroy()`
  - `getAlgorithm()`
  - `getDigest()`
  - `getEncoded()`
  - `getFormat()`
  - `getIterationCount()`
  - *(... and 13 more)*

---

### AlgorithmProvider [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.util.AlgorithmProvider`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.util`
- **Methods**: 1
- **Fields**: 0
- **Source**: `jcajce\provider\util\AlgorithmProvider.java`

**Key Methods**:
  - `configure()`

---

### AsymmetricAlgorithmProvider [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.util`
- **Extends**: `AlgorithmProvider`
- **Methods**: 6
- **Fields**: 4
- **Source**: `jcajce\provider\util\AsymmetricAlgorithmProvider.java`

**Key Methods**:
  - `addSignatureAlgorithm()`
  - `registerOid()`
  - `registerOidAlgorithmParameterGenerator()`
  - `registerOidAlgorithmParameters()`
  - `addSignatureAlgorithm()`
  - `addSignatureAlgorithm()`

---

### BadBlockException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.provider.util.BadBlockException`
- **Package**: `com.thingclips.bouncycastle.jcajce.provider.util`
- **Extends**: `BadPaddingException`
- **Methods**: 2
- **Fields**: 1
- **Source**: `jcajce\provider\util\BadBlockException.java`

**Key Methods**:
  - `BadBlockException()`
  - `getCause()`

---

### CompositeAlgorithmSpec [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.spec.CompositeAlgorithmSpec`
- **Package**: `com.thingclips.bouncycastle.jcajce.spec`
- **Implements**: `AlgorithmParameterSpec`
- **Methods**: 10
- **Fields**: 6
- **Source**: `bouncycastle\jcajce\spec\CompositeAlgorithmSpec.java`

**Key Methods**:
  - `CompositeAlgorithmSpec()`
  - `getAlgorithmNames()`
  - `getParameterSpecs()`
  - `ArrayList()`
  - `ArrayList()`
  - `add()`
  - `build()`
  - `IllegalStateException()`
  - `CompositeAlgorithmSpec()`
  - `add()`

---

### SkeinParameterSpec [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.spec.SkeinParameterSpec`
- **Package**: `com.thingclips.bouncycastle.jcajce.spec`
- **Implements**: `AlgorithmParameterSpec`
- **Methods**: 37
- **Fields**: 15
- **Source**: `bouncycastle\jcajce\spec\SkeinParameterSpec.java`

**Key Methods**:
  - `HashMap()`
  - `Builder()`
  - `build()`
  - `SkeinParameterSpec()`
  - `set()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `setKey()`
  - `set()`
  - *(... and 27 more)*

---

### AlgorithmParametersUtils [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jcajce.util.AlgorithmParametersUtils`
- **Package**: `com.thingclips.bouncycastle.jcajce.util`
- **Methods**: 3
- **Fields**: 0
- **Source**: `bouncycastle\jcajce\util\AlgorithmParametersUtils.java`

**Key Methods**:
  - `AlgorithmParametersUtils()`
  - `extractParameters()`
  - `loadParameters()`

---

### ECGOST3410NamedCurveTable [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jce.ECGOST3410NamedCurveTable`
- **Package**: `com.thingclips.bouncycastle.jce`
- **Methods**: 3
- **Fields**: 3
- **Source**: `thingclips\bouncycastle\jce\ECGOST3410NamedCurveTable.java`

**Key Methods**:
  - `getNames()`
  - `getParameterSpec()`
  - `ECNamedCurveParameterSpec()`

---

### ECNamedCurveTable [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jce.ECNamedCurveTable`
- **Package**: `com.thingclips.bouncycastle.jce`
- **Methods**: 3
- **Fields**: 2
- **Source**: `thingclips\bouncycastle\jce\ECNamedCurveTable.java`

**Key Methods**:
  - `getNames()`
  - `getParameterSpec()`
  - `ECNamedCurveParameterSpec()`

---

### X509Principal [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jce.X509Principal`
- **Package**: `com.thingclips.bouncycastle.jce`
- **Extends**: `X509Name`
- **Implements**: `Principal`
- **Methods**: 16
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\jce\X509Principal.java`

**Key Methods**:
  - `X509Principal()`
  - `readSequence()`
  - `IOException()`
  - `getEncoded()`
  - `getEncoded()`
  - `RuntimeException()`
  - `getName()`
  - `toString()`
  - `X509Principal()`
  - `X509Principal()`
  - *(... and 6 more)*

---

### BouncyCastleProvider [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jce.provider.BouncyCastleProvider`
- **Package**: `com.thingclips.bouncycastle.jce.provider`
- **Extends**: `Provider`
- **Implements**: `ConfigurableProvider`
- **Methods**: 18
- **Fields**: 23
- **Source**: `bouncycastle\jce\provider\BouncyCastleProvider.java`

**Key Methods**:
  - `BouncyCastleProviderConfiguration()`
  - `HashMap()`
  - `BouncyCastleProvider()`
  - `run()`
  - `getAsymmetricKeyInfoConverter()`
  - `getPrivateKey()`
  - `getPublicKey()`
  - `loadAlgorithms()`
  - `InternalError()`
  - `setup()`
  - *(... and 8 more)*

---

### ECNamedCurveSpec [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.jce.spec.ECNamedCurveSpec`
- **Package**: `com.thingclips.bouncycastle.jce.spec`
- **Extends**: `java.security.spec.ECParameterSpec`
- **Methods**: 11
- **Fields**: 3
- **Source**: `bouncycastle\jce\spec\ECNamedCurveSpec.java`

**Key Methods**:
  - `ECNamedCurveSpec()`
  - `convertCurve()`
  - `EllipticCurve()`
  - `convertField()`
  - `ECFieldFp()`
  - `ECFieldF2m()`
  - `getName()`
  - `ECNamedCurveSpec()`
  - `ECNamedCurveSpec()`
  - `ECNamedCurveSpec()`
  - *(... and 1 more)*

---

### AbstractECLookupTable [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.AbstractECLookupTable`
- **Package**: `com.thingclips.bouncycastle.math.ec`
- **Implements**: `ECLookupTable`
- **Methods**: 2
- **Fields**: 0
- **Source**: `bouncycastle\math\ec\AbstractECLookupTable.java`

**Key Methods**:
  - `lookupVar()`
  - `lookup()`

---

### ECFieldElement [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.ECFieldElement`
- **Package**: `com.thingclips.bouncycastle.math.ec`
- **Extends**: `ECFieldElement`
- **Implements**: `ECConstants`
- **Methods**: 136
- **Fields**: 126
- **Source**: `bouncycastle\math\ec\ECFieldElement.java`

**Key Methods**:
  - `halfTrace()`
  - `IllegalStateException()`
  - `hasFastTrace()`
  - `trace()`
  - `IllegalStateException()`
  - `C0170Fp()`
  - `calculateResidue()`
  - `checkSqrt()`
  - `lucasSequence()`
  - `add()`
  - *(... and 126 more)*

---

### ECLookupTable [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.ECLookupTable`
- **Package**: `com.thingclips.bouncycastle.math.ec`
- **Methods**: 3
- **Fields**: 0
- **Source**: `bouncycastle\math\ec\ECLookupTable.java`

**Key Methods**:
  - `getSize()`
  - `lookup()`
  - `lookupVar()`

---

### FixedPointCombMultiplier [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.FixedPointCombMultiplier`
- **Package**: `com.thingclips.bouncycastle.math.ec`
- **Extends**: `AbstractECMultiplier`
- **Methods**: 2
- **Fields**: 12
- **Source**: `bouncycastle\math\ec\FixedPointCombMultiplier.java`

**Key Methods**:
  - `multiplyPositive()`
  - `IllegalStateException()`

---

### FixedPointPreCompInfo [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.FixedPointPreCompInfo`
- **Package**: `com.thingclips.bouncycastle.math.ec`
- **Implements**: `PreCompInfo`
- **Methods**: 6
- **Fields**: 3
- **Source**: `bouncycastle\math\ec\FixedPointPreCompInfo.java`

**Key Methods**:
  - `getLookupTable()`
  - `getOffset()`
  - `getWidth()`
  - `setLookupTable()`
  - `setOffset()`
  - `setWidth()`

---

### FixedPointUtil [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.FixedPointUtil`
- **Package**: `com.thingclips.bouncycastle.math.ec`
- **Methods**: 8
- **Fields**: 21
- **Source**: `bouncycastle\math\ec\FixedPointUtil.java`

**Key Methods**:
  - `getCombSize()`
  - `getFixedPointPreCompInfo()`
  - `precompute()`
  - `PreCompCallback()`
  - `checkExisting()`
  - `checkTable()`
  - `precompute()`
  - `FixedPointPreCompInfo()`

---

### Tnaf [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.Tnaf`
- **Package**: `com.thingclips.bouncycastle.math.ec`
- **Methods**: 38
- **Fields**: 99
- **Source**: `bouncycastle\math\ec\Tnaf.java`

**Key Methods**:
  - `ZTauElement()`
  - `ZTauElement()`
  - `ZTauElement()`
  - `ZTauElement()`
  - `ZTauElement()`
  - `ZTauElement()`
  - `ZTauElement()`
  - `ZTauElement()`
  - `approximateDivisionByN()`
  - `SimpleBigDecimal()`
  - *(... and 28 more)*

---

### WNafL2RMultiplier [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.WNafL2RMultiplier`
- **Package**: `com.thingclips.bouncycastle.math.ec`
- **Extends**: `AbstractECMultiplier`
- **Methods**: 1
- **Fields**: 20
- **Source**: `bouncycastle\math\ec\WNafL2RMultiplier.java`

**Key Methods**:
  - `multiplyPositive()`

---

### WNafUtil [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.WNafUtil`
- **Package**: `com.thingclips.bouncycastle.math.ec`
- **Methods**: 45
- **Fields**: 123
- **Source**: `bouncycastle\math\ec\WNafUtil.java`

**Key Methods**:
  - `configureBasepoint()`
  - `PreCompCallback()`
  - `precompute()`
  - `WNafPreCompInfo()`
  - `generateCompactNaf()`
  - `IllegalArgumentException()`
  - `generateCompactWindowNaf()`
  - `generateCompactNaf()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - *(... and 35 more)*

---

### Curve25519 [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.custom.djb.Curve25519`
- **Package**: `com.thingclips.bouncycastle.math.ec.custom.djb`
- **Extends**: `ECCurve.AbstractFp`
- **Methods**: 31
- **Fields**: 30
- **Source**: `ec\custom\djb\Curve25519.java`

**Key Methods**:
  - `BigInteger()`
  - `BigInteger()`
  - `Curve25519FieldElement()`
  - `Curve25519()`
  - `Curve25519Point()`
  - `BigInteger()`
  - `cloneCurve()`
  - `Curve25519()`
  - `createCacheSafeLookupTable()`
  - `AbstractECLookupTable()`
  - *(... and 21 more)*

---

### SecP256R1Curve [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.custom.sec.SecP256R1Curve`
- **Package**: `com.thingclips.bouncycastle.math.ec.custom.sec`
- **Extends**: `ECCurve.AbstractFp`
- **Methods**: 28
- **Fields**: 27
- **Source**: `ec\custom\sec\SecP256R1Curve.java`

**Key Methods**:
  - `SecP256R1Curve()`
  - `SecP256R1Point()`
  - `BigInteger()`
  - `cloneCurve()`
  - `SecP256R1Curve()`
  - `createCacheSafeLookupTable()`
  - `AbstractECLookupTable()`
  - `createPoint()`
  - `SecP256R1FieldElement()`
  - `getSize()`
  - *(... and 18 more)*

---

### X25519 [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.rfc7748.X25519`
- **Package**: `com.thingclips.bouncycastle.math.ec.rfc7748`
- **Extends**: `X25519Field`
- **Methods**: 12
- **Fields**: 25
- **Source**: `math\ec\rfc7748\X25519.java`

**Key Methods**:
  - `C0182F()`
  - `Friend()`
  - `Friend()`
  - `calculateAgreement()`
  - `decode32()`
  - `decodeScalar()`
  - `generatePrivateKey()`
  - `generatePublicKey()`
  - `pointDouble()`
  - `precompute()`
  - *(... and 2 more)*

---

### X25519Field [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.rfc7748.X25519Field`
- **Package**: `com.thingclips.bouncycastle.math.ec.rfc7748`
- **Methods**: 45
- **Fields**: 350
- **Source**: `math\ec\rfc7748\X25519Field.java`

**Key Methods**:
  - `add()`
  - `addOne()`
  - `apm()`
  - `areEqual()`
  - `areEqualVar()`
  - `areEqual()`
  - `carry()`
  - `cmov()`
  - `cnegate()`
  - `copy()`
  - *(... and 35 more)*

---

### X448 [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.rfc7748.X448`
- **Package**: `com.thingclips.bouncycastle.math.ec.rfc7748`
- **Extends**: `X448Field`
- **Methods**: 12
- **Fields**: 23
- **Source**: `math\ec\rfc7748\X448.java`

**Key Methods**:
  - `C0183F()`
  - `Friend()`
  - `Friend()`
  - `calculateAgreement()`
  - `decode32()`
  - `decodeScalar()`
  - `generatePrivateKey()`
  - `generatePublicKey()`
  - `pointDouble()`
  - `precompute()`
  - *(... and 2 more)*

---

### X448Field [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.rfc7748.X448Field`
- **Package**: `com.thingclips.bouncycastle.math.ec.rfc7748`
- **Methods**: 46
- **Fields**: 611
- **Source**: `math\ec\rfc7748\X448Field.java`

**Key Methods**:
  - `add()`
  - `addOne()`
  - `areEqual()`
  - `areEqualVar()`
  - `areEqual()`
  - `carry()`
  - `cmov()`
  - `cnegate()`
  - `copy()`
  - `create()`
  - *(... and 36 more)*

---

### Ed25519 [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.ec.rfc8032.Ed25519`
- **Package**: `com.thingclips.bouncycastle.math.ec.rfc8032`
- **Extends**: `X25519Field`
- **Methods**: 115
- **Fields**: 383
- **Source**: `math\ec\rfc8032\Ed25519.java`

**Key Methods**:
  - `Object()`
  - `C0185F()`
  - `PointAccum()`
  - `PointAffine()`
  - `PointExt()`
  - `PointPrecomp()`
  - `calculateS()`
  - `reduceScalar()`
  - `checkContextVar()`
  - `checkPoint()`
  - *(... and 105 more)*

---

### FiniteField [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.field.FiniteField`
- **Package**: `com.thingclips.bouncycastle.math.field`
- **Methods**: 2
- **Fields**: 0
- **Source**: `bouncycastle\math\field\FiniteField.java`

**Key Methods**:
  - `getCharacteristic()`
  - `getDimension()`

---

### GenericPolynomialExtensionField [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.field.GenericPolynomialExtensionField`
- **Package**: `com.thingclips.bouncycastle.math.field`
- **Implements**: `PolynomialExtensionField`
- **Methods**: 8
- **Fields**: 5
- **Source**: `bouncycastle\math\field\GenericPolynomialExtensionField.java`

**Key Methods**:
  - `GenericPolynomialExtensionField()`
  - `equals()`
  - `getCharacteristic()`
  - `getDegree()`
  - `getDimension()`
  - `getMinimalPolynomial()`
  - `getSubfield()`
  - `hashCode()`

---

### PrimeField [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.field.PrimeField`
- **Package**: `com.thingclips.bouncycastle.math.field`
- **Implements**: `FiniteField`
- **Methods**: 5
- **Fields**: 4
- **Source**: `bouncycastle\math\field\PrimeField.java`

**Key Methods**:
  - `PrimeField()`
  - `equals()`
  - `getCharacteristic()`
  - `getDimension()`
  - `hashCode()`

---

### Interleave [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.raw.Interleave`
- **Package**: `com.thingclips.bouncycastle.math.raw`
- **Methods**: 17
- **Fields**: 13
- **Source**: `bouncycastle\math\raw\Interleave.java`

**Key Methods**:
  - `expand16to32()`
  - `expand32to64()`
  - `expand64To128()`
  - `expand64To128Rev()`
  - `expand8to16()`
  - `shuffle()`
  - `shuffle2()`
  - `shuffle3()`
  - `unshuffle()`
  - `unshuffle2()`
  - *(... and 7 more)*

---

### Mod [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.math.raw.Mod`
- **Package**: `com.thingclips.bouncycastle.math.raw`
- **Methods**: 23
- **Fields**: 211
- **Source**: `bouncycastle\math\raw\Mod.java`

**Key Methods**:
  - `add()`
  - `add30()`
  - `checkedModOddInverse()`
  - `ArithmeticException()`
  - `checkedModOddInverseVar()`
  - `ArithmeticException()`
  - `cnegate30()`
  - `cnormalize30()`
  - `decode30()`
  - `divsteps30()`
  - *(... and 13 more)*

---

### DefaultSignatureAlgorithmIdentifierFinder [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder`
- **Package**: `com.thingclips.bouncycastle.operator`
- **Implements**: `SignatureAlgorithmIdentifierFinder`
- **Methods**: 16
- **Fields**: 166
- **Source**: `thingclips\bouncycastle\operator\DefaultSignatureAlgorithmIdentifierFinder.java`

**Key Methods**:
  - `HashMap()`
  - `HashSet()`
  - `HashMap()`
  - `HashSet()`
  - `HashMap()`
  - `createPSSParams()`
  - `RSASSAPSSparams()`
  - `ASN1Integer()`
  - `ASN1Integer()`
  - `generate()`
  - *(... and 6 more)*

---

### OperatorCreationException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.operator.OperatorCreationException`
- **Package**: `com.thingclips.bouncycastle.operator`
- **Extends**: `OperatorException`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\operator\OperatorCreationException.java`

**Key Methods**:
  - `OperatorCreationException()`
  - `OperatorCreationException()`

---

### OperatorException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.operator.OperatorException`
- **Package**: `com.thingclips.bouncycastle.operator`
- **Extends**: `Exception`
- **Methods**: 3
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\operator\OperatorException.java`

**Key Methods**:
  - `OperatorException()`
  - `getCause()`
  - `OperatorException()`

---

### RuntimeOperatorException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.operator.RuntimeOperatorException`
- **Package**: `com.thingclips.bouncycastle.operator`
- **Extends**: `RuntimeException`
- **Methods**: 3
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\operator\RuntimeOperatorException.java`

**Key Methods**:
  - `RuntimeOperatorException()`
  - `getCause()`
  - `RuntimeOperatorException()`

---

### JcaContentSignerBuilder [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.operator.jcajce.JcaContentSignerBuilder`
- **Package**: `com.thingclips.bouncycastle.operator.jcajce`
- **Methods**: 44
- **Fields**: 34
- **Source**: `bouncycastle\operator\jcajce\JcaContentSignerBuilder.java`

**Key Methods**:
  - `JcaContentSignerBuilder()`
  - `OperatorHelper()`
  - `DefaultSignatureAlgorithmIdentifierFinder()`
  - `buildComposite()`
  - `TeeOutputStream()`
  - `ContentSigner()`
  - `getAlgorithmIdentifier()`
  - `getOutputStream()`
  - `getSignature()`
  - `ASN1EncodableVector()`
  - *(... and 34 more)*

---

### OperatorHelper [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.operator.jcajce.OperatorHelper`
- **Package**: `com.thingclips.bouncycastle.operator.jcajce`
- **Extends**: `CertificateException`
- **Methods**: 40
- **Fields**: 52
- **Source**: `bouncycastle\operator\jcajce\OperatorHelper.java`

**Key Methods**:
  - `OpCertificateException()`
  - `getCause()`
  - `HashMap()`
  - `HashMap()`
  - `HashMap()`
  - `HashMap()`
  - `HashMap()`
  - `OperatorHelper()`
  - `getDigestName()`
  - `getSignatureName()`
  - *(... and 30 more)*

---

### PKCS10CertificationRequest [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.pkcs.PKCS10CertificationRequest`
- **Package**: `com.thingclips.bouncycastle.pkcs`
- **Methods**: 22
- **Fields**: 18
- **Source**: `thingclips\bouncycastle\pkcs\PKCS10CertificationRequest.java`

**Key Methods**:
  - `PKCS10CertificationRequest()`
  - `NullPointerException()`
  - `parseBytes()`
  - `PKCSIOException()`
  - `PKCSIOException()`
  - `PKCSIOException()`
  - `equals()`
  - `toASN1Structure()`
  - `getAttributes()`
  - `getEncoded()`
  - *(... and 12 more)*

---

### PKCS10CertificationRequestBuilder [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.pkcs.PKCS10CertificationRequestBuilder`
- **Package**: `com.thingclips.bouncycastle.pkcs`
- **Methods**: 22
- **Fields**: 15
- **Source**: `thingclips\bouncycastle\pkcs\PKCS10CertificationRequestBuilder.java`

**Key Methods**:
  - `PKCS10CertificationRequestBuilder()`
  - `ArrayList()`
  - `ArrayList()`
  - `addAttribute()`
  - `DERSet()`
  - `build()`
  - `CertificationRequestInfo()`
  - `CertificationRequestInfo()`
  - `ASN1EncodableVector()`
  - `CertificationRequestInfo()`
  - *(... and 12 more)*

---

### PKCSException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.pkcs.PKCSException`
- **Package**: `com.thingclips.bouncycastle.pkcs`
- **Extends**: `Exception`
- **Methods**: 3
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\pkcs\PKCSException.java`

**Key Methods**:
  - `PKCSException()`
  - `getCause()`
  - `PKCSException()`

---

### PKCSIOException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.pkcs.PKCSIOException`
- **Package**: `com.thingclips.bouncycastle.pkcs`
- **Extends**: `IOException`
- **Methods**: 3
- **Fields**: 1
- **Source**: `thingclips\bouncycastle\pkcs\PKCSIOException.java`

**Key Methods**:
  - `PKCSIOException()`
  - `getCause()`
  - `PKCSIOException()`

---

### BigIntegers [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.BigIntegers`
- **Package**: `com.thingclips.bouncycastle.util`
- **Methods**: 34
- **Fields**: 50
- **Source**: `thingclips\bouncycastle\util\BigIntegers.java`

**Key Methods**:
  - `BigInteger()`
  - `asUnsignedByteArray()`
  - `createRandom()`
  - `IllegalArgumentException()`
  - `createRandomBigInteger()`
  - `BigInteger()`
  - `createRandomInRange()`
  - `IllegalArgumentException()`
  - `createRandomInRange()`
  - `createRandomBigInteger()`
  - *(... and 24 more)*

---

### Encodable [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.Encodable`
- **Package**: `com.thingclips.bouncycastle.util`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\util\Encodable.java`

**Key Methods**:
  - `getEncoded()`

---

### Iterable [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.Iterable`
- **Package**: `com.thingclips.bouncycastle.util`
- **Extends**: `java.lang.Iterable<T>`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\util\Iterable.java`

**Key Methods**:
  - `iterator()`

---

### Memoable [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.Memoable`
- **Package**: `com.thingclips.bouncycastle.util`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\util\Memoable.java`

**Key Methods**:
  - `copy()`
  - `reset()`

---

### MemoableResetException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.MemoableResetException`
- **Package**: `com.thingclips.bouncycastle.util`
- **Extends**: `ClassCastException`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\util\MemoableResetException.java`

**Key Methods**:
  - `MemoableResetException()`

---

### Properties [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.Properties`
- **Package**: `com.thingclips.bouncycastle.util`
- **Methods**: 18
- **Fields**: 30
- **Source**: `thingclips\bouncycastle\util\Properties.java`

**Key Methods**:
  - `ThreadLocal()`
  - `Properties()`
  - `asBigInteger()`
  - `BigInteger()`
  - `asKeySet()`
  - `HashSet()`
  - `StringTokenizer()`
  - `getPropertyValue()`
  - `run()`
  - `run()`
  - *(... and 8 more)*

---

### Selector [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.Selector`
- **Package**: `com.thingclips.bouncycastle.util`
- **Extends**: `Cloneable`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\util\Selector.java`

**Key Methods**:
  - `clone()`
  - `match()`

---

### StringList [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.StringList`
- **Package**: `com.thingclips.bouncycastle.util`
- **Extends**: `Iterable<String>`
- **Methods**: 5
- **Fields**: 0
- **Source**: `thingclips\bouncycastle\util\StringList.java`

**Key Methods**:
  - `add()`
  - `get()`
  - `size()`
  - `toStringArray()`
  - `toStringArray()`

---

### Strings [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.Strings`
- **Package**: `com.thingclips.bouncycastle.util`
- **Extends**: `ArrayList<String>`
- **Implements**: `StringList`
- **Methods**: 37
- **Fields**: 42
- **Source**: `thingclips\bouncycastle\util\Strings.java`

**Key Methods**:
  - `StringListImpl()`
  - `get()`
  - `toStringArray()`
  - `set()`
  - `add()`
  - `toStringArray()`
  - `add()`
  - `run()`
  - `asCharArray()`
  - `constantTimeAreEqual()`
  - *(... and 27 more)*

---

### Base64 [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.encoders.Base64`
- **Package**: `com.thingclips.bouncycastle.util.encoders`
- **Methods**: 20
- **Fields**: 5
- **Source**: `bouncycastle\util\encoders\Base64.java`

**Key Methods**:
  - `Base64Encoder()`
  - `decode()`
  - `ByteArrayOutputStream()`
  - `DecoderException()`
  - `encode()`
  - `encode()`
  - `toBase64String()`
  - `toBase64String()`
  - `encode()`
  - `ByteArrayOutputStream()`
  - *(... and 10 more)*

---

### Base64Encoder [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.encoders.Base64Encoder`
- **Package**: `com.thingclips.bouncycastle.util.encoders`
- **Implements**: `Encoder`
- **Methods**: 19
- **Fields**: 93
- **Source**: `bouncycastle\util\encoders\Base64Encoder.java`

**Key Methods**:
  - `Base64Encoder()`
  - `decodeLastBlock()`
  - `IOException()`
  - `IOException()`
  - `IOException()`
  - `IOException()`
  - `ignore()`
  - `nextI()`
  - `decode()`
  - `IOException()`
  - *(... and 9 more)*

---

### DecoderException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.encoders.DecoderException`
- **Package**: `com.thingclips.bouncycastle.util.encoders`
- **Extends**: `IllegalStateException`
- **Methods**: 2
- **Fields**: 1
- **Source**: `bouncycastle\util\encoders\DecoderException.java`

**Key Methods**:
  - `DecoderException()`
  - `getCause()`

---

### EncoderException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.encoders.EncoderException`
- **Package**: `com.thingclips.bouncycastle.util.encoders`
- **Extends**: `IllegalStateException`
- **Methods**: 2
- **Fields**: 1
- **Source**: `bouncycastle\util\encoders\EncoderException.java`

**Key Methods**:
  - `EncoderException()`
  - `getCause()`

---

### HexEncoder [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.encoders.HexEncoder`
- **Package**: `com.thingclips.bouncycastle.util.encoders`
- **Implements**: `Encoder`
- **Methods**: 16
- **Fields**: 45
- **Source**: `bouncycastle\util\encoders\HexEncoder.java`

**Key Methods**:
  - `HexEncoder()`
  - `ignore()`
  - `decode()`
  - `IOException()`
  - `decodeStrict()`
  - `NullPointerException()`
  - `IndexOutOfBoundsException()`
  - `IOException()`
  - `IOException()`
  - `encode()`
  - *(... and 6 more)*

---

### UTF8 [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.encoders.UTF8`
- **Package**: `com.thingclips.bouncycastle.util.encoders`
- **Methods**: 2
- **Fields**: 40
- **Source**: `bouncycastle\util\encoders\UTF8.java`

**Key Methods**:
  - `fill()`
  - `transcodeToUTF16()`

---

### TeeInputStream [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.io.TeeInputStream`
- **Package**: `com.thingclips.bouncycastle.util.io`
- **Extends**: `InputStream`
- **Methods**: 8
- **Fields**: 6
- **Source**: `bouncycastle\util\io\TeeInputStream.java`

**Key Methods**:
  - `TeeInputStream()`
  - `available()`
  - `close()`
  - `getOutputStream()`
  - `read()`
  - `read()`
  - `read()`
  - `read()`

---

### TeeOutputStream [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.io.TeeOutputStream`
- **Package**: `com.thingclips.bouncycastle.util.io`
- **Extends**: `OutputStream`
- **Methods**: 6
- **Fields**: 2
- **Source**: `bouncycastle\util\io\TeeOutputStream.java`

**Key Methods**:
  - `TeeOutputStream()`
  - `close()`
  - `flush()`
  - `write()`
  - `write()`
  - `write()`

---

### PemGenerationException [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.io.pem.PemGenerationException`
- **Package**: `com.thingclips.bouncycastle.util.io.pem`
- **Extends**: `IOException`
- **Methods**: 3
- **Fields**: 1
- **Source**: `util\io\pem\PemGenerationException.java`

**Key Methods**:
  - `PemGenerationException()`
  - `getCause()`
  - `PemGenerationException()`

---

### PemObject [MEDIUM]


- **Full Name**: `com.thingclips.bouncycastle.util.io.pem.PemObject`
- **Package**: `com.thingclips.bouncycastle.util.io.pem`
- **Implements**: `PemObjectGenerator`
- **Methods**: 6
- **Fields**: 5
- **Source**: `util\io\pem\PemObject.java`

**Key Methods**:
  - `PemObject()`
  - `generate()`
  - `getContent()`
  - `getHeaders()`
  - `getType()`
  - `PemObject()`

---

### DecryptImageRequest [MEDIUM]


- **Full Name**: `com.thingclips.imagepipeline.okhttp3.DecryptImageRequest`
- **Package**: `com.thingclips.imagepipeline.okhttp3`
- **Extends**: `ImageRequest`
- **Methods**: 11
- **Fields**: 12
- **Source**: `thingclips\imagepipeline\okhttp3\DecryptImageRequest.java`

**Key Methods**:
  - `DecryptImageRequest()`
  - `byteArray2Int()`
  - `IOException()`
  - `decryptHead()`
  - `IOException()`
  - `decryptStream()`
  - `getKey()`
  - `isExtraDiskCacheDisabled()`
  - `isValid()`
  - `setExtraDiskCacheDisabled()`
  - *(... and 1 more)*

---

### C0195R [MEDIUM]


- **Full Name**: `com.thingclips.libalgorithm.C0195R`
- **Package**: `com.thingclips.libalgorithm`
- **Methods**: 16
- **Fields**: 5788
- **Source**: `com\thingclips\libalgorithm\C0195R.java`

**Key Methods**:
  - `anim()`
  - `animator()`
  - `attr()`
  - `bool()`
  - `color()`
  - `dimen()`
  - `drawable()`
  - `id()`
  - `integer()`
  - `interpolator()`
  - *(... and 6 more)*

---

### ISceneContext [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.ISceneContext`
- **Package**: `com.thingclips.scene.core`
- **Methods**: 3
- **Fields**: 0
- **Source**: `thingclips\scene\core\ISceneContext.java`

**Key Methods**:
  - `env()`
  - `getNeedOutputs()`
  - `inputs()`

---

### DefaultImpls [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.DefaultImpls`
- **Package**: `com.thingclips.scene.core`
- **Extends**: `ISceneBizContainer`
- **Methods**: 5
- **Fields**: 0
- **Source**: `thingclips\scene\core\ISceneEditBizContainer.java`

**Key Methods**:
  - `UnsupportedOperationException()`
  - `UnsupportedOperationException()`
  - `updateEditScene()`
  - `updateEditSceneActions()`
  - `updateEditSceneConditions()`

---

### ThingSceneContext [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.ThingSceneContext`
- **Package**: `com.thingclips.scene.core`
- **Implements**: `ContainerHolder, ISceneContext`
- **Methods**: 6
- **Fields**: 5
- **Source**: `thingclips\scene\core\ThingSceneContext.java`

**Key Methods**:
  - `ThingSceneContext()`
  - `getEnv()`
  - `getContainer()`
  - `getCtx()`
  - `getNeedOutputs()`
  - `getBundle()`

---

### ActionBase [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.bean.ActionBase`
- **Package**: `com.thingclips.scene.core.bean`
- **Implements**: `IAction, Serializable`
- **Methods**: 24
- **Fields**: 8
- **Source**: `scene\core\bean\ActionBase.java`

**Key Methods**:
  - `getActionExecutor()`
  - `getActionStrategy()`
  - `getEntityId()`
  - `executorProperty()`
  - `extraProperty()`
  - `getActionExecutor()`
  - `getActionStrategy()`
  - `getEntityId()`
  - `getExecutorProperty()`
  - `getExtraProperty()`
  - *(... and 14 more)*

---

### ConditionBase [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.bean.ConditionBase`
- **Package**: `com.thingclips.scene.core.bean`
- **Implements**: `ICondition, Serializable`
- **Methods**: 24
- **Fields**: 8
- **Source**: `scene\core\bean\ConditionBase.java`

**Key Methods**:
  - `getCondType()`
  - `getDuration()`
  - `getEntityId()`
  - `getEntitySubIds()`
  - `getEntityType()`
  - `expr()`
  - `extraInfo()`
  - `getCondType()`
  - `getDuration()`
  - `getEntityId()`
  - *(... and 14 more)*

---

### LinkageRuleBase [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.bean.LinkageRuleBase`
- **Package**: `com.thingclips.scene.core.bean`
- **Implements**: `ILinkageRule, Serializable`
- **Methods**: 51
- **Fields**: 17
- **Source**: `scene\core\bean\LinkageRuleBase.java`

**Key Methods**:
  - `actions()`
  - `getAttribute()`
  - `getAuditStatus()`
  - `conditions()`
  - `getEnabled()`
  - `getActions()`
  - `getAttribute()`
  - `getAuditStatus()`
  - `getConditions()`
  - `getEnabled()`
  - *(... and 41 more)*

---

### PreConditionBase [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.bean.PreConditionBase`
- **Package**: `com.thingclips.scene.core.bean`
- **Implements**: `IPreCondition, Serializable`
- **Methods**: 9
- **Fields**: 3
- **Source**: `scene\core\bean\PreConditionBase.java`

**Key Methods**:
  - `getCondType()`
  - `expr()`
  - `getCondType()`
  - `getExpr()`
  - `getId()`
  - `mo267id()`
  - `setCondType()`
  - `setExpr()`
  - `setId()`

---

### ScopesAction [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.bean.ScopesAction`
- **Package**: `com.thingclips.scene.core.bean`
- **Implements**: `IAction, Serializable, IScopesExt<T>`
- **Methods**: 19
- **Fields**: 1
- **Source**: `scene\core\bean\ScopesAction.java`

**Key Methods**:
  - `ScopesAction()`
  - `getActionExecutor()`
  - `getAction()`
  - `getActionStrategy()`
  - `getAction()`
  - `getEntityId()`
  - `getAction()`
  - `executorProperty()`
  - `getAction()`
  - `extraProperty()`
  - *(... and 9 more)*

---

### ScopesCondition [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.bean.ScopesCondition`
- **Package**: `com.thingclips.scene.core.bean`
- **Implements**: `ICondition, Serializable, IScopesExt<T>`
- **Methods**: 19
- **Fields**: 1
- **Source**: `scene\core\bean\ScopesCondition.java`

**Key Methods**:
  - `ScopesCondition()`
  - `getCondType()`
  - `getCondition()`
  - `getDuration()`
  - `getCondition()`
  - `getEntityId()`
  - `getCondition()`
  - `getEntitySubIds()`
  - `getCondition()`
  - `getEntityType()`
  - *(... and 9 more)*

---

### ScopesLinkageRule [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.bean.ScopesLinkageRule`
- **Package**: `com.thingclips.scene.core.bean`
- **Implements**: `ILinkageRule, Serializable, IScopesExt<T>`
- **Methods**: 37
- **Fields**: 1
- **Source**: `scene\core\bean\ScopesLinkageRule.java`

**Key Methods**:
  - `ScopesLinkageRule()`
  - `actions()`
  - `getLinkageRule()`
  - `getAttribute()`
  - `getLinkageRule()`
  - `getAuditStatus()`
  - `getLinkageRule()`
  - `conditions()`
  - `getLinkageRule()`
  - `getEnabled()`
  - *(... and 27 more)*

---

### ScopesPreCondition [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.bean.ScopesPreCondition`
- **Package**: `com.thingclips.scene.core.bean`
- **Implements**: `IPreCondition, Serializable, IScopesExt<T>`
- **Methods**: 9
- **Fields**: 1
- **Source**: `scene\core\bean\ScopesPreCondition.java`

**Key Methods**:
  - `ScopesPreCondition()`
  - `getCondType()`
  - `getPreC()`
  - `expr()`
  - `getPreC()`
  - `getPreC()`
  - `mo267id()`
  - `getPreC()`
  - `setPreC()`

---

### PlugSceneExecute [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.execute.PlugSceneExecute`
- **Package**: `com.thingclips.scene.core.execute`
- **Methods**: 11
- **Fields**: 6
- **Source**: `scene\core\execute\PlugSceneExecute.java`

**Key Methods**:
  - `Companion()`
  - `Companion()`
  - `getInstance()`
  - `SingletonHolder()`
  - `PlugSceneExecute()`
  - `SingletonHolder()`
  - `getHolder()`
  - `PlugSceneExecute()`
  - `execute()`
  - `RuntimeException()`
  - *(... and 1 more)*

---

### ISceneExecute [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.execute.p009interface.ISceneExecute`
- **Package**: `com.thingclips.scene.core.execute.p009interface`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\execute\p009interface\ISceneExecute.java`

**Key Methods**:
  - `executeManual()`

---

### IAction [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.model.IAction`
- **Package**: `com.thingclips.scene.core.model`
- **Methods**: 8
- **Fields**: 0
- **Source**: `scene\core\model\IAction.java`

**Key Methods**:
  - `actionExecutor()`
  - `actionStrategy()`
  - `entityId()`
  - `executorProperty()`
  - `extraProperty()`
  - `mo264id()`
  - `orderNum()`
  - `ruleId()`

---

### ICondition [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.model.ICondition`
- **Package**: `com.thingclips.scene.core.model`
- **Methods**: 8
- **Fields**: 0
- **Source**: `scene\core\model\ICondition.java`

**Key Methods**:
  - `condType()`
  - `duration()`
  - `entityId()`
  - `entitySubIds()`
  - `entityType()`
  - `expr()`
  - `extraInfo()`
  - `mo265id()`

---

### ILinkageRule [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.model.ILinkageRule`
- **Package**: `com.thingclips.scene.core.model`
- **Methods**: 17
- **Fields**: 0
- **Source**: `scene\core\model\ILinkageRule.java`

**Key Methods**:
  - `actions()`
  - `attribute()`
  - `auditStatus()`
  - `conditions()`
  - `enabled()`
  - `mo266id()`
  - `matchStatus()`
  - `matchType()`
  - `name()`
  - `orderWeight()`
  - *(... and 7 more)*

---

### IPreCondition [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.model.IPreCondition`
- **Package**: `com.thingclips.scene.core.model`
- **Methods**: 3
- **Fields**: 0
- **Source**: `scene\core\model\IPreCondition.java`

**Key Methods**:
  - `condType()`
  - `expr()`
  - `mo267id()`

---

### SceneContext [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.SceneContext`
- **Package**: `com.thingclips.scene.core.protocol`
- **Methods**: 2
- **Fields**: 0
- **Source**: `scene\core\protocol\SceneContext.java`

**Key Methods**:
  - `env()`
  - `inputs()`

---

### TimerRule [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.expr.usualimpl.TimerRule`
- **Package**: `com.thingclips.scene.core.protocol.expr.usualimpl`
- **Extends**: `Rule`
- **Methods**: 8
- **Fields**: 2
- **Source**: `protocol\expr\usualimpl\TimerRule.java`

**Key Methods**:
  - `Companion()`
  - `Companion()`
  - `newInstance()`
  - `TimerRule()`
  - `newInstance()`
  - `TimerRule()`
  - `TimerRule()`
  - `HashMap()`

---

### ValueRule [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.expr.usualimpl.ValueRule`
- **Package**: `com.thingclips.scene.core.protocol.expr.usualimpl`
- **Extends**: `Rule`
- **Methods**: 9
- **Fields**: 3
- **Source**: `protocol\expr\usualimpl\ValueRule.java`

**Key Methods**:
  - `Companion()`
  - `Companion()`
  - `newInstance()`
  - `ValueRule()`
  - `newInstance()`
  - `ValueRule()`
  - `ValueRule()`
  - `if()`
  - `ValueRule()`

---

### DeviceCalculateDpExtra [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.extra.usualimpl.DeviceCalculateDpExtra`
- **Package**: `com.thingclips.scene.core.protocol.extra.usualimpl`
- **Extends**: `ExtraInfo`
- **Methods**: 1
- **Fields**: 0
- **Source**: `protocol\extra\usualimpl\DeviceCalculateDpExtra.java`

**Key Methods**:
  - `DeviceCalculateDpExtra()`

---

### GeofenceExtra [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.extra.usualimpl.GeofenceExtra`
- **Package**: `com.thingclips.scene.core.protocol.extra.usualimpl`
- **Extends**: `ExtraInfo`
- **Methods**: 1
- **Fields**: 0
- **Source**: `protocol\extra\usualimpl\GeofenceExtra.java`

**Key Methods**:
  - `GeofenceExtra()`

---

### TempExtra [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.extra.usualimpl.weather.TempExtra`
- **Package**: `com.thingclips.scene.core.protocol.extra.usualimpl.weather`
- **Extends**: `ExtraInfo`
- **Methods**: 1
- **Fields**: 0
- **Source**: `extra\usualimpl\weather\TempExtra.java`

**Key Methods**:
  - `TempExtra()`

---

### ActionFactory [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.factory.ActionFactory`
- **Package**: `com.thingclips.scene.core.protocol.factory`
- **Methods**: 2
- **Fields**: 0
- **Source**: `core\protocol\factory\ActionFactory.java`

**Key Methods**:
  - `addActionCreator()`
  - `getByType()`

---

### ConditionFactory [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.factory.ConditionFactory`
- **Package**: `com.thingclips.scene.core.protocol.factory`
- **Methods**: 3
- **Fields**: 0
- **Source**: `core\protocol\factory\ConditionFactory.java`

**Key Methods**:
  - `addConditionCreator()`
  - `getByType()`
  - `supportTypeSet()`

---

### LinkageRuleFactory [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.factory.LinkageRuleFactory`
- **Package**: `com.thingclips.scene.core.protocol.factory`
- **Extends**: `IPreCondition>`
- **Methods**: 3
- **Fields**: 0
- **Source**: `core\protocol\factory\LinkageRuleFactory.java`

**Key Methods**:
  - `assemble()`
  - `getActionFactory()`
  - `getConditionFactory()`

---

### IActionBuilder [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p003b.IActionBuilder`
- **Package**: `com.thingclips.scene.core.protocol.p003b`
- **Extends**: `IBuilder`
- **Methods**: 2
- **Fields**: 0
- **Source**: `core\protocol\p003b\IActionBuilder.java`

**Key Methods**:
  - `setExecutorProperty()`
  - `setExtraProperty()`

---

### DefaultImpls [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p003b.DefaultImpls`
- **Package**: `com.thingclips.scene.core.protocol.p003b`
- **Extends**: `IBuilder`
- **Methods**: 3
- **Fields**: 0
- **Source**: `core\protocol\p003b\IConditionBuilder.java`

**Key Methods**:
  - `UnsupportedOperationException()`
  - `setCondType()`
  - `setExtraInfo()`

---

### DelayActionBuilder [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p003b.usualimpl.DelayActionBuilder`
- **Package**: `com.thingclips.scene.core.protocol.p003b.usualimpl`
- **Extends**: `IActionBuilder>`
- **Implements**: `IActionBuilder`
- **Methods**: 9
- **Fields**: 15
- **Source**: `protocol\p003b\usualimpl\DelayActionBuilder.java`

**Key Methods**:
  - `DelayActionBuilder()`
  - `DelayActionBuilder()`
  - `build()`
  - `ActionBase()`
  - `LinkedHashMap()`
  - `setExecutorProperty()`
  - `setExtraProperty()`
  - `setMinutes()`
  - `setSeconds()`

---

### DeviceActionBuilder [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p003b.usualimpl.DeviceActionBuilder`
- **Package**: `com.thingclips.scene.core.protocol.p003b.usualimpl`
- **Extends**: `IActionBuilder>`
- **Implements**: `IActionBuilder`
- **Methods**: 23
- **Fields**: 63
- **Source**: `protocol\p003b\usualimpl\DeviceActionBuilder.java`

**Key Methods**:
  - `DeviceActionBuilder()`
  - `construct()`
  - `LinkedHashMap()`
  - `LinkedHashMap()`
  - `if()`
  - `if()`
  - `if()`
  - `if()`
  - `UnsupportedOperationException()`
  - `build()`
  - *(... and 13 more)*

---

### DeviceConditionBuilder [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p003b.usualimpl.DeviceConditionBuilder`
- **Package**: `com.thingclips.scene.core.protocol.p003b.usualimpl`
- **Extends**: `IConditionBuilder>`
- **Implements**: `IConditionBuilder`
- **Methods**: 29
- **Fields**: 95
- **Source**: `protocol\p003b\usualimpl\DeviceConditionBuilder.java`

**Key Methods**:
  - `DeviceConditionBuilder()`
  - `build()`
  - `ConditionBase()`
  - `if()`
  - `if()`
  - `LinkedHashMap()`
  - `if()`
  - `if()`
  - `LockMemberExtra()`
  - `setCalType()`
  - *(... and 19 more)*

---

### DeviceGroupActionBuilder [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p003b.usualimpl.DeviceGroupActionBuilder`
- **Package**: `com.thingclips.scene.core.protocol.p003b.usualimpl`
- **Extends**: `IActionBuilder>`
- **Implements**: `IActionBuilder`
- **Methods**: 5
- **Fields**: 10
- **Source**: `protocol\p003b\usualimpl\DeviceGroupActionBuilder.java`

**Key Methods**:
  - `build()`
  - `ActionBase()`
  - `setExecutorProperty()`
  - `setExtraProperty()`
  - `setGroupId()`

---

### GeofenceConditionBuilder [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p003b.usualimpl.GeofenceConditionBuilder`
- **Package**: `com.thingclips.scene.core.protocol.p003b.usualimpl`
- **Extends**: `IConditionBuilder>`
- **Implements**: `IConditionBuilder`
- **Methods**: 14
- **Fields**: 25
- **Source**: `protocol\p003b\usualimpl\GeofenceConditionBuilder.java`

**Key Methods**:
  - `GeofenceConditionBuilder()`
  - `build()`
  - `ConditionBase()`
  - `GeofenceExtra()`
  - `setAddress()`
  - `setCondType()`
  - `setExtraInfo()`
  - `setGeofenceId()`
  - `setGeofenceType()`
  - `setLat()`
  - *(... and 4 more)*

---

### LinkageRuleActionBuilder [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p003b.usualimpl.LinkageRuleActionBuilder`
- **Package**: `com.thingclips.scene.core.protocol.p003b.usualimpl`
- **Extends**: `IActionBuilder>`
- **Implements**: `IActionBuilder`
- **Methods**: 9
- **Fields**: 12
- **Source**: `protocol\p003b\usualimpl\LinkageRuleActionBuilder.java`

**Key Methods**:
  - `LinkageRuleActionBuilder()`
  - `method()`
  - `LinkageRuleActionBuilder()`
  - `build()`
  - `ActionBase()`
  - `setExecutorProperty()`
  - `setExtraProperty()`
  - `setLinkageOperator()`
  - `setLinkageRuleId()`

---

### NotifyActionBuilder [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p003b.usualimpl.NotifyActionBuilder`
- **Package**: `com.thingclips.scene.core.protocol.p003b.usualimpl`
- **Extends**: `IActionBuilder>`
- **Implements**: `IActionBuilder`
- **Methods**: 8
- **Fields**: 9
- **Source**: `protocol\p003b\usualimpl\NotifyActionBuilder.java`

**Key Methods**:
  - `NotifyActionBuilder()`
  - `method()`
  - `NotifyActionBuilder()`
  - `build()`
  - `ActionBase()`
  - `setExecutorProperty()`
  - `setExtraProperty()`
  - `setNotifyType()`

---

### SunRiseSetConditionBuilder [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p003b.usualimpl.SunRiseSetConditionBuilder`
- **Package**: `com.thingclips.scene.core.protocol.p003b.usualimpl`
- **Extends**: `IConditionBuilder>`
- **Implements**: `IConditionBuilder`
- **Methods**: 10
- **Fields**: 15
- **Source**: `protocol\p003b\usualimpl\SunRiseSetConditionBuilder.java`

**Key Methods**:
  - `SunRiseSetConditionBuilder()`
  - `build()`
  - `ConditionBase()`
  - `setCityId()`
  - `setCondType()`
  - `setExtraInfo()`
  - `setMinutes()`
  - `setSunType()`
  - `method()`
  - `SunRiseSetConditionBuilder()`

---

### TimingConditionBuilder [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p003b.usualimpl.TimingConditionBuilder`
- **Package**: `com.thingclips.scene.core.protocol.p003b.usualimpl`
- **Extends**: `IConditionBuilder>`
- **Implements**: `IConditionBuilder`
- **Methods**: 11
- **Fields**: 17
- **Source**: `protocol\p003b\usualimpl\TimingConditionBuilder.java`

**Key Methods**:
  - `TimingConditionBuilder()`
  - `build()`
  - `ConditionBase()`
  - `setCondType()`
  - `setDate()`
  - `setExtraInfo()`
  - `setLoops()`
  - `setTime()`
  - `setTimeZoneId()`
  - `method()`
  - *(... and 1 more)*

---

### WeatherConditionBuilder [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p003b.usualimpl.WeatherConditionBuilder`
- **Package**: `com.thingclips.scene.core.protocol.p003b.usualimpl`
- **Extends**: `IConditionBuilder>`
- **Implements**: `IConditionBuilder`
- **Methods**: 23
- **Fields**: 50
- **Source**: `protocol\p003b\usualimpl\WeatherConditionBuilder.java`

**Key Methods**:
  - `WeatherConditionBuilder()`
  - `build()`
  - `ConditionBase()`
  - `if()`
  - `if()`
  - `LinkedHashMap()`
  - `TempExtra()`
  - `if()`
  - `GeneralExtra()`
  - `WindSpeedExtra()`
  - *(... and 13 more)*

---

### ICreator [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p004c.ICreator`
- **Package**: `com.thingclips.scene.core.protocol.p004c`
- **Methods**: 2
- **Fields**: 0
- **Source**: `core\protocol\p004c\ICreator.java`

**Key Methods**:
  - `create()`
  - `type()`

---

### DelayActionCreator [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p004c.usualimpl.DelayActionCreator`
- **Package**: `com.thingclips.scene.core.protocol.p004c.usualimpl`
- **Extends**: `IAction>`
- **Implements**: `IActionCreator`
- **Methods**: 3
- **Fields**: 2
- **Source**: `protocol\p004c\usualimpl\DelayActionCreator.java`

**Key Methods**:
  - `type()`
  - `verify()`
  - `create()`

---

### DeviceActionCreator [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p004c.usualimpl.DeviceActionCreator`
- **Package**: `com.thingclips.scene.core.protocol.p004c.usualimpl`
- **Extends**: `IAction>`
- **Implements**: `IActionCreator`
- **Methods**: 3
- **Fields**: 2
- **Source**: `protocol\p004c\usualimpl\DeviceActionCreator.java`

**Key Methods**:
  - `type()`
  - `verify()`
  - `create()`

---

### DeviceConditionCreator [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p004c.usualimpl.DeviceConditionCreator`
- **Package**: `com.thingclips.scene.core.protocol.p004c.usualimpl`
- **Extends**: `ICondition>`
- **Implements**: `IConditionCreator`
- **Methods**: 3
- **Fields**: 2
- **Source**: `protocol\p004c\usualimpl\DeviceConditionCreator.java`

**Key Methods**:
  - `type()`
  - `verify()`
  - `create()`

---

### DeviceGroupActionCreator [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p004c.usualimpl.DeviceGroupActionCreator`
- **Package**: `com.thingclips.scene.core.protocol.p004c.usualimpl`
- **Extends**: `IAction>`
- **Implements**: `IActionCreator`
- **Methods**: 3
- **Fields**: 2
- **Source**: `protocol\p004c\usualimpl\DeviceGroupActionCreator.java`

**Key Methods**:
  - `type()`
  - `verify()`
  - `create()`

---

### GeofenceConditionCreator [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p004c.usualimpl.GeofenceConditionCreator`
- **Package**: `com.thingclips.scene.core.protocol.p004c.usualimpl`
- **Extends**: `ICondition>`
- **Implements**: `IConditionCreator`
- **Methods**: 3
- **Fields**: 2
- **Source**: `protocol\p004c\usualimpl\GeofenceConditionCreator.java`

**Key Methods**:
  - `type()`
  - `verify()`
  - `create()`

---

### LinkageRuleActionCreator [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p004c.usualimpl.LinkageRuleActionCreator`
- **Package**: `com.thingclips.scene.core.protocol.p004c.usualimpl`
- **Extends**: `IAction>`
- **Implements**: `IActionCreator`
- **Methods**: 3
- **Fields**: 2
- **Source**: `protocol\p004c\usualimpl\LinkageRuleActionCreator.java`

**Key Methods**:
  - `type()`
  - `verify()`
  - `create()`

---

### NotifyActionCreator [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p004c.usualimpl.NotifyActionCreator`
- **Package**: `com.thingclips.scene.core.protocol.p004c.usualimpl`
- **Extends**: `IAction>`
- **Implements**: `IActionCreator`
- **Methods**: 3
- **Fields**: 2
- **Source**: `protocol\p004c\usualimpl\NotifyActionCreator.java`

**Key Methods**:
  - `type()`
  - `verify()`
  - `create()`

---

### SunRiseSetConditionCreator [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p004c.usualimpl.SunRiseSetConditionCreator`
- **Package**: `com.thingclips.scene.core.protocol.p004c.usualimpl`
- **Extends**: `ICondition>`
- **Implements**: `IConditionCreator`
- **Methods**: 3
- **Fields**: 2
- **Source**: `protocol\p004c\usualimpl\SunRiseSetConditionCreator.java`

**Key Methods**:
  - `type()`
  - `verify()`
  - `create()`

---

### TimingConditionCreator [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p004c.usualimpl.TimingConditionCreator`
- **Package**: `com.thingclips.scene.core.protocol.p004c.usualimpl`
- **Extends**: `ICondition>`
- **Implements**: `IConditionCreator`
- **Methods**: 3
- **Fields**: 2
- **Source**: `protocol\p004c\usualimpl\TimingConditionCreator.java`

**Key Methods**:
  - `type()`
  - `verify()`
  - `create()`

---

### WeatherConditionCreator [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.protocol.p004c.usualimpl.WeatherConditionCreator`
- **Package**: `com.thingclips.scene.core.protocol.p004c.usualimpl`
- **Extends**: `ICondition>`
- **Implements**: `IConditionCreator`
- **Methods**: 3
- **Fields**: 2
- **Source**: `protocol\p004c\usualimpl\WeatherConditionCreator.java`

**Key Methods**:
  - `type()`
  - `verify()`
  - `create()`

---

### ActionTool [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.tool.ActionTool`
- **Package**: `com.thingclips.scene.core.tool`
- **Methods**: 3
- **Fields**: 3
- **Source**: `scene\core\tool\ActionTool.java`

**Key Methods**:
  - `ActionTool()`
  - `ActionTool()`
  - `create()`

---

### ConditionTool [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.tool.ConditionTool`
- **Package**: `com.thingclips.scene.core.tool`
- **Methods**: 3
- **Fields**: 3
- **Source**: `scene\core\tool\ConditionTool.java`

**Key Methods**:
  - `ConditionTool()`
  - `ConditionTool()`
  - `create()`

---

### DTOMapExtensionKt [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.tool.DTOMapExtensionKt`
- **Package**: `com.thingclips.scene.core.tool`
- **Extends**: `ActionDeviceDataPointDetail>`
- **Methods**: 25
- **Fields**: 130
- **Source**: `scene\core\tool\DTOMapExtensionKt.java`

**Key Methods**:
  - `mapToDeviceActionData()`
  - `DeviceActionDetailBean()`
  - `m433invoke()`
  - `mapToDeviceActionData()`
  - `mapToDeviceConditionData()`
  - `ArrayList()`
  - `ArrayList()`
  - `ArrayList()`
  - `ValueTypeData()`
  - `DeviceConditionData()`
  - *(... and 15 more)*

---

### LinkageRuleTool [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.tool.LinkageRuleTool`
- **Package**: `com.thingclips.scene.core.tool`
- **Extends**: `IPreCondition>`
- **Methods**: 3
- **Fields**: 1
- **Source**: `scene\core\tool\LinkageRuleTool.java`

**Key Methods**:
  - `LinkageRuleTool()`
  - `LinkageRuleTool()`
  - `create()`

---

### DeviceUtils [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.util.DeviceUtils`
- **Package**: `com.thingclips.scene.core.util`
- **Methods**: 6
- **Fields**: 19
- **Source**: `scene\core\util\DeviceUtils.java`

**Key Methods**:
  - `DeviceUtils()`
  - `DeviceUtils()`
  - `getDeviceDpValueType()`
  - `getSchemaMap()`
  - `HashMap()`
  - `ArrayList()`

---

### PercentUtils [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.util.PercentUtils`
- **Package**: `com.thingclips.scene.core.util`
- **Methods**: 6
- **Fields**: 5
- **Source**: `scene\core\util\PercentUtils.java`

**Key Methods**:
  - `PercentUtils()`
  - `PercentUtils()`
  - `getPercent()`
  - `getPercentFromOne()`
  - `valueToPercent()`
  - `valueToPercentFromOne()`

---

### TempUtils [MEDIUM]


- **Full Name**: `com.thingclips.scene.core.util.TempUtils`
- **Package**: `com.thingclips.scene.core.util`
- **Methods**: 7
- **Fields**: 5
- **Source**: `scene\core\util\TempUtils.java`

**Key Methods**:
  - `TempUtils()`
  - `TempUtils()`
  - `getTEMPER_CELSIUS_UNIT()`
  - `getTEMPER_FAHRENHEIT_UNIT()`
  - `isCelsiusTempUnit()`
  - `isFahrenheitTempUnit()`
  - `isTempUnit()`

---

### BLEActiveBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.beacon.bean.BLEActiveBean`
- **Package**: `com.thingclips.sdk.beacon.bean`
- **Methods**: 24
- **Fields**: 12
- **Source**: `sdk\beacon\bean\BLEActiveBean.java`

**Key Methods**:
  - `getBeaconKey()`
  - `getDevEtag()`
  - `getDevId()`
  - `getErrorCode()`
  - `getErrorMsg()`
  - `getIconUrl()`
  - `getLocalKey()`
  - `getName()`
  - `getSchema()`
  - `getSchemaId()`
  - *(... and 14 more)*

---

### BleProtocolInit [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.BleProtocolInit`
- **Package**: `com.thingclips.sdk.ble.core`
- **Implements**: `ILogPrinter`
- **Methods**: 13
- **Fields**: 3
- **Source**: `sdk\ble\core\BleProtocolInit.java`

**Key Methods**:
  - `bdpdqbp()`
  - `level_d()`
  - `level_e()`
  - `level_i()`
  - `level_v()`
  - `level_w()`
  - `BleProtocolInit()`
  - `getInstance()`
  - `debugLog()`
  - `bdpdqbp()`
  - *(... and 3 more)*

---

### BleBaseResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.ability.response.BleBaseResponse`
- **Package**: `com.thingclips.sdk.ble.core.ability.response`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\ability\response\BleBaseResponse.java`

**Key Methods**:
  - `onResponse()`

---

### BleConfigMtuBaseResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.ability.response.BleConfigMtuBaseResponse`
- **Package**: `com.thingclips.sdk.ble.core.ability.response`
- **Extends**: `BleTBaseResponse<Integer>`
- **Methods**: 0
- **Fields**: 0
- **Source**: `core\ability\response\BleConfigMtuBaseResponse.java`

---

### BleConnectStatusResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.ability.response.BleConnectStatusResponse`
- **Package**: `com.thingclips.sdk.ble.core.ability.response`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\ability\response\BleConnectStatusResponse.java`

**Key Methods**:
  - `onConnectStatusChanged()`

---

### BleGeneralBaseResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.ability.response.BleGeneralBaseResponse`
- **Package**: `com.thingclips.sdk.ble.core.ability.response`
- **Extends**: `BleTBaseResponse<Bundle>`
- **Methods**: 0
- **Fields**: 0
- **Source**: `core\ability\response\BleGeneralBaseResponse.java`

---

### BleGetRssiBaseResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.ability.response.BleGetRssiBaseResponse`
- **Package**: `com.thingclips.sdk.ble.core.ability.response`
- **Extends**: `BleTBaseResponse<Integer>`
- **Methods**: 0
- **Fields**: 0
- **Source**: `core\ability\response\BleGetRssiBaseResponse.java`

---

### BleNotifyAbilityResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.ability.response.BleNotifyAbilityResponse`
- **Package**: `com.thingclips.sdk.ble.core.ability.response`
- **Extends**: `BleBaseResponse`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\ability\response\BleNotifyAbilityResponse.java`

**Key Methods**:
  - `onNotify()`

---

### BleReadAbilityBaseResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.ability.response.BleReadAbilityBaseResponse`
- **Package**: `com.thingclips.sdk.ble.core.ability.response`
- **Extends**: `BleTBaseResponse<byte`
- **Methods**: 0
- **Fields**: 0
- **Source**: `core\ability\response\BleReadAbilityBaseResponse.java`

---

### BleTBaseResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.ability.response.BleTBaseResponse`
- **Package**: `com.thingclips.sdk.ble.core.ability.response`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\ability\response\BleTBaseResponse.java`

**Key Methods**:
  - `onResponse()`

---

### pdqppqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.analysis.pdqppqb`
- **Package**: `com.thingclips.sdk.ble.core.analysis`
- **Methods**: 0
- **Fields**: 52
- **Source**: `ble\core\analysis\pdqppqb.java`

---

### AccessoriesResultBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.AccessoriesResultBean`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 10
- **Fields**: 5
- **Source**: `ble\core\bean\AccessoriesResultBean.java`

**Key Methods**:
  - `getDevId()`
  - `getFailedReason()`
  - `getNodeId()`
  - `getUuid()`
  - `isActiveResult()`
  - `setActiveResult()`
  - `setDevId()`
  - `setFailedReason()`
  - `setNodeId()`
  - `setUuid()`

---

### BLEDpBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.BLEDpBean`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 14
- **Fields**: 5
- **Source**: `ble\core\bean\BLEDpBean.java`

**Key Methods**:
  - `BLEDpBean()`
  - `getAllBeanLen()`
  - `getLen()`
  - `getData()`
  - `getId()`
  - `getLen()`
  - `getType()`
  - `setData()`
  - `setId()`
  - `setLen()`
  - *(... and 4 more)*

---

### BLEDpResponseBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.BLEDpResponseBean`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 7
- **Fields**: 4
- **Source**: `ble\core\bean\BLEDpResponseBean.java`

**Key Methods**:
  - `ArrayList()`
  - `getDpList()`
  - `getType()`
  - `setDpList()`
  - `setType()`
  - `toString()`
  - `StringBuilder()`

---

### BLEOtaBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.BLEOtaBean`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 5
- **Fields**: 9
- **Source**: `ble\core\bean\BLEOtaBean.java`

**Key Methods**:
  - `BLEOtaBean()`
  - `create()`
  - `if()`
  - `BLEOtaBean()`
  - `getStatus()`

---

### BleOtaType [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.BleOtaType`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 0
- **Fields**: 6
- **Source**: `ble\core\bean\BleOtaType.java`

---

### BLEScanDevBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.BLEScanDevBean`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 15
- **Fields**: 28
- **Source**: `ble\core\bean\BLEScanDevBean.java`

**Key Methods**:
  - `BLEScanDevBean()`
  - `copyObj()`
  - `equals()`
  - `isAddressEquals()`
  - `getTyAdvertisingData()`
  - `hashCode()`
  - `isAddressEquals()`
  - `isDevUUIDEquals()`
  - `setBLEDevBeanInfo()`
  - `setDeviceName()`
  - *(... and 5 more)*

**Notable Strings**:
  - `"', devUuId='"`

---

### DpRule [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.DpRule`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 0
- **Fields**: 11
- **Source**: `ble\core\bean\DpRule.java`

---

### DpsCombine [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.DpsCombine`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 0
- **Fields**: 4
- **Source**: `ble\core\bean\DpsCombine.java`

---

### DpsQueryDp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.DpsQueryDp`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 0
- **Fields**: 1
- **Source**: `ble\core\bean\DpsQueryDp.java`

---

### EnumSchemaExBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.EnumSchemaExBean`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 2
- **Fields**: 2
- **Source**: `ble\core\bean\EnumSchemaExBean.java`

**Key Methods**:
  - `getRange()`
  - `setRange()`

---

### ExtTypeResponseBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.ExtTypeResponseBean`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 2
- **Fields**: 3
- **Source**: `ble\core\bean\ExtTypeResponseBean.java`

**Key Methods**:
  - `toString()`
  - `StringBuilder()`

---

### FileTransferInfo [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.FileTransferInfo`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 16
- **Fields**: 20
- **Source**: `ble\core\bean\FileTransferInfo.java`

**Key Methods**:
  - `build()`
  - `FileTransferInfo()`
  - `setData()`
  - `setFileId()`
  - `setFileIdentifier()`
  - `setFileMd5()`
  - `setFileType()`
  - `setFileVersion()`
  - `checkParamValid()`
  - `getData()`
  - *(... and 6 more)*

---

### NormalResponseBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.NormalResponseBean`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 10
- **Fields**: 5
- **Source**: `ble\core\bean\NormalResponseBean.java`

**Key Methods**:
  - `getData()`
  - `getMaximum()`
  - `getType()`
  - `getVersion()`
  - `setData()`
  - `setMaximum()`
  - `setType()`
  - `setVersion()`
  - `toString()`
  - `StringBuilder()`

---

### RequestPackage [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.RequestPackage`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 9
- **Fields**: 5
- **Source**: `ble\core\bean\RequestPackage.java`

**Key Methods**:
  - `RequestPackage()`
  - `getData()`
  - `getLen()`
  - `reversalByteArray()`
  - `setData()`
  - `setLen()`
  - `toString()`
  - `reversalByteArray()`
  - `RequestPackage()`

---

### SchemeExtContentBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.SchemeExtContentBean`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 5
- **Fields**: 2
- **Source**: `ble\core\bean\SchemeExtContentBean.java`

**Key Methods**:
  - `getCloudless()`
  - `getFrequency()`
  - `setCloudless()`
  - `setFrequency()`
  - `toString()`

---

### SecurityCertBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.SecurityCertBean`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 3
- **Fields**: 2
- **Source**: `ble\core\bean\SecurityCertBean.java`

**Key Methods**:
  - `SecurityCertBean()`
  - `getCaSignature()`
  - `getPublicKey()`

---

### SummerTime [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.SummerTime`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 9
- **Fields**: 4
- **Source**: `ble\core\bean\SummerTime.java`

**Key Methods**:
  - `Config()`
  - `getDstIntervals()`
  - `getStdTimeZone()`
  - `setDstIntervals()`
  - `setStdTimeZone()`
  - `getConfig()`
  - `getTime()`
  - `setConfig()`
  - `setTime()`

---

### WiFiDevInfo [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.bean.WiFiDevInfo`
- **Package**: `com.thingclips.sdk.ble.core.bean`
- **Methods**: 0
- **Fields**: 20
- **Source**: `ble\core\bean\WiFiDevInfo.java`

---

### AuthKeyBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.connect.bean.AuthKeyBean`
- **Package**: `com.thingclips.sdk.ble.core.connect.bean`
- **Methods**: 13
- **Fields**: 8
- **Source**: `core\connect\bean\AuthKeyBean.java`

**Key Methods**:
  - `getDevId()`
  - `getErrorCode()`
  - `getErrorMsg()`
  - `getIconUrl()`
  - `getName()`
  - `getResetKey()`
  - `setDevId()`
  - `setErrorCode()`
  - `setErrorMsg()`
  - `setIconUrl()`
  - *(... and 3 more)*

---

### BLEActiveBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.connect.bean.BLEActiveBean`
- **Package**: `com.thingclips.sdk.ble.core.connect.bean`
- **Methods**: 28
- **Fields**: 14
- **Source**: `core\connect\bean\BLEActiveBean.java`

**Key Methods**:
  - `getBeaconKey()`
  - `getDevEtag()`
  - `getDevId()`
  - `getErrorCode()`
  - `getErrorMsg()`
  - `getIconUrl()`
  - `getLocalKey()`
  - `getName()`
  - `getSchema()`
  - `getSchemaId()`
  - *(... and 18 more)*

---

### BLERegisterBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.connect.bean.BLERegisterBean`
- **Package**: `com.thingclips.sdk.ble.core.connect.bean`
- **Methods**: 2
- **Fields**: 1
- **Source**: `core\connect\bean\BLERegisterBean.java`

**Key Methods**:
  - `getDevId()`
  - `setDevId()`

---

### PairBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.connect.bean.PairBean`
- **Package**: `com.thingclips.sdk.ble.core.connect.bean`
- **Methods**: 1
- **Fields**: 24
- **Source**: `core\connect\bean\PairBean.java`

**Key Methods**:
  - `isNoConfig()`

---

### ResetKeyBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.connect.bean.ResetKeyBean`
- **Package**: `com.thingclips.sdk.ble.core.connect.bean`
- **Methods**: 16
- **Fields**: 10
- **Source**: `core\connect\bean\ResetKeyBean.java`

**Key Methods**:
  - `getDevId()`
  - `getErrorCode()`
  - `getErrorMsg()`
  - `getIconUrl()`
  - `getName()`
  - `getResetKey()`
  - `isBindStatus()`
  - `setBindStatus()`
  - `setDevId()`
  - `setErrorCode()`
  - *(... and 6 more)*

---

### SecretKeyBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.connect.bean.SecretKeyBean`
- **Package**: `com.thingclips.sdk.ble.core.connect.bean`
- **Methods**: 6
- **Fields**: 3
- **Source**: `core\connect\bean\SecretKeyBean.java`

**Key Methods**:
  - `getLocalKey()`
  - `getSecKey()`
  - `getSign()`
  - `setLocalKey()`
  - `setSecKey()`
  - `setSign()`

---

### SecurityRandomEncrypt [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.connect.bean.SecurityRandomEncrypt`
- **Package**: `com.thingclips.sdk.ble.core.connect.bean`
- **Methods**: 4
- **Fields**: 2
- **Source**: `core\connect\bean\SecurityRandomEncrypt.java`

**Key Methods**:
  - `getEncryptedVal()`
  - `getOriginalVal()`
  - `setEncryptedVal()`
  - `setOriginalVal()`

---

### SecurityServerCert [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.connect.bean.SecurityServerCert`
- **Package**: `com.thingclips.sdk.ble.core.connect.bean`
- **Methods**: 4
- **Fields**: 2
- **Source**: `core\connect\bean\SecurityServerCert.java`

**Key Methods**:
  - `getCaSignature()`
  - `getPublicKey()`
  - `setCaSignature()`
  - `setPublicKey()`

---

### TargetDeviceBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.connect.bean.TargetDeviceBean`
- **Package**: `com.thingclips.sdk.ble.core.connect.bean`
- **Methods**: 3
- **Fields**: 20
- **Source**: `core\connect\bean\TargetDeviceBean.java`

**Key Methods**:
  - `equals()`
  - `toString()`
  - `StringBuilder()`

**Notable Strings**:
  - `", uuid="`

---

### ActiveParam [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.controller.bean.ActiveParam`
- **Package**: `com.thingclips.sdk.ble.core.controller.bean`
- **Methods**: 0
- **Fields**: 1
- **Source**: `core\controller\bean\ActiveParam.java`

---

### ControllerBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.controller.bean.ControllerBean`
- **Package**: `com.thingclips.sdk.ble.core.controller.bean`
- **Methods**: 21
- **Fields**: 45
- **Source**: `core\controller\bean\ControllerBean.java`

**Key Methods**:
  - `ControllerBean()`
  - `address()`
  - `build()`
  - `devId()`
  - `devName()`
  - `deviceType()`
  - `directly()`
  - `flag()`
  - `isForce()`
  - `isShare()`
  - *(... and 11 more)*

---

### DeviceType [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.manager.DeviceType`
- **Package**: `com.thingclips.sdk.ble.core.manager`
- **Methods**: 0
- **Fields**: 19
- **Source**: `ble\core\manager\DeviceType.java`

---

### DpsParseHelper [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.manager.DpsParseHelper`
- **Package**: `com.thingclips.sdk.ble.core.manager`
- **Methods**: 16
- **Fields**: 18
- **Source**: `ble\core\manager\DpsParseHelper.java`

**Key Methods**:
  - `getBoolPackage()`
  - `RequestPackage()`
  - `getEnumPackage()`
  - `RequestPackage()`
  - `getRawPackage()`
  - `RequestPackage()`
  - `getStringPackage()`
  - `RequestPackage()`
  - `getValuePackage()`
  - `RequestPackage()`
  - *(... and 6 more)*

---

### AccessoriesActivateRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AccessoriesActivateRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 1
- **Source**: `core\packet\bean\AccessoriesActivateRep.java`

**Key Methods**:
  - `parseRep()`

---

### AccessoriesDpControlRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AccessoriesDpControlRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 11
- **Source**: `core\packet\bean\AccessoriesDpControlRep.java`

**Key Methods**:
  - `parseRep()`

---

### AccessoriesSyncDpRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AccessoriesSyncDpRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 3
- **Fields**: 9
- **Source**: `core\packet\bean\AccessoriesSyncDpRep.java`

**Key Methods**:
  - `parseRep()`
  - `AccessoriesExtInfo()`
  - `if()`

---

### AudioCommonCommandRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AudioCommonCommandRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 5
- **Source**: `core\packet\bean\AudioCommonCommandRep.java`

**Key Methods**:
  - `parseRep()`

---

### AudioControlCmd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AudioControlCmd`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 11
- **Fields**: 18
- **Source**: `core\packet\bean\AudioControlCmd.java`

**Key Methods**:
  - `parseRep()`
  - `AudioControlStartSpeech()`
  - `if()`
  - `AudioControlProvideSpeech()`
  - `if()`
  - `AudioControlData()`
  - `if()`
  - `if()`
  - `AudioControlData()`
  - `if()`
  - *(... and 1 more)*

---

### AudioControlData [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AudioControlData`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Methods**: 4
- **Fields**: 2
- **Source**: `core\packet\bean\AudioControlData.java`

**Key Methods**:
  - `getDialogId()`
  - `isAck()`
  - `setAck()`
  - `setDialogId()`

---

### AudioControlProvideSpeech [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AudioControlProvideSpeech`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `AudioControlData`
- **Methods**: 4
- **Fields**: 2
- **Source**: `core\packet\bean\AudioControlProvideSpeech.java`

**Key Methods**:
  - `getAudioFormat()`
  - `getAudioProfile()`
  - `setAudioFormat()`
  - `setAudioProfile()`

---

### AudioControlStartSpeech [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AudioControlStartSpeech`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `AudioControlData`
- **Methods**: 10
- **Fields**: 5
- **Source**: `core\packet\bean\AudioControlStartSpeech.java`

**Key Methods**:
  - `getAudioFormat()`
  - `getAudioProfile()`
  - `getMaxSize()`
  - `getPlayVoice()`
  - `getSuppressEarcon()`
  - `setAudioFormat()`
  - `setAudioProfile()`
  - `setMaxSize()`
  - `setPlayVoice()`
  - `setSuppressEarcon()`

---

### AudioData [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AudioData`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 5
- **Fields**: 16
- **Source**: `core\packet\bean\AudioData.java`

**Key Methods**:
  - `needResponse()`
  - `packAckData()`
  - `parseRep()`
  - `toString()`
  - `StringBuilder()`

---

### AudioResultRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.AudioResultRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 1
- **Source**: `core\packet\bean\AudioResultRep.java`

**Key Methods**:
  - `parseRep()`

---

### BaseAccessoriesDpReportRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.BaseAccessoriesDpReportRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 0
- **Fields**: 11
- **Source**: `core\packet\bean\BaseAccessoriesDpReportRep.java`

---

### BigDataBaseRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.BigDataBaseRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 0
- **Fields**: 6
- **Source**: `core\packet\bean\BigDataBaseRep.java`

---

### BigDataClearRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.BigDataClearRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `BigDataBaseRep`
- **Methods**: 1
- **Fields**: 4
- **Source**: `core\packet\bean\BigDataClearRep.java`

**Key Methods**:
  - `parseRep()`

---

### BigDataSummaryRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.BigDataSummaryRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `BigDataBaseRep`
- **Methods**: 1
- **Fields**: 16
- **Source**: `core\packet\bean\BigDataSummaryRep.java`

**Key Methods**:
  - `parseRep()`

---

### BigDataSyncRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.BigDataSyncRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `BigDataBaseRep`
- **Methods**: 1
- **Fields**: 9
- **Source**: `core\packet\bean\BigDataSyncRep.java`

**Key Methods**:
  - `parseRep()`

---

### BulkDataRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.BulkDataRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `BigDataBaseRep`
- **Methods**: 3
- **Fields**: 9
- **Source**: `core\packet\bean\BulkDataRep.java`

**Key Methods**:
  - `parseRep()`
  - `toString()`
  - `StringBuilder()`

---

### BulkDataSummaryRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.BulkDataSummaryRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `BigDataBaseRep`
- **Methods**: 1
- **Fields**: 12
- **Source**: `core\packet\bean\BulkDataSummaryRep.java`

**Key Methods**:
  - `parseRep()`

---

### DataTransferRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.DataTransferRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 1
- **Source**: `core\packet\bean\DataTransferRep.java`

**Key Methods**:
  - `parseRep()`

---

### DeviceNetStatusRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.DeviceNetStatusRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 1
- **Source**: `core\packet\bean\DeviceNetStatusRep.java`

**Key Methods**:
  - `parseRep()`

---

### DeviceStatusSendRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.DeviceStatusSendRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 1
- **Source**: `core\packet\bean\DeviceStatusSendRep.java`

**Key Methods**:
  - `parseRep()`

---

### ECDHRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.ECDHRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 4
- **Source**: `core\packet\bean\ECDHRep.java`

**Key Methods**:
  - `parseRep()`

---

### ExpandInfo [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.ExpandInfo`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Methods**: 12
- **Fields**: 6
- **Source**: `core\packet\bean\ExpandInfo.java`

**Key Methods**:
  - `getBv()`
  - `getH()`
  - `getI()`
  - `getOpt()`
  - `getPv()`
  - `getSv()`
  - `setBv()`
  - `setH()`
  - `setI()`
  - `setOpt()`
  - *(... and 2 more)*

---

### FileTransferBaseRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.FileTransferBaseRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 0
- **Fields**: 2
- **Source**: `core\packet\bean\FileTransferBaseRep.java`

---

### FileTransferDataRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.FileTransferDataRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `FileTransferBaseRep`
- **Methods**: 1
- **Fields**: 2
- **Source**: `core\packet\bean\FileTransferDataRep.java`

**Key Methods**:
  - `parseRep()`

---

### FileTransferOffsetRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.FileTransferOffsetRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `FileTransferBaseRep`
- **Methods**: 1
- **Fields**: 2
- **Source**: `core\packet\bean\FileTransferOffsetRep.java`

**Key Methods**:
  - `parseRep()`

---

### GetSummerTimeRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.GetSummerTimeRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 1
- **Source**: `core\packet\bean\GetSummerTimeRep.java`

**Key Methods**:
  - `parseRep()`

---

### LinkStatusRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.LinkStatusRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 2
- **Source**: `core\packet\bean\LinkStatusRep.java`

**Key Methods**:
  - `parseRep()`

---

### LocalTimeRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.LocalTimeRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\packet\bean\LocalTimeRep.java`

**Key Methods**:
  - `parseRep()`

---

### MultiChannelRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.MultiChannelRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 4
- **Fields**: 5
- **Source**: `core\packet\bean\MultiChannelRep.java`

**Key Methods**:
  - `getData()`
  - `getSubCmd()`
  - `setData()`
  - `setSubCmd()`

---

### OTAFileRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.OTAFileRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 8
- **Source**: `core\packet\bean\OTAFileRep.java`

**Key Methods**:
  - `parseRep()`

---

### OTAResultRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.OTAResultRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 3
- **Source**: `core\packet\bean\OTAResultRep.java`

**Key Methods**:
  - `parseRep()`

---

### OTASendRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.OTASendRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 3
- **Source**: `core\packet\bean\OTASendRep.java`

**Key Methods**:
  - `parseRep()`

---

### PairRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.PairRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 2
- **Source**: `core\packet\bean\PairRep.java`

**Key Methods**:
  - `parseRep()`

---

### Reps [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.Reps`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Methods**: 4
- **Fields**: 1
- **Source**: `core\packet\bean\Reps.java`

**Key Methods**:
  - `parseRep()`
  - `success()`
  - `toString()`
  - `getClass()`

---

### ResetRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.ResetRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 1
- **Source**: `core\packet\bean\ResetRep.java`

**Key Methods**:
  - `parseRep()`

---

### SendAppDataRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.SendAppDataRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 8
- **Source**: `core\packet\bean\SendAppDataRep.java`

**Key Methods**:
  - `parseRep()`

---

### SendDevActivateInfoRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.SendDevActivateInfoRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 1
- **Source**: `core\packet\bean\SendDevActivateInfoRep.java`

**Key Methods**:
  - `parseRep()`

---

### SendExpandActivateInfoRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.SendExpandActivateInfoRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 1
- **Source**: `core\packet\bean\SendExpandActivateInfoRep.java`

**Key Methods**:
  - `parseRep()`

---

### SendIOTDataRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.SendIOTDataRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 1
- **Source**: `core\packet\bean\SendIOTDataRep.java`

**Key Methods**:
  - `parseRep()`

---

### SendWiFiInfoRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.SendWiFiInfoRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `SimpleRep`
- **Methods**: 0
- **Fields**: 0
- **Source**: `core\packet\bean\SendWiFiInfoRep.java`

---

### SimpleRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.SimpleRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 1
- **Source**: `core\packet\bean\SimpleRep.java`

**Key Methods**:
  - `parseRep()`

---

### StatusRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.StatusRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 1
- **Source**: `core\packet\bean\StatusRep.java`

**Key Methods**:
  - `parseRep()`

---

### SubcontractCacheData [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.SubcontractCacheData`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Methods**: 5
- **Fields**: 10
- **Source**: `core\packet\bean\SubcontractCacheData.java`

**Key Methods**:
  - `ArrayList()`
  - `appendDataBytes()`
  - `clearDataBytes()`
  - `getReceivedByteData()`
  - `getReceivedLength()`

---

### Time1ReqRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.Time1ReqRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\packet\bean\Time1ReqRep.java`

**Key Methods**:
  - `parseRep()`

---

### Time2ReqRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.Time2ReqRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\packet\bean\Time2ReqRep.java`

**Key Methods**:
  - `parseRep()`

---

### UnbindForceRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.UnbindForceRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 1
- **Source**: `core\packet\bean\UnbindForceRep.java`

**Key Methods**:
  - `parseRep()`

---

### UnbindRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.UnbindRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 1
- **Source**: `core\packet\bean\UnbindRep.java`

**Key Methods**:
  - `parseRep()`

---

### WeatherGetRep [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.WeatherGetRep`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 3
- **Fields**: 5
- **Source**: `core\packet\bean\WeatherGetRep.java`

**Key Methods**:
  - `ArrayList()`
  - `parseRep()`
  - `String()`

---

### WeatherOfSpecifiedLocation [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.packet.bean.WeatherOfSpecifiedLocation`
- **Package**: `com.thingclips.sdk.ble.core.packet.bean`
- **Extends**: `Reps`
- **Methods**: 3
- **Fields**: 7
- **Source**: `core\packet\bean\WeatherOfSpecifiedLocation.java`

**Key Methods**:
  - `ArrayList()`
  - `parseRep()`
  - `String()`

---

### ActionNormalResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.ActionNormalResponse`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `core\protocol\api\ActionNormalResponse.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### ActionOtaResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.ActionOtaResponse`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Methods**: 4
- **Fields**: 0
- **Source**: `core\protocol\api\ActionOtaResponse.java`

**Key Methods**:
  - `onOtaError()`
  - `onOtaPercent()`
  - `onOtaReady()`
  - `onOtaSuccess()`

---

### ActionProgressResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.ActionProgressResponse`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Extends**: `ActionResponse<T>`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\protocol\api\ActionProgressResponse.java`

**Key Methods**:
  - `onProgress()`

---

### ActionReceiver [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.ActionReceiver`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\protocol\api\ActionReceiver.java`

**Key Methods**:
  - `onReceive()`

---

### ActionResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.ActionResponse`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `core\protocol\api\ActionResponse.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### CommonConstant [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.CommonConstant`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Methods**: 0
- **Fields**: 1
- **Source**: `core\protocol\api\CommonConstant.java`

---

### ConnectActionResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.ConnectActionResponse`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `core\protocol\api\ConnectActionResponse.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### DeviceCapabilityBit [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.DeviceCapabilityBit`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Methods**: 0
- **Fields**: 13
- **Source**: `core\protocol\api\DeviceCapabilityBit.java`

---

### IP4SuperSecurityAction [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.IP4SuperSecurityAction`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Methods**: 4
- **Fields**: 0
- **Source**: `core\protocol\api\IP4SuperSecurityAction.java`

**Key Methods**:
  - `encryptRandom()`
  - `fetchServerSecurityCert()`
  - `validateDeviceCert()`
  - `validateDeviceCertCorrect()`

---

### OnBleConnectStatusListener [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.OnBleConnectStatusListener`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\protocol\api\OnBleConnectStatusListener.java`

**Key Methods**:
  - `onStatusChanged()`

---

### OnBleDeviceRequestListener [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.OnBleDeviceRequestListener`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\protocol\api\OnBleDeviceRequestListener.java`

**Key Methods**:
  - `onRequest()`

---

### OnBleDpsReceiveListener [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.OnBleDpsReceiveListener`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\protocol\api\OnBleDpsReceiveListener.java`

**Key Methods**:
  - `onDpsUpload()`

---

### OnBleRetReceiveListener [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.OnBleRetReceiveListener`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\protocol\api\OnBleRetReceiveListener.java`

**Key Methods**:
  - `onRetReceive()`

---

### OnMultiModeDevStatusListener [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.OnMultiModeDevStatusListener`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\protocol\api\OnMultiModeDevStatusListener.java`

**Key Methods**:
  - `onActivatorStatusChanged()`

---

### Protocol4RequestDelegate [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.Protocol4RequestDelegate`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Extends**: `ProtocolActivatorDelegate`
- **Methods**: 1
- **Fields**: 0
- **Source**: `core\protocol\api\Protocol4RequestDelegate.java`

**Key Methods**:
  - `getSuperSecurityAction()`

---

### ProtocolAccessRequest [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.ProtocolAccessRequest`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `core\protocol\api\ProtocolAccessRequest.java`

**Key Methods**:
  - `onFail()`
  - `onResult()`

---

### ProtocolActivatorDelegate [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.ProtocolActivatorDelegate`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Extends**: `ProtocolRequestDelegate`
- **Methods**: 2
- **Fields**: 0
- **Source**: `core\protocol\api\ProtocolActivatorDelegate.java`

**Key Methods**:
  - `activatorToCloud()`
  - `requestAuthKey()`

---

### ProtocolRequestDelegate [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.ProtocolRequestDelegate`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Methods**: 3
- **Fields**: 0
- **Source**: `core\protocol\api\ProtocolRequestDelegate.java`

**Key Methods**:
  - `getConnectParam()`
  - `requestNewKey11()`
  - `requestSecretKeyAndLocalKey()`

---

### ProtocolSecurityUpdateDelegate [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.api.ProtocolSecurityUpdateDelegate`
- **Package**: `com.thingclips.sdk.ble.core.protocol.api`
- **Extends**: `ProtocolRequestDelegate`
- **Methods**: 0
- **Fields**: 0
- **Source**: `core\protocol\api\ProtocolSecurityUpdateDelegate.java`

---

### ActivatorResultParam [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.entity.ActivatorResultParam`
- **Package**: `com.thingclips.sdk.ble.core.protocol.entity`
- **Methods**: 0
- **Fields**: 5
- **Source**: `core\protocol\entity\ActivatorResultParam.java`

---

### AuthKeyParam [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.entity.AuthKeyParam`
- **Package**: `com.thingclips.sdk.ble.core.protocol.entity`
- **Methods**: 0
- **Fields**: 2
- **Source**: `core\protocol\entity\AuthKeyParam.java`

---

### BleDps [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.entity.BleDps`
- **Package**: `com.thingclips.sdk.ble.core.protocol.entity`
- **Methods**: 6
- **Fields**: 4
- **Source**: `core\protocol\entity\BleDps.java`

**Key Methods**:
  - `BleDps()`
  - `getDpResponseBean()`
  - `getFlag()`
  - `getTime()`
  - `getType()`
  - `setTime()`

---

### BleOtaParam [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.entity.BleOtaParam`
- **Package**: `com.thingclips.sdk.ble.core.protocol.entity`
- **Methods**: 0
- **Fields**: 4
- **Source**: `core\protocol\entity\BleOtaParam.java`

---

### ChannelDataDps [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.entity.ChannelDataDps`
- **Package**: `com.thingclips.sdk.ble.core.protocol.entity`
- **Methods**: 8
- **Fields**: 3
- **Source**: `core\protocol\entity\ChannelDataDps.java`

**Key Methods**:
  - `ChannelDataDps()`
  - `ChannelDataDps()`
  - `getDps()`
  - `getDpsTime()`
  - `setDps()`
  - `setDpsTime()`
  - `toString()`
  - `StringBuilder()`

---

### ConnectOpt [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.entity.ConnectOpt`
- **Package**: `com.thingclips.sdk.ble.core.protocol.entity`
- **Methods**: 23
- **Fields**: 20
- **Source**: `core\protocol\entity\ConnectOpt.java`

**Key Methods**:
  - `ConnectOpt()`
  - `build()`
  - `setAddress()`
  - `setConnectType()`
  - `setPhyConnectTimeout()`
  - `setRequestDelegate()`
  - `setSecurityLevel()`
  - `setTimeout()`
  - `backupToDefault()`
  - `getAddress()`
  - *(... and 13 more)*

---

### ConnectParam [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.entity.ConnectParam`
- **Package**: `com.thingclips.sdk.ble.core.protocol.entity`
- **Methods**: 1
- **Fields**: 5
- **Source**: `core\protocol\entity\ConnectParam.java`

**Key Methods**:
  - `setLocalKey()`

---

### ConnectRsp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.entity.ConnectRsp`
- **Package**: `com.thingclips.sdk.ble.core.protocol.entity`
- **Methods**: 0
- **Fields**: 3
- **Source**: `core\protocol\entity\ConnectRsp.java`

---

### DeviceActivatorStatus [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.entity.DeviceActivatorStatus`
- **Package**: `com.thingclips.sdk.ble.core.protocol.entity`
- **Methods**: 2
- **Fields**: 6
- **Source**: `core\protocol\entity\DeviceActivatorStatus.java`

**Key Methods**:
  - `toString()`
  - `StringBuilder()`

---

### DeviceInfoRsp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.entity.DeviceInfoRsp`
- **Package**: `com.thingclips.sdk.ble.core.protocol.entity`
- **Methods**: 0
- **Fields**: 16
- **Source**: `core\protocol\entity\DeviceInfoRsp.java`

---

### DevRequest [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.entity.DevRequest`
- **Package**: `com.thingclips.sdk.ble.core.protocol.entity`
- **Methods**: 7
- **Fields**: 14
- **Source**: `core\protocol\entity\DevRequest.java`

**Key Methods**:
  - `DevRequest()`
  - `getDr_code()`
  - `getInput()`
  - `getReq_sn()`
  - `getRequestParams()`
  - `setInput()`
  - `setRequestParams()`

---

### OtaExtChannel [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.entity.OtaExtChannel`
- **Package**: `com.thingclips.sdk.ble.core.protocol.entity`
- **Methods**: 2
- **Fields**: 3
- **Source**: `core\protocol\entity\OtaExtChannel.java`

**Key Methods**:
  - `toString()`
  - `StringBuilder()`

---

### PairParam [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.entity.PairParam`
- **Package**: `com.thingclips.sdk.ble.core.protocol.entity`
- **Methods**: 1
- **Fields**: 7
- **Source**: `core\protocol\entity\PairParam.java`

**Key Methods**:
  - `toString()`

**Notable Strings**:
  - `"PairParam{uuid='"`

---

### SecretKeyUpdateParam [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.entity.SecretKeyUpdateParam`
- **Package**: `com.thingclips.sdk.ble.core.protocol.entity`
- **Methods**: 0
- **Fields**: 3
- **Source**: `core\protocol\entity\SecretKeyUpdateParam.java`

---

### SupportType [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.protocol.entity.SupportType`
- **Package**: `com.thingclips.sdk.ble.core.protocol.entity`
- **Methods**: 1
- **Fields**: 9
- **Source**: `core\protocol\entity\SupportType.java`

**Key Methods**:
  - `isCapabilityEnable()`

---

### BlueScanResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ble.core.scan.BlueScanResponse`
- **Package**: `com.thingclips.sdk.ble.core.scan`
- **Methods**: 3
- **Fields**: 2
- **Source**: `ble\core\scan\BlueScanResponse.java`

**Key Methods**:
  - `onResult()`
  - `onScanStart()`
  - `onScanStop()`

---

### BuildConfig [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.BuildConfig`
- **Package**: `com.thingclips.sdk.blelib`
- **Methods**: 0
- **Fields**: 3
- **Source**: `thingclips\sdk\blelib\BuildConfig.java`

---

### ContextAgent [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.ContextAgent`
- **Package**: `com.thingclips.sdk.blelib`
- **Methods**: 5
- **Fields**: 3
- **Source**: `thingclips\sdk\blelib\ContextAgent.java`

**Key Methods**:
  - `ContextAgent()`
  - `getInstance()`
  - `ContextAgent()`
  - `getContext()`
  - `setContext()`

---

### Default [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.Default`
- **Package**: `com.thingclips.sdk.blelib`
- **Extends**: `IInterface`
- **Implements**: `IResponse`
- **Methods**: 15
- **Fields**: 17
- **Source**: `thingclips\sdk\blelib\IResponse.java`

**Key Methods**:
  - `asBinder()`
  - `onResponse()`
  - `Proxy()`
  - `asBinder()`
  - `getInterfaceDescriptor()`
  - `onResponse()`
  - `Stub()`
  - `asInterface()`
  - `Proxy()`
  - `getDefaultImpl()`
  - *(... and 5 more)*

---

### RuntimeChecker [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.RuntimeChecker`
- **Package**: `com.thingclips.sdk.blelib`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\blelib\RuntimeChecker.java`

**Key Methods**:
  - `checkRuntime()`

---

### Beacon [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.beacon.Beacon`
- **Package**: `com.thingclips.sdk.blelib.beacon`
- **Methods**: 4
- **Fields**: 4
- **Source**: `sdk\blelib\beacon\Beacon.java`

**Key Methods**:
  - `LinkedList()`
  - `Beacon()`
  - `toString()`
  - `StringBuilder()`

---

### BeaconItem [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.beacon.BeaconItem`
- **Package**: `com.thingclips.sdk.blelib.beacon`
- **Methods**: 1
- **Fields**: 3
- **Source**: `sdk\blelib\beacon\BeaconItem.java`

**Key Methods**:
  - `toString()`

---

### BeaconParser [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.beacon.BeaconParser`
- **Package**: `com.thingclips.sdk.blelib.beacon`
- **Methods**: 10
- **Fields**: 13
- **Source**: `sdk\blelib\beacon\BeaconParser.java`

**Key Methods**:
  - `BeaconParser()`
  - `parse()`
  - `BeaconItem()`
  - `parseBeacon()`
  - `ArrayList()`
  - `getBit()`
  - `readByte()`
  - `readShort()`
  - `setPosition()`
  - `BeaconParser()`

---

### ChannelCallback [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.channel.ChannelCallback`
- **Package**: `com.thingclips.sdk.blelib.channel`
- **Methods**: 1
- **Fields**: 0
- **Source**: `sdk\blelib\channel\ChannelCallback.java`

**Key Methods**:
  - `onCallback()`

---

### ChannelStateBlock [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.channel.ChannelStateBlock`
- **Package**: `com.thingclips.sdk.blelib.channel`
- **Methods**: 1
- **Fields**: 3
- **Source**: `sdk\blelib\channel\ChannelStateBlock.java`

**Key Methods**:
  - `ChannelStateBlock()`

---

### Code [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.channel.Code`
- **Package**: `com.thingclips.sdk.blelib.channel`
- **Methods**: 0
- **Fields**: 4
- **Source**: `sdk\blelib\channel\Code.java`

---

### CRC32 [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.channel.CRC32`
- **Package**: `com.thingclips.sdk.blelib.channel`
- **Methods**: 2
- **Fields**: 3
- **Source**: `sdk\blelib\channel\CRC32.java`

**Key Methods**:
  - `get()`
  - `getCrc()`

---

### IChannel [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.channel.IChannel`
- **Package**: `com.thingclips.sdk.blelib.channel`
- **Methods**: 4
- **Fields**: 0
- **Source**: `sdk\blelib\channel\IChannel.java`

**Key Methods**:
  - `onRead()`
  - `onRecv()`
  - `send()`
  - `write()`

---

### IChannelStateHandler [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.channel.IChannelStateHandler`
- **Package**: `com.thingclips.sdk.blelib.channel`
- **Methods**: 1
- **Fields**: 0
- **Source**: `sdk\blelib\channel\IChannelStateHandler.java`

**Key Methods**:
  - `handleState()`

---

### ACKPacket [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.channel.packet.ACKPacket`
- **Package**: `com.thingclips.sdk.blelib.channel.packet`
- **Extends**: `Packet`
- **Methods**: 9
- **Fields**: 10
- **Source**: `blelib\channel\packet\ACKPacket.java`

**Key Methods**:
  - `ACKPacket()`
  - `getStatusDesc()`
  - `getName()`
  - `getSeq()`
  - `getStatus()`
  - `toBytes()`
  - `toString()`
  - `StringBuilder()`
  - `ACKPacket()`

---

### CTRPacket [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.channel.packet.CTRPacket`
- **Package**: `com.thingclips.sdk.blelib.channel.packet`
- **Extends**: `Packet`
- **Methods**: 5
- **Fields**: 2
- **Source**: `blelib\channel\packet\CTRPacket.java`

**Key Methods**:
  - `CTRPacket()`
  - `getFrameCount()`
  - `getName()`
  - `toBytes()`
  - `toString()`

---

### DataPacket [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.channel.packet.DataPacket`
- **Package**: `com.thingclips.sdk.blelib.channel.packet`
- **Extends**: `Packet`
- **Methods**: 11
- **Fields**: 7
- **Source**: `blelib\channel\packet\DataPacket.java`

**Key Methods**:
  - `DataPacket()`
  - `fillByteBuffer()`
  - `getCrc()`
  - `getDataLength()`
  - `getName()`
  - `getSeq()`
  - `setLastFrame()`
  - `toBytes()`
  - `toString()`
  - `StringBuilder()`
  - *(... and 1 more)*

---

### InvalidPacket [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.channel.packet.InvalidPacket`
- **Package**: `com.thingclips.sdk.blelib.channel.packet`
- **Extends**: `Packet`
- **Methods**: 3
- **Fields**: 0
- **Source**: `blelib\channel\packet\InvalidPacket.java`

**Key Methods**:
  - `getName()`
  - `toBytes()`
  - `toString()`

---

### IBleConnectDispatcher [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.connect.IBleConnectDispatcher`
- **Package**: `com.thingclips.sdk.blelib.connect`
- **Methods**: 1
- **Fields**: 0
- **Source**: `sdk\blelib\connect\IBleConnectDispatcher.java`

**Key Methods**:
  - `onRequestCompleted()`

---

### BleConfigMtuRequest [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.BleConfigMtuRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Extends**: `BleRequest`
- **Implements**: `RequestMtuListener`
- **Methods**: 5
- **Fields**: 2
- **Source**: `blelib\connect\request\BleConfigMtuRequest.java`

**Key Methods**:
  - `BleConfigMtuRequest()`
  - `startConfigMtu()`
  - `onMtuChanged()`
  - `processRequest()`
  - `if()`

---

### IBleRequest [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.connect.request.IBleRequest`
- **Package**: `com.thingclips.sdk.blelib.connect.request`
- **Methods**: 2
- **Fields**: 0
- **Source**: `blelib\connect\request\IBleRequest.java`

**Key Methods**:
  - `cancel()`
  - `process()`

---

### BleGeneralResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.connect.response.BleGeneralResponse`
- **Package**: `com.thingclips.sdk.blelib.connect.response`
- **Extends**: `BleTResponse<Bundle>`
- **Methods**: 0
- **Fields**: 0
- **Source**: `blelib\connect\response\BleGeneralResponse.java`

---

### BleMtuResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.connect.response.BleMtuResponse`
- **Package**: `com.thingclips.sdk.blelib.connect.response`
- **Extends**: `BleTResponse<Integer>`
- **Methods**: 0
- **Fields**: 0
- **Source**: `blelib\connect\response\BleMtuResponse.java`

---

### BleNotifyResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.connect.response.BleNotifyResponse`
- **Package**: `com.thingclips.sdk.blelib.connect.response`
- **Extends**: `BleResponse`
- **Methods**: 1
- **Fields**: 0
- **Source**: `blelib\connect\response\BleNotifyResponse.java`

**Key Methods**:
  - `onNotify()`

---

### BleReadResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.connect.response.BleReadResponse`
- **Package**: `com.thingclips.sdk.blelib.connect.response`
- **Extends**: `BleTResponse<byte`
- **Methods**: 0
- **Fields**: 0
- **Source**: `blelib\connect\response\BleReadResponse.java`

---

### BleReadRssiResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.connect.response.BleReadRssiResponse`
- **Package**: `com.thingclips.sdk.blelib.connect.response`
- **Extends**: `BleTResponse<Integer>`
- **Methods**: 0
- **Fields**: 0
- **Source**: `blelib\connect\response\BleReadRssiResponse.java`

---

### BleResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.connect.response.BleResponse`
- **Package**: `com.thingclips.sdk.blelib.connect.response`
- **Methods**: 1
- **Fields**: 0
- **Source**: `blelib\connect\response\BleResponse.java`

**Key Methods**:
  - `onResponse()`

---

### BleTResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.connect.response.BleTResponse`
- **Package**: `com.thingclips.sdk.blelib.connect.response`
- **Methods**: 1
- **Fields**: 0
- **Source**: `blelib\connect\response\BleTResponse.java`

**Key Methods**:
  - `onResponse()`

---

### BleUnnotifyResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.connect.response.BleUnnotifyResponse`
- **Package**: `com.thingclips.sdk.blelib.connect.response`
- **Extends**: `BleResponse`
- **Methods**: 0
- **Fields**: 0
- **Source**: `blelib\connect\response\BleUnnotifyResponse.java`

---

### BleWriteResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.connect.response.BleWriteResponse`
- **Package**: `com.thingclips.sdk.blelib.connect.response`
- **Extends**: `BleResponse`
- **Methods**: 0
- **Fields**: 0
- **Source**: `blelib\connect\response\BleWriteResponse.java`

---

### ReadRssiBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.model.ReadRssiBean`
- **Package**: `com.thingclips.sdk.blelib.model`
- **Methods**: 8
- **Fields**: 4
- **Source**: `sdk\blelib\model\ReadRssiBean.java`

**Key Methods**:
  - `ReadRssiBean()`
  - `ArrayList()`
  - `addResponse()`
  - `ArrayList()`
  - `clearResponseList()`
  - `getMac()`
  - `getResponseList()`
  - `setMac()`

---

### SearchTask [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.search.SearchTask`
- **Package**: `com.thingclips.sdk.blelib.search`
- **Implements**: `Parcelable`
- **Methods**: 13
- **Fields**: 4
- **Source**: `sdk\blelib\search\SearchTask.java`

**Key Methods**:
  - `createFromParcel()`
  - `SearchTask()`
  - `newArray()`
  - `SearchTask()`
  - `describeContents()`
  - `getSearchDuration()`
  - `getSearchLevel()`
  - `getSearchType()`
  - `setSearchDuration()`
  - `setSearchLevel()`
  - *(... and 3 more)*

---

### SearchResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.search.response.SearchResponse`
- **Package**: `com.thingclips.sdk.blelib.search.response`
- **Methods**: 4
- **Fields**: 0
- **Source**: `blelib\search\response\SearchResponse.java`

**Key Methods**:
  - `onDeviceFounded()`
  - `onSearchCanceled()`
  - `onSearchStarted()`
  - `onSearchStopped()`

---

### ByteUtils [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.utils.ByteUtils`
- **Package**: `com.thingclips.sdk.blelib.utils`
- **Methods**: 30
- **Fields**: 51
- **Source**: `sdk\blelib\utils\ByteUtils.java`

**Key Methods**:
  - `byteEquals()`
  - `byteToAsciiString()`
  - `StringBuffer()`
  - `byteToString()`
  - `StringBuilder()`
  - `copy()`
  - `cutAfterBytes()`
  - `cutBeforeBytes()`
  - `equals()`
  - `equals()`
  - *(... and 20 more)*

---

### ILogPrinter [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.utils.ILogPrinter`
- **Package**: `com.thingclips.sdk.blelib.utils`
- **Methods**: 5
- **Fields**: 0
- **Source**: `sdk\blelib\utils\ILogPrinter.java`

**Key Methods**:
  - `level_d()`
  - `level_e()`
  - `level_i()`
  - `level_v()`
  - `level_w()`

---

### ListUtils [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.utils.ListUtils`
- **Package**: `com.thingclips.sdk.blelib.utils`
- **Methods**: 3
- **Fields**: 1
- **Source**: `sdk\blelib\utils\ListUtils.java`

**Key Methods**:
  - `getEmptyList()`
  - `ArrayList()`
  - `isEmpty()`

---

### MD5Utils [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.utils.MD5Utils`
- **Package**: `com.thingclips.sdk.blelib.utils`
- **Methods**: 1
- **Fields**: 5
- **Source**: `sdk\blelib\utils\MD5Utils.java`

**Key Methods**:
  - `MD5_12()`

---

### SpecialString [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.utils.SpecialString`
- **Package**: `com.thingclips.sdk.blelib.utils`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\blelib\utils\SpecialString.java`

**Key Methods**:
  - `getHoUpperCase()`
  - `getHwUpperCase()`

---

### StringUtils [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.utils.StringUtils`
- **Package**: `com.thingclips.sdk.blelib.utils`
- **Methods**: 3
- **Fields**: 5
- **Source**: `sdk\blelib\utils\StringUtils.java`

**Key Methods**:
  - `isBlank()`
  - `isNotBlank()`
  - `nullToEmpty()`

---

### UUIDUtils [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.utils.UUIDUtils`
- **Package**: `com.thingclips.sdk.blelib.utils`
- **Methods**: 1
- **Fields**: 1
- **Source**: `sdk\blelib\utils\UUIDUtils.java`

**Key Methods**:
  - `getValue()`

---

### Version [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.utils.Version`
- **Package**: `com.thingclips.sdk.blelib.utils`
- **Methods**: 2
- **Fields**: 2
- **Source**: `sdk\blelib\utils\Version.java`

**Key Methods**:
  - `isHighLollipop()`
  - `isMarshmallow()`

---

### WtUtil [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.utils.WtUtil`
- **Package**: `com.thingclips.sdk.blelib.utils`
- **Methods**: 2
- **Fields**: 2
- **Source**: `sdk\blelib\utils\WtUtil.java`

**Key Methods**:
  - `format()`
  - `StringBuilder()`

---

### FieldUtils [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.utils.hook.utils.FieldUtils`
- **Package**: `com.thingclips.sdk.blelib.utils.hook.utils`
- **Methods**: 1
- **Fields**: 4
- **Source**: `utils\hook\utils\FieldUtils.java`

**Key Methods**:
  - `getDeclaredField()`

---

### HookUtils [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.utils.hook.utils.HookUtils`
- **Package**: `com.thingclips.sdk.blelib.utils.hook.utils`
- **Methods**: 5
- **Fields**: 6
- **Source**: `utils\hook\utils\HookUtils.java`

**Key Methods**:
  - `getField()`
  - `getMethod()`
  - `getValue()`
  - `invoke()`
  - `getValue()`

---

### MemberUtils [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.utils.hook.utils.MemberUtils`
- **Package**: `com.thingclips.sdk.blelib.utils.hook.utils`
- **Methods**: 1
- **Fields**: 0
- **Source**: `utils\hook\utils\MemberUtils.java`

**Key Methods**:
  - `isAccessible()`

---

### MethodUtils [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.utils.hook.utils.MethodUtils`
- **Package**: `com.thingclips.sdk.blelib.utils.hook.utils`
- **Methods**: 5
- **Fields**: 12
- **Source**: `utils\hook\utils\MethodUtils.java`

**Key Methods**:
  - `getAccessibleMethod()`
  - `getAccessibleMethod()`
  - `getAccessibleMethodFromInterfaceNest()`
  - `getAccessibleMethodFromSuperclass()`
  - `getAccessibleMethod()`

---

### Validate [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.utils.hook.utils.Validate`
- **Package**: `com.thingclips.sdk.blelib.utils.hook.utils`
- **Methods**: 2
- **Fields**: 0
- **Source**: `utils\hook\utils\Validate.java`

**Key Methods**:
  - `isTrue()`
  - `IllegalArgumentException()`

---

### ProxyInterceptor [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.utils.proxy.ProxyInterceptor`
- **Package**: `com.thingclips.sdk.blelib.utils.proxy`
- **Methods**: 1
- **Fields**: 0
- **Source**: `blelib\utils\proxy\ProxyInterceptor.java`

**Key Methods**:
  - `onIntercept()`

---

### ProxyUtils [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blelib.utils.proxy.ProxyUtils`
- **Package**: `com.thingclips.sdk.blelib.utils.proxy`
- **Methods**: 10
- **Fields**: 0
- **Source**: `blelib\utils\proxy\ProxyUtils.java`

**Key Methods**:
  - `getProxy()`
  - `ProxyInvocationHandler()`
  - `getUIProxy()`
  - `getWeakUIProxy()`
  - `getProxy()`
  - `getUIProxy()`
  - `getProxy()`
  - `getUIProxy()`
  - `getProxy()`
  - `getUIProxy()`

---

### BuildConfig [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blescan.BuildConfig`
- **Package**: `com.thingclips.sdk.blescan`
- **Methods**: 0
- **Fields**: 3
- **Source**: `thingclips\sdk\blescan\BuildConfig.java`

---

### IThingBleScanner [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blescan.IThingBleScanner`
- **Package**: `com.thingclips.sdk.blescan`
- **Methods**: 5
- **Fields**: 0
- **Source**: `thingclips\sdk\blescan\IThingBleScanner.java`

**Key Methods**:
  - `addScanRequest()`
  - `clearCache()`
  - `removeScanRequest()`
  - `stopScan()`
  - `updateAppForeground()`

---

### LeScanResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blescan.LeScanResponse`
- **Package**: `com.thingclips.sdk.blescan`
- **Methods**: 4
- **Fields**: 0
- **Source**: `thingclips\sdk\blescan\LeScanResponse.java`

**Key Methods**:
  - `onDeviceFounded()`
  - `onScanCancel()`
  - `onScanStart()`
  - `onScanStop()`

---

### QueueProcessor [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blescan.QueueProcessor`
- **Package**: `com.thingclips.sdk.blescan`
- **Methods**: 5
- **Fields**: 14
- **Source**: `thingclips\sdk\blescan\QueueProcessor.java`

**Key Methods**:
  - `obtain()`
  - `ConcurrentHashMap()`
  - `HandlerThread()`
  - `quit()`
  - `quit()`

---

### ScanFilter [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blescan.ScanFilter`
- **Package**: `com.thingclips.sdk.blescan`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\blescan\ScanFilter.java`

**Key Methods**:
  - `filter()`
  - `filterOnly()`

---

### ScanRequest [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blescan.ScanRequest`
- **Package**: `com.thingclips.sdk.blescan`
- **Methods**: 21
- **Fields**: 19
- **Source**: `thingclips\sdk\blescan\ScanRequest.java`

**Key Methods**:
  - `build()`
  - `ScanRequest()`
  - `setDuration()`
  - `setResponse()`
  - `setScanFilter()`
  - `setTag()`
  - `setType()`
  - `getDuration()`
  - `getReqTag()`
  - `getResponse()`
  - *(... and 11 more)*

---

### ParseByteUtils [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blescan.utils.ParseByteUtils`
- **Package**: `com.thingclips.sdk.blescan.utils`
- **Methods**: 1
- **Fields**: 5
- **Source**: `sdk\blescan\utils\ParseByteUtils.java`

**Key Methods**:
  - `parse()`

---

### SafeHandler [MEDIUM]


- **Full Name**: `com.thingclips.sdk.blescan.utils.SafeHandler`
- **Package**: `com.thingclips.sdk.blescan.utils`
- **Extends**: `Handler`
- **Methods**: 14
- **Fields**: 6
- **Source**: `sdk\blescan\utils\SafeHandler.java`

**Key Methods**:
  - `SafeHandler()`
  - `setDebugMode()`
  - `clearMsg()`
  - `destroy()`
  - `dispatchMessage()`
  - `if()`
  - `if()`
  - `sendMessageAtTime()`
  - `SafeHandler()`
  - `SafeHandler()`
  - *(... and 4 more)*

---

### bbbbddp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbbbddp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qppbddd`
- **Methods**: 3
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bbbbddp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pppbppp()`
  - `qddqppb()`

---

### bbbdbqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbbdbqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 10
- **Source**: `thingclips\sdk\bluetooth\bbbdbqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ArrayList()`
  - `bdpdqbp()`

---

### bbbqddp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbbqddp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\bbbqddp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`

---

### bbdppqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbdppqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\bbdppqp.java`

---

### bbdpqdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbdpqdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pppbppp`
- **Methods**: 7
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\bbdpqdq.java`

**Key Methods**:
  - `bbdpqdq()`
  - `bpbbqdb()`
  - `bpqqdpq()`
  - `pdqppqb()`
  - `qpbpqpq()`
  - `qqdbbpp()`
  - `pdqppqb()`

---

### bbdqqbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbdqqbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 6
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\bbdqqbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`

---

### bbpdqpd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbpdqpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 19
- **Fields**: 19
- **Source**: `thingclips\sdk\bluetooth\bbpdqpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pbddddb()`
  - `pbpdbqp()`
  - `pbpdpdp()`
  - `pppbppp()`
  - `qddqppb()`
  - `qpppdqb()`
  - `bdpdqbp()`
  - *(... and 9 more)*

---

### bbppqqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbppqqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bqqpdpd`
- **Methods**: 1
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\bbppqqq.java`

**Key Methods**:
  - `bbppqqq()`

---

### bbpqqdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bbpqqdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bbpqqdq.java`

**Key Methods**:
  - `onFailure()`
  - `onSuccess()`

---

### bdbbqqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdbbqqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\bdbbqqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pdqppqb()`

---

### bdbqbpp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdbqbpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 10
- **Source**: `thingclips\sdk\bluetooth\bdbqbpp.java`

---

### bdbqdpq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdbqdpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bdbqdpq.java`

**Key Methods**:
  - `bdpdqbp()`

---

### bdbqpbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdbqpbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\bdbqpbb.java`

**Key Methods**:
  - `bdpdqbp()`

---

### bdbqpbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdbqpbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bdbqpbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`

---

### bddpddp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bddpddp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 3
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\bddpddp.java`

**Key Methods**:
  - `bddpddp()`
  - `pbpdpdp()`
  - `pdqppqb()`

---

### bddppbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bddppbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\bddppbd.java`

---

### bddqdbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bddqdbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 7
- **Fields**: 31
- **Source**: `thingclips\sdk\bluetooth\bddqdbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### bddqdbq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bddqdbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\bddqdbq.java`

**Key Methods**:
  - `bddqdbq()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### bddqpdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bddqpdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\bddqpdp.java`

---

### bdpbqbq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdpbqbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 7
- **Fields**: 23
- **Source**: `thingclips\sdk\bluetooth\bdpbqbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `ArrayList()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `ArrayList()`

---

### bdpdqbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdpdqbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 7
- **Fields**: 37
- **Source**: `thingclips\sdk\bluetooth\bdpdqbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `SecretKeySpec()`
  - `pdqppqb()`
  - `SecretKeySpec()`
  - `pdqppqb()`
  - `bdpdqbp()`

---

### bdpppdd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdpppdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\bdpppdd.java`

---

### bdpqbdd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdpqbdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\bdpqbdd.java`

**Key Methods**:
  - `AtomicInteger()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### bdpqqdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdpqqdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 17
- **Fields**: 19
- **Source**: `thingclips\sdk\bluetooth\bdpqqdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pbddddb()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `qpppdqb()`
  - `bdpdqbp()`
  - *(... and 7 more)*

---

### bdqbdpp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdqbdpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bdqbdpp.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### bdqqbqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdqqbqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 11
- **Fields**: 19
- **Source**: `thingclips\sdk\bluetooth\bdqqbqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `String()`
  - `bdpdqbp()`
  - `StringBuilder()`
  - `bdpdqbp()`
  - `StringBuilder()`
  - `Formatter()`
  - *(... and 1 more)*

---

### bdqqdqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdqqdqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bdqqdqp.java`

---

### bdqqqbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdqqqbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\bdqqqbd.java`

---

### bdqqqbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdqqqbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 33
- **Fields**: 22
- **Source**: `thingclips\sdk\bluetooth\bdqqqbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bpbbqdb()`
  - `bppdpdq()`
  - `bqqppqq()`
  - `dpdbqdp()`
  - `dpdqppp()`
  - `StringBuilder()`
  - `dqdbbqp()`
  - `dqdpbbd()`
  - `pbbppqb()`
  - *(... and 23 more)*

---

### bdqqqdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bdqqqdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bdqqqdq.java`

**Key Methods**:
  - `exchange()`

---

### bpbbbbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpbbbbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\bpbbbbb.java`

**Key Methods**:
  - `bpbbbbb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### bpbbqqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpbbqqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bpbbqqp.java`

**Key Methods**:
  - `dpdbqdp()`

---

### bpbpqdd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpbpqdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 10
- **Source**: `thingclips\sdk\bluetooth\bpbpqdd.java`

---

### bpddddq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpddddq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pbbppqb`
- **Methods**: 8
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\bpddddq.java`

**Key Methods**:
  - `bpddddq()`
  - `bdpdqbp()`
  - `bdqqbqd()`
  - `bpbbqdb()`
  - `bpqqdpq()`
  - `pdqppqb()`
  - `ppdpppq()`
  - `pdqppqb()`

---

### bppbqqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bppbqqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 6
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\bppbqqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `IvParameterSpec()`
  - `SecretKeySpec()`
  - `pdqppqb()`
  - `IvParameterSpec()`
  - `SecretKeySpec()`

---

### bppdbpp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bppdbpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qbdpdpp`
- **Methods**: 6
- **Fields**: 15
- **Source**: `thingclips\sdk\bluetooth\bppdbpp.java`

**Key Methods**:
  - `bppdbpp()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `pbddddb()`
  - `pdqppqb()`
  - `qddqppb()`

---

### bppdpdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bppdpdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 13
- **Fields**: 26
- **Source**: `thingclips\sdk\bluetooth\bppdpdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `StringBuffer()`
  - `bppdpdq()`
  - `pdqppqb()`
  - *(... and 3 more)*

---

### bppppdb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bppppdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bqpqpqb`
- **Methods**: 1
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\bppppdb.java`

**Key Methods**:
  - `toString()`

---

### bppppqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bppppqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 15
- **Source**: `thingclips\sdk\bluetooth\bppppqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `bdpdqbp()`

---

### bpqpbdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpqpbdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 6
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\bpqpbdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `String()`
  - `bdpdqbp()`

---

### bpqppbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bpqppbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\bpqppbd.java`

---

### bqbdbqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqbdbqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dddbppd`
- **Methods**: 1
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\bqbdbqb.java`

**Key Methods**:
  - `bdpdqbp()`

---

### bqbppdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqbppdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 14
- **Fields**: 10
- **Source**: `thingclips\sdk\bluetooth\bqbppdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `toString()`
  - `StringBuilder()`
  - `bppdpdq()`
  - `pdqppqb()`
  - *(... and 4 more)*

---

### bqbppqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqbppqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\bqbppqb.java`

---

### bqdpdbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqdpdbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\bqdpdbb.java`

**Key Methods**:
  - `bdpdqbp()`

---

### bqdqdqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqdqdqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 7
- **Fields**: 12
- **Source**: `thingclips\sdk\bluetooth\bqdqdqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `StringBuilder()`
  - `bppdpdq()`
  - `StringBuilder()`
  - `pdqppqb()`
  - `StringBuilder()`
  - `bdpdqbp()`

---

### bqpbppp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqpbppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\bqpbppp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`

---

### bqpqpqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqpqpqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\bqpqpqb.java`

**Key Methods**:
  - `toString()`

---

### bqpqqbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqpqqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 8
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\bqpqqbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `toString()`
  - `StringBuilder()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### bqqbpqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqqbpqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 12
- **Source**: `thingclips\sdk\bluetooth\bqqbpqb.java`

**Notable Strings**:
  - `"bluetooth_gateway_prior"`
  - `"bluetooth_connection"`

---

### bqqbpqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqqbpqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 44
- **Source**: `thingclips\sdk\bluetooth\bqqbpqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `bdpdqbp()`

---

### bqqpdpd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.bqqpdpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\bqqpdpd.java`

**Key Methods**:
  - `toString()`
  - `getClass()`

---

### dbbdpbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbbdpbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 10
- **Fields**: 20
- **Source**: `thingclips\sdk\bluetooth\dbbdpbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `BigInteger()`
  - `StringBuilder()`
  - `StringBuilder()`
  - `if()`
  - `if()`
  - `bdpdqbp()`
  - `StringBuilder()`
  - `StringBuilder()`
  - `ArrayList()`

---

### dbbpdqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbbpdqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 31
- **Fields**: 63
- **Source**: `thingclips\sdk\bluetooth\dbbpdqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `StringBuilder()`
  - `pbddddb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `String()`
  - `qddqppb()`
  - `BigInteger()`
  - *(... and 21 more)*

---

### dbddpbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbddpbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 27
- **Fields**: 51
- **Source**: `thingclips\sdk\bluetooth\dbddpbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - *(... and 17 more)*

---

### dbppbbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbppbbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 11
- **Fields**: 23
- **Source**: `thingclips\sdk\bluetooth\dbppbbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bqpqpqb()`
  - `bdpdqbp()`
  - `qdpqpqd()`
  - `ppbbppb()`
  - `dpqpppd()`
  - `qdqddqb()`
  - `bqbdbqb()`
  - `if()`
  - `qdbbdbb()`
  - *(... and 1 more)*

---

### dbpqpqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbpqpqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\dbpqpqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### dbpqqpq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbpqqpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 8
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\dbpqqpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `String()`
  - `bdpdqbp()`
  - `StringBuffer()`
  - `bdpdqbp()`
  - `StringBuilder()`
  - `Formatter()`

---

### dbqbbpb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbqbbpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 35
- **Fields**: 66
- **Source**: `thingclips\sdk\bluetooth\dbqbbpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `StringBuilder()`
  - `pbddddb()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `pppbppp()`
  - `String()`
  - `qddqppb()`
  - *(... and 25 more)*

---

### dbqbqdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbqbqdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\dbqbqdp.java`

**Key Methods**:
  - `bdpdqbp()`

---

### dbqpdqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dbqpdqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dbqpdqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pbpdbqp()`
  - `qpppdqb()`
  - `stopActivator()`

---

### ddbbppb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbbppb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\ddbbppb.java`

**Key Methods**:
  - `bdpdqbp()`

---

### ddbbqbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbbqbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 1
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\ddbbqbp.java`

**Key Methods**:
  - `ddbbqbp()`

---

### ddbdpdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbdpdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\ddbdpdp.java`

**Notable Strings**:
  - `"com.thingclips.smart.bluetooth"`

---

### ddbpdbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbpdbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qbdpdpp`
- **Methods**: 6
- **Fields**: 15
- **Source**: `thingclips\sdk\bluetooth\ddbpdbd.java`

**Key Methods**:
  - `ddbpdbd()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `pbddddb()`
  - `pdqppqb()`
  - `qddqppb()`

---

### ddbqqdd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddbqqdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\ddbqqdd.java`

---

### dddbppd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dddbppd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\dddbppd.java`

**Key Methods**:
  - `bdpdqbp()`

---

### dddddpb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dddddpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\dddddpb.java`

---

### dddpppb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dddpppb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dddpppb.java`

**Key Methods**:
  - `bdpdqbp()`

---

### dddqqdd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dddqqdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 16
- **Fields**: 19
- **Source**: `thingclips\sdk\bluetooth\dddqqdd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `StringBuilder()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - *(... and 6 more)*

---

### ddpbbqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddpbbqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 11
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\ddpbbqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 1 more)*

---

### ddpdbpd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddpdbpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\ddpdbpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### ddpddpb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddpddpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pppbppp`
- **Methods**: 7
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\ddpddpb.java`

**Key Methods**:
  - `ddpddpb()`
  - `bdpdqbp()`
  - `bpbbqdb()`
  - `pdqppqb()`
  - `qpbpqpq()`
  - `qqdbbpp()`
  - `pdqppqb()`

---

### ddppddd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddppddd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 8
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\ddppddd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `publishDps()`

---

### ddpqpqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddpqpqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 9
- **Source**: `thingclips\sdk\bluetooth\ddpqpqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `String()`

---

### ddqddpb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddqddpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 6
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\ddqddpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `String()`
  - `bdpdqbp()`

---

### ddqqbbq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddqqbbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 7
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\ddqqbbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `qpqpqbb()`
  - `handleBeaconNormalMessage()`
  - `toString()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### ddqqqpb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ddqqqpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\ddqqqpb.java`

**Key Methods**:
  - `disConnect()`
  - `inConfig()`
  - `isConnect()`
  - `startConnect()`

---

### dpbbbbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpbbbbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dpbbbbb.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### dpbdbpb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpbdbpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\dpbdbpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`

---

### dpbdpqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpbdpqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\dpbdpqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### dpbpppp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpbpppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dpbpppp.java`

**Key Methods**:
  - `bdpdqbp()`

---

### dpbqppd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpbqppd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dpbqppd.java`

**Key Methods**:
  - `getSecretKey()`

---

### dpdbppp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpdbppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bbbbddp`
- **Methods**: 3
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\dpdbppp.java`

**Key Methods**:
  - `dpdbppp()`
  - `pppbppp()`
  - `qddqppb()`

---

### dpdpqpd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpdpqpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dpdpqpd.java`

**Key Methods**:
  - `bdpdqbp()`

---

### dpdqddb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpdqddb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 7
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\dpdqddb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `StringBuilder()`
  - `pdqppqb()`
  - `StringBuilder()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### dppdpbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dppdpbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 15
- **Source**: `thingclips\sdk\bluetooth\dppdpbd.java`

---

### dppdpdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dppdpdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\dppdpdp.java`

---

### dpqdpqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpqdpqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\dpqdpqd.java`

---

### dpqpppd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpqpppd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dddbppd`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dpqpppd.java`

**Key Methods**:
  - `bdpdqbp()`

---

### dpqqqqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dpqqqqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dpqqqqp.java`

**Key Methods**:
  - `onFailure()`
  - `onSuccess()`

---

### dqbdpqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqbdpqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dqbdpqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### dqbpdbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqbpdbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bqqpdpd`
- **Methods**: 1
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\dqbpdbb.java`

**Key Methods**:
  - `dqbpdbb()`

---

### dqdbdpd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqdbdpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 6
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\dqdbdpd.java`

**Key Methods**:
  - `dqdbdpd()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `dqdbdpd()`
  - `bbppbbd()`
  - `bdpdqbp()`

---

### dqdbqdd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqdbqdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 16
- **Fields**: 9
- **Source**: `thingclips\sdk\bluetooth\dqdbqdd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pbddddb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `qpppdqb()`
  - `toString()`
  - `bdpdqbp()`
  - *(... and 6 more)*

---

### dqddqdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqddqdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 20
- **Fields**: 25
- **Source**: `thingclips\sdk\bluetooth\dqddqdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `dqddqdp()`
  - `bdpdqbp()`
  - *(... and 10 more)*

---

### dqddqqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqddqqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\dqddqqb.java`

---

### dqdpdpq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqdpdpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 8
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dqdpdpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `pdqppqb()`

---

### dqpqppb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqpqppb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\dqpqppb.java`

**Key Methods**:
  - `dqpqppb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`

---

### dqpqpqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqpqpqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\dqpqpqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`

---

### dqqbppb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqqbppb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\dqqbppb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### dqqdbpp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqqdbpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qbdpdpp`
- **Methods**: 5
- **Fields**: 14
- **Source**: `thingclips\sdk\bluetooth\dqqdbpp.java`

**Key Methods**:
  - `dqqdbpp()`
  - `pbddddb()`
  - `pdqppqb()`
  - `qddqppb()`
  - `dqqdbpp()`

---

### dqqddpb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqqddpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 14
- **Fields**: 27
- **Source**: `thingclips\sdk\bluetooth\dqqddpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `ByteArrayOutputStream()`
  - `String()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `StringBuilder()`
  - `pdqppqb()`
  - *(... and 4 more)*

---

### dqqpqbq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqqpqbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 35
- **Fields**: 66
- **Source**: `thingclips\sdk\bluetooth\dqqpqbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `StringBuilder()`
  - `pbddddb()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `pppbppp()`
  - `String()`
  - `qddqppb()`
  - *(... and 25 more)*

---

### dqqqdbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.dqqqdbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\dqqqdbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pbbdbdd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbbdbdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpbbbbb`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pbbdbdd.java`

**Key Methods**:
  - `bdpdqbp()`

---

### pbbdpdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbbdpdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\pbbdpdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pbbdpdp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pbbpbdb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbbpbdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pbbpbdb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`

---

### pbdddbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbdddbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pbdddbp.java`

**Key Methods**:
  - `onFailure()`
  - `onSuccess()`

---

### pbdddqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbdddqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `TypeReference<HashMap<String`
- **Methods**: 9
- **Fields**: 10
- **Source**: `thingclips\sdk\bluetooth\pbdddqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `HashMap()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `HashMap()`
  - `bdpdqbp()`
  - `qddqppb()`
  - `bdpdqbp()`

---

### pbdqqdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbdqqdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pbdqqdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`

---

### pbppbbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbppbbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 16
- **Fields**: 19
- **Source**: `thingclips\sdk\bluetooth\pbppbbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `StringBuilder()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - *(... and 6 more)*

---

### pbpqbbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbpqbbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\pbpqbbd.java`

---

### pbpqbdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbpqbdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\pbpqbdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`

---

### pbqbqbq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbqbqbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pppbppp`
- **Methods**: 10
- **Fields**: 12
- **Source**: `thingclips\sdk\bluetooth\pbqbqbq.java`

**Key Methods**:
  - `pbqbqbq()`
  - `HashSet()`
  - `StringBuilder()`
  - `bpbbqdb()`
  - `dqdpbbd()`
  - `pdqppqb()`
  - `pqpbpqd()`
  - `qpbpqpq()`
  - `qqdbbpp()`
  - `pdqppqb()`

---

### pbqppbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbqppbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 10
- **Source**: `thingclips\sdk\bluetooth\pbqppbb.java`

---

### pbqpqdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbqpqdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 26
- **Source**: `thingclips\sdk\bluetooth\pbqpqdq.java`

---

### pbqqbbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pbqqbbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\pbqqbbb.java`

**Key Methods**:
  - `AtomicInteger()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### pdbbqdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdbbqdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 8
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\pdbbqdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `DeviceOnlineStatusEventModel()`
  - `bdpdqbp()`
  - `DeviceDpsUpdateEventModel()`
  - `bdpdqbp()`
  - `DeviceDpsUpdateEventModel()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pdbdbpp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdbdbpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\pdbdbpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bpdpqqd()`

---

### pdbqddq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdbqddq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 6
- **Fields**: 36
- **Source**: `thingclips\sdk\bluetooth\pdbqddq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pdddqqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdddqqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\pdddqqd.java`

**Key Methods**:
  - `pdddqqd()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### pddpddq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pddpddq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\pddpddq.java`

---

### pdpdpqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdpdpqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\pdpdpqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pdppddb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdppddb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qqpqqbb`
- **Methods**: 4
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\pdppddb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `getAid()`
  - `getAkf()`
  - `getParameters()`

---

### pdppdpp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdppdpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pdppdpp.java`

**Key Methods**:
  - `bdpdqbp()`

---

### pdpqbdd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdpqbdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pdpqbdd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`

---

### pdqbqdd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdqbqdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 12
- **Fields**: 27
- **Source**: `thingclips\sdk\bluetooth\pdqbqdd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `SimpleDateFormat()`
  - `toString()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqbqdd()`
  - `pdqbqdd()`
  - `pdqppqb()`
  - `bppdpdq()`
  - `qddqppb()`
  - *(... and 2 more)*

---

### pdqbqdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdqbqdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\pdqbqdq.java`

**Key Methods**:
  - `ByteArrayOutputStream()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pdqppqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pdqppqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 8
- **Fields**: 21
- **Source**: `thingclips\sdk\bluetooth\pdqppqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `StringBuffer()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### ppbbbpd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppbbbpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dqqbdqb`
- **Methods**: 2
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\ppbbbpd.java`

**Key Methods**:
  - `ppbbbpd()`
  - `bdpdqbp()`

---

### ppbbdpd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppbbdpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qbdpdpp`
- **Methods**: 8
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\ppbbdpd.java`

**Key Methods**:
  - `ppbbdpd()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `pbddddb()`
  - `pbpdbqp()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `qddqppb()`

---

### ppbbppb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppbbppb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dddbppd`
- **Methods**: 1
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\ppbbppb.java`

**Key Methods**:
  - `bdpdqbp()`

---

### ppbdqqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppbdqqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qbdpdpp`
- **Methods**: 4
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\ppbdqqp.java`

**Key Methods**:
  - `ppbdqqp()`
  - `pbddddb()`
  - `pdqppqb()`
  - `qddqppb()`

---

### ppdbdpd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppdbdpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 14
- **Fields**: 14
- **Source**: `thingclips\sdk\bluetooth\ppdbdpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `qpppdqb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - *(... and 4 more)*

---

### ppdbqqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppdbqqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\ppdbqqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `stopConfig()`

---

### ppdpdbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppdpdbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 15
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\ppdpdbd.java`

**Key Methods**:
  - `AtomicInteger()`
  - `AtomicInteger()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `dpdbqdp()`
  - `pbbppqb()`
  - `pbddddb()`
  - `pbpdbqp()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - *(... and 5 more)*

---

### ppdpppq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppdpppq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 54
- **Source**: `thingclips\sdk\bluetooth\ppdpppq.java`

---

### pppbbbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pppbbbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pppbbbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### pppbppp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pppbppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdqqqbp`
- **Methods**: 17
- **Fields**: 14
- **Source**: `thingclips\sdk\bluetooth\pppbppp.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `pppbppp()`
  - `bdpdqbp()`
  - `bpbbqdb()`
  - `bpqqdpq()`
  - `bdpdqbp()`
  - `dbbpbbb()`
  - `pbbppqb()`
  - `pbddddb()`
  - `pdqppqb()`
  - *(... and 7 more)*

---

### ppqbqbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppqbqbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\ppqbqbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `parseDataReceived()`

---

### ppqdqpp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppqdqpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 57
- **Source**: `thingclips\sdk\bluetooth\ppqdqpp.java`

---

### ppqpqbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppqpqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 1
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\ppqpqbb.java`

**Key Methods**:
  - `ppqpqbb()`

---

### ppqpqpd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.ppqpqpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 38
- **Fields**: 64
- **Source**: `thingclips\sdk\bluetooth\ppqpqpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `BigInteger()`
  - `pbddddb()`
  - `StringBuilder()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `qpppdqb()`
  - *(... and 28 more)*

---

### pqbbbbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqbbbbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\pqbbbbd.java`

---

### pqbdpqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqbdpqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\pqbdpqq.java`

---

### pqdbbqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqdbbqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pqdbbqp.java`

**Key Methods**:
  - `onDestroy()`

---

### pqdddpq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqdddpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 6
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pqdddpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppddpq()`
  - `dpdpppb()`
  - `dbddpdp()`
  - `qbdbbdb()`
  - `dqbdbpp()`

---

### pqddpbq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqddpbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 6
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pqddpbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `ivIndexReport()`
  - `pdqppqb()`

---

### pqddpqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqddpqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\pqddpqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `bdpdqbp()`

---

### pqdqddp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqdqddp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qbdpdpp`
- **Methods**: 5
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\pqdqddp.java`

**Key Methods**:
  - `pqdqddp()`
  - `IllegalArgumentException()`
  - `pbddddb()`
  - `pdqppqb()`
  - `qddqppb()`

---

### pqdqqbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqdqqbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 16
- **Fields**: 34
- **Source**: `thingclips\sdk\bluetooth\pqdqqbd.java`

**Key Methods**:
  - `ArrayList()`
  - `bppdpdq()`
  - `bppdpdq()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - *(... and 6 more)*

**Notable Strings**:
  - `"AuthKeyUUIDParser"`

---

### pqpbbpp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqpbbpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bdbbdpd`
- **Methods**: 1
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\pqpbbpp.java`

**Key Methods**:
  - `pqpbbpp()`

---

### pqpbpqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqpbpqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pqpbpqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pqpbpqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqpbpqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pqpbpqp.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### pqqdpdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.pqqdpdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dpbqppd`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\pqqdpdp.java`

**Key Methods**:
  - `getSecurityUpdateFlag()`

---

### qbbdpbq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbbdpbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 11
- **Fields**: 19
- **Source**: `thingclips\sdk\bluetooth\qbbdpbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `String()`
  - `bdpdqbp()`
  - `StringBuilder()`
  - `bdpdqbp()`
  - `StringBuilder()`
  - `Formatter()`
  - *(... and 1 more)*

---

### qbdbqpd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbdbqpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qbdbqpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onError()`
  - `onProgress()`

---

### qbdddpd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbdddpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 8
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\qbdddpd.java`

**Key Methods**:
  - `AtomicInteger()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `qpppdqb()`

---

### qbdpdpp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbdpdpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qppbddd`
- **Methods**: 10
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\qbdpdpp.java`

**Key Methods**:
  - `qbdpdpp()`
  - `bdpdqbp()`
  - `pbbppqb()`
  - `pbddddb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `qpppdqb()`
  - `qbdpdpp()`
  - `bdpdqbp()`

---

### qbdpqqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbdpqqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qbdpqqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### qbdqpqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbdqpqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\qbdqpqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qbpbpqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbpbpqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 20
- **Fields**: 42
- **Source**: `thingclips\sdk\bluetooth\qbpbpqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ArrayList()`
  - `pdqppqb()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `bdpdqbp()`
  - *(... and 10 more)*

---

### qbqdpqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbqdpqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 7
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\qbqdpqp.java`

**Key Methods**:
  - `qbqdpqp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qbqdpqp()`
  - `CopyOnWriteArraySet()`
  - `bdpdqbp()`

---

### qbqppdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbqppdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qbqppdq.java`

**Key Methods**:
  - `bdpdqbp()`

---

### qbqqdqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbqqdqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\qbqqdqq.java`

**Key Methods**:
  - `bdpdqbp()`

---

### qbqqqdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qbqqqdp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dqqbdqb`
- **Methods**: 2
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\qbqqqdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`

---

### qdbbdbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdbbdbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dddbppd`
- **Methods**: 3
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\qdbbdbb.java`

**Key Methods**:
  - `HashSet()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qdbbdpd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdbbdpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qdbbdpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`

---

### qdbpqqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdbpqqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bqqpdpd`
- **Methods**: 1
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\qdbpqqq.java`

**Key Methods**:
  - `qdbpqqq()`

---

### qdddbdb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdddbdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\qdddbdb.java`

**Key Methods**:
  - `bdpdqbp()`

---

### qdddbpp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdddbpp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\qdddbpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qddddbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qddddbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\qddddbd.java`

---

### qddppqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qddppqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\qddppqd.java`

**Key Methods**:
  - `bdpdqbp()`

---

### qddqppb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qddqppb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 13
- **Fields**: 26
- **Source**: `thingclips\sdk\bluetooth\qddqppb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `StringBuffer()`
  - `bppdpdq()`
  - `pdqppqb()`
  - *(... and 3 more)*

---

### qddqqdd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qddqqdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BaseEventSender`
- **Methods**: 1
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\qddqqdd.java`

**Key Methods**:
  - `bdpdqbp()`

---

### qdpqpqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdpqpqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dddbppd`
- **Methods**: 2
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\qdpqpqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `toString()`

---

### qdqbdbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdqbdbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 7
- **Source**: `thingclips\sdk\bluetooth\qdqbdbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`

---

### qdqdddq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdqdddq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `bqqpdpd`
- **Methods**: 1
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\qdqdddq.java`

**Key Methods**:
  - `qdqdddq()`

---

### qdqddqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qdqddqb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `dddbppd`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qdqddqb.java`

**Key Methods**:
  - `bdpdqbp()`

---

### qpbdppb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpbdppb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qbdpdpp`
- **Methods**: 5
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\qpbdppb.java`

**Key Methods**:
  - `qpbdppb()`
  - `pbddddb()`
  - `pdqppqb()`
  - `qddqppb()`
  - `qpbdppb()`

---

### qpdbdpd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpdbdpd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 7
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\qpdbdpd.java`

**Key Methods**:
  - `qpdbdpd()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `qpdbdpd()`
  - `HashMap()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qpddpqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpddpqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qpddpqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`

---

### qpddqdd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpddqdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 3
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qpddqdd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qpdqbpb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpdqbpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qpdqbpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### qpdqppb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpdqppb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\qpdqppb.java`

**Key Methods**:
  - `toString()`
  - `StringBuilder()`

**Notable Strings**:
  - `"[uuid:"`

---

### qppbdqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qppbdqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 8
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\qppbdqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `String()`
  - `bdpdqbp()`
  - `StringBuffer()`
  - `bdpdqbp()`
  - `StringBuilder()`
  - `Formatter()`

---

### qppbpqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qppbpqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qppbpqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`

---

### qpppdbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpppdbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 25
- **Fields**: 49
- **Source**: `thingclips\sdk\bluetooth\qpppdbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - *(... and 15 more)*

---

### qpqpppd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqpppd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 8
- **Fields**: 18
- **Source**: `thingclips\sdk\bluetooth\qpqpppd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `qpqpppd()`
  - `bdpdqbp()`
  - `qpqpppd()`

---

### qpqpqbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqpqbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qpqpqbb.java`

**Key Methods**:
  - `handleBeaconNormalMessage()`

---

### qpqqpdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qpqqpdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qpqqpdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onConnectStatusChanged()`

---

### qqbbdbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqbbdbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 4
- **Source**: `thingclips\sdk\bluetooth\qqbbdbb.java`

---

### qqbbddb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqbbddb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 12
- **Fields**: 9
- **Source**: `thingclips\sdk\bluetooth\qqbbddb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `toString()`
  - `StringBuilder()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - *(... and 2 more)*

---

### qqbbpbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqbbpbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `IModel`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qqbbpbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `remove()`

---

### qqbdbbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqbdbbb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 5
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qqbdbbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### qqbddbq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqbddbq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 73
- **Source**: `thingclips\sdk\bluetooth\qqbddbq.java`

---

### qqbppqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqbppqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `pppbppp`
- **Methods**: 6
- **Fields**: 8
- **Source**: `thingclips\sdk\bluetooth\qqbppqp.java`

**Key Methods**:
  - `qqbppqp()`
  - `bpbbqdb()`
  - `pdqppqb()`
  - `qpbpqpq()`
  - `qqdbbpp()`
  - `pdqppqb()`

---

### qqbpqqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqbpqqq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 6
- **Fields**: 36
- **Source**: `thingclips\sdk\bluetooth\qqbpqqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qqbqppp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqbqppp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 46
- **Source**: `thingclips\sdk\bluetooth\qqbqppp.java`

---

### qqddbbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqddbbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 4
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\qqddbbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qqddbpb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqddbpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 17
- **Fields**: 31
- **Source**: `thingclips\sdk\bluetooth\qqddbpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `AESUtil()`
  - `bppdpdq()`
  - `AESUtil()`
  - `pdqppqb()`
  - `AESUtil()`
  - `pppbppp()`
  - `AESUtil()`
  - `qddqppb()`
  - `AESUtil()`
  - *(... and 7 more)*

---

### qqpbpbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpbpbp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Implements**: `dpbdpqq`
- **Methods**: 12
- **Fields**: 10
- **Source**: `thingclips\sdk\bluetooth\qqpbpbp.java`

**Key Methods**:
  - `qqpbpbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `qqpbpbp()`
  - `ddbdpqb()`
  - `pdqppqb()`
  - `ArrayList()`
  - `bdpdqbp()`
  - *(... and 2 more)*

---

### qqpbpdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpbpdq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 12
- **Fields**: 11
- **Source**: `thingclips\sdk\bluetooth\qqpbpdq.java`

**Key Methods**:
  - `qqpbpdq()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `qqpbpdq()`
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - *(... and 2 more)*

---

### qqpdddb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpdddb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qqpdddb.java`

**Key Methods**:
  - `onEventMainThread()`

---

### qqppdpq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqppdpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qqppdpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `stopActivator()`

---

### qqpppqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpppqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 12
- **Source**: `thingclips\sdk\bluetooth\qqpppqd.java`

---

### qqppqqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqppqqd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `BaseEventSender`
- **Methods**: 1
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\qqppqqd.java`

**Key Methods**:
  - `bdpdqbp()`

---

### qqpqppd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpqppd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qppbddd`
- **Methods**: 12
- **Fields**: 5
- **Source**: `thingclips\sdk\bluetooth\qqpqppd.java`

**Key Methods**:
  - `qqpqppd()`
  - `bdpdqbp()`
  - `pbbppqb()`
  - `pbddddb()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `qpppdqb()`
  - *(... and 2 more)*

---

### qqpqqbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpqqbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 6
- **Fields**: 6
- **Source**: `thingclips\sdk\bluetooth\qqpqqbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qqpqqpq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqpqqpq`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Extends**: `qbdpdpp`
- **Methods**: 16
- **Fields**: 25
- **Source**: `thingclips\sdk\bluetooth\qqpqqpq.java`

**Key Methods**:
  - `qqpqqpq()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `bpbbqdb()`
  - `bqqppqq()`
  - `dpdbqdp()`
  - `dqdbbqp()`
  - `pbddddb()`
  - `pbpdbqp()`
  - `pbpdpdp()`
  - *(... and 6 more)*

---

### qqqbpdd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqqbpdd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 1
- **Source**: `thingclips\sdk\bluetooth\qqqbpdd.java`

---

### qqqddbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqqddbd`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 25
- **Fields**: 25
- **Source**: `thingclips\sdk\bluetooth\qqqddbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `dpdbqdp()`
  - `pbbppqb()`
  - `pbddddb()`
  - `pbpdbqp()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `pppbppp()`
  - `pqdbppq()`
  - *(... and 15 more)*

---

### qqqdqdb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqqdqdb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 1
- **Fields**: 0
- **Source**: `thingclips\sdk\bluetooth\qqqdqdb.java`

**Key Methods**:
  - `updateSchemaMap()`

---

### qqqpdpb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqqpdpb`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 9
- **Fields**: 3
- **Source**: `thingclips\sdk\bluetooth\qqqpdpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `DeviceOnlineStatusEventModel()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `DeviceDpsUpdateEventModel()`
  - `bdpdqbp()`
  - `DeviceDpsUpdateEventModel()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qqqqbqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.bluetooth.qqqqbqp`
- **Package**: `com.thingclips.sdk.bluetooth`
- **Methods**: 0
- **Fields**: 2
- **Source**: `thingclips\sdk\bluetooth\qqqqbqp.java`

---

### ClientBusiness [MEDIUM]


- **Full Name**: `com.thingclips.sdk.business.ClientBusiness`
- **Package**: `com.thingclips.sdk.business`
- **Extends**: `Business`
- **Methods**: 1
- **Fields**: 1
- **Source**: `thingclips\sdk\business\ClientBusiness.java`

**Key Methods**:
  - `getTime()`

---

### bppdpdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.cache.business.bppdpdq`
- **Package**: `com.thingclips.sdk.cache.business`
- **Implements**: `ISmartStatusManager`
- **Methods**: 16
- **Fields**: 28
- **Source**: `sdk\cache\business\bppdpdq.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `run()`
  - `bdpdqbp()`
  - `registerListener()`
  - `registerRelationListener()`
  - *(... and 6 more)*

---

### ThingActivatorPlugin [MEDIUM]


- **Full Name**: `com.thingclips.sdk.config.ThingActivatorPlugin`
- **Package**: `com.thingclips.sdk.config`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingDeviceActivatorPlugin`
- **Methods**: 6
- **Fields**: 0
- **Source**: `thingclips\sdk\config\ThingActivatorPlugin.java`

**Key Methods**:
  - `dependencies()`
  - `getActivator()`
  - `getActivatorInstance()`
  - `init()`
  - `newCheckDevAcitveStatusByToken()`
  - `bqbdbqb()`

---

### BatchPairLogBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.config.bean.BatchPairLogBean`
- **Package**: `com.thingclips.sdk.config.bean`
- **Methods**: 2
- **Fields**: 16
- **Source**: `sdk\config\bean\BatchPairLogBean.java`

**Key Methods**:
  - `toString()`
  - `StringBuilder()`

**Notable Strings**:
  - `"', uuid='"`

---

### EnableWifiBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.config.bean.EnableWifiBean`
- **Package**: `com.thingclips.sdk.config.bean`
- **Methods**: 4
- **Fields**: 3
- **Source**: `sdk\config\bean\EnableWifiBean.java`

**Key Methods**:
  - `getTime()`
  - `getType()`
  - `setTime()`
  - `setType()`

---

### ParallelParamBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.config.bean.ParallelParamBean`
- **Package**: `com.thingclips.sdk.config.bean`
- **Methods**: 1
- **Fields**: 7
- **Source**: `sdk\config\bean\ParallelParamBean.java`

**Key Methods**:
  - `ParallelParamBean()`

---

### VersionMaintenance [MEDIUM]


- **Full Name**: `com.thingclips.sdk.constant.VersionMaintenance`
- **Package**: `com.thingclips.sdk.constant`
- **Methods**: 1
- **Fields**: 9
- **Source**: `thingclips\sdk\constant\VersionMaintenance.java`

**Key Methods**:
  - `isLANAndMqttVersionSupport()`

---

### AbstractComponentService [MEDIUM]


- **Full Name**: `com.thingclips.sdk.core.AbstractComponentService`
- **Package**: `com.thingclips.sdk.core`
- **Methods**: 3
- **Fields**: 0
- **Source**: `thingclips\sdk\core\AbstractComponentService.java`

**Key Methods**:
  - `dependencies()`
  - `dependsOn()`
  - `init()`

---

### C0279b [MEDIUM]


- **Full Name**: `com.thingclips.sdk.core.C0279b`
- **Package**: `com.thingclips.sdk.core`
- **Extends**: `ZipEntry>`
- **Methods**: 6
- **Fields**: 13
- **Source**: `thingclips\sdk\core\C0279b.java`

**Key Methods**:
  - `m360a()`
  - `m361a()`
  - `ArrayList()`
  - `ArrayList()`
  - `File()`
  - `ZipFile()`

---

### bbppbbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.bbppbbd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `BaseModel`
- **Implements**: `Business.ResultListener<Boolean>`
- **Methods**: 52
- **Fields**: 36
- **Source**: `thingclips\sdk\device\bbppbbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `ArrayList()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 42 more)*

---

### bbpqdqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.bbpqdqb`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `Runnable`
- **Methods**: 10
- **Fields**: 15
- **Source**: `thingclips\sdk\device\bbpqdqb.java`

**Key Methods**:
  - `ThingHandler()`
  - `AtomicInteger()`
  - `b()`
  - `bdpdqbp()`
  - `run()`
  - `bdpdqbp()`
  - `bbpqdqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`

---

### bdbbqbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.bdbbqbd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `Business`
- **Methods**: 10
- **Fields**: 28
- **Source**: `thingclips\sdk\device\bdbbqbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ApiParams()`
  - `pdqppqb()`
  - `ApiParams()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ApiParams()`
  - `bdpdqbp()`

---

### bdpdqbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.bdpdqbp`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `AbsThingDevice`
- **Methods**: 5
- **Fields**: 3
- **Source**: `thingclips\sdk\device\bdpdqbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `registerDevListener()`
  - `pdqppqb()`
  - `requestWifiSignal()`
  - `unRegisterDevListener()`

---

### bdqbdpp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.bdqbdpp`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Methods**: 7
- **Fields**: 9
- **Source**: `thingclips\sdk\device\bdqbdpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdqbdpp()`
  - `bdpdqbp()`
  - `toString()`
  - `StringBuilder()`
  - `bdqbdpp()`
  - `bdpdqbp()`

---

### bpbqqdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.bpbqqdq`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `TypeReference<ArrayList<Object>>`
- **Methods**: 14
- **Fields**: 48
- **Source**: `thingclips\sdk\device\bpbqqdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ArrayList()`
  - `pdqppqb()`
  - `if()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 4 more)*

---

### bppdpdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.bppdpdq`
- **Package**: `com.thingclips.sdk.device`
- **Methods**: 3
- **Fields**: 34
- **Source**: `thingclips\sdk\device\bppdpdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `HashMap()`
  - `pdqppqb()`

---

### bqdpddb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.bqdpddb`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingDeviceOperator`
- **Methods**: 18
- **Fields**: 11
- **Source**: `thingclips\sdk\device\bqdpddb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bqdpddb()`
  - `bdpdqbp()`
  - `dpsFromProperties()`
  - `getAuthPropertyByUUID()`
  - `getThingModelWithProductId()`
  - `removeDeviceCloud()`
  - `dpdqppp()`
  - *(... and 8 more)*

---

### bqpbddq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.bqpbddq`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `ppbqqdd`
- **Methods**: 5
- **Fields**: 0
- **Source**: `thingclips\sdk\device\bqpbddq.java`

**Key Methods**:
  - `bqpbddq()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pdqppqb()`

---

### bqpdqdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.bqpdqdp`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `ppqpqpd`
- **Implements**: `GwOtaTypeEvent`
- **Methods**: 34
- **Fields**: 45
- **Source**: `thingclips\sdk\device\bqpdqdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `handleMessage()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onFailureWithText()`
  - `onProgress()`
  - `onStatusChanged()`
  - *(... and 24 more)*

---

### bqpqpqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.bqpqpqb`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Implements**: `Runnable`
- **Methods**: 14
- **Fields**: 11
- **Source**: `thingclips\sdk\device\bqpqpqb.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `bqpqpqb()`
  - `pdqppqb()`
  - `run()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `MQ_Link_DeviceMessageBean()`
  - `if()`
  - `if()`
  - *(... and 4 more)*

---

### dbddpbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.dbddpbp`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingServer`
- **Methods**: 3
- **Fields**: 4
- **Source**: `thingclips\sdk\device\dbddpbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `dbddpbp()`
  - `isServerConnect()`

---

### dbqbbpb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.dbqbbpb`
- **Package**: `com.thingclips.sdk.device`
- **Methods**: 11
- **Fields**: 12
- **Source**: `thingclips\sdk\device\dbqbbpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `dbqbbpb()`
  - `qddqppb()`
  - `bppdpdq()`
  - `ConcurrentHashMap()`
  - `ArrayList()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `ConcurrentHashMap()`
  - `b()`
  - *(... and 1 more)*

---

### dbqqppp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.dbqqppp`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingDpsUpdateManager`
- **Methods**: 15
- **Fields**: 22
- **Source**: `thingclips\sdk\device\dbqqppp.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `bdpdqbp()`
  - `ConcurrentHashMap()`
  - `pdqppqb()`
  - `ConcurrentHashMap()`
  - `dbqqppp()`
  - `bdpdqbp()`
  - `updateDpsCache()`
  - `if()`
  - `bdpdqbp()`
  - *(... and 5 more)*

---

### ddbdpdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.ddbdpdp`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingMqttChannel`
- **Methods**: 14
- **Fields**: 19
- **Source**: `thingclips\sdk\device\ddbdpdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `bdpdqbp()`
  - `ddbdpdp()`
  - `pdqppqb()`
  - `onEvent()`
  - `registerMqttRetainChannelListener()`
  - `sendDeviceMqttMessage()`
  - `JSONObject()`
  - `JSONObject()`
  - *(... and 4 more)*

---

### ddqpdpp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.ddqpdpp`
- **Package**: `com.thingclips.sdk.device`
- **Methods**: 8
- **Fields**: 35
- **Source**: `thingclips\sdk\device\ddqpdpp.java`

**Key Methods**:
  - `ddqpdpp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `StringBuilder()`

---

### dpppdpq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.dpppdpq`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `Runnable`
- **Methods**: 5
- **Fields**: 4
- **Source**: `thingclips\sdk\device\dpppdpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `dpppdpq()`
  - `bdpdqbp()`
  - `onEvent()`

---

### dqbdpqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.dqbdpqb`
- **Package**: `com.thingclips.sdk.device`
- **Methods**: 11
- **Fields**: 13
- **Source**: `thingclips\sdk\device\dqbdpqb.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `pdqppqb()`
  - `dqbdpqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `StringBuilder()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `HashMap()`
  - *(... and 1 more)*

---

### dqdbbqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.dqdbbqp`
- **Package**: `com.thingclips.sdk.device`
- **Methods**: 6
- **Fields**: 6
- **Source**: `thingclips\sdk\device\dqdbbqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `JSONObject()`
  - `bdpdqbp()`
  - `JSONObject()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### dqqpqbq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.dqqpqbq`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingProductPanelManager`
- **Methods**: 21
- **Fields**: 20
- **Source**: `thingclips\sdk\device\dqqpqbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `dqqpqbq()`
  - `pdqppqb()`
  - `bppdpdq()`
  - `b()`
  - `clearCache()`
  - `clearLocalMemory()`
  - `getProductPanelInfoBean()`
  - `getProductPanelInfoBeanFromLocal()`
  - `ConcurrentHashMap()`
  - *(... and 11 more)*

---

### pbddddb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.pbddddb`
- **Package**: `com.thingclips.sdk.device`
- **Methods**: 0
- **Fields**: 3
- **Source**: `thingclips\sdk\device\pbddddb.java`

---

### pbqpppp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.pbqpppp`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingSingleTransfer, MqttFlowRespParseListener, IMqttServerStatusCallback`
- **Methods**: 23
- **Fields**: 20
- **Source**: `thingclips\sdk\device\pbqpppp.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `pbqpppp()`
  - `bdpdqbp()`
  - `getLocalKey()`
  - `isOnline()`
  - `onConnectError()`
  - `onConnectSuccess()`
  - *(... and 13 more)*

---

### pdbpddd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.pdbpddd`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IDeviceMqttProtocolListener<MQ_203_DataReceivedBean>`
- **Methods**: 9
- **Fields**: 17
- **Source**: `thingclips\sdk\device\pdbpddd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `pdbpddd()`
  - `dpdqppp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onResult()`

---

### pdddqqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.pdddqqd`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingTimer`
- **Methods**: 62
- **Fields**: 30
- **Source**: `thingclips\sdk\device\pdddqqd.java`

**Key Methods**:
  - `qqbbddb()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 52 more)*

---

### pdpdpqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.pdpdpqp`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Methods**: 13
- **Fields**: 27
- **Source**: `thingclips\sdk\device\pdpdpqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `HashMap()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `HashMap()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 3 more)*

---

### ppbqqdd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.ppbqqdd`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IResultCallback`
- **Methods**: 11
- **Fields**: 11
- **Source**: `thingclips\sdk\device\ppbqqdd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `ppbqqdd()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `StringBuilder()`
  - `bppdpdq()`
  - `pdqppqb()`
  - *(... and 1 more)*

---

### pppppqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.pppppqd`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingCommonTimer`
- **Methods**: 39
- **Fields**: 27
- **Source**: `thingclips\sdk\device\pppppqd.java`

**Key Methods**:
  - `qqpddqd()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 29 more)*

---

### ppqdpdb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.ppqdpdb`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `dddbqdq`
- **Methods**: 5
- **Fields**: 0
- **Source**: `thingclips\sdk\device\ppqdpdb.java`

**Key Methods**:
  - `ppqdpdb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pdqppqb()`

---

### pqdppqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.pqdppqd`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `NetWorkStatusEvent, ForeGroundStatusEvent`
- **Methods**: 6
- **Fields**: 7
- **Source**: `thingclips\sdk\device\pqdppqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pqdppqd()`
  - `bdpdqbp()`
  - `onEvent()`
  - `pdqppqb()`
  - `onEvent()`

---

### qbdqdbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.qbdqdbd`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingSmartTimer`
- **Methods**: 41
- **Fields**: 30
- **Source**: `thingclips\sdk\device\qbdqdbd.java`

**Key Methods**:
  - `qqbbddb()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 31 more)*

---

### qbdqpqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.qbdqpqq`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IResultCallback`
- **Methods**: 10
- **Fields**: 17
- **Source**: `thingclips\sdk\device\qbdqpqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `HashMap()`
  - `onSuccess()`
  - `HashMap()`
  - `bdpdqbp()`
  - `if()`
  - `bdpdqbp()`
  - `MqttControlBuilder()`
  - `bdpdqbp()`

---

### qbqpbbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.qbqpbbd`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `Runnable`
- **Methods**: 5
- **Fields**: 3
- **Source**: `thingclips\sdk\device\qbqpbbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `qbqpbbd()`
  - `bdpdqbp()`
  - `onEvent()`

---

### qddddbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.qddddbd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `ppqpqpd`
- **Implements**: `dbpdpbp`
- **Methods**: 12
- **Fields**: 19
- **Source**: `thingclips\sdk\device\qddddbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onProgress()`
  - `onSuccess()`
  - `qddddbd()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `JSONObject()`
  - `bqpdbqq()`
  - `NullPointerException()`
  - *(... and 2 more)*

---

### qdpppbq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.qdpppbq`
- **Package**: `com.thingclips.sdk.device`
- **Methods**: 2
- **Fields**: 15
- **Source**: `thingclips\sdk\device\qdpppbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `HashMap()`

---

### qpdbdpd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.qpdbdpd`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingGroup`
- **Methods**: 33
- **Fields**: 38
- **Source**: `thingclips\sdk\device\qpdbdpd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - `qddqppb()`
  - *(... and 23 more)*

---

### qpppbpq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.qpppbpq`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingVoiceTransfer, IDeviceMqttProtocolListener`
- **Methods**: 9
- **Fields**: 10
- **Source**: `thingclips\sdk\device\qpppbpq.java`

**Key Methods**:
  - `ArrayList()`
  - `qpppbpq()`
  - `bdpdqbp()`
  - `onConnect()`
  - `onDestroy()`
  - `onResult()`
  - `SpeechTTSBean()`
  - `subscribeServer()`
  - `unSubscribeServer()`

---

### qqbbddb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.qqbbddb`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `Business`
- **Methods**: 14
- **Fields**: 20
- **Source**: `thingclips\sdk\device\qqbbddb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 4 more)*

---

### qqdqbpb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.qqdqbpb`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `IThingDeviceBizPropBeanListManager`
- **Methods**: 20
- **Fields**: 14
- **Source**: `thingclips\sdk\device\qqdqbpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `qqdqbpb()`
  - `pdqppqb()`
  - `bppdpdq()`
  - `b()`
  - `clear()`
  - `clearByDevId()`
  - `getDeviceBizPropBean()`
  - `getDeviceBizPropBeanList()`
  - `ArrayList()`
  - *(... and 10 more)*

---

### qqpddqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.qqpddqd`
- **Package**: `com.thingclips.sdk.device`
- **Extends**: `Business`
- **Methods**: 10
- **Fields**: 13
- **Source**: `thingclips\sdk\device\qqpddqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `StringBuilder()`
  - `bdpdqbp()`

---

### RunnableC0281a [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.RunnableC0281a`
- **Package**: `com.thingclips.sdk.device`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 12
- **Source**: `thingclips\sdk\device\RunnableC0281a.java`

**Key Methods**:
  - `run()`

---

### DpBuriedConfig [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.analysis.DpBuriedConfig`
- **Package**: `com.thingclips.sdk.device.analysis`
- **Methods**: 14
- **Fields**: 7
- **Source**: `sdk\device\analysis\DpBuriedConfig.java`

**Key Methods**:
  - `getDpSame()`
  - `getInterval()`
  - `getOsCategoryBlack()`
  - `getOsCategorySampling()`
  - `getSampling()`
  - `getTimeout()`
  - `isEnable()`
  - `setDpSame()`
  - `setEnable()`
  - `setInterval()`
  - *(... and 4 more)*

---

### DevUpgradeBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.bean.DevUpgradeBean`
- **Package**: `com.thingclips.sdk.device.bean`
- **Implements**: `Serializable`
- **Methods**: 22
- **Fields**: 11
- **Source**: `sdk\device\bean\DevUpgradeBean.java`

**Key Methods**:
  - `getChannel()`
  - `getDevId()`
  - `getFirmwareKey()`
  - `getId()`
  - `getStatus()`
  - `getUpgradeStatus()`
  - `getVerBaseline()`
  - `getVerCAD()`
  - `getVerCD()`
  - `getVerProtocol()`
  - *(... and 12 more)*

---

### SmartCacheRelationManager [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.cache.SmartCacheRelationManager`
- **Package**: `com.thingclips.sdk.device.cache`
- **Implements**: `ISmartCacheManager.Relation`
- **Methods**: 46
- **Fields**: 80
- **Source**: `sdk\device\cache\SmartCacheRelationManager.java`

**Key Methods**:
  - `CacheManager()`
  - `ReentrantReadWriteLock()`
  - `RelationKey()`
  - `equals()`
  - `hashCode()`
  - `RelationKey()`
  - `run()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - *(... and 36 more)*

---

### ThingCachePlugin [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.cache.ThingCachePlugin`
- **Package**: `com.thingclips.sdk.device.cache`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingCachePlugin`
- **Methods**: 3
- **Fields**: 0
- **Source**: `sdk\device\cache\ThingCachePlugin.java`

**Key Methods**:
  - `dependencies()`
  - `getCacheManager()`
  - `init()`

---

### bdpdqbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.presnter.bdpdqbp`
- **Package**: `com.thingclips.sdk.device.presnter`
- **Extends**: `Handler`
- **Implements**: `GwOtaTypeEvent`
- **Methods**: 18
- **Fields**: 21
- **Source**: `sdk\device\presnter\ThingGwOTACheck.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - `getDeviceBean()`
  - `getMqttChannel()`
  - `getQueryGwContent()`
  - *(... and 8 more)*

---

### ThingDeviceSharePlugin [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.share.ThingDeviceSharePlugin`
- **Package**: `com.thingclips.sdk.device.share`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingDeviceSharePlugin`
- **Methods**: 5
- **Fields**: 0
- **Source**: `sdk\device\share\ThingDeviceSharePlugin.java`

**Key Methods**:
  - `dependencies()`
  - `getGroupShareList()`
  - `getShareInstance()`
  - `getShareList()`
  - `init()`

---

### StatUtils [MEDIUM]


- **Full Name**: `com.thingclips.sdk.device.stat.StatUtils`
- **Package**: `com.thingclips.sdk.device.stat`
- **Implements**: `ITemporaryCallBack`
- **Methods**: 25
- **Fields**: 63
- **Source**: `sdk\device\stat\StatUtils.java`

**Key Methods**:
  - `onHandler()`
  - `ArrayList()`
  - `HashMap()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `HashMap()`
  - `bdpdqbp()`
  - *(... and 15 more)*

---

### EventBusException [MEDIUM]


- **Full Name**: `com.thingclips.sdk.eventbus.EventBusException`
- **Package**: `com.thingclips.sdk.eventbus`
- **Extends**: `RuntimeException`
- **Methods**: 3
- **Fields**: 1
- **Source**: `thingclips\sdk\eventbus\EventBusException.java`

**Key Methods**:
  - `EventBusException()`
  - `EventBusException()`
  - `EventBusException()`

---

### HandlerPoster [MEDIUM]


- **Full Name**: `com.thingclips.sdk.eventbus.HandlerPoster`
- **Package**: `com.thingclips.sdk.eventbus`
- **Extends**: `Handler`
- **Methods**: 6
- **Fields**: 8
- **Source**: `thingclips\sdk\eventbus\HandlerPoster.java`

**Key Methods**:
  - `HandlerPoster()`
  - `PendingPostQueue()`
  - `enqueue()`
  - `EventBusException()`
  - `handleMessage()`
  - `EventBusException()`

---

### PendingPost [MEDIUM]


- **Full Name**: `com.thingclips.sdk.eventbus.PendingPost`
- **Package**: `com.thingclips.sdk.eventbus`
- **Methods**: 5
- **Fields**: 11
- **Source**: `thingclips\sdk\eventbus\PendingPost.java`

**Key Methods**:
  - `ArrayList()`
  - `PendingPost()`
  - `obtainPendingPost()`
  - `PendingPost()`
  - `releasePendingPost()`

---

### PendingPostQueue [MEDIUM]


- **Full Name**: `com.thingclips.sdk.eventbus.PendingPostQueue`
- **Package**: `com.thingclips.sdk.eventbus`
- **Methods**: 6
- **Fields**: 8
- **Source**: `thingclips\sdk\eventbus\PendingPostQueue.java`

**Key Methods**:
  - `enqueue()`
  - `NullPointerException()`
  - `IllegalStateException()`
  - `poll()`
  - `poll()`
  - `poll()`

---

### SubscriberExceptionEvent [MEDIUM]


- **Full Name**: `com.thingclips.sdk.eventbus.SubscriberExceptionEvent`
- **Package**: `com.thingclips.sdk.eventbus`
- **Methods**: 1
- **Fields**: 4
- **Source**: `thingclips\sdk\eventbus\SubscriberExceptionEvent.java`

**Key Methods**:
  - `SubscriberExceptionEvent()`

---

### AsyncExecutor [MEDIUM]


- **Full Name**: `com.thingclips.sdk.eventbus.util.AsyncExecutor`
- **Package**: `com.thingclips.sdk.eventbus.util`
- **Methods**: 20
- **Fields**: 9
- **Source**: `sdk\eventbus\util\AsyncExecutor.java`

**Key Methods**:
  - `build()`
  - `buildForScope()`
  - `buildForActivityScope()`
  - `buildForScope()`
  - `buildForScope()`
  - `AsyncExecutor()`
  - `eventBus()`
  - `failureEventType()`
  - `threadPool()`
  - `Builder()`
  - *(... and 10 more)*

---

### ThrowableFailureEvent [MEDIUM]


- **Full Name**: `com.thingclips.sdk.eventbus.util.ThrowableFailureEvent`
- **Package**: `com.thingclips.sdk.eventbus.util`
- **Implements**: `HasExecutionScope`
- **Methods**: 6
- **Fields**: 3
- **Source**: `sdk\eventbus\util\ThrowableFailureEvent.java`

**Key Methods**:
  - `ThrowableFailureEvent()`
  - `getExecutionScope()`
  - `getThrowable()`
  - `isSuppressErrorUi()`
  - `setExecutionScope()`
  - `ThrowableFailureEvent()`

---

### bppdpdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.geofence.bppdpdq`
- **Package**: `com.thingclips.sdk.geofence`
- **Extends**: `Business`
- **Methods**: 2
- **Fields**: 3
- **Source**: `thingclips\sdk\geofence\bppdpdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### ThingGeoFenceOperatePlugin [MEDIUM]


- **Full Name**: `com.thingclips.sdk.geofence.ThingGeoFenceOperatePlugin`
- **Package**: `com.thingclips.sdk.geofence`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingGeoFenceOperatePlugin`
- **Methods**: 5
- **Fields**: 6
- **Source**: `thingclips\sdk\geofence\ThingGeoFenceOperatePlugin.java`

**Key Methods**:
  - `createGoogleOperate()`
  - `createHWOperate()`
  - `dependencies()`
  - `getGeoFenceOperateInstance()`
  - `init()`

---

### ThingGeoFencePlugin [MEDIUM]


- **Full Name**: `com.thingclips.sdk.geofence.ThingGeoFencePlugin`
- **Package**: `com.thingclips.sdk.geofence`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingGeoFencePlugin`
- **Methods**: 3
- **Fields**: 0
- **Source**: `thingclips\sdk\geofence\ThingGeoFencePlugin.java`

**Key Methods**:
  - `dependencies()`
  - `getGeoFenceInstance()`
  - `init()`

---

### bbbbppp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.bbbbppp`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `dddpppb`
- **Methods**: 29
- **Fields**: 4
- **Source**: `thingclips\sdk\hardware\bbbbppp.java`

**Key Methods**:
  - `GwTransferModel()`
  - `GwBroadcastMonitorModel()`
  - `addHgw()`
  - `addOnParsePkgFrameChangeListener()`
  - `bdpdqbp()`
  - `deleteAllDev()`
  - `deleteDev()`
  - `getDevId()`
  - `justStartHardwareServiceUDPPort()`
  - `justStopHardwareServiceUDPPort()`
  - *(... and 19 more)*

---

### bpbbpdd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.bpbbpdd`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `IThingSmartBroadbandActivator, IThingBroadbandConnectTypeListener`
- **Methods**: 24
- **Fields**: 34
- **Source**: `thingclips\sdk\hardware\bpbbpdd.java`

**Key Methods**:
  - `SafeHandler()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `pdqppqb()`
  - `onDevOnline()`
  - `onFind()`
  - `onFindErrorList()`
  - `bdpdqbp()`
  - `onError()`
  - *(... and 14 more)*

---

### bppdpdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.bppdpdq`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `IThingAPSLConfigListener`
- **Methods**: 15
- **Fields**: 12
- **Source**: `thingclips\sdk\hardware\bppdpdq.java`

**Key Methods**:
  - `C0341bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `C0341bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `onDevOnline()`
  - *(... and 5 more)*

---

### bpqqdpq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.bpqqdpq`
- **Package**: `com.thingclips.sdk.hardware`
- **Methods**: 8
- **Fields**: 7
- **Source**: `thingclips\sdk\hardware\bpqqdpq.java`

**Key Methods**:
  - `Semaphore()`
  - `bpqqdpq()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bppdpdq()`
  - `pppbppp()`
  - `CountDownLatch()`
  - `qddqppb()`

---

### bqpdbqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.bqpdbqq`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `IThingActivator`
- **Methods**: 55
- **Fields**: 44
- **Source**: `thingclips\sdk\hardware\bqpdbqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onActiveError()`
  - `onActiveSuccess()`
  - `onConfigEnd()`
  - `onConfigStart()`
  - `onDeviceBindSuccess()`
  - `onDeviceFind()`
  - `onWifiError()`
  - `bppdpdq()`
  - `onActiveCommandError()`
  - *(... and 45 more)*

---

### dbbpbbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.dbbpbbb`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `pbbppqb`
- **Implements**: `IThingResultCallback<String>`
- **Methods**: 20
- **Fields**: 8
- **Source**: `thingclips\sdk\hardware\dbbpbbb.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `dpdbqdp()`
  - *(... and 10 more)*

---

### dbpqpqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.dbpqpqd`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `com.thingclips.sdk.hardware.pppbppp`
- **Implements**: `IThingMqttRetainChannelListener`
- **Methods**: 35
- **Fields**: 17
- **Source**: `thingclips\sdk\hardware\dbpqpqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onMessageReceived()`
  - `if()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `bppdpdq()`
  - `onSuccess()`
  - `bdpdqbp()`
  - *(... and 25 more)*

**Notable Strings**:
  - `"[checkParam] 'uuid' cannot be empty."`

---

### dbqqppp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.dbqqppp`
- **Package**: `com.thingclips.sdk.hardware`
- **Methods**: 10
- **Fields**: 17
- **Source**: `thingclips\sdk\hardware\dbqqppp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ThingFrame()`
  - `bdpdqbp()`
  - `ThingFrame()`
  - `bdpdqbp()`
  - `StringBuilder()`
  - `bdpdqbp()`

---

### ddbdqbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.ddbdqbd`
- **Package**: `com.thingclips.sdk.hardware`
- **Methods**: 4
- **Fields**: 166
- **Source**: `thingclips\sdk\hardware\ddbdqbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`

---

### dddpppb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.dddpppb`
- **Package**: `com.thingclips.sdk.hardware`
- **Methods**: 27
- **Fields**: 0
- **Source**: `thingclips\sdk\hardware\dddpppb.java`

**Key Methods**:
  - `addHgw()`
  - `addHgw()`
  - `addHgw()`
  - `addHgw()`
  - `addOnParsePkgFrameChangeListener()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 17 more)*

---

### ddpdbbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.ddpdbbp`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `IThingGwSearcher, IDeviceHardwareFindListener`
- **Methods**: 10
- **Fields**: 18
- **Source**: `thingclips\sdk\hardware\ddpdbbp.java`

**Key Methods**:
  - `ddpdbbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `onFind()`
  - `pdqppqb()`
  - `qddqppb()`
  - `registerGwSearchListener()`
  - `unRegisterGwSearchListener()`
  - `bdpdqbp()`
  - `ddpdbbp()`

---

### ddqqbbq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.ddqqbbq`
- **Package**: `com.thingclips.sdk.hardware`
- **Methods**: 10
- **Fields**: 0
- **Source**: `thingclips\sdk\hardware\ddqqbbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `deleteAllDev()`
  - `deleteDev()`
  - `getDevId()`
  - `pdqppqb()`
  - `queryDev()`
  - `startService()`
  - `stopService()`

---

### dpbbdqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.dpbbdqq`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `BasePresenter`
- **Implements**: `IThingActivator, ICheckDevActiveStatusByTokenListener`
- **Methods**: 22
- **Fields**: 20
- **Source**: `thingclips\sdk\hardware\dpbbdqq.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `dpbbdqq()`
  - `NullPointerException()`
  - `NullPointerException()`
  - *(... and 12 more)*

---

### dpdqddb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.dpdqddb`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `dqdbbqp`
- **Implements**: `IConnectListener, IConfig`
- **Methods**: 23
- **Fields**: 35
- **Source**: `thingclips\sdk\hardware\dpdqddb.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `dpdqddb()`
  - `bppdpdq()`
  - `cancel()`
  - `onActiveError()`
  - `if()`
  - `HashMap()`
  - `if()`
  - `HashMap()`
  - *(... and 13 more)*

---

### dpppdpq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.dpppdpq`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `IThingHardwareQuery, qpbdppq`
- **Methods**: 24
- **Fields**: 12
- **Source**: `thingclips\sdk\hardware\dpppdpq.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `SafeHandler()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `run()`
  - `pdqppqb()`
  - `run()`
  - `dpppdpq()`
  - *(... and 14 more)*

---

### dpqdqbb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.dpqdqbb`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `qpbpqpq`
- **Implements**: `IThingMqttRetainChannelListener`
- **Methods**: 47
- **Fields**: 26
- **Source**: `thingclips\sdk\hardware\dpqdqbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `onMessageReceived()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 37 more)*

---

### dpqqbqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.dpqqbqd`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `BasePresenter`
- **Implements**: `IThingDirectActivator, IDeviceHardwareResultListener, IDeviceHardwareFindListener, ApConfigUDPDataCallback`
- **Methods**: 33
- **Fields**: 40
- **Source**: `thingclips\sdk\hardware\dpqqbqd.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `bdpdqbp()`
  - `discoveryDeviceWithActive()`
  - `onActiveSuccess()`
  - `onError()`
  - `dpqqbqd()`
  - `NullPointerException()`
  - `NullPointerException()`
  - `OnApConfigDeviceInfoReportCallback()`
  - `StringBuilder()`
  - *(... and 23 more)*

---

### dqqpqbq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.dqqpqbq`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `dqdbbqp`
- **Implements**: `IOptimizedConfig, IApConnectListener`
- **Methods**: 25
- **Fields**: 29
- **Source**: `thingclips\sdk\hardware\dqqpqbq.java`

**Key Methods**:
  - `AtomicInteger()`
  - `dqqpqbq()`
  - `bdpdqbp()`
  - `bqqppqq()`
  - `bppdpdq()`
  - `cancel()`
  - `onActiveCommandError()`
  - `onActiveCommandSuccess()`
  - `onActiveError()`
  - `onActiveSuccess()`
  - *(... and 15 more)*

---

### pbpdbqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.pbpdbqp`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `IActivator`
- **Methods**: 6
- **Fields**: 2
- **Source**: `thingclips\sdk\hardware\pbpdbqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pbpdbqp()`
  - `newBleActivator()`
  - `dqdpbbd()`
  - `newMultiModeActivator()`
  - `newMultiModeParallelActivator()`

---

### pbpqqdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.pbpqqdp`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `Runnable`
- **Methods**: 15
- **Fields**: 17
- **Source**: `thingclips\sdk\hardware\pbpqqdp.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `CountDownLatch()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `pbpqqdp()`
  - `MultiModeActivatorBean()`
  - `dbbpbbb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - *(... and 5 more)*

**Notable Strings**:
  - `"success uuid = "`
  - `"onStartConfig uuid = "`

---

### pdbbqdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.pdbbqdp`
- **Package**: `com.thingclips.sdk.hardware`
- **Methods**: 1
- **Fields**: 3
- **Source**: `thingclips\sdk\hardware\pdbbqdp.java`

**Key Methods**:
  - `bdpdqbp()`

---

### pdpdpqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.pdpdpqp`
- **Package**: `com.thingclips.sdk.hardware`
- **Methods**: 17
- **Fields**: 28
- **Source**: `thingclips\sdk\hardware\pdpdpqp.java`

**Key Methods**:
  - `pdpdpqp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `qddqppb()`
  - `pdqppqb()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 7 more)*

---

### ppqdbbq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.ppqdbbq`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `Business.ResultListener<LocalDeviceBean>`
- **Methods**: 19
- **Fields**: 17
- **Source**: `thingclips\sdk\hardware\ppqdbbq.java`

**Key Methods**:
  - `C0348bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `DeviceRespBean()`
  - `ArrayList()`
  - `HashMap()`
  - `ArrayList()`
  - *(... and 9 more)*

---

### pqdqqbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.pqdqqbd`
- **Package**: `com.thingclips.sdk.hardware`
- **Methods**: 3
- **Fields**: 8
- **Source**: `thingclips\sdk\hardware\pqdqqbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pqqpdpp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.pqqpdpp`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `BasePresenter`
- **Implements**: `IThingActivator, ICheckDevActiveStatusByTokenListener`
- **Methods**: 18
- **Fields**: 21
- **Source**: `thingclips\sdk\hardware\pqqpdpp.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `pqqpdpp()`
  - `NullPointerException()`
  - `NullPointerException()`
  - `RuntimeException()`
  - `bdpdqbp()`
  - `bqbdbqb()`
  - *(... and 8 more)*

---

### qbpppdb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.qbpppdb`
- **Package**: `com.thingclips.sdk.hardware`
- **Methods**: 0
- **Fields**: 99
- **Source**: `thingclips\sdk\hardware\qbpppdb.java`

**Notable Strings**:
  - `"uuid"`

---

### qpppdqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.qpppdqb`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `Thread`
- **Methods**: 5
- **Fields**: 1
- **Source**: `thingclips\sdk\hardware\qpppdqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `run()`

---

### qqdbbpp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.qqdbbpp`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `pppbppp`
- **Implements**: `OnBleSendChannelListener`
- **Methods**: 10
- **Fields**: 2
- **Source**: `thingclips\sdk\hardware\qqdbbpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `pbpdbqp()`
  - `pdqppqb()`
  - `qqpdpbp()`
  - `HashMap()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qqddbpb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.qqddbpb`
- **Package**: `com.thingclips.sdk.hardware`
- **Methods**: 10
- **Fields**: 7
- **Source**: `thingclips\sdk\hardware\qqddbpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qqdqbpb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.qqdqbpb`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `SafeHandler`
- **Implements**: `IGwSearchListener`
- **Methods**: 14
- **Fields**: 12
- **Source**: `thingclips\sdk\hardware\qqdqbpb.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `ddpdbbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `qqdqbpb()`
  - `bdpdqbp()`
  - `qqdqbpb()`
  - `bppdpdq()`
  - *(... and 4 more)*

---

### qqpppdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.qqpppdp`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `Business`
- **Methods**: 38
- **Fields**: 47
- **Source**: `thingclips\sdk\hardware\qqpppdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pbddddb()`
  - `ApiParams()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `qpppdqb()`
  - `bdpdqbp()`
  - *(... and 28 more)*

---

### RunnableC0292b [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.RunnableC0292b`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 6
- **Source**: `thingclips\sdk\hardware\RunnableC0292b.java`

**Key Methods**:
  - `run()`

---

### RunnableC0294c [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.RunnableC0294c`
- **Package**: `com.thingclips.sdk.hardware`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 8
- **Source**: `thingclips\sdk\hardware\RunnableC0294c.java`

**Key Methods**:
  - `run()`

---

### ThingHardwareBusinessPlugin [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.ThingHardwareBusinessPlugin`
- **Package**: `com.thingclips.sdk.hardware`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingHardwarePlugin`
- **Methods**: 8
- **Fields**: 0
- **Source**: `thingclips\sdk\hardware\ThingHardwareBusinessPlugin.java`

**Key Methods**:
  - `dependencies()`
  - `getAPInstance()`
  - `getEZInstance()`
  - `getHardwareBusinessInstance()`
  - `getHardwareInstance()`
  - `getOptimizedAPInstance()`
  - `getWareConfigInstance()`
  - `init()`

---

### HResponse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.bean.HResponse`
- **Package**: `com.thingclips.sdk.hardware.bean`
- **Implements**: `Parcelable`
- **Methods**: 20
- **Fields**: 7
- **Source**: `sdk\hardware\bean\HResponse.java`

**Key Methods**:
  - `createFromParcel()`
  - `HResponse()`
  - `newArray()`
  - `HResponse()`
  - `describeContents()`
  - `getCode()`
  - `getDataBinary()`
  - `getDevId()`
  - `getSeq()`
  - `getType()`
  - *(... and 10 more)*

---

### DevTranfserServiceBinder [MEDIUM]


- **Full Name**: `com.thingclips.sdk.hardware.service.DevTranfserServiceBinder`
- **Package**: `com.thingclips.sdk.hardware.service`
- **Extends**: `Binder`
- **Methods**: 5
- **Fields**: 4
- **Source**: `sdk\hardware\service\DevTranfserServiceBinder.java`

**Key Methods**:
  - `DevTranfserServiceBinder()`
  - `getService()`
  - `onDevResponse()`
  - `onDevUpdate()`
  - `setHResponseListener()`

---

### o00000 [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o00000`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `Runnable`
- **Methods**: 5
- **Fields**: 5
- **Source**: `thingclips\sdk\home\o00000.java`

**Key Methods**:
  - `o00000()`
  - `OooO00o()`
  - `run()`
  - `OooO00o()`
  - `o00000()`

---

### o00000OO [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o00000OO`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `IThingDeviceMultiControl`
- **Methods**: 45
- **Fields**: 28
- **Source**: `thingclips\sdk\home\o00000OO.java`

**Key Methods**:
  - `o00000O()`
  - `OooO()`
  - `onFailure()`
  - `onSuccess()`
  - `OooO00o()`
  - `onFailure()`
  - `onSuccess()`
  - `OooO0O0()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 35 more)*

---

### o0000oo [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o0000oo`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `Business`
- **Methods**: 11
- **Fields**: 11
- **Source**: `thingclips\sdk\home\o0000oo.java`

**Key Methods**:
  - `OooO00o()`
  - `ApiParams()`
  - `OooO0O0()`
  - `ApiParams()`
  - `OooO00o()`
  - `ApiParams()`
  - `OooO0O0()`
  - `ApiParams()`
  - `OooO00o()`
  - `OooO00o()`
  - *(... and 1 more)*

---

### o0000OO0 [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o0000OO0`
- **Package**: `com.thingclips.sdk.home`
- **Methods**: 16
- **Fields**: 32
- **Source**: `thingclips\sdk\home\o0000OO0.java`

**Key Methods**:
  - `OooO0O0()`
  - `o0000OO0()`
  - `OooO00o()`
  - `ConcurrentHashMap()`
  - `CopyOnWriteArrayList()`
  - `OooO0OO()`
  - `OooO0O0()`
  - `OooO0O0()`
  - `OooO00o()`
  - `OooO00o()`
  - *(... and 6 more)*

---

### o0000Ooo [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o0000Ooo`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `OooO0O0`
- **Methods**: 5
- **Fields**: 6
- **Source**: `thingclips\sdk\home\o0000Ooo.java`

**Key Methods**:
  - `o0000Ooo()`
  - `OooO00o()`
  - `o00000O0()`
  - `OooO0oO()`
  - `OooO0oo()`

---

### o000O [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o000O`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `IThingHomeMember`
- **Methods**: 30
- **Fields**: 3
- **Source**: `thingclips\sdk\home\o000O.java`

**Key Methods**:
  - `o0Oo0oo()`
  - `OooO00o()`
  - `o000O()`
  - `addMember()`
  - `addMemberAccount()`
  - `cancelMemberInvitationCode()`
  - `getAuthRoomList()`
  - `getAuthSceneList()`
  - `getInvitationFamilyInfo()`
  - `getInvitationList()`
  - *(... and 20 more)*

---

### o000O0 [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o000O0`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `IThingDevice`
- **Methods**: 34
- **Fields**: 7
- **Source**: `thingclips\sdk\home\o000O0.java`

**Key Methods**:
  - `OooO00o()`
  - `onError()`
  - `onSuccess()`
  - `o000O0()`
  - `RuntimeException()`
  - `getDataPointStat()`
  - `getDeviceProperty()`
  - `getDp()`
  - `getDpList()`
  - `getInitiativeQueryDpsInfoWithDpsArray()`
  - *(... and 24 more)*

---

### o000O00 [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o000O00`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `IThingHomeDataLocalCache`
- **Methods**: 13
- **Fields**: 11
- **Source**: `thingclips\sdk\home\o000O00.java`

**Key Methods**:
  - `Object()`
  - `OooOOO0()`
  - `OooO00o()`
  - `run()`
  - `clearHomeCache()`
  - `getHomeListLocalCache()`
  - `getProductRefList()`
  - `getStandardProductConfigList()`
  - `saveHomeDevToLocalCache()`
  - `OooO00o()`
  - *(... and 3 more)*

---

### o000O0O0 [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o000O0O0`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `IThingHomeManager`
- **Methods**: 10
- **Fields**: 3
- **Source**: `thingclips\sdk\home\o000O0O0.java`

**Key Methods**:
  - `o00Oo0()`
  - `OooO00o()`
  - `o000O0O0()`
  - `createHome()`
  - `joinHomeByInviteCode()`
  - `onDestroy()`
  - `queryHomeInfo()`
  - `queryHomeList()`
  - `registerThingHomeChangeListener()`
  - `unRegisterThingHomeChangeListener()`

---

### o000O0Oo [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o000O0Oo`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `IThingGroup`
- **Methods**: 32
- **Fields**: 21
- **Source**: `thingclips\sdk\home\o000O0Oo.java`

**Key Methods**:
  - `OooO()`
  - `onError()`
  - `onSuccess()`
  - `OooO00o()`
  - `onError()`
  - `onSuccess()`
  - `OooO0O0()`
  - `onError()`
  - `onSuccess()`
  - `OooO0OO()`
  - *(... and 22 more)*

---

### o000OO [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o000OO`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `Business`
- **Methods**: 8
- **Fields**: 9
- **Source**: `thingclips\sdk\home\o000OO.java`

**Key Methods**:
  - `OooO00o()`
  - `ApiParams()`
  - `OooO0O0()`
  - `OooO00o()`
  - `ApiParams()`
  - `OooO00o()`
  - `OooO00o()`
  - `OooO()`

---

### o000OO0O [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o000OO0O`
- **Package**: `com.thingclips.sdk.home`
- **Methods**: 9
- **Fields**: 5
- **Source**: `thingclips\sdk\home\o000OO0O.java`

**Key Methods**:
  - `OooO0OO()`
  - `o000OO0O()`
  - `OooO00o()`
  - `OooO0O0()`
  - `ArrayList()`
  - `OooO00o()`
  - `OooO0O0()`
  - `OooO00o()`
  - `OooO00o()`

---

### o000OOo [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o000OOo`
- **Package**: `com.thingclips.sdk.home`
- **Methods**: 27
- **Fields**: 0
- **Source**: `thingclips\sdk\home\o000OOo.java`

**Key Methods**:
  - `addMember()`
  - `addMember()`
  - `addMemberAccount()`
  - `addMemberAccount()`
  - `addMemberAccount()`
  - `cancelMemberInvitationCode()`
  - `getAuthRoomList()`
  - `getAuthSceneList()`
  - `getInvitationFamilyInfo()`
  - `getInvitationList()`
  - *(... and 17 more)*

---

### o00O0000 [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o00O0000`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `IThingHomeSpeech`
- **Methods**: 26
- **Fields**: 24
- **Source**: `thingclips\sdk\home\o00O0000.java`

**Key Methods**:
  - `o000OO()`
  - `OooO()`
  - `onFailure()`
  - `onSuccess()`
  - `OooO00o()`
  - `onFailure()`
  - `onSuccess()`
  - `OooO0O0()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 16 more)*

---

### o00Oo0 [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o00Oo0`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `BasePresenter`
- **Implements**: `IThingHomeManager`
- **Methods**: 7
- **Fields**: 1
- **Source**: `thingclips\sdk\home\o00Oo0.java`

**Key Methods**:
  - `o0OOO0o()`
  - `createHome()`
  - `joinHomeByInviteCode()`
  - `queryHomeInfo()`
  - `queryHomeList()`
  - `registerThingHomeChangeListener()`
  - `unRegisterThingHomeChangeListener()`

---

### o00oOoo [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o00oOoo`
- **Package**: `com.thingclips.sdk.home`
- **Methods**: 4
- **Fields**: 5
- **Source**: `thingclips\sdk\home\o00oOoo.java`

**Key Methods**:
  - `OooO00o()`
  - `HomeBean()`
  - `ArrayList()`
  - `OooO0O0()`

---

### o0O0O00 [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o0O0O00`
- **Package**: `com.thingclips.sdk.home`
- **Methods**: 4
- **Fields**: 0
- **Source**: `thingclips\sdk\home\o0O0O00.java`

**Key Methods**:
  - `OooO00o()`
  - `createHome()`
  - `joinHomeByInviteCode()`
  - `queryHomeList()`

---

### o0Oo0oo [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o0Oo0oo`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `BaseModel`
- **Implements**: `com.thingclips.sdk.home.o000OOo`
- **Methods**: 144
- **Fields**: 87
- **Source**: `thingclips\sdk\home\o0Oo0oo.java`

**Key Methods**:
  - `OooO()`
  - `onFailure()`
  - `onSuccess()`
  - `OooO00o()`
  - `onFailure()`
  - `onSuccess()`
  - `OooO0O0()`
  - `onFailure()`
  - `onSuccess()`
  - `OooO0OO()`
  - *(... and 134 more)*

---

### o0OOO0o [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o0OOO0o`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `BaseModel`
- **Implements**: `o0O0O00`
- **Methods**: 25
- **Fields**: 17
- **Source**: `thingclips\sdk\home\o0OOO0o.java`

**Key Methods**:
  - `OooO00o()`
  - `onFailure()`
  - `onSuccess()`
  - `OooO0O0()`
  - `onFailure()`
  - `onSuccess()`
  - `OooO0OO()`
  - `onFailure()`
  - `onSuccess()`
  - `OooO0o()`
  - *(... and 15 more)*

---

### o0ooOOo [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.o0ooOOo`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `OooO0OO`
- **Implements**: `Runnable, Supplier<ThingLocalDeviceListDataBean>`
- **Methods**: 8
- **Fields**: 8
- **Source**: `thingclips\sdk\home\o0ooOOo.java`

**Key Methods**:
  - `OooO00o()`
  - `onSuccess()`
  - `ArrayList()`
  - `onFailure()`
  - `o0ooOOo()`
  - `get()`
  - `run()`
  - `OooO00o()`

---

### oo0o0Oo [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.oo0o0Oo`
- **Package**: `com.thingclips.sdk.home`
- **Methods**: 16
- **Fields**: 0
- **Source**: `thingclips\sdk\home\oo0o0Oo.java`

**Key Methods**:
  - `OooO00o()`
  - `OooO00o()`
  - `OooO00o()`
  - `addRoom()`
  - `bindNewConfigDevs()`
  - `dismissHome()`
  - `getHomeDetail()`
  - `queryRoomInfoByDevice()`
  - `queryRoomInfoByGroup()`
  - `queryRoomList()`
  - *(... and 6 more)*

---

### Oooo0 [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.Oooo0`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `OooO0OO`
- **Implements**: `Runnable, Supplier<ThingListDataBean>`
- **Methods**: 10
- **Fields**: 7
- **Source**: `thingclips\sdk\home\Oooo0.java`

**Key Methods**:
  - `OooO00o()`
  - `onSuccess()`
  - `onFailure()`
  - `OooO0O0()`
  - `OooO0O0()`
  - `Oooo0()`
  - `get()`
  - `OooO0OO()`
  - `run()`
  - `OooO00o()`

---

### Oooo000 [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.Oooo000`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `Runnable`
- **Methods**: 17
- **Fields**: 20
- **Source**: `thingclips\sdk\home\Oooo000.java`

**Key Methods**:
  - `run()`
  - `if()`
  - `Oooo000()`
  - `Handler()`
  - `Handler()`
  - `OooO00o()`
  - `OooO00o()`
  - `CopyOnWriteArrayList()`
  - `OooO0O0()`
  - `OooO00o()`
  - *(... and 7 more)*

---

### OooO0OO [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.OooO0OO`
- **Package**: `com.thingclips.sdk.home`
- **Methods**: 2
- **Fields**: 2
- **Source**: `thingclips\sdk\home\OooO0OO.java`

**Key Methods**:
  - `OooO00o()`
  - `OooO00o()`

---

### OooOo [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.OooOo`
- **Package**: `com.thingclips.sdk.home`
- **Extends**: `OooO0OO`
- **Implements**: `Runnable, Supplier<ThingListDataBean>`
- **Methods**: 10
- **Fields**: 7
- **Source**: `thingclips\sdk\home\OooOo.java`

**Key Methods**:
  - `OooO00o()`
  - `onSuccess()`
  - `onFailure()`
  - `OooO0O0()`
  - `OooO0O0()`
  - `OooOo()`
  - `get()`
  - `OooO0OO()`
  - `run()`
  - `OooO00o()`

---

### OooOO0 [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.OooOO0`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `IThingDeviceMultiControl`
- **Methods**: 12
- **Fields**: 4
- **Source**: `thingclips\sdk\home\OooOO0.java`

**Key Methods**:
  - `o00000OO()`
  - `OooO00o()`
  - `OooOO0()`
  - `OooO0O0()`
  - `disableMultiControl()`
  - `enableMultiControl()`
  - `getDeviceDpInfoList()`
  - `getDeviceDpLinkRelation()`
  - `getMultiControlDeviceList()`
  - `queryLinkInfoByDp()`
  - *(... and 2 more)*

---

### RunnableC0298a [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.RunnableC0298a`
- **Package**: `com.thingclips.sdk.home`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 4
- **Source**: `thingclips\sdk\home\RunnableC0298a.java`

**Key Methods**:
  - `run()`

---

### HomeResponseBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.home.bean.HomeResponseBean`
- **Package**: `com.thingclips.sdk.home.bean`
- **Methods**: 31
- **Fields**: 14
- **Source**: `sdk\home\bean\HomeResponseBean.java`

**Key Methods**:
  - `getBackground()`
  - `getCustomRole()`
  - `getDealStatus()`
  - `getGeoName()`
  - `getGid()`
  - `getId()`
  - `getLat()`
  - `getLon()`
  - `getName()`
  - `getNickName()`
  - *(... and 21 more)*

---

### ThingLogSdk [MEDIUM]


- **Full Name**: `com.thingclips.sdk.log.ThingLogSdk`
- **Package**: `com.thingclips.sdk.log`
- **Methods**: 9
- **Fields**: 15
- **Source**: `thingclips\sdk\log\ThingLogSdk.java`

**Key Methods**:
  - `ThingLogSdk()`
  - `beginEvent()`
  - `endEvent()`
  - `event()`
  - `eventOnDebugTool()`
  - `flush()`
  - `pushTemporaryEvent()`
  - `temporaryEvent()`
  - `trackEvent()`

---

### ConfigErrorCode [LOW]


- **Full Name**: `com.thingclips.sdk.config.bean.ConfigErrorCode`
- **Package**: `com.thingclips.sdk.config.bean`
- **Methods**: 0
- **Fields**: 31
- **Source**: `sdk\config\bean\ConfigErrorCode.java`

---

## Package Structure

### Package Hierarchy

```
com/ (2649 classes)
      ├── device/ (23 classes)
        ├── manager/ (59 classes)
        ├── mappers/ (33 classes)
        ├── service/ (189 classes)
      ├── extensions/ (3 classes)
      ├── glide/ (3 classes)
      ├── notifications/ (3 classes)
      ├── p000di/ (8 classes)
      ├── playback/ (18 classes)
      ├── user/ (6 classes)
  └── ... and 197 more packages

p008u/ (3 classes)
├── p008u/ (3 classes)

```

### Top 20 Packages by Class Count

| Package | Classes |
| --- | --- |
| com.thingclips.sdk.bluetooth | 685 |
| com.savantsystems.yisdk.device.service | 189 |
| com.thingclips.sdk.device | 177 |
| com.thingclips.sdk.hardware | 155 |
| com.thingclips.bouncycastle.asn1 | 107 |
| com.thingclips.sdk.ble.core.packet.bean | 82 |
| com.thingclips.sdk.home | 67 |
| com.savantsystems.yisdk.device.manager | 59 |
| com.thingclips.bouncycastle.crypto.params | 43 |
| com.thingclips.bouncycastle.asn1.x509 | 38 |
| com.savantsystems.yisdk.device.mappers | 33 |
| com.thingclips.bouncycastle.crypto | 33 |
| com.thingclips.bouncycastle.math.ec | 28 |
| com.thingclips.bouncycastle.crypto.digests | 25 |
| com.thingclips.sdk.ble.core.bean | 25 |
| com.savantsystems.yisdk.device | 23 |
| com.thingclips.sdk.ble.core.protocol.api | 19 |
| com.thingclips.sdk.device.bean | 19 |
| com.savantsystems.yisdk.playback | 18 |
| com.thingclips.sdk.blelib.connect.request | 17 |

## String Constants & UUIDs

### UUID Definitions Found

| UUID | Purpose | Occurrences | Files |
| --- | --- | --- | --- |
| 00000000-0000-1000-8000-00805f9b34fb | Unknown | 2 | qqpqqpd.java |
| 00000001-0000-1001-8001-00805f9b07d0 | Unknown | 4 | bppbqbb.java, qpqqdbp.java |
| 00000002-0000-1001-8001-00805f9b07d0 | Unknown | 4 | bppbqbb.java, qpqqdbp.java |
| 00000003-0000-1001-8001-00805f9b07d0 | Unknown | 2 | bppdpdq.java |
| 00001000-7475-7961-626c-636f6e666967 | Unknown | 2 | dpdpppb.java |
| 00001001-7475-7961-626c-636f6e666967 | Unknown | 2 | dpdpppb.java |
| 00001002-7475-7961-626c-636f6e666967 | Unknown | 2 | dpdpppb.java |
| 0000180a-0000-1000-8000-00805f9b34fb | Unknown | 2 | bppbqbb.java |
| 00001827-0000-1000-8000-00805f9b34fb | Unknown | 4 | bppbqbb.java, bppqbqb.java |
| 00001828-0000-1000-8000-00805f9b34fb | Unknown | 2 | bppbqbb.java |
| 00001910-0000-1000-8000-00805f9b34fb | Unknown | 6 | bppbqbb.java, qpqqdbp.java |
| 00001912-0000-1000-8000-00805f9b34fb | Telink Command | 2 | qpqqdbp.java |
| 00001920-0000-1000-8000-00805f9b34fb | Unknown | 4 | qpqqdbp.java |
| 00002901-0000-1000-8000-00805f9b34fb | Unknown | 2 | Constants.java |
| 00002902-0000-1000-8000-00805f9b34fb | Unknown | 4 | Constants.java, bppbqbb.java |
| 00002a26-0000-1000-8000-00805f9b34fb | Unknown | 2 | bppbqbb.java |
| 00002adb-0000-1000-8000-00805f9b34fb | Mesh Provisioning In | 2 | bppbqbb.java |
| 00002adc-0000-1000-8000-00805f9b34fb | Unknown | 2 | bppbqbb.java |
| 00002add-0000-1000-8000-00805f9b34fb | Mesh Proxy In | 4 | bppbqbb.java |
| 00002ade-0000-1000-8000-00805f9b34fb | Mesh Proxy Out | 4 | bppbqbb.java |
| 00002b10-0000-1000-8000-00805f9b34fb | Unknown | 4 | bppbqbb.java, qpqqdbp.java |
| 00002b11-0000-1000-8000-00805f9b34fb | Unknown | 4 | bppbqbb.java, qpqqdbp.java |
| 00002b12-0000-1000-8000-00805f9b34fb | Unknown | 2 | qpqqdbp.java |
| 00002b23-0000-1000-8000-00805f9b34fb | Unknown | 2 | qpqqdbp.java |
| 00002b24-0000-1000-8000-00805f9b34fb | Unknown | 2 | qpqqdbp.java |
| 00007fdd-0000-1000-8000-00805f9b34fb | Unknown | 2 | bppbqbb.java |
| 0000fd50-0000-1000-8000-00805f9b34fb | Unknown | 8 | bppbqbb.java, bppdpdq.java, qpqqdbp.java |
| 00010203-0405-0607-0809-0a0b0c0d1912 | Telink Command | 2 | bppbqbb.java |
| 00010203-0405-0607-0809-0a0b0c0d2b12 | Telink Service | 2 | bppbqbb.java |

## BLE Write Operations

Found 27 BLE write operations:

#### BleConnectWorker.java

- **Line 647**: `writeCharacteristic(character)`

<details>
<summary>Show code snippet</summary>

```java
bArr = ByteUtils.EMPTY_BYTES;
        }
        character.setValue(bArr);
        try {
            if (this.mBluetoothGatt.writeCharacteristic(character)) {
                return true;
            }
            BluetoothLog.m287e(WtUtil.format("writeCharacteristic failed", new Object[0]));
            return false;
        } catch (Exception e) {
```

</details>

- **Line 677**: `writeCharacteristic(character)`

<details>
<summary>Show code snippet</summary>

```java
}
        character.setValue(bArr);
        character.setWriteType(1);
        try {
            if (this.mBluetoothGatt.writeCharacteristic(character)) {
                return true;
            }
            BluetoothLog.m287e(WtUtil.format("writeCharacteristic failed", new Object[0]));
            return false;
        } catch (Exception e) {
```

</details>

- **Line 563**: `setValue(descriptor)`

<details>
<summary>Show code snippet</summary>

```java
if (descriptor == null) {
                BluetoothLog.m287e(WtUtil.format("getDescriptor for indicate null!", new Object[0]));
                return false;
            }
            if (!descriptor.setValue(z ? BluetoothGattDescriptor.ENABLE_INDICATION_VALUE : BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE)) {
                BluetoothLog.m287e(WtUtil.format("setValue for indicate descriptor failed!", new Object[0]));
                return false;
            }
            try {
                if (this.mBluetoothGatt.writeDescriptor(descriptor)) {
```

</details>

- **Line 610**: `setValue(descriptor)`

<details>
<summary>Show code snippet</summary>

```java
}
                BluetoothLog.m287e(WtUtil.format("getDescriptor for notify null!", new Object[0]));
                return false;
            }
            if (!descriptor.setValue(z ? BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE : BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE)) {
                BluetoothLog.m287e(WtUtil.format("setValue for notify descriptor failed!", new Object[0]));
                return false;
            }
            try {
                if (this.mBluetoothGatt.writeDescriptor(descriptor)) {
```

</details>

- **Line 645**: `setValue(character)`

<details>
<summary>Show code snippet</summary>

```java
}
        if (bArr == null) {
            bArr = ByteUtils.EMPTY_BYTES;
        }
        character.setValue(bArr);
        try {
            if (this.mBluetoothGatt.writeCharacteristic(character)) {
                return true;
            }
            BluetoothLog.m287e(WtUtil.format("writeCharacteristic failed", new Object[0]));
```

</details>

- *(... and 2 more operations)*

#### BleRequest.java

- **Line 267**: `writeCharacteristic(uuid, uuid2, bArr)`

<details>
<summary>Show code snippet</summary>

```java
}

    @Override // com.thingclips.sdk.blelib.connect.IBleConnectWorker
    public boolean writeCharacteristic(UUID uuid, UUID uuid2, byte[] bArr) {
        return this.mWorker.writeCharacteristic(uuid, uuid2, bArr);
    }

    @Override // com.thingclips.sdk.blelib.connect.IBleConnectWorker
    public boolean writeCharacteristicWithNoRsp(UUID uuid, UUID uuid2, byte[] bArr) {
        return this.mWorker.writeCharacteristicWithNoRsp(uuid, uuid2, bArr);
```

</details>


#### DTOMapExtensionKt.java

- **Line 401**: `setValue(dpEnumTypeData)`

<details>
<summary>Show code snippet</summary>

```java
i = 0;
                        i2 = i;
                        i3 = i4;
                    }
                    dpEnumTypeData.setValue(arrayList2);
                    dpEnumTypeData.setValueKey(arrayList3);
                    deviceActionData.setDpEnumTypeData(dpEnumTypeData);
                }
                if (sceneAction != null && (executorProperty2 = sceneAction.getExecutorProperty()) != null && executorProperty2.containsKey(DeviceConditionBuilder.entitySubIds) && (Intrinsics.areEqual(executorProperty2.get(DeviceConditionBuilder.entitySubIds), Integer.valueOf(actionDeviceDataPointDetail3.getDpId())) || Intrinsics.areEqual(executorProperty2.get(DeviceConditionBuilder.entitySubIds), String.valueOf(actionDeviceDataPointDetail3.getDpId())))) {
                    if (executorProperty2.containsKey("step")) {
```

</details>


#### DevUtil.java

- **Line 427**: `setValue(entry)`

<details>
<summary>Show code snippet</summary>

```java
for (Map.Entry<String, Object> entry : map.entrySet()) {
                SchemaBean schemaBean = map2.get(entry.getKey());
                if (schemaBean != null && schemaBean.getType().equals(DataTypeEnum.RAW.getType())) {
                    try {
                        entry.setValue(HexUtil.bytesToHexString(Base64.decodeBase64(((String) entry.getValue()).getBytes())));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    z = true;
                }
```

</details>

- **Line 592**: `setValue(entry)`

<details>
<summary>Show code snippet</summary>

```java
for (Map.Entry<String, Object> entry : map2.entrySet()) {
                SchemaBean schemaBean = map.get(entry.getKey());
                if (schemaBean != null && schemaBean.getType().equals(DataTypeEnum.RAW.getType())) {
                    try {
                        entry.setValue(new String(Base64.encodeBase64(HexUtil.hexStringToBytes((String) entry.getValue()))));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    z = true;
                }
```

</details>

- **Line 732**: `setValue(entry)`

<details>
<summary>Show code snippet</summary>

```java
for (Map.Entry<String, Object> entry : map2.entrySet()) {
                SchemaBean schemaBean = map.get(entry.getKey());
                if (schemaBean != null && schemaBean.getType().equals(DataTypeEnum.RAW.getType())) {
                    try {
                        entry.setValue(new String(Base64.encodeBase64(HexUtil.hexStringToBytes((String) entry.getValue()))));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
```

</details>


#### YiDeviceInfoManagerImpl.java

- **Line 131**: `setValue(f201d)`

<details>
<summary>Show code snippet</summary>

```java
forest.q("YiDeviceInfoManager(" + yiDeviceInfoManagerImpl.f198a.getId() + ")");
            StringBuilder sb = new StringBuilder("Static info updated: ");
            sb.append(yiStaticDeviceInfo);
            forest.b(sb.toString(), new Object[0]);
            yiDeviceInfoManagerImpl.f201d.setValue(yiStaticDeviceInfo);
            return Unit.INSTANCE;
        }
    }

    @Metadata(d1 = {"\u0000\n\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\u0018\u00002\u00020\u0001¨\u0006\u0002"}, d2 = {"Lcom/savantsystems/yisdk/device/manager/YiDeviceInfoManagerImpl$Factory;", "", "yi-sdk_release"}, k = 1, mv = {1, 9, 0})
```

</details>


#### YiDeviceManagerImpl.java

- **Line 534**: `setValue(f49f)`

<details>
<summary>Show code snippet</summary>

```java
@Override // com.savantsystems.yisdk.device.YiDeviceManager
    @Nullable
    /* renamed from: g */
    public final Unit mo7g(boolean z) {
        this.f49f.setValue(Boxing.boxBoolean(z));
        return Unit.INSTANCE;
    }

    @Override // com.savantsystems.yisdk.device.YiDeviceManager
    @NotNull
```

</details>


#### YiFirmwareManagerImpl.java

- **Line 469**: `setValue(f243g)`

<details>
<summary>Show code snippet</summary>

```java
ok2 = ok;
                        if (ok2 instanceof Ok) {
                            FirmwareVersion firmwareVersion = (FirmwareVersion) ok2.a;
                            yiFirmwareManagerImpl.m38e().g("Current firmware version: " + firmwareVersion, new Object[0]);
                            yiFirmwareManagerImpl.f243g.setValue(firmwareVersion);
                            if (firmwareVersion != null) {
                                BuildersKt.d(yiFirmwareManagerImpl.f242f, (CoroutineContext) null, (CoroutineStart) null, new YiFirmwareManagerImpl$setCurrentVersion$1(yiFirmwareManagerImpl, firmwareVersion, null), 3);
                            }
                        }
                        if (ok2 instanceof Err) {
```

</details>

- **Line 821**: `setValue(f244h)`

<details>
<summary>Show code snippet</summary>

```java
}
                        if (ok instanceof Ok) {
                            FirmwareUpdateInfo firmwareUpdateInfo3 = (FirmwareUpdateInfo) ok.a;
                            yiFirmwareManagerImpl2.m38e().m("Successfully fetch firmware update info for " + yiFirmwareManagerImpl2.f237a.getF44a() + ", info = " + firmwareUpdateInfo3, new Object[0]);
                            yiFirmwareManagerImpl2.f244h.setValue(firmwareUpdateInfo3);
                        }
                        if (ok instanceof Err) {
                            FirmwareUpdateInfoYiError firmwareUpdateInfoYiError = (FirmwareUpdateInfoYiError) ((Err) ok).a;
                            Timber.Forest m38e = yiFirmwareManagerImpl2.m38e();
                            StringBuilder r = d.r("fetchUpdateVersion errorCode = ", ((YiError) firmwareUpdateInfoYiError).a, " errorMsg = ");
```

</details>

- **Line 970**: `setValue(f243g)`

<details>
<summary>Show code snippet</summary>

```java
if (downloadableFirmwareImageInfo == null) {
                        return FlowKt.y(new SuspendLambda(2, (Continuation) null));
                    }
                    m38e().g("Starting firmware upgrade to " + downloadableFirmwareImageInfo.d + "...", new Object[0]);
                    this.f243g.setValue((Object) null);
                    mutableStateFlow.setValue((Object) null);
                    YiFirmwareManagerImpl$performUpdate$2 yiFirmwareManagerImpl$performUpdate$2 = new YiFirmwareManagerImpl$performUpdate$2(this, downloadableFirmwareImageInfo, null);
                    yiFirmwareManagerImpl$performUpdate$1.f289a = this;
                    yiFirmwareManagerImpl$performUpdate$1.f292d = 1;
                    obj = TimeoutKt.c(15000L, yiFirmwareManagerImpl$performUpdate$1, yiFirmwareManagerImpl$performUpdate$2);
```

</details>

- **Line 971**: `setValue(mutableStateFlow)`

<details>
<summary>Show code snippet</summary>

```java
return FlowKt.y(new SuspendLambda(2, (Continuation) null));
                    }
                    m38e().g("Starting firmware upgrade to " + downloadableFirmwareImageInfo.d + "...", new Object[0]);
                    this.f243g.setValue((Object) null);
                    mutableStateFlow.setValue((Object) null);
                    YiFirmwareManagerImpl$performUpdate$2 yiFirmwareManagerImpl$performUpdate$2 = new YiFirmwareManagerImpl$performUpdate$2(this, downloadableFirmwareImageInfo, null);
                    yiFirmwareManagerImpl$performUpdate$1.f289a = this;
                    yiFirmwareManagerImpl$performUpdate$1.f292d = 1;
                    obj = TimeoutKt.c(15000L, yiFirmwareManagerImpl$performUpdate$1, yiFirmwareManagerImpl$performUpdate$2);
                    if (obj == coroutine_suspended) {
```

</details>


#### YiPeerConnectionManagerImpl$monitorConnection$5.java

- **Line 47**: `setValue(f336e)`

<details>
<summary>Show code snippet</summary>

```java
@Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        IntrinsicsKt.getCOROUTINE_SUSPENDED();
        ResultKt.throwOnFailure(obj);
        this.f399b.f336e.setValue((YiDeviceConnection) this.f398a);
        return Unit.INSTANCE;
    }
}
```

</details>


#### YiPeerConnectionManagerImpl$resetConnection$2.java

- **Line 68**: `setValue(mutableStateFlow)`

<details>
<summary>Show code snippet</summary>

```java
MutableStateFlow<YiDeviceConnection> mutableStateFlow = yiPeerConnectionManagerImpl.f336e;
        if (mutableStateFlow.getValue() == YiDeviceConnection.f40b && (iYiCameraP2P = (IYiCameraP2P) yiPeerConnectionManagerImpl.f335d.getValue()) != null) {
            iYiCameraP2P.disconnect((YiCallback) null);
        }
        mutableStateFlow.setValue(YiDeviceConnection.f39a);
        yiPeerConnectionManagerImpl.m50h();
        yiPeerConnectionManagerImpl.m51i();
        return Unit.INSTANCE;
    }
}
```

</details>


#### YiPeerConnectionManagerImpl.java

- **Line 213**: `setValue(f336e)`

<details>
<summary>Show code snippet</summary>

```java
Integer num = (Integer) obj2;
                    YiPeerConnectionManagerImpl yiPeerConnectionManagerImpl2 = YiPeerConnectionManagerImpl.this;
                    YiPeerConnectionManagerImpl.m48f(yiPeerConnectionManagerImpl2).m("P2P connect progress " + num, new Object[0]);
                    if (num != null && num.intValue() == 25) {
                        yiPeerConnectionManagerImpl2.f336e.setValue(YiDeviceConnection.f40b);
                    }
                }
            });
            mutableStateFlow.setValue(createYiCameraP2PInstance);
            return Unit.INSTANCE;
```

</details>

- **Line 217**: `setValue(mutableStateFlow)`

<details>
<summary>Show code snippet</summary>

```java
yiPeerConnectionManagerImpl2.f336e.setValue(YiDeviceConnection.f40b);
                    }
                }
            });
            mutableStateFlow.setValue(createYiCameraP2PInstance);
            return Unit.INSTANCE;
        }
    }

    @Metadata(d1 = {"\u0000\n\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u008a@"}, d2 = {"<anonymous>", "", "Lkotlinx/coroutines/CoroutineScope;"}, k = 3, mv = {1, 9, 0}, xi = 48)
```

</details>

- **Line 607**: `setValue(mutableStateFlow)`

<details>
<summary>Show code snippet</summary>

```java
IYiCameraP2P iYiCameraP2P2 = (IYiCameraP2P) mutableStateFlow.getValue();
        if (iYiCameraP2P2 != null) {
            iYiCameraP2P2.destroyYiCameraP2P();
        }
        mutableStateFlow.setValue((Object) null);
    }

    /* renamed from: h */
    public final void m50h() {
        Flow flow = new FlowKt__TransformKt$filterNotNull$.inlined.unsafeTransform.1(this.f335d);
```

</details>


## Command Sequences

*No command sequences found in this DEX file.*

## Method Index

### Write/Send Methods

- `getOTA2FileDataSendOver()` in `BLEJniLib`
- `getUpgradeSendOverRequest()` in `BLEJniLib`
- `writeField()` in `ASN1ObjectIdentifier`
- `writeField()` in `ASN1ObjectIdentifier`
- `write()` in `ASN1OutputStream`
- `writeElements()` in `ASN1OutputStream`
- `writeEncoded()` in `ASN1OutputStream`
- `writeEncodedIndef()` in `ASN1OutputStream`
- `writeLength()` in `ASN1OutputStream`
- `writeObject()` in `ASN1OutputStream`
- `writePrimitive()` in `ASN1OutputStream`
- `writeTag()` in `ASN1OutputStream`
- `write()` in `ASN1OutputStream`
- `writeElements()` in `ASN1OutputStream`
- `writeEncoded()` in `ASN1OutputStream`
- *(... and 391 more)*

### Callback/Event Methods

- `onFail()` in `YiPeerConnectionManagerImpl`
- `onSuccess()` in `YiPeerConnectionManagerImpl`
- `onFail()` in `YiPeerConnectionManagerImpl`
- `onSuccess()` in `YiPeerConnectionManagerImpl`
- `onFail()` in `YiPeerServiceImpl`
- `onSuccess()` in `YiPeerServiceImpl`
- `onFail()` in `YiPeerVideoControllerImpl`
- `onSuccess()` in `YiPeerVideoControllerImpl`
- `onFail()` in `YiPeerVideoControllerImpl`
- `onSuccess()` in `YiPeerVideoControllerImpl`
- `onFail()` in `CallbackExtensionsKt`
- `onSuccess()` in `CallbackExtensionsKt`
- `onlyContainsAttributeCerts()` in `IssuingDistributionPoint`
- `onlyContainsCACerts()` in `IssuingDistributionPoint`
- `onlyContainsUserCerts()` in `IssuingDistributionPoint`
- *(... and 3034 more)*

## Full Class List

<details>
<summary>Click to expand full class list (2652 classes)</summary>

Total: 2652 classes

### com.savantsystems.yisdk.device

- `com.savantsystems.yisdk.device.Companion`
- `com.savantsystems.yisdk.device.YiAlertAreaSettings`
- `com.savantsystems.yisdk.device.YiBatteryStatus`
- `com.savantsystems.yisdk.device.YiCameraScheduleTimerId`
- `com.savantsystems.yisdk.device.YiCameraSettingCommand`
- `com.savantsystems.yisdk.device.YiCameraSettings`
- `com.savantsystems.yisdk.device.YiDeviceManagerImpl`
- `com.savantsystems.yisdk.device.YiDeviceManagerImpl_Factory_Factory`
- `com.savantsystems.yisdk.device.YiDeviceState`
- `com.savantsystems.yisdk.device.YiDeviceState`
- `com.savantsystems.yisdk.device.YiDeviceStatePart`
- `com.savantsystems.yisdk.device.YiDeviceStatePartKey`
- `com.savantsystems.yisdk.device.YiExtendedCameraSettings`
- `com.savantsystems.yisdk.device.YiPlaybackState`
- `com.savantsystems.yisdk.device.YiSdCardInfo`
- `com.savantsystems.yisdk.device.YiStaticDeviceInfo`
- `com.savantsystems.yisdk.device.YiThumbnailImage`
- `com.savantsystems.yisdk.device.removed`
- `com.savantsystems.yisdk.device.removed`
- `com.savantsystems.yisdk.device.removed`
- `com.savantsystems.yisdk.device.removed`
- `com.savantsystems.yisdk.device.removed`
- `com.savantsystems.yisdk.device.removed`

### com.savantsystems.yisdk.device.manager

- `com.savantsystems.yisdk.device.manager.C0002xc5264345`
- `com.savantsystems.yisdk.device.manager.C0003xed66f95d`
- `com.savantsystems.yisdk.device.manager.C0004xed66f95e`
- `com.savantsystems.yisdk.device.manager.C0015xa7c3fb91`
- `com.savantsystems.yisdk.device.manager.DefaultImpls`
- `com.savantsystems.yisdk.device.manager.YiConnectionLock`
- `com.savantsystems.yisdk.device.manager.YiConnectionLockManager`
- `com.savantsystems.yisdk.device.manager.YiConnectionLockManagerKt`
- `com.savantsystems.yisdk.device.manager.YiDeviceInfoManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiDeviceInfoManagerImpl_Factory_Factory`
- `com.savantsystems.yisdk.device.manager.YiDeviceSubscriptionManager`
- `com.savantsystems.yisdk.device.manager.YiDeviceSubscriptionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiDeviceSubscriptionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiDeviceSubscriptionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiDeviceSubscriptionManagerImplKt`
- `com.savantsystems.yisdk.device.manager.YiDeviceSubscriptionManagerImpl_Factory_Factory`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManager`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiFirmwareManagerImpl_Factory_Factory`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManager`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImplKt`
- `com.savantsystems.yisdk.device.manager.YiPeerConnectionManagerImpl_Factory_Factory`

### com.savantsystems.yisdk.device.mappers

- `com.savantsystems.yisdk.device.mappers.CameraClipMetaDataToYiPlaybackClipMapper`
- `com.savantsystems.yisdk.device.mappers.CameraClipMetaDataToYiPlaybackClipMapper_Factory`
- `com.savantsystems.yisdk.device.mappers.ClipToYiPlaybackClipMapper`
- `com.savantsystems.yisdk.device.mappers.ClipToYiPlaybackClipMapper_Factory`
- `com.savantsystems.yisdk.device.mappers.CloudClipEventTypeToDetectionType`
- `com.savantsystems.yisdk.device.mappers.CloudClipEventTypeToDetectionType_Factory`
- `com.savantsystems.yisdk.device.mappers.DetectionTypeToCloudDetectionTypesMapper`
- `com.savantsystems.yisdk.device.mappers.DetectionTypeToCloudDetectionTypesMapper_Factory`
- `com.savantsystems.yisdk.device.mappers.YiAlertCategoryToDetectionType`
- `com.savantsystems.yisdk.device.mappers.YiAlertCategoryToDetectionType_Factory`
- `com.savantsystems.yisdk.device.mappers.YiAlertTimePeriodsMapper`
- `com.savantsystems.yisdk.device.mappers.YiAlertTimePeriodsMapper_Factory`
- `com.savantsystems.yisdk.device.mappers.YiCameraToYiIpcDeviceMapper`
- `com.savantsystems.yisdk.device.mappers.YiCameraToYiIpcDeviceMapper_Factory`
- `com.savantsystems.yisdk.device.mappers.YiDeviceIdMapper`
- `com.savantsystems.yisdk.device.mappers.YiDeviceIdMapper_Factory`
- `com.savantsystems.yisdk.device.mappers.YiDeviceMapper`
- `com.savantsystems.yisdk.device.mappers.YiDeviceMapperKt`
- `com.savantsystems.yisdk.device.mappers.YiDeviceMapper_Factory`
- `com.savantsystems.yisdk.device.mappers.YiDeviceTypeToDeviceModelMapper`
- `com.savantsystems.yisdk.device.mappers.YiDeviceTypeToDeviceModelMapper_Factory`
- `com.savantsystems.yisdk.device.mappers.YiPlaybackClipToClipMapper`
- `com.savantsystems.yisdk.device.mappers.YiPlaybackClipToClipMapper_Factory`
- `com.savantsystems.yisdk.device.mappers.YiPlaybackEventToYiPlaybackClipMapper`
- `com.savantsystems.yisdk.device.mappers.YiPlaybackEventToYiPlaybackClipMapper_Factory`
- `com.savantsystems.yisdk.device.mappers.YiPlaybackStateToPlaybackStateMapper`
- `com.savantsystems.yisdk.device.mappers.YiPlaybackStateToPlaybackStateMapper_Factory`
- `com.savantsystems.yisdk.device.mappers.YiStaticDeviceInfoMapper`
- `com.savantsystems.yisdk.device.mappers.YiStaticDeviceInfoMapper_Factory`
- `com.savantsystems.yisdk.device.mappers.YiThumbnailSnapshotFileToThumbnailImageMapper`
- `com.savantsystems.yisdk.device.mappers.YiThumbnailSnapshotFileToThumbnailImageMapper_Factory`
- `com.savantsystems.yisdk.device.mappers.YiVideoQualityMapper`
- `com.savantsystems.yisdk.device.mappers.YiVideoQualityMapper_Factory`

### com.savantsystems.yisdk.device.service

- `com.savantsystems.yisdk.device.service.C0073x1f4519a3`
- `com.savantsystems.yisdk.device.service.C0076a`
- `com.savantsystems.yisdk.device.service.DefaultImpls`
- `com.savantsystems.yisdk.device.service.YiAudioController`
- `com.savantsystems.yisdk.device.service.YiAudioControllerImpl`
- `com.savantsystems.yisdk.device.service.YiAudioControllerImpl`
- `com.savantsystems.yisdk.device.service.YiAudioControllerImpl_Factory_Factory`
- `com.savantsystems.yisdk.device.service.YiCloudPlaybackControllerImpl`
- `com.savantsystems.yisdk.device.service.YiCloudPlaybackControllerImpl`
- `com.savantsystems.yisdk.device.service.YiCloudPlaybackControllerImpl`
- `com.savantsystems.yisdk.device.service.YiCloudPlaybackControllerImpl`
- `com.savantsystems.yisdk.device.service.YiCloudPlaybackControllerImpl`
- `com.savantsystems.yisdk.device.service.YiCloudPlaybackControllerImpl`
- `com.savantsystems.yisdk.device.service.YiCloudPlaybackControllerImpl`
- `com.savantsystems.yisdk.device.service.YiCloudPlaybackControllerImpl_Factory_Factory`
- `com.savantsystems.yisdk.device.service.YiDeviceService`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl`
- `com.savantsystems.yisdk.device.service.YiDeviceServiceImpl_Factory_Factory`
- `com.savantsystems.yisdk.device.service.YiNotificationService`
- `com.savantsystems.yisdk.device.service.YiNotificationServiceImpl`
- `com.savantsystems.yisdk.device.service.YiNotificationServiceImpl`
- `com.savantsystems.yisdk.device.service.YiNotificationServiceImpl`
- `com.savantsystems.yisdk.device.service.YiNotificationServiceImpl_Factory_Factory`
- `com.savantsystems.yisdk.device.service.YiPeerService`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImplKt`
- `com.savantsystems.yisdk.device.service.YiPeerServiceImpl_Factory_Factory`
- `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl`
- `com.savantsystems.yisdk.device.service.YiPeerVideoControllerImpl_Factory_Factory`
- `com.savantsystems.yisdk.device.service.YiPlaybackController`
- `com.savantsystems.yisdk.device.service.YiPreviewService`
- `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl`
- `com.savantsystems.yisdk.device.service.YiPreviewServiceImpl_Factory_Factory`
- `com.savantsystems.yisdk.device.service.YiSdCardService`
- `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl`
- `com.savantsystems.yisdk.device.service.YiSdCardServiceImplKt`
- `com.savantsystems.yisdk.device.service.YiSdCardServiceImpl_Factory_Factory`
- `com.savantsystems.yisdk.device.service.YiSnapshotHelper`
- `com.savantsystems.yisdk.device.service.removed`

### com.savantsystems.yisdk.extensions

- `com.savantsystems.yisdk.extensions.CallbackExtensionsKt`
- `com.savantsystems.yisdk.extensions.CallbackExtensionsKt`
- `com.savantsystems.yisdk.extensions.DeviceStateExtensionsKt`

### com.savantsystems.yisdk.glide

- `com.savantsystems.yisdk.glide.YiClipPreviewImageModelLoader`
- `com.savantsystems.yisdk.glide.YiClipPreviewImageModelLoader_Factory_Factory`
- `com.savantsystems.yisdk.glide.YiGlideModule`

### com.savantsystems.yisdk.notifications

- `com.savantsystems.yisdk.notifications.YiPushTokenReceiver`
- `com.savantsystems.yisdk.notifications.YiPushTokenReceiver`
- `com.savantsystems.yisdk.notifications.YiPushTokenReceiver_Factory`

### com.savantsystems.yisdk.p000di

- `com.savantsystems.yisdk.p000di.HiltWrapper_YiSdkModule`
- `com.savantsystems.yisdk.p000di.YiSdkModule`
- `com.savantsystems.yisdk.p000di.YiSdkModule_ProvidePushTokenReceiverFactory`
- `com.savantsystems.yisdk.p000di.YiSdkModule_ProvideYiActivationServiceFactory`
- `com.savantsystems.yisdk.p000di.YiSdkModule_ProvideYiCameraListServiceFactory`
- `com.savantsystems.yisdk.p000di.YiSdkModule_ProvideYiCameraSettingsServiceFactory`
- `com.savantsystems.yisdk.p000di.YiSdkModule_ProvideYiManagerFactory`
- `com.savantsystems.yisdk.p000di.YiSdkModule_ProvideYiUserServiceFactory`

### com.savantsystems.yisdk.playback

- `com.savantsystems.yisdk.playback.DefaultImpls`
- `com.savantsystems.yisdk.playback.YiPlaybackClip`
- `com.savantsystems.yisdk.playback.YiPlaybackManager`
- `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl`
- `com.savantsystems.yisdk.playback.YiPlaybackManagerImpl_Factory_Factory`

### com.savantsystems.yisdk.user

- `com.savantsystems.yisdk.user.YiUserService`
- `com.savantsystems.yisdk.user.YiUserServiceImpl`
- `com.savantsystems.yisdk.user.YiUserServiceImpl`
- `com.savantsystems.yisdk.user.YiUserServiceImpl_Factory_Factory`
- `com.savantsystems.yisdk.user.YiUserState`
- `com.savantsystems.yisdk.user.YiUserStateProvider`

### com.sinaapp.bashell

- `com.sinaapp.bashell.VoAACEncoder`

### com.thing.smart.openssl

- `com.thing.smart.openssl.BuildConfig`
- `com.thing.smart.openssl.C0078R`
- `com.thing.smart.openssl.ThingOpensslManager`

### com.thingclips.ble.jni

- `com.thingclips.ble.jni.BLEJniLib`

### com.thingclips.bouncycastle

- `com.thingclips.bouncycastle.BouncyCastleProviderInstance`
- `com.thingclips.bouncycastle.LICENSE`

### com.thingclips.bouncycastle.asn1

- `com.thingclips.bouncycastle.asn1.ASN1ApplicationSpecific`
- `com.thingclips.bouncycastle.asn1.ASN1ApplicationSpecificParser`
- `com.thingclips.bouncycastle.asn1.ASN1BitString`
- `com.thingclips.bouncycastle.asn1.ASN1Boolean`
- `com.thingclips.bouncycastle.asn1.ASN1Choice`
- `com.thingclips.bouncycastle.asn1.ASN1Encodable`
- `com.thingclips.bouncycastle.asn1.ASN1EncodableVector`
- `com.thingclips.bouncycastle.asn1.ASN1Encoding`
- `com.thingclips.bouncycastle.asn1.ASN1Enumerated`
- `com.thingclips.bouncycastle.asn1.ASN1Exception`
- `com.thingclips.bouncycastle.asn1.ASN1External`
- `com.thingclips.bouncycastle.asn1.ASN1GeneralizedTime`
- `com.thingclips.bouncycastle.asn1.ASN1Generator`
- `com.thingclips.bouncycastle.asn1.ASN1InputStream`
- `com.thingclips.bouncycastle.asn1.ASN1Integer`
- `com.thingclips.bouncycastle.asn1.ASN1Null`
- `com.thingclips.bouncycastle.asn1.ASN1Object`
- `com.thingclips.bouncycastle.asn1.ASN1ObjectIdentifier`
- `com.thingclips.bouncycastle.asn1.ASN1OctetString`
- `com.thingclips.bouncycastle.asn1.ASN1OctetStringParser`
- `com.thingclips.bouncycastle.asn1.ASN1OutputStream`
- `com.thingclips.bouncycastle.asn1.ASN1ParsingException`
- `com.thingclips.bouncycastle.asn1.ASN1Primitive`
- `com.thingclips.bouncycastle.asn1.ASN1Private`
- `com.thingclips.bouncycastle.asn1.ASN1PrivateParser`
- `com.thingclips.bouncycastle.asn1.ASN1Sequence`
- `com.thingclips.bouncycastle.asn1.ASN1SequenceParser`
- `com.thingclips.bouncycastle.asn1.ASN1Set`
- `com.thingclips.bouncycastle.asn1.ASN1SetParser`
- `com.thingclips.bouncycastle.asn1.ASN1StreamParser`
- `com.thingclips.bouncycastle.asn1.ASN1String`
- `com.thingclips.bouncycastle.asn1.ASN1TaggedObject`
- `com.thingclips.bouncycastle.asn1.ASN1TaggedObjectParser`
- `com.thingclips.bouncycastle.asn1.ASN1UTCTime`
- `com.thingclips.bouncycastle.asn1.BERApplicationSpecific`
- `com.thingclips.bouncycastle.asn1.BERApplicationSpecificParser`
- `com.thingclips.bouncycastle.asn1.BERConstructedOctetString`
- `com.thingclips.bouncycastle.asn1.BERFactory`
- `com.thingclips.bouncycastle.asn1.BERGenerator`
- `com.thingclips.bouncycastle.asn1.BEROctetString`
- `com.thingclips.bouncycastle.asn1.BEROctetStringGenerator`
- `com.thingclips.bouncycastle.asn1.BEROctetStringParser`
- `com.thingclips.bouncycastle.asn1.BEROutputStream`
- `com.thingclips.bouncycastle.asn1.BERPrivate`
- `com.thingclips.bouncycastle.asn1.BERPrivateParser`
- `com.thingclips.bouncycastle.asn1.BERSequence`
- `com.thingclips.bouncycastle.asn1.BERSequenceGenerator`
- `com.thingclips.bouncycastle.asn1.BERSequenceParser`
- `com.thingclips.bouncycastle.asn1.BERSet`
- `com.thingclips.bouncycastle.asn1.BERSetParser`
- `com.thingclips.bouncycastle.asn1.BERTaggedObject`
- `com.thingclips.bouncycastle.asn1.BERTaggedObjectParser`
- `com.thingclips.bouncycastle.asn1.BERTags`
- `com.thingclips.bouncycastle.asn1.ConstructedOctetStream`
- `com.thingclips.bouncycastle.asn1.DERApplicationSpecific`
- `com.thingclips.bouncycastle.asn1.DERBMPString`
- `com.thingclips.bouncycastle.asn1.DERBitString`
- `com.thingclips.bouncycastle.asn1.DEREncodableVector`
- `com.thingclips.bouncycastle.asn1.DEREnumerated`
- `com.thingclips.bouncycastle.asn1.DERExternal`
- `com.thingclips.bouncycastle.asn1.DERExternalParser`
- `com.thingclips.bouncycastle.asn1.DERFactory`
- `com.thingclips.bouncycastle.asn1.DERGeneralString`
- `com.thingclips.bouncycastle.asn1.DERGeneralizedTime`
- `com.thingclips.bouncycastle.asn1.DERGenerator`
- `com.thingclips.bouncycastle.asn1.DERGraphicString`
- `com.thingclips.bouncycastle.asn1.DERIA5String`
- `com.thingclips.bouncycastle.asn1.DERInteger`
- `com.thingclips.bouncycastle.asn1.DERNull`
- `com.thingclips.bouncycastle.asn1.DERNumericString`
- `com.thingclips.bouncycastle.asn1.DERObjectIdentifier`
- `com.thingclips.bouncycastle.asn1.DEROctetString`
- `com.thingclips.bouncycastle.asn1.DEROctetStringParser`
- `com.thingclips.bouncycastle.asn1.DEROutputStream`
- `com.thingclips.bouncycastle.asn1.DERPrintableString`
- `com.thingclips.bouncycastle.asn1.DERSequence`
- `com.thingclips.bouncycastle.asn1.DERSequenceGenerator`
- `com.thingclips.bouncycastle.asn1.DERSequenceParser`
- `com.thingclips.bouncycastle.asn1.DERSet`
- `com.thingclips.bouncycastle.asn1.DERT61String`
- `com.thingclips.bouncycastle.asn1.DERTaggedObject`
- `com.thingclips.bouncycastle.asn1.DERTags`
- `com.thingclips.bouncycastle.asn1.DERUTCTime`
- `com.thingclips.bouncycastle.asn1.DERUTF8String`
- `com.thingclips.bouncycastle.asn1.DERUniversalString`
- `com.thingclips.bouncycastle.asn1.DERVideotexString`
- `com.thingclips.bouncycastle.asn1.DERVisibleString`
- `com.thingclips.bouncycastle.asn1.DLApplicationSpecific`
- `com.thingclips.bouncycastle.asn1.DLBitString`
- `com.thingclips.bouncycastle.asn1.DLExternal`
- `com.thingclips.bouncycastle.asn1.DLFactory`
- `com.thingclips.bouncycastle.asn1.DLOutputStream`
- `com.thingclips.bouncycastle.asn1.DLPrivate`
- `com.thingclips.bouncycastle.asn1.DLSequence`
- `com.thingclips.bouncycastle.asn1.DLSequenceParser`
- `com.thingclips.bouncycastle.asn1.DLSet`
- `com.thingclips.bouncycastle.asn1.DLSetParser`
- `com.thingclips.bouncycastle.asn1.DLTaggedObject`
- `com.thingclips.bouncycastle.asn1.DateUtil`
- `com.thingclips.bouncycastle.asn1.DefiniteLengthInputStream`
- `com.thingclips.bouncycastle.asn1.InMemoryRepresentable`
- `com.thingclips.bouncycastle.asn1.IndefiniteLengthInputStream`
- `com.thingclips.bouncycastle.asn1.LazyConstructionEnumeration`
- `com.thingclips.bouncycastle.asn1.LazyEncodedSequence`
- `com.thingclips.bouncycastle.asn1.LimitedInputStream`
- `com.thingclips.bouncycastle.asn1.OIDTokenizer`
- `com.thingclips.bouncycastle.asn1.StreamUtil`

### com.thingclips.bouncycastle.asn1.anssi

- `com.thingclips.bouncycastle.asn1.anssi.ANSSINamedCurves`
- `com.thingclips.bouncycastle.asn1.anssi.ANSSIObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.bsi

- `com.thingclips.bouncycastle.asn1.bsi.BSIObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.cms

- `com.thingclips.bouncycastle.asn1.cms.CMSObjectIdentifiers`
- `com.thingclips.bouncycastle.asn1.cms.GCMParameters`

### com.thingclips.bouncycastle.asn1.cryptlib

- `com.thingclips.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.cryptopro

- `com.thingclips.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers`
- `com.thingclips.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves`
- `com.thingclips.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters`

### com.thingclips.bouncycastle.asn1.eac

- `com.thingclips.bouncycastle.asn1.eac.EACObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.edec

- `com.thingclips.bouncycastle.asn1.edec.EdECObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.gm

- `com.thingclips.bouncycastle.asn1.gm.GMObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.gnu

- `com.thingclips.bouncycastle.asn1.gnu.GNUObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.isara

- `com.thingclips.bouncycastle.asn1.isara.IsaraObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.iso

- `com.thingclips.bouncycastle.asn1.iso.ISOIECObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.kisa

- `com.thingclips.bouncycastle.asn1.kisa.KISAObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.misc

- `com.thingclips.bouncycastle.asn1.misc.MiscObjectIdentifiers`
- `com.thingclips.bouncycastle.asn1.misc.NetscapeCertType`
- `com.thingclips.bouncycastle.asn1.misc.NetscapeRevocationURL`
- `com.thingclips.bouncycastle.asn1.misc.VerisignCzagExtension`

### com.thingclips.bouncycastle.asn1.nist

- `com.thingclips.bouncycastle.asn1.nist.NISTNamedCurves`
- `com.thingclips.bouncycastle.asn1.nist.NISTObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.ntt

- `com.thingclips.bouncycastle.asn1.ntt.NTTObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.oiw

- `com.thingclips.bouncycastle.asn1.oiw.ElGamalParameter`
- `com.thingclips.bouncycastle.asn1.oiw.OIWObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.p001bc

- `com.thingclips.bouncycastle.asn1.p001bc.BCObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.p002x9

- `com.thingclips.bouncycastle.asn1.p002x9.ECNamedCurveTable`
- `com.thingclips.bouncycastle.asn1.p002x9.X962NamedCurves`
- `com.thingclips.bouncycastle.asn1.p002x9.X962Parameters`
- `com.thingclips.bouncycastle.asn1.p002x9.X9Curve`
- `com.thingclips.bouncycastle.asn1.p002x9.X9ECParameters`
- `com.thingclips.bouncycastle.asn1.p002x9.X9ECParametersHolder`
- `com.thingclips.bouncycastle.asn1.p002x9.X9ECPoint`
- `com.thingclips.bouncycastle.asn1.p002x9.X9FieldElement`
- `com.thingclips.bouncycastle.asn1.p002x9.X9FieldID`
- `com.thingclips.bouncycastle.asn1.p002x9.X9IntegerConverter`
- `com.thingclips.bouncycastle.asn1.p002x9.X9ObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.pkcs

- `com.thingclips.bouncycastle.asn1.pkcs.Attribute`
- `com.thingclips.bouncycastle.asn1.pkcs.CertificationRequest`
- `com.thingclips.bouncycastle.asn1.pkcs.CertificationRequestInfo`
- `com.thingclips.bouncycastle.asn1.pkcs.ContentInfo`
- `com.thingclips.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers`
- `com.thingclips.bouncycastle.asn1.pkcs.PrivateKeyInfo`
- `com.thingclips.bouncycastle.asn1.pkcs.RSAESOAEPparams`
- `com.thingclips.bouncycastle.asn1.pkcs.RSAPrivateKey`
- `com.thingclips.bouncycastle.asn1.pkcs.RSAPublicKey`
- `com.thingclips.bouncycastle.asn1.pkcs.RSASSAPSSparams`
- `com.thingclips.bouncycastle.asn1.pkcs.SignedData`

### com.thingclips.bouncycastle.asn1.rosstandart

- `com.thingclips.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.sec

- `com.thingclips.bouncycastle.asn1.sec.ECPrivateKey`
- `com.thingclips.bouncycastle.asn1.sec.SECNamedCurves`
- `com.thingclips.bouncycastle.asn1.sec.SECObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.teletrust

- `com.thingclips.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves`
- `com.thingclips.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers`

### com.thingclips.bouncycastle.asn1.util

- `com.thingclips.bouncycastle.asn1.util.ASN1Dump`

### com.thingclips.bouncycastle.asn1.x500

- `com.thingclips.bouncycastle.asn1.x500.AttributeTypeAndValue`
- `com.thingclips.bouncycastle.asn1.x500.RDN`
- `com.thingclips.bouncycastle.asn1.x500.X500Name`
- `com.thingclips.bouncycastle.asn1.x500.X500NameBuilder`
- `com.thingclips.bouncycastle.asn1.x500.X500NameStyle`

### com.thingclips.bouncycastle.asn1.x500.style

- `com.thingclips.bouncycastle.asn1.x500.style.AbstractX500NameStyle`
- `com.thingclips.bouncycastle.asn1.x500.style.BCStyle`
- `com.thingclips.bouncycastle.asn1.x500.style.IETFUtils`
- `com.thingclips.bouncycastle.asn1.x500.style.RFC4519Style`
- `com.thingclips.bouncycastle.asn1.x500.style.X500NameTokenizer`

### com.thingclips.bouncycastle.asn1.x509

- `com.thingclips.bouncycastle.asn1.x509.AlgorithmIdentifier`
- `com.thingclips.bouncycastle.asn1.x509.AttCertIssuer`
- `com.thingclips.bouncycastle.asn1.x509.AttCertValidityPeriod`
- `com.thingclips.bouncycastle.asn1.x509.Attribute`
- `com.thingclips.bouncycastle.asn1.x509.AttributeCertificate`
- `com.thingclips.bouncycastle.asn1.x509.AttributeCertificateInfo`
- `com.thingclips.bouncycastle.asn1.x509.BasicConstraints`
- `com.thingclips.bouncycastle.asn1.x509.CRLDistPoint`
- `com.thingclips.bouncycastle.asn1.x509.CRLNumber`
- `com.thingclips.bouncycastle.asn1.x509.CRLReason`
- `com.thingclips.bouncycastle.asn1.x509.Certificate`
- `com.thingclips.bouncycastle.asn1.x509.CertificateList`
- `com.thingclips.bouncycastle.asn1.x509.DSAParameter`
- `com.thingclips.bouncycastle.asn1.x509.DigestInfo`
- `com.thingclips.bouncycastle.asn1.x509.DistributionPoint`
- `com.thingclips.bouncycastle.asn1.x509.DistributionPointName`
- `com.thingclips.bouncycastle.asn1.x509.Extension`
- `com.thingclips.bouncycastle.asn1.x509.Extensions`
- `com.thingclips.bouncycastle.asn1.x509.ExtensionsGenerator`
- `com.thingclips.bouncycastle.asn1.x509.GeneralName`
- `com.thingclips.bouncycastle.asn1.x509.GeneralNames`
- `com.thingclips.bouncycastle.asn1.x509.Holder`
- `com.thingclips.bouncycastle.asn1.x509.IssuerSerial`
- `com.thingclips.bouncycastle.asn1.x509.IssuingDistributionPoint`
- `com.thingclips.bouncycastle.asn1.x509.KeyUsage`
- `com.thingclips.bouncycastle.asn1.x509.ObjectDigestInfo`
- `com.thingclips.bouncycastle.asn1.x509.ReasonFlags`
- `com.thingclips.bouncycastle.asn1.x509.SubjectPublicKeyInfo`
- `com.thingclips.bouncycastle.asn1.x509.TBSCertList`
- `com.thingclips.bouncycastle.asn1.x509.TBSCertificate`
- `com.thingclips.bouncycastle.asn1.x509.Time`
- `com.thingclips.bouncycastle.asn1.x509.V2Form`
- `com.thingclips.bouncycastle.asn1.x509.X509DefaultEntryConverter`
- `com.thingclips.bouncycastle.asn1.x509.X509Extension`
- `com.thingclips.bouncycastle.asn1.x509.X509Name`
- `com.thingclips.bouncycastle.asn1.x509.X509NameEntryConverter`
- `com.thingclips.bouncycastle.asn1.x509.X509NameTokenizer`
- `com.thingclips.bouncycastle.asn1.x509.X509ObjectIdentifiers`

### com.thingclips.bouncycastle.cert

- `com.thingclips.bouncycastle.cert.AttributeCertificateHolder`
- `com.thingclips.bouncycastle.cert.AttributeCertificateIssuer`
- `com.thingclips.bouncycastle.cert.CertException`
- `com.thingclips.bouncycastle.cert.CertIOException`
- `com.thingclips.bouncycastle.cert.CertUtils`
- `com.thingclips.bouncycastle.cert.X509AttributeCertificateHolder`
- `com.thingclips.bouncycastle.cert.X509CRLEntryHolder`
- `com.thingclips.bouncycastle.cert.X509CRLHolder`
- `com.thingclips.bouncycastle.cert.X509CertificateHolder`

### com.thingclips.bouncycastle.cms

- `com.thingclips.bouncycastle.cms.CMSException`

### com.thingclips.bouncycastle.crypto

- `com.thingclips.bouncycastle.crypto.AsymmetricBlockCipher`
- `com.thingclips.bouncycastle.crypto.AsymmetricCipherKeyPair`
- `com.thingclips.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator`
- `com.thingclips.bouncycastle.crypto.BasicAgreement`
- `com.thingclips.bouncycastle.crypto.BlockCipher`
- `com.thingclips.bouncycastle.crypto.CipherKeyGenerator`
- `com.thingclips.bouncycastle.crypto.CipherParameters`
- `com.thingclips.bouncycastle.crypto.CryptoException`
- `com.thingclips.bouncycastle.crypto.CryptoServicesPermission`
- `com.thingclips.bouncycastle.crypto.CryptoServicesRegistrar`
- `com.thingclips.bouncycastle.crypto.DSA`
- `com.thingclips.bouncycastle.crypto.DSAExt`
- `com.thingclips.bouncycastle.crypto.DataLengthException`
- `com.thingclips.bouncycastle.crypto.DerivationFunction`
- `com.thingclips.bouncycastle.crypto.DerivationParameters`
- `com.thingclips.bouncycastle.crypto.Digest`
- `com.thingclips.bouncycastle.crypto.DigestDerivationFunction`
- `com.thingclips.bouncycastle.crypto.ExtendedDigest`
- `com.thingclips.bouncycastle.crypto.InvalidCipherTextException`
- `com.thingclips.bouncycastle.crypto.KeyGenerationParameters`
- `com.thingclips.bouncycastle.crypto.Mac`
- `com.thingclips.bouncycastle.crypto.MaxBytesExceededException`
- `com.thingclips.bouncycastle.crypto.OutputLengthException`
- `com.thingclips.bouncycastle.crypto.PBEParametersGenerator`
- `com.thingclips.bouncycastle.crypto.RuntimeCryptoException`
- `com.thingclips.bouncycastle.crypto.Signer`
- `com.thingclips.bouncycastle.crypto.SignerWithRecovery`
- `com.thingclips.bouncycastle.crypto.SkippingCipher`
- `com.thingclips.bouncycastle.crypto.SkippingStreamCipher`
- `com.thingclips.bouncycastle.crypto.StreamBlockCipher`
- `com.thingclips.bouncycastle.crypto.StreamCipher`
- `com.thingclips.bouncycastle.crypto.Wrapper`
- `com.thingclips.bouncycastle.crypto.Xof`

### com.thingclips.bouncycastle.crypto.agreement

- `com.thingclips.bouncycastle.crypto.agreement.ECDHBasicAgreement`
- `com.thingclips.bouncycastle.crypto.agreement.ECDHCBasicAgreement`
- `com.thingclips.bouncycastle.crypto.agreement.ECDHCUnifiedAgreement`
- `com.thingclips.bouncycastle.crypto.agreement.ECMQVBasicAgreement`

### com.thingclips.bouncycastle.crypto.agreement.kdf

- `com.thingclips.bouncycastle.crypto.agreement.kdf.DHKDFParameters`
- `com.thingclips.bouncycastle.crypto.agreement.kdf.DHKEKGenerator`

### com.thingclips.bouncycastle.crypto.digests

- `com.thingclips.bouncycastle.crypto.digests.EncodableDigest`
- `com.thingclips.bouncycastle.crypto.digests.GOST3411Digest`
- `com.thingclips.bouncycastle.crypto.digests.GeneralDigest`
- `com.thingclips.bouncycastle.crypto.digests.KeccakDigest`
- `com.thingclips.bouncycastle.crypto.digests.LongDigest`
- `com.thingclips.bouncycastle.crypto.digests.MD2Digest`
- `com.thingclips.bouncycastle.crypto.digests.MD4Digest`
- `com.thingclips.bouncycastle.crypto.digests.MD5Digest`
- `com.thingclips.bouncycastle.crypto.digests.NullDigest`
- `com.thingclips.bouncycastle.crypto.digests.RIPEMD128Digest`
- `com.thingclips.bouncycastle.crypto.digests.RIPEMD160Digest`
- `com.thingclips.bouncycastle.crypto.digests.RIPEMD256Digest`
- `com.thingclips.bouncycastle.crypto.digests.SHA1Digest`
- `com.thingclips.bouncycastle.crypto.digests.SHA224Digest`
- `com.thingclips.bouncycastle.crypto.digests.SHA256Digest`
- `com.thingclips.bouncycastle.crypto.digests.SHA384Digest`
- `com.thingclips.bouncycastle.crypto.digests.SHA3Digest`
- `com.thingclips.bouncycastle.crypto.digests.SHA512Digest`
- `com.thingclips.bouncycastle.crypto.digests.SHA512tDigest`
- `com.thingclips.bouncycastle.crypto.digests.SHAKEDigest`
- `com.thingclips.bouncycastle.crypto.digests.SM3Digest`
- `com.thingclips.bouncycastle.crypto.digests.SkeinDigest`
- `com.thingclips.bouncycastle.crypto.digests.SkeinEngine`
- `com.thingclips.bouncycastle.crypto.digests.TigerDigest`
- `com.thingclips.bouncycastle.crypto.digests.WhirlpoolDigest`

### com.thingclips.bouncycastle.crypto.ec

- `com.thingclips.bouncycastle.crypto.ec.CustomNamedCurves`

### com.thingclips.bouncycastle.crypto.encodings

- `com.thingclips.bouncycastle.crypto.encodings.ISO9796d1Encoding`
- `com.thingclips.bouncycastle.crypto.encodings.OAEPEncoding`
- `com.thingclips.bouncycastle.crypto.encodings.PKCS1Encoding`

### com.thingclips.bouncycastle.crypto.engines

- `com.thingclips.bouncycastle.crypto.engines.AESEngine`
- `com.thingclips.bouncycastle.crypto.engines.AESLightEngine`
- `com.thingclips.bouncycastle.crypto.engines.GOST28147Engine`
- `com.thingclips.bouncycastle.crypto.engines.RSABlindedEngine`
- `com.thingclips.bouncycastle.crypto.engines.RSACoreEngine`
- `com.thingclips.bouncycastle.crypto.engines.ThreefishEngine`

### com.thingclips.bouncycastle.crypto.generators

- `com.thingclips.bouncycastle.crypto.generators.ECKeyPairGenerator`
- `com.thingclips.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator`
- `com.thingclips.bouncycastle.crypto.generators.PKCS12ParametersGenerator`
- `com.thingclips.bouncycastle.crypto.generators.PKCS5S1ParametersGenerator`
- `com.thingclips.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator`
- `com.thingclips.bouncycastle.crypto.generators.RSAKeyPairGenerator`

### com.thingclips.bouncycastle.crypto.macs

- `com.thingclips.bouncycastle.crypto.macs.CBCBlockCipherMac`
- `com.thingclips.bouncycastle.crypto.macs.CMac`
- `com.thingclips.bouncycastle.crypto.macs.HMac`
- `com.thingclips.bouncycastle.crypto.macs.SkeinMac`

### com.thingclips.bouncycastle.crypto.modes

- `com.thingclips.bouncycastle.crypto.modes.AEADBlockCipher`
- `com.thingclips.bouncycastle.crypto.modes.CBCBlockCipher`
- `com.thingclips.bouncycastle.crypto.modes.CCMBlockCipher`
- `com.thingclips.bouncycastle.crypto.modes.SICBlockCipher`

### com.thingclips.bouncycastle.crypto.paddings

- `com.thingclips.bouncycastle.crypto.paddings.BlockCipherPadding`
- `com.thingclips.bouncycastle.crypto.paddings.ISO7816d4Padding`

### com.thingclips.bouncycastle.crypto.params

- `com.thingclips.bouncycastle.crypto.params.AEADParameters`
- `com.thingclips.bouncycastle.crypto.params.AsymmetricKeyParameter`
- `com.thingclips.bouncycastle.crypto.params.DESParameters`
- `com.thingclips.bouncycastle.crypto.params.DHParameters`
- `com.thingclips.bouncycastle.crypto.params.DHValidationParameters`
- `com.thingclips.bouncycastle.crypto.params.DSAKeyParameters`
- `com.thingclips.bouncycastle.crypto.params.DSAParameters`
- `com.thingclips.bouncycastle.crypto.params.DSAPrivateKeyParameters`
- `com.thingclips.bouncycastle.crypto.params.DSAPublicKeyParameters`
- `com.thingclips.bouncycastle.crypto.params.DSAValidationParameters`
- `com.thingclips.bouncycastle.crypto.params.ECDHUPrivateParameters`
- `com.thingclips.bouncycastle.crypto.params.ECDHUPublicParameters`
- `com.thingclips.bouncycastle.crypto.params.ECDomainParameters`
- `com.thingclips.bouncycastle.crypto.params.ECGOST3410Parameters`
- `com.thingclips.bouncycastle.crypto.params.ECKeyGenerationParameters`
- `com.thingclips.bouncycastle.crypto.params.ECKeyParameters`
- `com.thingclips.bouncycastle.crypto.params.ECNamedDomainParameters`
- `com.thingclips.bouncycastle.crypto.params.ECPrivateKeyParameters`
- `com.thingclips.bouncycastle.crypto.params.ECPublicKeyParameters`
- `com.thingclips.bouncycastle.crypto.params.Ed25519PrivateKeyParameters`
- `com.thingclips.bouncycastle.crypto.params.Ed25519PublicKeyParameters`
- `com.thingclips.bouncycastle.crypto.params.Ed448PrivateKeyParameters`
- `com.thingclips.bouncycastle.crypto.params.Ed448PublicKeyParameters`
- `com.thingclips.bouncycastle.crypto.params.ISO18033KDFParameters`
- `com.thingclips.bouncycastle.crypto.params.KDFParameters`
- `com.thingclips.bouncycastle.crypto.params.KeyParameter`
- `com.thingclips.bouncycastle.crypto.params.MQVPrivateParameters`
- `com.thingclips.bouncycastle.crypto.params.MQVPublicParameters`
- `com.thingclips.bouncycastle.crypto.params.ParametersWithID`
- `com.thingclips.bouncycastle.crypto.params.ParametersWithIV`
- `com.thingclips.bouncycastle.crypto.params.ParametersWithRandom`
- `com.thingclips.bouncycastle.crypto.params.ParametersWithSBox`
- `com.thingclips.bouncycastle.crypto.params.RC2Parameters`
- `com.thingclips.bouncycastle.crypto.params.RSABlindingParameters`
- `com.thingclips.bouncycastle.crypto.params.RSAKeyGenerationParameters`
- `com.thingclips.bouncycastle.crypto.params.RSAKeyParameters`
- `com.thingclips.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters`
- `com.thingclips.bouncycastle.crypto.params.SkeinParameters`
- `com.thingclips.bouncycastle.crypto.params.TweakableBlockCipherParameters`
- `com.thingclips.bouncycastle.crypto.params.X25519PrivateKeyParameters`
- `com.thingclips.bouncycastle.crypto.params.X25519PublicKeyParameters`
- `com.thingclips.bouncycastle.crypto.params.X448PrivateKeyParameters`
- `com.thingclips.bouncycastle.crypto.params.X448PublicKeyParameters`

### com.thingclips.bouncycastle.crypto.signers

- `com.thingclips.bouncycastle.crypto.signers.DSAEncoding`
- `com.thingclips.bouncycastle.crypto.signers.DSAKCalculator`
- `com.thingclips.bouncycastle.crypto.signers.ECDSASigner`
- `com.thingclips.bouncycastle.crypto.signers.ECNRSigner`
- `com.thingclips.bouncycastle.crypto.signers.HMacDSAKCalculator`
- `com.thingclips.bouncycastle.crypto.signers.ISO9796d2Signer`
- `com.thingclips.bouncycastle.crypto.signers.ISOTrailers`
- `com.thingclips.bouncycastle.crypto.signers.PSSSigner`
- `com.thingclips.bouncycastle.crypto.signers.RandomDSAKCalculator`
- `com.thingclips.bouncycastle.crypto.signers.X931Signer`

### com.thingclips.bouncycastle.crypto.util

- `com.thingclips.bouncycastle.crypto.util.DigestFactory`
- `com.thingclips.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil`
- `com.thingclips.bouncycastle.crypto.util.OpenSSHPublicKeyUtil`
- `com.thingclips.bouncycastle.crypto.util.PrivateKeyInfoFactory`
- `com.thingclips.bouncycastle.crypto.util.SSHBuffer`
- `com.thingclips.bouncycastle.crypto.util.SSHBuilder`
- `com.thingclips.bouncycastle.crypto.util.SSHNamedCurves`

### com.thingclips.bouncycastle.jcajce

- `com.thingclips.bouncycastle.jcajce.CompositePrivateKey`
- `com.thingclips.bouncycastle.jcajce.CompositePublicKey`
- `com.thingclips.bouncycastle.jcajce.PBKDFKey`
- `com.thingclips.bouncycastle.jcajce.PKCS12Key`

### com.thingclips.bouncycastle.jcajce.interfaces

- `com.thingclips.bouncycastle.jcajce.interfaces.BCX509Certificate`

### com.thingclips.bouncycastle.jcajce.io

- `com.thingclips.bouncycastle.jcajce.io.DigestUpdatingOutputStream`
- `com.thingclips.bouncycastle.jcajce.io.MacUpdatingOutputStream`
- `com.thingclips.bouncycastle.jcajce.io.OutputStreamFactory`
- `com.thingclips.bouncycastle.jcajce.io.SignatureUpdatingOutputStream`

### com.thingclips.bouncycastle.jcajce.provider.asymmetric

- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.C0146EC`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.RSA`

### com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec

- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec.ECUtils`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec.KeyAgreementSpi`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi`

### com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa

- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.AlgorithmParametersSpi`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.CipherSpi`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSignatureSpi`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.ISOSignatureSpi`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.PSSSignatureSpi`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.RSAUtil`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.rsa.X931SignatureSpi`

### com.thingclips.bouncycastle.jcajce.provider.asymmetric.util

- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.DSABase`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.DSAEncoder`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.EC5Util`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.ECUtil`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.ExtendedInvalidKeySpecException`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator`

### com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509

- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.ExtCRLException`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.PEMUtil`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.PKIXCertPath`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.SignatureCreator`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.X509CRLEntryObject`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.X509CRLImpl`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.X509CRLInternal`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.X509CRLObject`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.X509CertificateImpl`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.X509CertificateInternal`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.X509CertificateObject`
- `com.thingclips.bouncycastle.jcajce.provider.asymmetric.x509.X509SignatureUtil`

### com.thingclips.bouncycastle.jcajce.provider.config

- `com.thingclips.bouncycastle.jcajce.provider.config.ConfigurableProvider`
- `com.thingclips.bouncycastle.jcajce.provider.config.ProviderConfiguration`
- `com.thingclips.bouncycastle.jcajce.provider.config.ProviderConfigurationPermission`

### com.thingclips.bouncycastle.jcajce.provider.digest

- `com.thingclips.bouncycastle.jcajce.provider.digest.BCMessageDigest`
- `com.thingclips.bouncycastle.jcajce.provider.digest.DigestAlgorithmProvider`
- `com.thingclips.bouncycastle.jcajce.provider.digest.SHA256`

### com.thingclips.bouncycastle.jcajce.provider.symmetric.util

- `com.thingclips.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey`
- `com.thingclips.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator`
- `com.thingclips.bouncycastle.jcajce.provider.symmetric.util.BaseMac`
- `com.thingclips.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory`
- `com.thingclips.bouncycastle.jcajce.provider.symmetric.util.ClassUtil`
- `com.thingclips.bouncycastle.jcajce.provider.symmetric.util.GcmSpecUtil`
- `com.thingclips.bouncycastle.jcajce.provider.symmetric.util.PBESecretKeyFactory`
- `com.thingclips.bouncycastle.jcajce.provider.symmetric.util.Util`

### com.thingclips.bouncycastle.jcajce.provider.util

- `com.thingclips.bouncycastle.jcajce.provider.util.AlgorithmProvider`
- `com.thingclips.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider`
- `com.thingclips.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter`
- `com.thingclips.bouncycastle.jcajce.provider.util.BadBlockException`
- `com.thingclips.bouncycastle.jcajce.provider.util.DigestFactory`

### com.thingclips.bouncycastle.jcajce.spec

- `com.thingclips.bouncycastle.jcajce.spec.AEADParameterSpec`
- `com.thingclips.bouncycastle.jcajce.spec.CompositeAlgorithmSpec`
- `com.thingclips.bouncycastle.jcajce.spec.DHDomainParameterSpec`
- `com.thingclips.bouncycastle.jcajce.spec.DHUParameterSpec`
- `com.thingclips.bouncycastle.jcajce.spec.MQVParameterSpec`
- `com.thingclips.bouncycastle.jcajce.spec.OpenSSHPrivateKeySpec`
- `com.thingclips.bouncycastle.jcajce.spec.OpenSSHPublicKeySpec`
- `com.thingclips.bouncycastle.jcajce.spec.SkeinParameterSpec`
- `com.thingclips.bouncycastle.jcajce.spec.UserKeyingMaterialSpec`

### com.thingclips.bouncycastle.jcajce.util

- `com.thingclips.bouncycastle.jcajce.util.AlgorithmParametersUtils`
- `com.thingclips.bouncycastle.jcajce.util.BCJcaJceHelper`
- `com.thingclips.bouncycastle.jcajce.util.DefaultJcaJceHelper`
- `com.thingclips.bouncycastle.jcajce.util.JcaJceHelper`
- `com.thingclips.bouncycastle.jcajce.util.MessageDigestUtils`
- `com.thingclips.bouncycastle.jcajce.util.NamedJcaJceHelper`
- `com.thingclips.bouncycastle.jcajce.util.ProviderJcaJceHelper`

### com.thingclips.bouncycastle.jce

- `com.thingclips.bouncycastle.jce.ECGOST3410NamedCurveTable`
- `com.thingclips.bouncycastle.jce.ECNamedCurveTable`
- `com.thingclips.bouncycastle.jce.X509Principal`

### com.thingclips.bouncycastle.jce.interfaces

- `com.thingclips.bouncycastle.jce.interfaces.ECKey`
- `com.thingclips.bouncycastle.jce.interfaces.ECPointEncoder`
- `com.thingclips.bouncycastle.jce.interfaces.ECPrivateKey`
- `com.thingclips.bouncycastle.jce.interfaces.ECPublicKey`
- `com.thingclips.bouncycastle.jce.interfaces.MQVPrivateKey`
- `com.thingclips.bouncycastle.jce.interfaces.MQVPublicKey`
- `com.thingclips.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier`

### com.thingclips.bouncycastle.jce.provider

- `com.thingclips.bouncycastle.jce.provider.BouncyCastleProvider`
- `com.thingclips.bouncycastle.jce.provider.BouncyCastleProviderConfiguration`

### com.thingclips.bouncycastle.jce.spec

- `com.thingclips.bouncycastle.jce.spec.ECKeySpec`
- `com.thingclips.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec`
- `com.thingclips.bouncycastle.jce.spec.ECNamedCurveParameterSpec`
- `com.thingclips.bouncycastle.jce.spec.ECNamedCurveSpec`
- `com.thingclips.bouncycastle.jce.spec.ECParameterSpec`
- `com.thingclips.bouncycastle.jce.spec.ECPrivateKeySpec`
- `com.thingclips.bouncycastle.jce.spec.ECPublicKeySpec`

### com.thingclips.bouncycastle.math

- `com.thingclips.bouncycastle.math.Primes`

### com.thingclips.bouncycastle.math.ec

- `com.thingclips.bouncycastle.math.ec.AbstractECLookupTable`
- `com.thingclips.bouncycastle.math.ec.AbstractECMultiplier`
- `com.thingclips.bouncycastle.math.ec.ECAlgorithms`
- `com.thingclips.bouncycastle.math.ec.ECConstants`
- `com.thingclips.bouncycastle.math.ec.ECCurve`
- `com.thingclips.bouncycastle.math.ec.ECFieldElement`
- `com.thingclips.bouncycastle.math.ec.ECLookupTable`
- `com.thingclips.bouncycastle.math.ec.ECMultiplier`
- `com.thingclips.bouncycastle.math.ec.ECPoint`
- `com.thingclips.bouncycastle.math.ec.ECPointMap`
- `com.thingclips.bouncycastle.math.ec.FixedPointCombMultiplier`
- `com.thingclips.bouncycastle.math.ec.FixedPointPreCompInfo`
- `com.thingclips.bouncycastle.math.ec.FixedPointUtil`
- `com.thingclips.bouncycastle.math.ec.GLVMultiplier`
- `com.thingclips.bouncycastle.math.ec.LongArray`
- `com.thingclips.bouncycastle.math.ec.PreCompCallback`
- `com.thingclips.bouncycastle.math.ec.PreCompInfo`
- `com.thingclips.bouncycastle.math.ec.ScaleXPointMap`
- `com.thingclips.bouncycastle.math.ec.ScaleYPointMap`
- `com.thingclips.bouncycastle.math.ec.SimpleBigDecimal`
- `com.thingclips.bouncycastle.math.ec.Tnaf`
- `com.thingclips.bouncycastle.math.ec.ValidityPrecompInfo`
- `com.thingclips.bouncycastle.math.ec.WNafL2RMultiplier`
- `com.thingclips.bouncycastle.math.ec.WNafPreCompInfo`
- `com.thingclips.bouncycastle.math.ec.WNafUtil`
- `com.thingclips.bouncycastle.math.ec.WTauNafMultiplier`
- `com.thingclips.bouncycastle.math.ec.WTauNafPreCompInfo`
- `com.thingclips.bouncycastle.math.ec.ZTauElement`

### com.thingclips.bouncycastle.math.ec.custom.djb

- `com.thingclips.bouncycastle.math.ec.custom.djb.Curve25519`
- `com.thingclips.bouncycastle.math.ec.custom.djb.Curve25519Field`
- `com.thingclips.bouncycastle.math.ec.custom.djb.Curve25519FieldElement`
- `com.thingclips.bouncycastle.math.ec.custom.djb.Curve25519Point`

### com.thingclips.bouncycastle.math.ec.custom.sec

- `com.thingclips.bouncycastle.math.ec.custom.sec.SecP256R1Curve`
- `com.thingclips.bouncycastle.math.ec.custom.sec.SecP256R1Field`
- `com.thingclips.bouncycastle.math.ec.custom.sec.SecP256R1FieldElement`
- `com.thingclips.bouncycastle.math.ec.custom.sec.SecP256R1Point`

### com.thingclips.bouncycastle.math.ec.endo

- `com.thingclips.bouncycastle.math.ec.endo.ECEndomorphism`
- `com.thingclips.bouncycastle.math.ec.endo.EndoPreCompInfo`
- `com.thingclips.bouncycastle.math.ec.endo.EndoUtil`
- `com.thingclips.bouncycastle.math.ec.endo.GLVEndomorphism`
- `com.thingclips.bouncycastle.math.ec.endo.ScalarSplitParameters`

### com.thingclips.bouncycastle.math.ec.rfc7748

- `com.thingclips.bouncycastle.math.ec.rfc7748.X25519`
- `com.thingclips.bouncycastle.math.ec.rfc7748.X25519Field`
- `com.thingclips.bouncycastle.math.ec.rfc7748.X448`
- `com.thingclips.bouncycastle.math.ec.rfc7748.X448Field`

### com.thingclips.bouncycastle.math.ec.rfc8032

- `com.thingclips.bouncycastle.math.ec.rfc8032.Ed25519`
- `com.thingclips.bouncycastle.math.ec.rfc8032.Ed448`

### com.thingclips.bouncycastle.math.field

- `com.thingclips.bouncycastle.math.field.ExtensionField`
- `com.thingclips.bouncycastle.math.field.FiniteField`
- `com.thingclips.bouncycastle.math.field.FiniteFields`
- `com.thingclips.bouncycastle.math.field.GF2Polynomial`
- `com.thingclips.bouncycastle.math.field.GenericPolynomialExtensionField`
- `com.thingclips.bouncycastle.math.field.Polynomial`
- `com.thingclips.bouncycastle.math.field.PolynomialExtensionField`
- `com.thingclips.bouncycastle.math.field.PrimeField`

### com.thingclips.bouncycastle.math.raw

- `com.thingclips.bouncycastle.math.raw.Bits`
- `com.thingclips.bouncycastle.math.raw.Interleave`
- `com.thingclips.bouncycastle.math.raw.Mod`
- `com.thingclips.bouncycastle.math.raw.Nat`
- `com.thingclips.bouncycastle.math.raw.Nat256`

### com.thingclips.bouncycastle.operator

- `com.thingclips.bouncycastle.operator.ContentSigner`
- `com.thingclips.bouncycastle.operator.ContentVerifier`
- `com.thingclips.bouncycastle.operator.ContentVerifierProvider`
- `com.thingclips.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder`
- `com.thingclips.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder`
- `com.thingclips.bouncycastle.operator.DigestAlgorithmIdentifierFinder`
- `com.thingclips.bouncycastle.operator.DigestCalculator`
- `com.thingclips.bouncycastle.operator.DigestCalculatorProvider`
- `com.thingclips.bouncycastle.operator.OperatorCreationException`
- `com.thingclips.bouncycastle.operator.OperatorException`
- `com.thingclips.bouncycastle.operator.RuntimeOperatorException`
- `com.thingclips.bouncycastle.operator.SignatureAlgorithmIdentifierFinder`

### com.thingclips.bouncycastle.operator.jcajce

- `com.thingclips.bouncycastle.operator.jcajce.JcaContentSignerBuilder`
- `com.thingclips.bouncycastle.operator.jcajce.OperatorHelper`

### com.thingclips.bouncycastle.pkcs

- `com.thingclips.bouncycastle.pkcs.PKCS10CertificationRequest`
- `com.thingclips.bouncycastle.pkcs.PKCS10CertificationRequestBuilder`
- `com.thingclips.bouncycastle.pkcs.PKCSException`
- `com.thingclips.bouncycastle.pkcs.PKCSIOException`

### com.thingclips.bouncycastle.pkcs.jcajce

- `com.thingclips.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder`

### com.thingclips.bouncycastle.util

- `com.thingclips.bouncycastle.util.Arrays`
- `com.thingclips.bouncycastle.util.BigIntegers`
- `com.thingclips.bouncycastle.util.Encodable`
- `com.thingclips.bouncycastle.util.Fingerprint`
- `com.thingclips.bouncycastle.util.IPAddress`
- `com.thingclips.bouncycastle.util.Integers`
- `com.thingclips.bouncycastle.util.Iterable`
- `com.thingclips.bouncycastle.util.Memoable`
- `com.thingclips.bouncycastle.util.MemoableResetException`
- `com.thingclips.bouncycastle.util.Objects`
- `com.thingclips.bouncycastle.util.Pack`
- `com.thingclips.bouncycastle.util.Properties`
- `com.thingclips.bouncycastle.util.Selector`
- `com.thingclips.bouncycastle.util.StringList`
- `com.thingclips.bouncycastle.util.Strings`

### com.thingclips.bouncycastle.util.encoders

- `com.thingclips.bouncycastle.util.encoders.Base64`
- `com.thingclips.bouncycastle.util.encoders.Base64Encoder`
- `com.thingclips.bouncycastle.util.encoders.DecoderException`
- `com.thingclips.bouncycastle.util.encoders.Encoder`
- `com.thingclips.bouncycastle.util.encoders.EncoderException`
- `com.thingclips.bouncycastle.util.encoders.Hex`
- `com.thingclips.bouncycastle.util.encoders.HexEncoder`
- `com.thingclips.bouncycastle.util.encoders.UTF8`

### com.thingclips.bouncycastle.util.io

- `com.thingclips.bouncycastle.util.io.StreamOverflowException`
- `com.thingclips.bouncycastle.util.io.Streams`
- `com.thingclips.bouncycastle.util.io.TeeInputStream`
- `com.thingclips.bouncycastle.util.io.TeeOutputStream`

### com.thingclips.bouncycastle.util.io.pem

- `com.thingclips.bouncycastle.util.io.pem.PemGenerationException`
- `com.thingclips.bouncycastle.util.io.pem.PemHeader`
- `com.thingclips.bouncycastle.util.io.pem.PemObject`
- `com.thingclips.bouncycastle.util.io.pem.PemObjectGenerator`
- `com.thingclips.bouncycastle.util.io.pem.PemWriter`

### com.thingclips.crypto

- `com.thingclips.crypto.Manufacture`

### com.thingclips.drawee.view

- `com.thingclips.drawee.view.DecryptImageView`

### com.thingclips.imagepipeline.okhttp3

- `com.thingclips.imagepipeline.okhttp3.ChaCha20`
- `com.thingclips.imagepipeline.okhttp3.ChaCha20InputStream`
- `com.thingclips.imagepipeline.okhttp3.DecryptFilter`
- `com.thingclips.imagepipeline.okhttp3.DecryptImageRequest`
- `com.thingclips.imagepipeline.okhttp3.OkHttpImagePipelineConfigFactory`
- `com.thingclips.imagepipeline.okhttp3.OkHttpNetworkFetcher`

### com.thingclips.libalgorithm

- `com.thingclips.libalgorithm.BuildConfig`
- `com.thingclips.libalgorithm.C0195R`

### com.thingclips.scene.core

- `com.thingclips.scene.core.BuildConfig`
- `com.thingclips.scene.core.C0196R`
- `com.thingclips.scene.core.ContainerHolder`
- `com.thingclips.scene.core.DefaultImpls`
- `com.thingclips.scene.core.ISceneBizContainer`
- `com.thingclips.scene.core.ISceneBizContainerKt`
- `com.thingclips.scene.core.ISceneContext`
- `com.thingclips.scene.core.ISceneHomeBizContainer`
- `com.thingclips.scene.core.Options`
- `com.thingclips.scene.core.ThingSceneContext`

### com.thingclips.scene.core.bean

- `com.thingclips.scene.core.bean.ActionBase`
- `com.thingclips.scene.core.bean.ConditionBase`
- `com.thingclips.scene.core.bean.LinkageRuleBase`
- `com.thingclips.scene.core.bean.PreConditionBase`
- `com.thingclips.scene.core.bean.ScopesAction`
- `com.thingclips.scene.core.bean.ScopesCondition`
- `com.thingclips.scene.core.bean.ScopesLinkageRule`
- `com.thingclips.scene.core.bean.ScopesPreCondition`

### com.thingclips.scene.core.execute

- `com.thingclips.scene.core.execute.PlugSceneExecute`

### com.thingclips.scene.core.execute.p009interface

- `com.thingclips.scene.core.execute.p009interface.ISceneExecute`

*(... and 108 more packages)*

</details>
