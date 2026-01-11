# DEX Analysis: classes5.dex


**File Size**: 2.7 MB
**Total Classes**: 1,114
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
| Total Classes | 1,114 |
| Total Methods | 15,111 |
| Total Fields | 65,249 |
| Total Packages | 182 |
| BLE-Related Classes | 624 |
| UUIDs Found | 14 |
| BLE Write Operations | 2 |
| Command Sequences | 0 |

## BLE-Related Classes

Found 624 BLE-related classes:

### MatterConnectCallback [CRITICAL]


- **Full Name**: `com.thingclips.sdk.matter.api.MatterConnectCallback`
- **Package**: `com.thingclips.sdk.matter.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\matter\api\MatterConnectCallback.java`

**Key Methods**:
  - `invokeOnCancellation()`
  - `resume()`

---

### bppdpdq [CRITICAL]


- **Full Name**: `com.thingclips.sdk.matter.discover.bppdpdq`
- **Package**: `com.thingclips.sdk.matter.discover`
- **Extends**: `BluetoothGattCallback`
- **Implements**: `BleCallback`
- **Methods**: 49
- **Fields**: 55
- **Source**: `sdk\matter\discover\BluetoothHelper.java`

**Key Methods**:
  - `Handler()`
  - `bppdpdq()`
  - `onCharacteristicChanged()`
  - `onCharacteristicRead()`
  - `onCharacteristicWrite()`
  - `onConnectionStateChange()`
  - `StringBuilder()`
  - `onDescriptorRead()`
  - `onDescriptorWrite()`
  - `onMtuChanged()`
  - *(... and 39 more)*

**Notable Strings**:
  - `"thing_matter BluetoothManager"`
  - `"thing_matter BluetoothManager"`
  - `"thing_matter BluetoothManager"`
  - `"thing_matter BluetoothManager"`
  - `"thing_matter BluetoothManager"`
  - *(... and 49 more)*

---

### bdpdqbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.matter.discover.ble.bdpdqbp`
- **Package**: `com.thingclips.sdk.matter.discover.ble`
- **Implements**: `MatterConnectCallback`
- **Methods**: 25
- **Fields**: 27
- **Source**: `matter\discover\ble\BleServiceConnectManager.java`

**Key Methods**:
  - `bdpdqbp()`
  - `invokeOnCancellation()`
  - `resume()`
  - `UuidInfo()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `pdqppqb()`
  - `invokeOnCancellation()`
  - `resume()`
  - *(... and 15 more)*

**Notable Strings**:
  - `"BluetoothGatt invoke on cancellation"`
  - `"[dealWithScanResult ] Bluetooth device connect success"`
  - `"BluetoothGatt invoke on cancellation"`
  - `"[dealWithAutoScanResult ] Bluetooth device connect success"`
  - `"parse thing uuid error："`
  - *(... and 1 more)*

---

### bdpdqbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.matter.presenter.connect.bdpdqbp`
- **Package**: `com.thingclips.sdk.matter.presenter.connect`
- **Implements**: `IDeviceMqttProtocolListener<MQ_1_ConnectStatusChangeBean>`
- **Methods**: 9
- **Fields**: 15
- **Source**: `matter\presenter\connect\GatewayOnlineStatusMonitor.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `bdpdqbp()`
  - `onResult()`
  - `StringBuilder()`
  - `bdpdqbp()`
  - `dealWithSubDeviceConnection()`
  - `addToMonitor()`
  - `clear()`
  - `removeGateway()`

**Notable Strings**:
  - `"sub matter device MQTT online, meshId: "`

---

### dqqbdqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.matterlib.dqqbdqb`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `IMatterDiscoveryActivator, dqdbbqp`
- **Methods**: 31
- **Fields**: 36
- **Source**: `thingclips\sdk\matterlib\dqqbdqb.java`

**Key Methods**:
  - `CopyOnWriteArraySet()`
  - `CopyOnWriteArraySet()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `pdqppqb()`
  - `onSuccess()`
  - `onError()`
  - `dqqbdqb()`
  - `bdpdqbp()`
  - *(... and 21 more)*

**Notable Strings**:
  - `"uuid"`

---

### pdqppqb [CRITICAL]


- **Full Name**: `com.thingclips.sdk.matterlib.pdqppqb`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `pqdqqbd`
- **Methods**: 31
- **Fields**: 63
- **Source**: `thingclips\sdk\matterlib\pdqppqb.java`

**Key Methods**:
  - `ArrayList()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `onCommandSuccess()`
  - `onError()`
  - `addConnection()`
  - `bdpdqbp()`
  - `getCallback()`
  - `getConnection()`
  - `hasFlag()`
  - *(... and 21 more)*

---

### pppbppp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.matterlib.pppbppp`
- **Package**: `com.thingclips.sdk.matterlib`
- **Extends**: `ChipDeviceController`
- **Methods**: 57
- **Fields**: 7
- **Source**: `thingclips\sdk\matterlib\pppbppp.java`

**Key Methods**:
  - `pppbppp()`
  - `cleanSession()`
  - `close()`
  - `commissionDevice()`
  - `StringBuilder()`
  - `computePaseVerifier()`
  - `continueCommissioning()`
  - `StringBuilder()`
  - `convertX509CertToMatterCert()`
  - `discoverCommissionableNodes()`
  - *(... and 47 more)*

---

### ThingOSMesh [CRITICAL]


- **Full Name**: `com.thingclips.sdk.p000os.ThingOSMesh`
- **Package**: `com.thingclips.sdk.p000os`
- **Extends**: `IMeshCommonControl>`
- **Methods**: 20
- **Fields**: 23
- **Source**: `thingclips\sdk\p000os\ThingOSMesh.java`

**Key Methods**:
  - `activator()`
  - `createMeshAdvPreControl()`
  - `bddddpp()`
  - `createSigMeshPreControl()`
  - `pppqpdb()`
  - `getMeshControl()`
  - `getMeshDataAnalysis()`
  - `pdqpqbb()`
  - `getMeshManager()`
  - `getSigMeshControl()`
  - *(... and 10 more)*

---

### ThingOSTyMesh [CRITICAL]


- **Full Name**: `com.thingclips.sdk.p000os.ThingOSTyMesh`
- **Package**: `com.thingclips.sdk.p000os`
- **Methods**: 3
- **Fields**: 6
- **Source**: `thingclips\sdk\p000os\ThingOSTyMesh.java`

**Key Methods**:
  - `getThingBlueMeshClient()`
  - `newDevice()`
  - `newGroup()`

---

### pbpdbqp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.scenelib.pbpdbqp`
- **Package**: `com.thingclips.sdk.scenelib`
- **Extends**: `BaseModel`
- **Implements**: `Business.ResultListener<ArrayList<SceneIdBean>>`
- **Methods**: 13
- **Fields**: 18
- **Source**: `thingclips\sdk\scenelib\pbpdbqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `StringBuilder()`
  - `onSuccess()`
  - `pbpdbqp()`
  - `pdqppqb()`
  - `onDestroy()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `ArrayList()`
  - *(... and 3 more)*

**Notable Strings**:
  - `"meshIds start:"`
  - `"meshIds filter:"`

---

### Features [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.Features`
- **Package**: `com.thingclips.sdk.sigmesh`
- **Implements**: `Parcelable`
- **Methods**: 20
- **Fields**: 8
- **Source**: `thingclips\sdk\sigmesh\Features.java`

**Key Methods**:
  - `bdpdqbp()`
  - `createFromParcel()`
  - `Features()`
  - `newArray()`
  - `describeContents()`
  - `getFriend()`
  - `getLowPower()`
  - `getProxy()`
  - `getRelay()`
  - `isFriendFeatureSupported()`
  - *(... and 10 more)*

---

### AccessMessage [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.AccessMessage`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Extends**: `Message`
- **Methods**: 8
- **Fields**: 3
- **Source**: `sdk\sigmesh\bean\AccessMessage.java`

**Key Methods**:
  - `AccessMessage()`
  - `getAccessPdu()`
  - `getCtl()`
  - `getLowerTransportAccessPdu()`
  - `getUpperTransportPdu()`
  - `setAccessPdu()`
  - `setLowerTransportAccessPdu()`
  - `setUpperTransportPdu()`

---

### CommandPackage [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.CommandPackage`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Methods**: 0
- **Fields**: 6
- **Source**: `sdk\sigmesh\bean\CommandPackage.java`

---

### ControlMessage [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.ControlMessage`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Extends**: `Message`
- **Methods**: 8
- **Fields**: 3
- **Source**: `sdk\sigmesh\bean\ControlMessage.java`

**Key Methods**:
  - `ControlMessage()`
  - `getCtl()`
  - `getLowerTransportControlPdu()`
  - `getTransportControlMessage()`
  - `getTransportControlPdu()`
  - `setLowerTransportControlPdu()`
  - `setTransportControlMessage()`
  - `setTransportControlPdu()`

---

### DeviceInfoRep [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.DeviceInfoRep`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Extends**: `Reps`
- **Methods**: 2
- **Fields**: 13
- **Source**: `sdk\sigmesh\bean\DeviceInfoRep.java`

**Key Methods**:
  - `version()`
  - `parseRep()`

---

### DpCommandBean [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.DpCommandBean`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Methods**: 8
- **Fields**: 4
- **Source**: `sdk\sigmesh\bean\DpCommandBean.java`

**Key Methods**:
  - `getDpId()`
  - `getDpType()`
  - `getDpValue()`
  - `setDpId()`
  - `setDpType()`
  - `setDpValue()`
  - `toString()`
  - `StringBuilder()`

---

### MeshTransferBean [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.MeshTransferBean`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Methods**: 13
- **Fields**: 10
- **Source**: `sdk\sigmesh\bean\MeshTransferBean.java`

**Key Methods**:
  - `getIvIndex()`
  - `getMeshTransport()`
  - `pbdpddb()`
  - `getMtuSize()`
  - `getProvisionedMeshNode()`
  - `getProvisionerAddress()`
  - `increaseAndGetSeqNumber()`
  - `setAppkey()`
  - `setIvIndex()`
  - `setMtuSize()`
  - *(... and 3 more)*

---

### Message [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.Message`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Methods**: 37
- **Fields**: 19
- **Source**: `sdk\sigmesh\bean\Message.java`

**Key Methods**:
  - `getAid()`
  - `getAkf()`
  - `getAszmic()`
  - `getCompanyIdentifier()`
  - `getCtl()`
  - `getDst()`
  - `getEncryptionKey()`
  - `getIvIndex()`
  - `getKey()`
  - `getNetKey()`
  - *(... and 27 more)*

---

### ModelBindBean [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.ModelBindBean`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Methods**: 7
- **Fields**: 3
- **Source**: `sdk\sigmesh\bean\ModelBindBean.java`

**Key Methods**:
  - `ModelBindBean()`
  - `getMeshAddress()`
  - `getMeshModel()`
  - `getModelId()`
  - `setMeshAddress()`
  - `setMeshModel()`
  - `setModelId()`

---

### NetworkKey [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.NetworkKey`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Implements**: `Parcelable`
- **Methods**: 23
- **Fields**: 12
- **Source**: `sdk\sigmesh\bean\NetworkKey.java`

**Key Methods**:
  - `createFromParcel()`
  - `NetworkKey()`
  - `newArray()`
  - `NetworkKey()`
  - `describeContents()`
  - `getKey()`
  - `getKeyIndex()`
  - `getMeshUuid()`
  - `getName()`
  - `getOldKey()`
  - *(... and 13 more)*

---

### OTAFileRep [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.OTAFileRep`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 8
- **Source**: `sdk\sigmesh\bean\OTAFileRep.java`

**Key Methods**:
  - `parseRep()`

---

### OTAOffsetRep [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.OTAOffsetRep`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 3
- **Source**: `sdk\sigmesh\bean\OTAOffsetRep.java`

**Key Methods**:
  - `parseRep()`

---

### OTAResultRep [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.OTAResultRep`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 4
- **Source**: `sdk\sigmesh\bean\OTAResultRep.java`

**Key Methods**:
  - `parseRep()`

---

### OTASendRep [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.OTASendRep`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 4
- **Source**: `sdk\sigmesh\bean\OTASendRep.java`

**Key Methods**:
  - `parseRep()`

---

### OTAStartRep [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.OTAStartRep`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Extends**: `Reps`
- **Methods**: 1
- **Fields**: 9
- **Source**: `sdk\sigmesh\bean\OTAStartRep.java`

**Key Methods**:
  - `parseRep()`

---

### ProvisionedBaseMeshNode [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.ProvisionedBaseMeshNode`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Implements**: `Parcelable`
- **Methods**: 43
- **Fields**: 47
- **Source**: `sdk\sigmesh\bean\ProvisionedBaseMeshNode.java`

**Key Methods**:
  - `ArrayList()`
  - `LinkedHashMap()`
  - `ArrayList()`
  - `ArrayList()`
  - `LinkedHashMap()`
  - `SparseIntArrayParcelable()`
  - `getAddedAppKeyIndexes()`
  - `getConfigurationSrc()`
  - `getFlags()`
  - `getIdentityKey()`
  - *(... and 33 more)*

**Notable Strings**:
  - `"ProvisionedBaseMeshNode"`

---

### ProvisionedMeshNode [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.ProvisionedMeshNode`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Extends**: `ProvisionedBaseMeshNode`
- **Methods**: 65
- **Fields**: 9
- **Source**: `sdk\sigmesh\bean\ProvisionedMeshNode.java`

**Key Methods**:
  - `createFromParcel()`
  - `ProvisionedMeshNode()`
  - `newArray()`
  - `ProvisionedMeshNode()`
  - `createDefaultMeshNode()`
  - `ProvisionedMeshNode()`
  - `NetworkKey()`
  - `ApplicationKey()`
  - `getFeatureState()`
  - `describeContents()`
  - *(... and 55 more)*

---

### ProvisioningCapabilities [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.ProvisioningCapabilities`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Implements**: `Parcelable`
- **Methods**: 25
- **Fields**: 10
- **Source**: `sdk\sigmesh\bean\ProvisioningCapabilities.java`

**Key Methods**:
  - `createFromParcel()`
  - `ProvisioningCapabilities()`
  - `newArray()`
  - `ProvisioningCapabilities()`
  - `describeContents()`
  - `getInputOOBAction()`
  - `getInputOOBSize()`
  - `getNumberOfElements()`
  - `getOutputOOBAction()`
  - `getOutputOOBSize()`
  - *(... and 15 more)*

---

### Reps [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.Reps`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Methods**: 4
- **Fields**: 1
- **Source**: `sdk\sigmesh\bean\Reps.java`

**Key Methods**:
  - `parseRep()`
  - `success()`
  - `toString()`
  - `getClass()`

---

### Ret [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.Ret`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Methods**: 14
- **Fields**: 34
- **Source**: `sdk\sigmesh\bean\Ret.java`

**Key Methods**:
  - `Reps()`
  - `dataParse()`
  - `StringBuilder()`
  - `DeviceInfoRep()`
  - `OTAStartRep()`
  - `OTAFileRep()`
  - `OTAOffsetRep()`
  - `if()`
  - `OTASendRep()`
  - `if()`
  - *(... and 4 more)*

---

### ScanRecord [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.ScanRecord`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Methods**: 30
- **Fields**: 53
- **Source**: `sdk\sigmesh\bean\ScanRecord.java`

**Key Methods**:
  - `ScanRecord()`
  - `extractBytes()`
  - `parseFromBytes()`
  - `ArrayList()`
  - `SparseArray()`
  - `HashMap()`
  - `ScanRecord()`
  - `if()`
  - `String()`
  - `ScanRecord()`
  - *(... and 20 more)*

**Notable Strings**:
  - `"uuidBytes cannot be null"`
  - `"uuidBytes length invalid - "`
  - `", mServiceUuids="`

---

### SecureNetworkBeacon [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.SecureNetworkBeacon`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Extends**: `MeshBeacon`
- **Methods**: 12
- **Fields**: 10
- **Source**: `sdk\sigmesh\bean\SecureNetworkBeacon.java`

**Key Methods**:
  - `createFromParcel()`
  - `SecureNetworkBeacon()`
  - `newArray()`
  - `SecureNetworkBeacon()`
  - `IllegalArgumentException()`
  - `describeContents()`
  - `getAuthenticationValue()`
  - `getBeaconType()`
  - `getFlags()`
  - `getIvIndex()`
  - *(... and 2 more)*

---

### SigConfigBean [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.SigConfigBean`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Methods**: 4
- **Fields**: 6
- **Source**: `sdk\sigmesh\bean\SigConfigBean.java`

**Key Methods**:
  - `isCanRetry()`
  - `isCanRetryNotify()`
  - `setStatus()`
  - `setStep()`

---

### ThingSigMeshBean [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.ThingSigMeshBean`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Extends**: `SigMeshBean`
- **Methods**: 11
- **Fields**: 4
- **Source**: `sdk\sigmesh\bean\ThingSigMeshBean.java`

**Key Methods**:
  - `ThingSigMeshBean()`
  - `getMacAdress()`
  - `getProvisionedMeshNode()`
  - `getStatus()`
  - `getWireProvisionedMeshNode()`
  - `setMacAdress()`
  - `setProvisionedMeshNode()`
  - `setStatus()`
  - `setThingSigmeshBeanData()`
  - `setWireProvisionedMeshNode()`
  - *(... and 1 more)*

---

### UnprovisionedBaseMeshNode [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.UnprovisionedBaseMeshNode`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Implements**: `Parcelable`
- **Methods**: 28
- **Fields**: 29
- **Source**: `sdk\sigmesh\bean\UnprovisionedBaseMeshNode.java`

**Key Methods**:
  - `UnprovisionedBaseMeshNode()`
  - `describeContents()`
  - `getConfigurationSrc()`
  - `getDeviceKey()`
  - `getDeviceUuid()`
  - `getFlags()`
  - `getIdentityKey()`
  - `getIvIndex()`
  - `getKeyIndex()`
  - `getNodeName()`
  - *(... and 18 more)*

**Notable Strings**:
  - `"UnprovisionedBaseMeshNode"`

---

### UnprovisionedBeacon [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.UnprovisionedBeacon`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Extends**: `MeshBeacon`
- **Methods**: 12
- **Fields**: 10
- **Source**: `sdk\sigmesh\bean\UnprovisionedBeacon.java`

**Key Methods**:
  - `createFromParcel()`
  - `UnprovisionedBeacon()`
  - `newArray()`
  - `UnprovisionedBeacon()`
  - `IllegalArgumentException()`
  - `UUID()`
  - `describeContents()`
  - `getBeaconType()`
  - `getOobInformation()`
  - `getUriHash()`
  - *(... and 2 more)*

---

### UnprovisionedMeshNode [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.bean.UnprovisionedMeshNode`
- **Package**: `com.thingclips.sdk.sigmesh.bean`
- **Extends**: `UnprovisionedBaseMeshNode`
- **Methods**: 46
- **Fields**: 2
- **Source**: `sdk\sigmesh\bean\UnprovisionedMeshNode.java`

**Key Methods**:
  - `createFromParcel()`
  - `UnprovisionedMeshNode()`
  - `newArray()`
  - `UnprovisionedMeshNode()`
  - `describeContents()`
  - `getAuthenticationValue()`
  - `getDeviceKey()`
  - `getDeviceUuid()`
  - `getFlags()`
  - `getIvIndex()`
  - *(... and 36 more)*

---

### bdpdqbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.control.bdpdqbp`
- **Package**: `com.thingclips.sdk.sigmesh.control`
- **Extends**: `TransportControlMessage`
- **Methods**: 5
- **Fields**: 20
- **Source**: `sdk\sigmesh\control\bdpdqbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### TransportControlMessage [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.control.TransportControlMessage`
- **Package**: `com.thingclips.sdk.sigmesh.control`
- **Methods**: 2
- **Fields**: 2
- **Source**: `sdk\sigmesh\control\TransportControlMessage.java`

**Key Methods**:
  - `getState()`
  - `bdpdqbp()`

---

### bdpdqbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.manager.bdpdqbp`
- **Package**: `com.thingclips.sdk.sigmesh.manager`
- **Implements**: `IResultCallback`
- **Methods**: 16
- **Fields**: 24
- **Source**: `sdk\sigmesh\manager\ThingSigMeshTimeManager.java`

**Key Methods**:
  - `HashMap()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - `syncDSTTimeToSigMeshDevice()`
  - `dpddbbb()`
  - `ArrayList()`
  - *(... and 6 more)*

**Notable Strings**:
  - `"ThingSigMeshTimeManager"`
  - `"syncTimeToSigMeshDevice onError "`
  - `"syncTimeToSigMeshDevice  onSuccess"`
  - `"syncDSTTimeToSigMeshDevice onError "`
  - `"syncDSTTimeToSigMeshDevice  onSuccess"`
  - *(... and 2 more)*

---

### SigModel [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.model.SigModel`
- **Package**: `com.thingclips.sdk.sigmesh.model`
- **Extends**: `MeshModel`
- **Implements**: `Parcelable`
- **Methods**: 3
- **Fields**: 1
- **Source**: `sdk\sigmesh\model\SigModel.java`

**Key Methods**:
  - `SigModel()`
  - `getModelId()`
  - `SigModel()`

---

### VendorModel [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.model.VendorModel`
- **Package**: `com.thingclips.sdk.sigmesh.model`
- **Extends**: `MeshModel`
- **Implements**: `Parcelable.Creator<VendorModel>`
- **Methods**: 12
- **Fields**: 9
- **Source**: `sdk\sigmesh\model\VendorModel.java`

**Key Methods**:
  - `bdpdqbp()`
  - `createFromParcel()`
  - `VendorModel()`
  - `newArray()`
  - `describeContents()`
  - `getCompanyIdentifier()`
  - `getCompanyName()`
  - `getModelId()`
  - `getModelName()`
  - `writeToParcel()`
  - *(... and 2 more)*

---

### bdpdqbp [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.parse.bdpdqbp`
- **Package**: `com.thingclips.sdk.sigmesh.parse`
- **Extends**: `ThingSigMeshParser`
- **Methods**: 56
- **Fields**: 99
- **Source**: `sdk\sigmesh\parse\bdpdqbp.java`

**Key Methods**:
  - `C0198bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `qdqqbqb()`
  - `ppqpqbb()`
  - `pdqppqb()`
  - `ArrayList()`
  - `C0198bdpdqbp()`
  - `ArrayList()`
  - *(... and 46 more)*

---

### ThingSigMeshParser [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.parse.ThingSigMeshParser`
- **Package**: `com.thingclips.sdk.sigmesh.parse`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Implements**: `qqbdbbb`
- **Methods**: 49
- **Fields**: 84
- **Source**: `sdk\sigmesh\parse\ThingSigMeshParser.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `HashMap()`
  - `HashMap()`
  - `bdpdqbp()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `ArrayList()`
  - `pdqppqb()`
  - *(... and 39 more)*

**Notable Strings**:
  - `"ThingSigMeshParser"`
  - `" meshId:"`

---

### ConfigAppKeyStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.ConfigAppKeyStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `ConfigStatusMessage`
- **Implements**: `Parcelable`
- **Methods**: 13
- **Fields**: 16
- **Source**: `sdk\sigmesh\provisioner\ConfigAppKeyStatus.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ConfigAppKeyStatus()`
  - `describeContents()`
  - `getAppKeyIndex()`
  - `getNetKeyIndex()`
  - `getOpCode()`
  - `isSuccessful()`
  - `parseStatusParameters()`
  - `StringBuilder()`
  - `writeToParcel()`
  - *(... and 3 more)*

---

### ConfigCompositionDataStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.ConfigCompositionDataStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `ConfigStatusMessage`
- **Implements**: `Parcelable`
- **Methods**: 30
- **Fields**: 41
- **Source**: `sdk\sigmesh\provisioner\ConfigCompositionDataStatus.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ConfigCompositionDataStatus()`
  - `LinkedHashMap()`
  - `parseCompanyIdentifier()`
  - `parseCompositionDataPages()`
  - `parseCrpl()`
  - `parseElements()`
  - `LinkedHashMap()`
  - `VendorModel()`
  - `Element()`
  - *(... and 20 more)*

---

### ConfigModelAppStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.ConfigModelAppStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `ConfigStatusMessage`
- **Implements**: `Parcelable`
- **Methods**: 14
- **Fields**: 22
- **Source**: `sdk\sigmesh\provisioner\ConfigModelAppStatus.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ConfigModelAppStatus()`
  - `describeContents()`
  - `getAppKeyIndex()`
  - `getElementAddress()`
  - `getModelIdentifier()`
  - `getOpCode()`
  - `isSuccessful()`
  - `parseStatusParameters()`
  - `StringBuilder()`
  - *(... and 4 more)*

---

### ConfigModelPublicationStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.ConfigModelPublicationStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `ConfigStatusMessage`
- **Implements**: `Parcelable`
- **Methods**: 20
- **Fields**: 32
- **Source**: `sdk\sigmesh\provisioner\ConfigModelPublicationStatus.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ConfigModelPublicationStatus()`
  - `describeContents()`
  - `getAppKeyIndex()`
  - `getCredentialFlag()`
  - `getElementAddress()`
  - `getModelIdentifier()`
  - `getOpCode()`
  - `getPublicationResolution()`
  - `getPublicationSteps()`
  - *(... and 10 more)*

---

### ConfigModelSubscriptionStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.ConfigModelSubscriptionStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `ConfigStatusMessage`
- **Implements**: `Parcelable`
- **Methods**: 14
- **Fields**: 19
- **Source**: `sdk\sigmesh\provisioner\ConfigModelSubscriptionStatus.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ConfigModelSubscriptionStatus()`
  - `describeContents()`
  - `getElementAddress()`
  - `getModelIdentifier()`
  - `getOpCode()`
  - `getSubscriptionAddress()`
  - `isSuccessful()`
  - `parseStatusParameters()`
  - `StringBuilder()`
  - *(... and 4 more)*

---

### ConfigNetworkTransmitStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.ConfigNetworkTransmitStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `ConfigStatusMessage`
- **Implements**: `Parcelable`
- **Methods**: 11
- **Fields**: 7
- **Source**: `sdk\sigmesh\provisioner\ConfigNetworkTransmitStatus.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ConfigNetworkTransmitStatus()`
  - `describeContents()`
  - `getNetworkTransmitCount()`
  - `getNetworkTransmitIntervalSteps()`
  - `getOpCode()`
  - `parseStatusParameters()`
  - `writeToParcel()`
  - `createFromParcel()`
  - `ConfigNetworkTransmitStatus()`
  - *(... and 1 more)*

---

### ConfigNodeResetStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.ConfigNodeResetStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `ConfigStatusMessage`
- **Implements**: `Parcelable`
- **Methods**: 9
- **Fields**: 4
- **Source**: `sdk\sigmesh\provisioner\ConfigNodeResetStatus.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ConfigNodeResetStatus()`
  - `describeContents()`
  - `getOpCode()`
  - `parseStatusParameters()`
  - `writeToParcel()`
  - `createFromParcel()`
  - `ConfigNodeResetStatus()`
  - `newArray()`

---

### FittingsStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.FittingsStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `VendorModelMessageStatus`
- **Implements**: `Parcelable`
- **Methods**: 9
- **Fields**: 13
- **Source**: `sdk\sigmesh\provisioner\FittingsStatus.java`

**Key Methods**:
  - `FittingsStatus()`
  - `getGroupId()`
  - `getMac()`
  - `getOpCode()`
  - `getOpt()`
  - `getS1()`
  - `isSuccess()`
  - `parseStatusParameters()`
  - `if()`

---

### GenericOnOffStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.GenericOnOffStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `bqdqqqp`
- **Implements**: `Parcelable`
- **Methods**: 13
- **Fields**: 16
- **Source**: `sdk\sigmesh\provisioner\GenericOnOffStatus.java`

**Key Methods**:
  - `bdpdqbp()`
  - `GenericOnOffStatus()`
  - `describeContents()`
  - `getOpCode()`
  - `getPresentState()`
  - `getTargetState()`
  - `getTransitionResolution()`
  - `getTransitionSteps()`
  - `parseStatusParameters()`
  - `writeToParcel()`
  - *(... and 3 more)*

---

### GroupDeviceGetStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.GroupDeviceGetStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `VendorModelMessageStatus`
- **Implements**: `Parcelable`
- **Methods**: 6
- **Fields**: 8
- **Source**: `sdk\sigmesh\provisioner\GroupDeviceGetStatus.java`

**Key Methods**:
  - `GroupDeviceGetStatus()`
  - `describeContents()`
  - `getGroupAddress()`
  - `getOpCode()`
  - `parseStatusParameters()`
  - `writeToParcel()`

---

### HeartBeatStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.HeartBeatStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `VendorModelMessageStatus`
- **Implements**: `Parcelable`
- **Methods**: 11
- **Fields**: 13
- **Source**: `sdk\sigmesh\provisioner\HeartBeatStatus.java`

**Key Methods**:
  - `HeartBeatStatus()`
  - `describeContents()`
  - `getCommandType()`
  - `getDpId()`
  - `getOpCode()`
  - `getReason()`
  - `isOnOffStatus()`
  - `parseStatusParameters()`
  - `setCommandType()`
  - `setReason()`
  - *(... and 1 more)*

---

### LightCtlStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.LightCtlStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `bqdqqqp`
- **Implements**: `Parcelable`
- **Methods**: 15
- **Fields**: 16
- **Source**: `sdk\sigmesh\provisioner\LightCtlStatus.java`

**Key Methods**:
  - `bdpdqbp()`
  - `LightCtlStatus()`
  - `describeContents()`
  - `getOpCode()`
  - `getPresentLightness()`
  - `getPresentTemperature()`
  - `getTargetLightness()`
  - `getTargetTemperature()`
  - `getTransitionResolution()`
  - `getTransitionSteps()`
  - *(... and 5 more)*

---

### LightCtlTemperatureStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.LightCtlTemperatureStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `bqdqqqp`
- **Implements**: `Parcelable`
- **Methods**: 13
- **Fields**: 15
- **Source**: `sdk\sigmesh\provisioner\LightCtlTemperatureStatus.java`

**Key Methods**:
  - `bdpdqbp()`
  - `LightCtlTemperatureStatus()`
  - `describeContents()`
  - `getOpCode()`
  - `getPresentTemperature()`
  - `getTargetTemperature()`
  - `getTransitionResolution()`
  - `getTransitionSteps()`
  - `parseStatusParameters()`
  - `writeToParcel()`
  - *(... and 3 more)*

---

### LightHslStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.LightHslStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `bqdqqqp`
- **Implements**: `Parcelable`
- **Methods**: 15
- **Fields**: 18
- **Source**: `sdk\sigmesh\provisioner\LightHslStatus.java`

**Key Methods**:
  - `bdpdqbp()`
  - `LightHslStatus()`
  - `describeContents()`
  - `getOpCode()`
  - `getPresentHue()`
  - `getPresentLightness()`
  - `getPresentSaturation()`
  - `getTransitionResolution()`
  - `getTransitionSteps()`
  - `parseStatusParameters()`
  - *(... and 5 more)*

---

### LightLightnessStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.LightLightnessStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `bqdqqqp`
- **Implements**: `Parcelable`
- **Methods**: 13
- **Fields**: 15
- **Source**: `sdk\sigmesh\provisioner\LightLightnessStatus.java`

**Key Methods**:
  - `bdpdqbp()`
  - `LightLightnessStatus()`
  - `describeContents()`
  - `getOpCode()`
  - `getPresentLightness()`
  - `getTargetLightness()`
  - `getTransitionResolution()`
  - `getTransitionSteps()`
  - `parseStatusParameters()`
  - `writeToParcel()`
  - *(... and 3 more)*

---

### LightModeStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.LightModeStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `VendorModelMessageStatus`
- **Implements**: `Parcelable`
- **Methods**: 11
- **Fields**: 6
- **Source**: `sdk\sigmesh\provisioner\LightModeStatus.java`

**Key Methods**:
  - `bdpdqbp()`
  - `LightModeStatus()`
  - `describeContents()`
  - `getMode()`
  - `getOpCode()`
  - `parseStatusParameters()`
  - `setMode()`
  - `writeToParcel()`
  - `createFromParcel()`
  - `LightModeStatus()`
  - *(... and 1 more)*

---

### ThingVendorModelStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.ThingVendorModelStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `VendorModelMessageStatus`
- **Implements**: `Parcelable`
- **Methods**: 12
- **Fields**: 26
- **Source**: `sdk\sigmesh\provisioner\ThingVendorModelStatus.java`

**Key Methods**:
  - `ThingVendorModelStatus()`
  - `getValueByType()`
  - `String()`
  - `if()`
  - `describeContents()`
  - `getDpList()`
  - `getOpCode()`
  - `getTypeStringByType()`
  - `getValueLengthByDpType()`
  - `parseStatusParameters()`
  - *(... and 2 more)*

---

### ThingVendorTidModelStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.ThingVendorTidModelStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `VendorModelMessageStatus`
- **Implements**: `Parcelable`
- **Methods**: 7
- **Fields**: 8
- **Source**: `sdk\sigmesh\provisioner\ThingVendorTidModelStatus.java`

**Key Methods**:
  - `ThingVendorTidModelStatus()`
  - `describeContents()`
  - `getOpCode()`
  - `getStatus()`
  - `getTid()`
  - `parseStatusParameters()`
  - `StringBuilder()`

---

### ThingVendorTidReportModelStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.ThingVendorTidReportModelStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `ThingVendorModelStatus`
- **Implements**: `Parcelable`
- **Methods**: 12
- **Fields**: 27
- **Source**: `sdk\sigmesh\provisioner\ThingVendorTidReportModelStatus.java`

**Key Methods**:
  - `ThingVendorTidReportModelStatus()`
  - `getValueByType()`
  - `String()`
  - `if()`
  - `describeContents()`
  - `getDpList()`
  - `getOpCode()`
  - `getTypeStringByType()`
  - `getValueLengthByDpType()`
  - `parseStatusParameters()`
  - *(... and 2 more)*

---

### VendorDSTRequestStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.VendorDSTRequestStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `VendorModelMessageStatus`
- **Implements**: `Parcelable`
- **Methods**: 7
- **Fields**: 7
- **Source**: `sdk\sigmesh\provisioner\VendorDSTRequestStatus.java`

**Key Methods**:
  - `VendorDSTRequestStatus()`
  - `describeContents()`
  - `getCommandType()`
  - `getData()`
  - `getOpCode()`
  - `parseStatusParameters()`
  - `writeToParcel()`

---

### VendorModelMessageStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.VendorModelMessageStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `bqdqqqp`
- **Implements**: `Parcelable`
- **Methods**: 12
- **Fields**: 4
- **Source**: `sdk\sigmesh\provisioner\VendorModelMessageStatus.java`

**Key Methods**:
  - `bdpdqbp()`
  - `VendorModelMessageStatus()`
  - `describeContents()`
  - `getAccessPayload()`
  - `getModelIdentifier()`
  - `getOpCode()`
  - `parseStatusParameters()`
  - `StringBuilder()`
  - `writeToParcel()`
  - `createFromParcel()`
  - *(... and 2 more)*

---

### VendorModelStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.VendorModelStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `VendorModelMessageStatus`
- **Implements**: `Parcelable`
- **Methods**: 2
- **Fields**: 5
- **Source**: `sdk\sigmesh\provisioner\VendorModelStatus.java`

**Key Methods**:
  - `VendorModelStatus()`
  - `getOpCode()`

---

### VendorSubscriptionListStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.VendorSubscriptionListStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `bqdqqqp`
- **Implements**: `Parcelable`
- **Methods**: 15
- **Fields**: 9
- **Source**: `sdk\sigmesh\provisioner\VendorSubscriptionListStatus.java`

**Key Methods**:
  - `bdpdqbp()`
  - `VendorSubscriptionListStatus()`
  - `ArrayList()`
  - `describeContents()`
  - `getAccessPayload()`
  - `getLocalIdList()`
  - `getModelIdentifier()`
  - `getOpCode()`
  - `getState()`
  - `parseStatusParameters()`
  - *(... and 5 more)*

---

### VendorTimeRequestStatus [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.VendorTimeRequestStatus`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner`
- **Extends**: `VendorModelMessageStatus`
- **Implements**: `Parcelable`
- **Methods**: 7
- **Fields**: 7
- **Source**: `sdk\sigmesh\provisioner\VendorTimeRequestStatus.java`

**Key Methods**:
  - `VendorTimeRequestStatus()`
  - `describeContents()`
  - `getCommandType()`
  - `getData()`
  - `getOpCode()`
  - `parseStatusParameters()`
  - `writeToParcel()`

---

### FastConfirmProvisionState [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.fast.FastConfirmProvisionState`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner.fast`
- **Extends**: `VendorModelMessageStatus`
- **Implements**: `Parcelable`
- **Methods**: 6
- **Fields**: 6
- **Source**: `sigmesh\provisioner\fast\FastConfirmProvisionState.java`

**Key Methods**:
  - `FastConfirmProvisionState()`
  - `describeContents()`
  - `getConfirmStatus()`
  - `getOpCode()`
  - `parseStatusParameters()`
  - `writeToParcel()`

---

### FastDefaultNodeIdModelState [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.fast.FastDefaultNodeIdModelState`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner.fast`
- **Extends**: `VendorModelMessageStatus`
- **Methods**: 4
- **Fields**: 7
- **Source**: `sigmesh\provisioner\fast\FastDefaultNodeIdModelState.java`

**Key Methods**:
  - `FastDefaultNodeIdModelState()`
  - `getMac()`
  - `getOpCode()`
  - `parseStatusParameters()`

---

### FastGroupConfirmState [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.fast.FastGroupConfirmState`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner.fast`
- **Extends**: `VendorModelMessageStatus`
- **Implements**: `Parcelable`
- **Methods**: 4
- **Fields**: 9
- **Source**: `sigmesh\provisioner\fast\FastGroupConfirmState.java`

**Key Methods**:
  - `FastGroupConfirmState()`
  - `getOpCode()`
  - `isSuccess()`
  - `parseStatusParameters()`

---

### FastSetAddressModelState [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.provisioner.fast.FastSetAddressModelState`
- **Package**: `com.thingclips.sdk.sigmesh.provisioner.fast`
- **Extends**: `VendorModelMessageStatus`
- **Methods**: 8
- **Fields**: 14
- **Source**: `sigmesh\provisioner\fast\FastSetAddressModelState.java`

**Key Methods**:
  - `FastSetAddressModelState()`
  - `getMeshAddress()`
  - `getMeshCategoryExt()`
  - `getOpCode()`
  - `getProductIdentifier()`
  - `getProductKey()`
  - `getVersion()`
  - `parseStatusParameters()`

---

### ApplicationKey [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.transport.ApplicationKey`
- **Package**: `com.thingclips.sdk.sigmesh.transport`
- **Implements**: `Parcelable`
- **Methods**: 22
- **Fields**: 8
- **Source**: `sdk\sigmesh\transport\ApplicationKey.java`

**Key Methods**:
  - `bdpdqbp()`
  - `createFromParcel()`
  - `ApplicationKey()`
  - `newArray()`
  - `ApplicationKey()`
  - `describeContents()`
  - `getBoundNetKeyIndex()`
  - `getId()`
  - `getKey()`
  - `getKeyIndex()`
  - *(... and 12 more)*

---

### ConfigStatusMessage [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.transport.ConfigStatusMessage`
- **Package**: `com.thingclips.sdk.sigmesh.transport`
- **Extends**: `qqpqqbb`
- **Methods**: 11
- **Fields**: 6
- **Source**: `sdk\sigmesh\transport\ConfigStatusMessage.java`

**Key Methods**:
  - `fromStatusCode()`
  - `IllegalArgumentException()`
  - `getStatusCode()`
  - `ConfigStatusMessage()`
  - `getAid()`
  - `getAkf()`
  - `getParameters()`
  - `getStatusCode()`
  - `getStatusCodeName()`
  - `parseStatusParameters()`
  - *(... and 1 more)*

---

### MeshModel [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.transport.MeshModel`
- **Package**: `com.thingclips.sdk.sigmesh.transport`
- **Implements**: `Parcelable`
- **Methods**: 37
- **Fields**: 26
- **Source**: `sdk\sigmesh\transport\MeshModel.java`

**Key Methods**:
  - `MeshModel()`
  - `ArrayList()`
  - `LinkedHashMap()`
  - `LinkedHashMap()`
  - `ArrayList()`
  - `checkIfAlreadySubscribed()`
  - `getIndex()`
  - `sortAppKeys()`
  - `ArrayList()`
  - `addSubscriptionAddress()`
  - *(... and 27 more)*

---

### AddressArray [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.util.AddressArray`
- **Package**: `com.thingclips.sdk.sigmesh.util`
- **Implements**: `Parcelable`
- **Methods**: 9
- **Fields**: 5
- **Source**: `sdk\sigmesh\util\AddressArray.java`

**Key Methods**:
  - `bdpdqbp()`
  - `createFromParcel()`
  - `AddressArray()`
  - `newArray()`
  - `AddressArray()`
  - `describeContents()`
  - `getAddress()`
  - `writeToParcel()`
  - `AddressArray()`

---

### ExtendedInvalidCipherTextException [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.util.ExtendedInvalidCipherTextException`
- **Package**: `com.thingclips.sdk.sigmesh.util`
- **Extends**: `InvalidCipherTextException`
- **Methods**: 4
- **Fields**: 3
- **Source**: `sdk\sigmesh\util\ExtendedInvalidCipherTextException.java`

**Key Methods**:
  - `ExtendedInvalidCipherTextException()`
  - `getCause()`
  - `getMessage()`
  - `getTag()`

---

### PublicationSettings [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.util.PublicationSettings`
- **Package**: `com.thingclips.sdk.sigmesh.util`
- **Implements**: `Parcelable`
- **Methods**: 28
- **Fields**: 14
- **Source**: `sdk\sigmesh\util\PublicationSettings.java`

**Key Methods**:
  - `bdpdqbp()`
  - `createFromParcel()`
  - `PublicationSettings()`
  - `newArray()`
  - `calculatePublicationPeriod()`
  - `describeContents()`
  - `getAppKeyIndex()`
  - `getCredentialFlag()`
  - `getPublicationResolution()`
  - `getPublicationSteps()`
  - *(... and 18 more)*

---

### RelaySettings [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.util.RelaySettings`
- **Package**: `com.thingclips.sdk.sigmesh.util`
- **Implements**: `Parcelable`
- **Methods**: 13
- **Fields**: 7
- **Source**: `sdk\sigmesh\util\RelaySettings.java`

**Key Methods**:
  - `bdpdqbp()`
  - `createFromParcel()`
  - `RelaySettings()`
  - `newArray()`
  - `RelaySettings()`
  - `isRelaySupported()`
  - `describeContents()`
  - `getRelayIntervalSteps()`
  - `getRelayTransmitCount()`
  - `getRetransmissionIntervals()`
  - *(... and 3 more)*

---

### SecureUtils [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.util.SecureUtils`
- **Package**: `com.thingclips.sdk.sigmesh.util`
- **Implements**: `Parcelable`
- **Methods**: 58
- **Fields**: 94
- **Source**: `sdk\sigmesh\util\SecureUtils.java`

**Key Methods**:
  - `bdpdqbp()`
  - `createFromParcel()`
  - `K2Output()`
  - `newArray()`
  - `describeContents()`
  - `getEncryptionKey()`
  - `getNid()`
  - `getPrivacyKey()`
  - `writeToParcel()`
  - `K2Output()`
  - *(... and 48 more)*

---

### SparseIntArrayParcelable [CRITICAL]


- **Full Name**: `com.thingclips.sdk.sigmesh.util.SparseIntArrayParcelable`
- **Package**: `com.thingclips.sdk.sigmesh.util`
- **Extends**: `SparseIntArray`
- **Implements**: `Parcelable`
- **Methods**: 9
- **Fields**: 9
- **Source**: `sdk\sigmesh\util\SparseIntArrayParcelable.java`

**Key Methods**:
  - `bdpdqbp()`
  - `SparseIntArrayParcelable()`
  - `describeContents()`
  - `writeToParcel()`
  - `size()`
  - `SparseIntArrayParcelable()`
  - `createFromParcel()`
  - `SparseIntArrayParcelable()`
  - `newArray()`

---

### CommandBean [CRITICAL]


- **Full Name**: `com.thingclips.sdk.thingmesh.bean.CommandBean`
- **Package**: `com.thingclips.sdk.thingmesh.bean`
- **Methods**: 11
- **Fields**: 10
- **Source**: `sdk\thingmesh\bean\CommandBean.java`

**Key Methods**:
  - `CommandBean()`
  - `newInstance()`
  - `CommandBean()`
  - `clear()`
  - `getMacAddress()`
  - `setMacAddress()`
  - `toString()`
  - `StringBuilder()`
  - `CommandBean()`
  - `CommandBean()`
  - *(... and 1 more)*

**Notable Strings**:
  - `" characteristicUUID :"`

---

### IThingBeaconManager [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.ble.IThingBeaconManager`
- **Package**: `com.thingclips.smart.android.ble`
- **Methods**: 18
- **Fields**: 0
- **Source**: `smart\android\ble\IThingBeaconManager.java`

**Key Methods**:
  - `addDevice()`
  - `deleteDevice()`
  - `dismissGroup()`
  - `isBeaconLocalOnline()`
  - `publishDps()`
  - `publishGroupDps()`
  - `queryDevicesStatus()`
  - `registerAuthListener()`
  - `resetFactoryLocal()`
  - `sendBeaconAuth()`
  - *(... and 8 more)*

---

### IMeshCommonControl [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.IMeshCommonControl`
- **Package**: `com.thingclips.smart.android.blemesh`
- **Extends**: `IMeshDevListener>`
- **Methods**: 18
- **Fields**: 0
- **Source**: `smart\android\blemesh\IMeshCommonControl.java`

**Key Methods**:
  - `addGroup()`
  - `clearDevice()`
  - `connect()`
  - `disConnectWireNodeId()`
  - `disconnect()`
  - `getMeshGroupLocalId()`
  - `getStatus()`
  - `isInConfig()`
  - `isMeshLocalOnLine()`
  - `multicastDps()`
  - *(... and 8 more)*

---

### IMeshDataAnalysis [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.IMeshDataAnalysis`
- **Package**: `com.thingclips.smart.android.blemesh`
- **Methods**: 15
- **Fields**: 0
- **Source**: `smart\android\blemesh\IMeshDataAnalysis.java`

**Key Methods**:
  - `getDeviceType()`
  - `getDeviceType()`
  - `getMeshCategory()`
  - `getProductSubType()`
  - `getProductSubType()`
  - `getProductType()`
  - `getProductType()`
  - `mustConnected()`
  - `mustConnected()`
  - `needShutDownHeartBeat()`
  - *(... and 5 more)*

---

### IMeshLocalController [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.IMeshLocalController`
- **Package**: `com.thingclips.smart.android.blemesh`
- **Methods**: 14
- **Fields**: 0
- **Source**: `smart\android\blemesh\IMeshLocalController.java`

**Key Methods**:
  - `getDpList()`
  - `multicastDps()`
  - `onDestroy()`
  - `passThroughByLocal()`
  - `publishCommands()`
  - `publishDps()`
  - `publishDps()`
  - `queryAllMeshSubDeviceStatusByLocal()`
  - `queryAllOnLineStatusByLocal()`
  - `queryOfflineDeviceStatusByLocal()`
  - *(... and 4 more)*

---

### ISigMeshControl [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.ISigMeshControl`
- **Package**: `com.thingclips.smart.android.blemesh`
- **Extends**: `IMeshCommonControl`
- **Methods**: 7
- **Fields**: 0
- **Source**: `smart\android\blemesh\ISigMeshControl.java`

**Key Methods**:
  - `batchQueryDps()`
  - `getSigMeshConfiguration()`
  - `multicastDps()`
  - `publishCommands()`
  - `queryMeshDeviceOnlineStatusByLocal()`
  - `startBatchExecution()`
  - `startSceneDataTransfer()`

---

### ISigMeshRssi [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.ISigMeshRssi`
- **Package**: `com.thingclips.smart.android.blemesh`
- **Methods**: 6
- **Fields**: 0
- **Source**: `smart\android\blemesh\ISigMeshRssi.java`

**Key Methods**:
  - `destroy()`
  - `registerMeshDeviceRssiListener()`
  - `startSearchMeshDeviceRssi()`
  - `startSearchMeshDeviceRssi()`
  - `stopSearchMeshDeviceRssi()`
  - `unRegisterMeshDeviceRssiListener()`

---

### IThingMeshControl [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.IThingMeshControl`
- **Package**: `com.thingclips.smart.android.blemesh`
- **Extends**: `IMeshCommonControl`
- **Methods**: 5
- **Fields**: 0
- **Source**: `smart\android\blemesh\IThingMeshControl.java`

**Key Methods**:
  - `broadcastDps()`
  - `getDataByDpIds()`
  - `publishDps()`
  - `publishRawData()`
  - `queryAllStatusByLocal()`

---

### IThingMeshManager [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.IThingMeshManager`
- **Package**: `com.thingclips.smart.android.blemesh`
- **Extends**: `IMeshCommonControl>`
- **Methods**: 24
- **Fields**: 0
- **Source**: `smart\android\blemesh\IThingMeshManager.java`

**Key Methods**:
  - `clearGattService()`
  - `connectMesh()`
  - `createMeshGroup()`
  - `createMeshGroupLocalId()`
  - `createSigMesh()`
  - `createThingMesh()`
  - `destroyMesh()`
  - `disConnectWireNodeId()`
  - `disconnectMesh()`
  - `getAllMeshController()`
  - *(... and 14 more)*

---

### IThingMeshService [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.IThingMeshService`
- **Package**: `com.thingclips.smart.android.blemesh`
- **Methods**: 1
- **Fields**: 0
- **Source**: `smart\android\blemesh\IThingMeshService.java`

**Key Methods**:
  - `passThroughByLocal()`

---

### BusinessResultListener [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.BusinessResultListener`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\blemesh\api\BusinessResultListener.java`

**Key Methods**:
  - `onFailure()`
  - `onSuccess()`

---

### IMeshEventHandler [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.IMeshEventHandler`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Methods**: 5
- **Fields**: 0
- **Source**: `android\blemesh\api\IMeshEventHandler.java`

**Key Methods**:
  - `convertIdToCodeMap()`
  - `dpCacheUpdate()`
  - `getDevListStatus()`
  - `onLineStatusCacheUpdate()`
  - `rawParser()`

---

### IMeshManager [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.IMeshManager`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Methods**: 19
- **Fields**: 0
- **Source**: `android\blemesh\api\IMeshManager.java`

**Key Methods**:
  - `addSubDev()`
  - `addSubDev()`
  - `createSigMesh()`
  - `createThingMesh()`
  - `destroyMesh()`
  - `getMeshSubDevBean()`
  - `getMeshSubDevBeanByMac()`
  - `getMeshSubDevBeanByNodeId()`
  - `getMeshSubDevList()`
  - `getSigMeshList()`
  - *(... and 9 more)*

---

### IResultWithDataCallback [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.IResultWithDataCallback`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Extends**: `IResultCallback`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\blemesh\api\IResultWithDataCallback.java`

**Key Methods**:
  - `onReceive()`

---

### IThingBlueMeshActivatorListener [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.IThingBlueMeshActivatorListener`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Methods**: 3
- **Fields**: 0
- **Source**: `android\blemesh\api\IThingBlueMeshActivatorListener.java`

**Key Methods**:
  - `onError()`
  - `onFinish()`
  - `onSuccess()`

---

### IThingBlueMeshBusiness [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.IThingBlueMeshBusiness`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Methods**: 3
- **Fields**: 0
- **Source**: `android\blemesh\api\IThingBlueMeshBusiness.java`

**Key Methods**:
  - `getMeshList()`
  - `getSigMeshList()`
  - `meshFirmwareUpgradeCheck()`

---

### IThingBlueMeshClient [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.IThingBlueMeshClient`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Methods**: 10
- **Fields**: 0
- **Source**: `android\blemesh\api\IThingBlueMeshClient.java`

**Key Methods**:
  - `destroyMesh()`
  - `destroyMesh()`
  - `getStatus()`
  - `initMesh()`
  - `initMesh()`
  - `startClient()`
  - `startClient()`
  - `startSearch()`
  - `stopClient()`
  - `stopSearch()`

---

### IThingBlueMeshConfig [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.IThingBlueMeshConfig`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Methods**: 4
- **Fields**: 0
- **Source**: `android\blemesh\api\IThingBlueMeshConfig.java`

**Key Methods**:
  - `newActivator()`
  - `newSigActivator()`
  - `newThingBlueMeshSearch()`
  - `newWifiActivator()`

---

### IThingBlueMeshDevice [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.IThingBlueMeshDevice`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Extends**: `IThingBlueMesh`
- **Methods**: 9
- **Fields**: 0
- **Source**: `android\blemesh\api\IThingBlueMeshDevice.java`

**Key Methods**:
  - `publishCommands()`
  - `publishDps()`
  - `queryAllOnLineStatusByLocal()`
  - `queryAllStatusByLocal()`
  - `querySubDevStatusByLocal()`
  - `registerMeshDevListener()`
  - `registerMeshDevListener()`
  - `registerMeshDevListenerV2()`
  - `unRegisterMeshDevListener()`

---

### IThingBlueMeshGroup [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.IThingBlueMeshGroup`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Extends**: `IThingGroup`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\blemesh\api\IThingBlueMeshGroup.java`

**Key Methods**:
  - `queryDeviceInGroupByLocal()`
  - `queryGroupStatus()`

---

### IThingBlueMeshInit [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.IThingBlueMeshInit`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\blemesh\api\IThingBlueMeshInit.java`

**Key Methods**:
  - `initMesh()`
  - `onDestroy()`

---

### IThingBlueMeshOta [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.IThingBlueMeshOta`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Methods**: 3
- **Fields**: 0
- **Source**: `android\blemesh\api\IThingBlueMeshOta.java`

**Key Methods**:
  - `onDestroy()`
  - `startOta()`
  - `stopOta()`

---

### IThingBlueMeshSearch [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.IThingBlueMeshSearch`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\blemesh\api\IThingBlueMeshSearch.java`

**Key Methods**:
  - `startSearch()`
  - `stopSearch()`

---

### IThingBlueMeshSearchListener [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.IThingBlueMeshSearchListener`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\blemesh\api\IThingBlueMeshSearchListener.java`

**Key Methods**:
  - `onSearchFinish()`
  - `onSearched()`

---

### IThingExtBlueMeshOta [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.IThingExtBlueMeshOta`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Extends**: `IThingBlueMeshOta`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\blemesh\api\IThingExtBlueMeshOta.java`

**Key Methods**:
  - `getOtaInfo()`

---

### IThingMeshCallback [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.IThingMeshCallback`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\blemesh\api\IThingMeshCallback.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### IThingSigMeshClient [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.IThingSigMeshClient`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Methods**: 13
- **Fields**: 0
- **Source**: `android\blemesh\api\IThingSigMeshClient.java`

**Key Methods**:
  - `destroyMesh()`
  - `getConnectMeshNodeId()`
  - `getStatus()`
  - `initMesh()`
  - `initMesh()`
  - `startClient()`
  - `startClient()`
  - `startConnect()`
  - `startConnect()`
  - `startSearch()`
  - *(... and 3 more)*

---

### MeshConnectStatus [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.MeshConnectStatus`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Methods**: 0
- **Fields**: 4
- **Source**: `android\blemesh\api\MeshConnectStatus.java`

---

### MeshConnectStatusListener [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.MeshConnectStatusListener`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\blemesh\api\MeshConnectStatusListener.java`

**Key Methods**:
  - `onConnectStatusChanged()`

---

### MeshUpgradeListener [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.api.MeshUpgradeListener`
- **Package**: `com.thingclips.smart.android.blemesh.api`
- **Methods**: 4
- **Fields**: 0
- **Source**: `android\blemesh\api\MeshUpgradeListener.java`

**Key Methods**:
  - `onFail()`
  - `onSendSuccess()`
  - `onUpgrade()`
  - `onUpgradeSuccess()`

---

### BLEUpgradeBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.BLEUpgradeBean`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Extends**: `UpgradeInfoBean`
- **Methods**: 8
- **Fields**: 4
- **Source**: `android\blemesh\bean\BLEUpgradeBean.java`

**Key Methods**:
  - `getFileSize()`
  - `getMd5()`
  - `getSign()`
  - `getUrl()`
  - `setFileSize()`
  - `setMd5()`
  - `setSign()`
  - `setUrl()`

---

### BLEUpgradeInfoBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.BLEUpgradeInfoBean`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 8
- **Fields**: 2
- **Source**: `android\blemesh\bean\BLEUpgradeInfoBean.java`

**Key Methods**:
  - `getGw()`
  - `getUpgradeType()`
  - `getGw()`
  - `getVersionHintMessage()`
  - `isNeedUpgrade()`
  - `getGw()`
  - `setGw()`
  - `setVersionHintMessage()`

---

### BlueMeshLinkageBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.BlueMeshLinkageBean`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 17
- **Fields**: 21
- **Source**: `android\blemesh\bean\BlueMeshLinkageBean.java`

**Key Methods**:
  - `build()`
  - `BlueMeshLinkageBean()`
  - `setAll()`
  - `setAutoProperties()`
  - `setAutomationID()`
  - `setConditions()`
  - `setContinuous()`
  - `setLinkageActions()`
  - `setLinkageConditions()`
  - `getAutoProperties()`
  - *(... and 7 more)*

---

### CommandType [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.CommandType`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 0
- **Fields**: 5
- **Source**: `android\blemesh\bean\CommandType.java`

---

### ConditionLinkageData [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.ConditionLinkageData`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 4
- **Fields**: 2
- **Source**: `android\blemesh\bean\ConditionLinkageData.java`

**Key Methods**:
  - `getDataBytes()`
  - `getPubAddress()`
  - `setDataBytes()`
  - `setPubAddress()`

---

### DeviceType [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.DeviceType`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 0
- **Fields**: 2
- **Source**: `android\blemesh\bean\DeviceType.java`

---

### DevSceneDataBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.DevSceneDataBean`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 12
- **Fields**: 6
- **Source**: `android\blemesh\bean\DevSceneDataBean.java`

**Key Methods**:
  - `getDps()`
  - `getLocalId()`
  - `getNodeId()`
  - `getNodeIdList()`
  - `getSceneId()`
  - `getType()`
  - `setDps()`
  - `setLocalId()`
  - `setNodeId()`
  - `setNodeIdList()`
  - *(... and 2 more)*

---

### DpsParseBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.DpsParseBean`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 4
- **Fields**: 4
- **Source**: `android\blemesh\bean\DpsParseBean.java`

**Key Methods**:
  - `getOpCode()`
  - `getParams()`
  - `setOpCode()`
  - `setParams()`

---

### Element [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.Element`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Implements**: `Parcelable`
- **Methods**: 17
- **Fields**: 13
- **Source**: `android\blemesh\bean\Element.java`

**Key Methods**:
  - `createFromParcel()`
  - `Element()`
  - `newArray()`
  - `Element()`
  - `sortModels()`
  - `ArrayList()`
  - `describeContents()`
  - `getElementAddress()`
  - `getElementAddressInt()`
  - `getLocationDescriptor()`
  - *(... and 7 more)*

---

### LinkageHash [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.LinkageHash`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 8
- **Fields**: 3
- **Source**: `android\blemesh\bean\LinkageHash.java`

**Key Methods**:
  - `LinkageHash()`
  - `getAutomationID()`
  - `getBodyHash()`
  - `getHeadHash()`
  - `isLinkageOpen()`
  - `setAutomationID()`
  - `setBodyHash()`
  - `setHeadHash()`

---

### MeshActionLinkageData [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.MeshActionLinkageData`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 17
- **Fields**: 21
- **Source**: `android\blemesh\bean\MeshActionLinkageData.java`

**Key Methods**:
  - `build()`
  - `MeshActionLinkageData()`
  - `setActionType()`
  - `setAutomationID()`
  - `setAutomationOperate()`
  - `setDelayTime()`
  - `setDpId()`
  - `setOperateParam()`
  - `setOperator()`
  - `getActionType()`
  - *(... and 7 more)*

---

### MeshBeacon [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.MeshBeacon`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Implements**: `Parcelable`
- **Methods**: 3
- **Fields**: 4
- **Source**: `android\blemesh\bean\MeshBeacon.java`

**Key Methods**:
  - `MeshBeacon()`
  - `IllegalArgumentException()`
  - `getBeaconType()`

**Notable Strings**:
  - `"MeshBeacon"`

---

### MeshConditionLinkageData [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.MeshConditionLinkageData`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Extends**: `ConditionLinkageData`
- **Methods**: 15
- **Fields**: 17
- **Source**: `android\blemesh\bean\MeshConditionLinkageData.java`

**Key Methods**:
  - `build()`
  - `MeshConditionLinkageData()`
  - `setContinuous()`
  - `setDevId()`
  - `setDpId()`
  - `setOperateParams()`
  - `setOperator()`
  - `setPubAddress()`
  - `MeshConditionLinkageData()`
  - `getDevId()`
  - *(... and 5 more)*

---

### MeshDeviceOperationType [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.MeshDeviceOperationType`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 0
- **Fields**: 2
- **Source**: `android\blemesh\bean\MeshDeviceOperationType.java`

---

### MeshGroupOperationBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.MeshGroupOperationBean`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 7
- **Fields**: 3
- **Source**: `android\blemesh\bean\MeshGroupOperationBean.java`

**Key Methods**:
  - `MeshGroupOperationBean()`
  - `getDeviceId()`
  - `getMeshId()`
  - `getName()`
  - `setDeviceId()`
  - `setMeshId()`
  - `setName()`

---

### MeshLinkageHash [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.MeshLinkageHash`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Extends**: `LinkageHash`
- **Methods**: 3
- **Fields**: 1
- **Source**: `android\blemesh\bean\MeshLinkageHash.java`

**Key Methods**:
  - `MeshLinkageHash()`
  - `getNodeId()`
  - `setNodeId()`

---

### MeshLogUploadDataBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.MeshLogUploadDataBean`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 13
- **Fields**: 6
- **Source**: `android\blemesh\bean\MeshLogUploadDataBean.java`

**Key Methods**:
  - `MeshLogUploadDataBean()`
  - `getDes()`
  - `getDevId()`
  - `getDps()`
  - `getExtInfo()`
  - `getTime()`
  - `getType()`
  - `setDes()`
  - `setDevId()`
  - `setDps()`
  - *(... and 3 more)*

---

### MeshOperationBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.MeshOperationBean`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 11
- **Fields**: 5
- **Source**: `android\blemesh\bean\MeshOperationBean.java`

**Key Methods**:
  - `MeshOperationBean()`
  - `getDeviceId()`
  - `getMeshId()`
  - `getName()`
  - `getParentId()`
  - `getType()`
  - `setDeviceId()`
  - `setMeshId()`
  - `setName()`
  - `setParentId()`
  - *(... and 1 more)*

---

### SceneType [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.SceneType`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 0
- **Fields**: 3
- **Source**: `android\blemesh\bean\SceneType.java`

---

### SearchDeviceBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.SearchDeviceBean`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Implements**: `Parcelable`
- **Methods**: 31
- **Fields**: 19
- **Source**: `android\blemesh\bean\SearchDeviceBean.java`

**Key Methods**:
  - `createFromParcel()`
  - `SearchDeviceBean()`
  - `newArray()`
  - `SearchDeviceBean()`
  - `describeContents()`
  - `getDevice()`
  - `getMacAdress()`
  - `getMeshAddress()`
  - `getMeshName()`
  - `getProductId()`
  - *(... and 21 more)*

---

### SendCommandParams [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.SendCommandParams`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 31
- **Fields**: 34
- **Source**: `android\blemesh\bean\SendCommandParams.java`

**Key Methods**:
  - `getCommandType()`
  - `getDpParams()`
  - `getDps()`
  - `getKey()`
  - `getMac()`
  - `getNodeId()`
  - `getOpCode()`
  - `getPcc()`
  - `getSchemaMap()`
  - `getSessionKey()`
  - *(... and 21 more)*

---

### SigMeshConfiguration [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.SigMeshConfiguration`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 2
- **Fields**: 1
- **Source**: `android\blemesh\bean\SigMeshConfiguration.java`

**Key Methods**:
  - `getOnlineMode()`
  - `setOnlineMode()`

---

### SigMeshGlobalConfiguration [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.SigMeshGlobalConfiguration`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Methods**: 4
- **Fields**: 2
- **Source**: `android\blemesh\bean\SigMeshGlobalConfiguration.java`

**Key Methods**:
  - `getMeshSubDeviceOnlineTimeout()`
  - `isMeshActivatorAutoOnline()`
  - `setMeshActivatorAutoOnline()`
  - `setMeshSubDeviceOnlineTimeout()`

---

### SigMeshSearchDeviceBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.SigMeshSearchDeviceBean`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Extends**: `SearchDeviceBean`
- **Implements**: `Parcelable`
- **Methods**: 29
- **Fields**: 12
- **Source**: `android\blemesh\bean\SigMeshSearchDeviceBean.java`

**Key Methods**:
  - `createFromParcel()`
  - `SigMeshSearchDeviceBean()`
  - `newArray()`
  - `SigMeshSearchDeviceBean()`
  - `describeContents()`
  - `getCapabilities()`
  - `getCategory()`
  - `getCompanyIdentifier()`
  - `getElement()`
  - `getMeshBeacon()`
  - *(... and 19 more)*

---

### TimeMillisConditionLinkageData [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.TimeMillisConditionLinkageData`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Extends**: `ConditionLinkageData`
- **Methods**: 4
- **Fields**: 2
- **Source**: `android\blemesh\bean\TimeMillisConditionLinkageData.java`

**Key Methods**:
  - `TimeMillisConditionLinkageData()`
  - `getCalendar()`
  - `getUnixTimeMinutes()`
  - `handleData()`

---

### TimerDayConditionLinkageData [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.bean.TimerDayConditionLinkageData`
- **Package**: `com.thingclips.smart.android.blemesh.bean`
- **Extends**: `ConditionLinkageData`
- **Methods**: 9
- **Fields**: 20
- **Source**: `android\blemesh\bean\TimerDayConditionLinkageData.java`

**Key Methods**:
  - `TimerDayConditionLinkageData()`
  - `checkMinutes()`
  - `fillWeekByte()`
  - `handleData()`
  - `transferDayOfWeek()`
  - `getDayOfWeek()`
  - `getMinutes()`
  - `getSunRiseAndSet()`
  - `TimerDayConditionLinkageData()`

---

### MeshLocalGroupBuilder [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.builder.MeshLocalGroupBuilder`
- **Package**: `com.thingclips.smart.android.blemesh.builder`
- **Methods**: 13
- **Fields**: 12
- **Source**: `android\blemesh\builder\MeshLocalGroupBuilder.java`

**Key Methods**:
  - `MeshLocalGroupBuilder()`
  - `builder()`
  - `getCategoryCode()`
  - `getDeviceId()`
  - `getHomeId()`
  - `getLocalId()`
  - `getMeshId()`
  - `getVendorId()`
  - `isSupportGateway()`
  - `setCategoryCode()`
  - *(... and 3 more)*

---

### SearchBuilder [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.builder.SearchBuilder`
- **Package**: `com.thingclips.smart.android.blemesh.builder`
- **Methods**: 9
- **Fields**: 9
- **Source**: `android\blemesh\builder\SearchBuilder.java`

**Key Methods**:
  - `build()`
  - `getMeshName()`
  - `getServiceUUIDs()`
  - `getThingBlueMeshSearchListener()`
  - `getTimeOut()`
  - `setMeshName()`
  - `setServiceUUIDs()`
  - `setThingBlueMeshSearchListener()`
  - `setTimeOut()`

---

### ThingBlueMeshActivatorBuilder [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.builder.ThingBlueMeshActivatorBuilder`
- **Package**: `com.thingclips.smart.android.blemesh.builder`
- **Methods**: 28
- **Fields**: 28
- **Source**: `android\blemesh\builder\ThingBlueMeshActivatorBuilder.java`

**Key Methods**:
  - `getBlueMeshBean()`
  - `getHomeId()`
  - `getMeshId()`
  - `getMeshName()`
  - `getMeshOriginName()`
  - `getMeshOriginPassword()`
  - `getMeshPassword()`
  - `getProductKey()`
  - `getSearchDeviceBeans()`
  - `getThingBlueMeshActivatorListener()`
  - *(... and 18 more)*

**Notable Strings**:
  - `"out_of_mesh"`

---

### ThingBlueMeshOtaBuilder [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.builder.ThingBlueMeshOtaBuilder`
- **Package**: `com.thingclips.smart.android.blemesh.builder`
- **Methods**: 23
- **Fields**: 25
- **Source**: `android\blemesh\builder\ThingBlueMeshOtaBuilder.java`

**Key Methods**:
  - `bulid()`
  - `getData()`
  - `getDevId()`
  - `getMac()`
  - `getMeshId()`
  - `getNodeId()`
  - `getProductKey()`
  - `getSign()`
  - `getThingBlueMeshActivatorListener()`
  - `getTimeOut()`
  - *(... and 13 more)*

---

### ThingSigMeshActivatorBuilder [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.builder.ThingSigMeshActivatorBuilder`
- **Package**: `com.thingclips.smart.android.blemesh.builder`
- **Methods**: 10
- **Fields**: 10
- **Source**: `android\blemesh\builder\ThingSigMeshActivatorBuilder.java`

**Key Methods**:
  - `getHomeId()`
  - `getSearchDeviceBeans()`
  - `getSigMeshBean()`
  - `getThingBlueMeshActivatorListener()`
  - `getTimeOut()`
  - `setHomeId()`
  - `setSearchDeviceBeans()`
  - `setSigMeshBean()`
  - `setThingBlueMeshActivatorListener()`
  - `setTimeOut()`

---

### ILocalQueryGroupDevCallback [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.callback.ILocalQueryGroupDevCallback`
- **Package**: `com.thingclips.smart.android.blemesh.callback`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\blemesh\callback\ILocalQueryGroupDevCallback.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### BlueMeshGroupUpdateEvent [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.BlueMeshGroupUpdateEvent`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\blemesh\event\BlueMeshGroupUpdateEvent.java`

**Key Methods**:
  - `onEvent()`

---

### BlueMeshGroupUpdateEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.BlueMeshGroupUpdateEventModel`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 5
- **Fields**: 4
- **Source**: `android\blemesh\event\BlueMeshGroupUpdateEventModel.java`

**Key Methods**:
  - `BlueMeshGroupUpdateEventModel()`
  - `getErrorCode()`
  - `getMsg()`
  - `getNodeId()`
  - `isSuccess()`

---

### BlueMeshQueryGroupDevEvent [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.BlueMeshQueryGroupDevEvent`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\blemesh\event\BlueMeshQueryGroupDevEvent.java`

**Key Methods**:
  - `onEvent()`

---

### BlueMeshQueryGroupDevEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.BlueMeshQueryGroupDevEventModel`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 3
- **Fields**: 2
- **Source**: `android\blemesh\event\BlueMeshQueryGroupDevEventModel.java`

**Key Methods**:
  - `BlueMeshQueryGroupDevEventModel()`
  - `getLocalId()`
  - `getNodeId()`

---

### MeshBatchReportEvent [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MeshBatchReportEvent`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\blemesh\event\MeshBatchReportEvent.java`

**Key Methods**:
  - `onEventMainThread()`

---

### MeshBatchReportEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MeshBatchReportEventModel`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 3
- **Fields**: 2
- **Source**: `android\blemesh\event\MeshBatchReportEventModel.java`

**Key Methods**:
  - `MeshBatchReportEventModel()`
  - `getBlueMeshBatchReportBeen()`
  - `getTopicId()`

---

### MeshDeviceRelationUpdateEvent [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MeshDeviceRelationUpdateEvent`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\blemesh\event\MeshDeviceRelationUpdateEvent.java`

**Key Methods**:
  - `onEventMainThread()`

---

### MeshDeviceRelationUpdateEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MeshDeviceRelationUpdateEventModel`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 6
- **Fields**: 4
- **Source**: `android\blemesh\event\MeshDeviceRelationUpdateEventModel.java`

**Key Methods**:
  - `MeshDeviceRelationUpdateEventModel()`
  - `getCids()`
  - `getTopicId()`
  - `getType()`
  - `toString()`
  - `StringBuilder()`

**Notable Strings**:
  - `"MeshDeviceRelationUpdateEventModel{topicId='"`

---

### MeshDpUpdateEvent [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MeshDpUpdateEvent`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\blemesh\event\MeshDpUpdateEvent.java`

**Key Methods**:
  - `onEventMainThread()`
  - `onEventMainThread()`

---

### MeshDpUpdateEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MeshDpUpdateEventModel`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 8
- **Fields**: 6
- **Source**: `android\blemesh\event\MeshDpUpdateEventModel.java`

**Key Methods**:
  - `MeshDpUpdateEventModel()`
  - `getCid()`
  - `getDevId()`
  - `getDps()`
  - `getMeshId()`
  - `getType()`
  - `toString()`
  - `StringBuilder()`

**Notable Strings**:
  - `"MeshDpUpdateEventModel{meshId='"`

---

### MeshLocalOnlineStatusUpdateEvent [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MeshLocalOnlineStatusUpdateEvent`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\blemesh\event\MeshLocalOnlineStatusUpdateEvent.java`

**Key Methods**:
  - `onEvent()`

---

### MeshLocalOnlineStatusUpdateEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MeshLocalOnlineStatusUpdateEventModel`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 5
- **Fields**: 3
- **Source**: `android\blemesh\event\MeshLocalOnlineStatusUpdateEventModel.java`

**Key Methods**:
  - `MeshLocalOnlineStatusUpdateEventModel()`
  - `getMeshId()`
  - `getOffline()`
  - `getOnline()`
  - `toString()`

**Notable Strings**:
  - `"MeshLocalOnlineStatusUpdateEventModel{meshId='"`

---

### MeshOnlineStatusUpdateEvent [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MeshOnlineStatusUpdateEvent`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\blemesh\event\MeshOnlineStatusUpdateEvent.java`

**Key Methods**:
  - `onEventMainThread()`

---

### MeshOnlineStatusUpdateEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MeshOnlineStatusUpdateEventModel`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 6
- **Fields**: 4
- **Source**: `android\blemesh\event\MeshOnlineStatusUpdateEventModel.java`

**Key Methods**:
  - `MeshOnlineStatusUpdateEventModel()`
  - `getDevId()`
  - `getMeshId()`
  - `getOffline()`
  - `getOnline()`
  - `toString()`

**Notable Strings**:
  - `"MeshOnlineStatusUpdateEventModel{meshId='"`

---

### MeshPassThroughEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MeshPassThroughEventModel`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 4
- **Fields**: 3
- **Source**: `android\blemesh\event\MeshPassThroughEventModel.java`

**Key Methods**:
  - `MeshPassThroughEventModel()`
  - `getMeshId()`
  - `getOpCode()`
  - `getRaw()`

---

### MeshRawReportEvent [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MeshRawReportEvent`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\blemesh\event\MeshRawReportEvent.java`

**Key Methods**:
  - `onEvent()`

---

### MeshRawReportEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MeshRawReportEventModel`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 3
- **Fields**: 2
- **Source**: `android\blemesh\event\MeshRawReportEventModel.java`

**Key Methods**:
  - `MeshRawReportEventModel()`
  - `getMeshId()`
  - `getRaw()`

---

### MeshUpdateEvent [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MeshUpdateEvent`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\blemesh\event\MeshUpdateEvent.java`

**Key Methods**:
  - `onEventMainThread()`

---

### MeshUpdateEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MeshUpdateEventModel`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 3
- **Fields**: 2
- **Source**: `android\blemesh\event\MeshUpdateEventModel.java`

**Key Methods**:
  - `MeshUpdateEventModel()`
  - `getHomeId()`
  - `getMeshId()`

---

### MqttConnectStatusEvent [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MqttConnectStatusEvent`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\blemesh\event\MqttConnectStatusEvent.java`

**Key Methods**:
  - `onEventMainThread()`

---

### MqttConnectStatusEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.event.MqttConnectStatusEventModel`
- **Package**: `com.thingclips.smart.android.blemesh.event`
- **Methods**: 2
- **Fields**: 1
- **Source**: `android\blemesh\event\MqttConnectStatusEventModel.java`

**Key Methods**:
  - `MqttConnectStatusEventModel()`
  - `isConnect()`

---

### ILinkage [CRITICAL]


- **Full Name**: `com.thingclips.smart.android.blemesh.linkage.ILinkage`
- **Package**: `com.thingclips.smart.android.blemesh.linkage`
- **Methods**: 5
- **Fields**: 0
- **Source**: `android\blemesh\linkage\ILinkage.java`

**Key Methods**:
  - `addLinkage()`
  - `compareLinkageHash()`
  - `deleteLinkage()`
  - `operateLinkage()`
  - `queryLinkageHash()`

---

### IDiscoverBonjourService [HIGH]


- **Full Name**: `com.thingclips.sdk.matter.api.IDiscoverBonjourService`
- **Package**: `com.thingclips.sdk.matter.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\matter\api\IDiscoverBonjourService.java`

**Key Methods**:
  - `connectDeviceByBle()`
  - `startDiscoveryServicesByNsd()`

---

### bdpdqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.matter.control.bdpdqbp`
- **Package**: `com.thingclips.sdk.matter.control`
- **Extends**: `Handler`
- **Implements**: `ConnectedDeviceCallback`
- **Methods**: 117
- **Fields**: 107
- **Source**: `sdk\matter\control\ThingMatterController.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `CopyOnWriteArraySet()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bppdpdq()`
  - `onConnectionFailure()`
  - `onDeviceConnected()`
  - *(... and 107 more)*

---

### bdpdqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.matter.control.cache.bdpdqbp`
- **Package**: `com.thingclips.sdk.matter.control.cache`
- **Implements**: `IThingDataCallback<ArrayList<ProductCloudFileBean>>`
- **Methods**: 34
- **Fields**: 53
- **Source**: `matter\control\cache\EngineFileCacheManager.java`

**Key Methods**:
  - `HashMap()`
  - `HashMap()`
  - `CopyOnWriteArraySet()`
  - `CopyOnWriteArraySet()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `pdqppqb()`
  - `onDownloadError()`
  - `onDownloadFinish()`
  - *(... and 24 more)*

---

### DiscoverServiceImp [HIGH]


- **Full Name**: `com.thingclips.sdk.matter.discover.DiscoverServiceImp`
- **Package**: `com.thingclips.sdk.matter.discover`
- **Extends**: `Handler`
- **Implements**: `IDiscoverBonjourService`
- **Methods**: 22
- **Fields**: 19
- **Source**: `sdk\matter\discover\DiscoverServiceImp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `RetryBean()`
  - `toString()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `pdqppqb()`
  - `hostAddress()`
  - `onFailure()`
  - `DiscoverServiceImp()`
  - `pdqppqb()`
  - *(... and 12 more)*

**Notable Strings**:
  - `"tuya uuid info is empty."`
  - `"parse tuya uuid error："`

---

### bdpdqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.matter.discover.bdpdqbp`
- **Package**: `com.thingclips.sdk.matter.discover`
- **Implements**: `qqpdpbp`
- **Methods**: 36
- **Fields**: 26
- **Source**: `sdk\matter\discover\DiscoveryDeviceManager.java`

**Key Methods**:
  - `CopyOnWriteArrayList()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `DiscoveryBean()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `DiscoveryBean()`
  - `dualChannelScan()`
  - *(... and 26 more)*

**Notable Strings**:
  - `"Bluetooth scan failed, errorCode = "`

---

### bdpdqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.matter.discover.bdpdqbp`
- **Package**: `com.thingclips.sdk.matter.discover`
- **Extends**: `ScanCallback`
- **Methods**: 13
- **Fields**: 10
- **Source**: `sdk\matter\discover\MatterBleScanner.java`

**Key Methods**:
  - `Object()`
  - `bdpdqbp()`
  - `onScanFailed()`
  - `onScanResult()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `createNewInnerScanCallback()`
  - `bdpdqbp()`
  - `getBluetoothAdapter()`
  - `setScanCallback()`
  - *(... and 3 more)*

**Notable Strings**:
  - `"BluetoothAdapter isEnabled = "`

---

### bdpdqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.matter.discover.bdpdqbp`
- **Package**: `com.thingclips.sdk.matter.discover`
- **Implements**: `DNSSDListener`
- **Methods**: 21
- **Fields**: 21
- **Source**: `sdk\matter\discover\NsdUDPResolver.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `pdqppqb()`
  - `run()`
  - `handleSuccess()`
  - `resolveSuccess()`
  - `startDiscovery()`
  - `MulticastDNSService()`
  - `MulticastDNSQuerier()`
  - `Browse()`
  - *(... and 11 more)*

---

### NsdResolver [HIGH]


- **Full Name**: `com.thingclips.sdk.matter.discover.nsd.NsdResolver`
- **Package**: `com.thingclips.sdk.matter.discover.nsd`
- **Extends**: `Handler`
- **Implements**: `ServiceResolver`
- **Methods**: 45
- **Fields**: 74
- **Source**: `matter\discover\nsd\NsdResolver.java`

**Key Methods**:
  - `HashMap()`
  - `HashMap()`
  - `HashMap()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bppdpdq()`
  - `run()`
  - `NsdResolver()`
  - *(... and 35 more)*

---

### NsdResolveService [HIGH]


- **Full Name**: `com.thingclips.sdk.matter.discover.nsd.NsdResolveService`
- **Package**: `com.thingclips.sdk.matter.discover.nsd`
- **Extends**: `Service`
- **Implements**: `Runnable`
- **Methods**: 21
- **Fields**: 16
- **Source**: `matter\discover\nsd\NsdResolveService.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `pdqppqb()`
  - `run()`
  - `destroy()`
  - `resolve()`
  - `AtomicInteger()`
  - `bdpdqbp()`
  - `onResolveFailed()`
  - `onServiceResolved()`
  - *(... and 11 more)*

---

### Default [HIGH]


- **Full Name**: `com.thingclips.sdk.matter.nsd.Default`
- **Package**: `com.thingclips.sdk.matter.nsd`
- **Extends**: `IInterface`
- **Implements**: `INsdResolveService`
- **Methods**: 18
- **Fields**: 19
- **Source**: `sdk\matter\nsd\INsdResolveService.java`

**Key Methods**:
  - `asBinder()`
  - `destroy()`
  - `resolve()`
  - `Proxy()`
  - `asBinder()`
  - `destroy()`
  - `getInterfaceDescriptor()`
  - `resolve()`
  - `Stub()`
  - `asInterface()`
  - *(... and 8 more)*

---

### Default [HIGH]


- **Full Name**: `com.thingclips.sdk.matter.nsd.Default`
- **Package**: `com.thingclips.sdk.matter.nsd`
- **Extends**: `IInterface`
- **Implements**: `IResolveListener`
- **Methods**: 18
- **Fields**: 20
- **Source**: `sdk\matter\nsd\IResolveListener.java`

**Key Methods**:
  - `asBinder()`
  - `onResolveFailed()`
  - `onServiceResolved()`
  - `Proxy()`
  - `asBinder()`
  - `getInterfaceDescriptor()`
  - `onResolveFailed()`
  - `onServiceResolved()`
  - `Stub()`
  - `asInterface()`
  - *(... and 8 more)*

---

### bppdpdq [HIGH]


- **Full Name**: `com.thingclips.sdk.matter.presenter.bppdpdq`
- **Package**: `com.thingclips.sdk.matter.presenter`
- **Implements**: `IThingMatterDevice, ThingMatterDpCallback`
- **Methods**: 46
- **Fields**: 24
- **Source**: `sdk\matter\presenter\bppdpdq.java`

**Key Methods**:
  - `bppdpdq()`
  - `getDeviceBean()`
  - `checkPipelineAvailable()`
  - `getDataPointStat()`
  - `getDeviceProperty()`
  - `getDp()`
  - `getDpList()`
  - `getInitiativeQueryDpsInfoWithDpsArray()`
  - `getOfflineReminderStatus()`
  - `getOfflineReminderSupportStatus()`
  - *(... and 36 more)*

---

### pdqppqb [HIGH]


- **Full Name**: `com.thingclips.sdk.matter.presenter.pdqppqb`
- **Package**: `com.thingclips.sdk.matter.presenter`
- **Implements**: `IThingMatterFabricManager, IThingHardwareOnlineStatusListener`
- **Methods**: 96
- **Fields**: 110
- **Source**: `sdk\matter\presenter\pdqppqb.java`

**Key Methods**:
  - `ppdpppq()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `onMessageIntercept()`
  - `onMessageReceived()`
  - `HashSet()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `run()`
  - *(... and 86 more)*

---

### bdpdqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.matter.presenter.bdpdqbp`
- **Package**: `com.thingclips.sdk.matter.presenter`
- **Implements**: `IThingMatterDeviceConnectManager`
- **Methods**: 47
- **Fields**: 64
- **Source**: `sdk\matter\presenter\ThingMatterDeviceConnectManager.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `CopyOnWriteArraySet()`
  - `CopyOnWriteArraySet()`
  - `bdpdqbp()`
  - `run()`
  - `dbbpbbb()`
  - `bppdpdq()`
  - `onConnectionFailure()`
  - `onDeviceConnected()`
  - `pdqppqb()`
  - *(... and 37 more)*

---

### ThingMatterMultipleFabricDevice [HIGH]


- **Full Name**: `com.thingclips.sdk.matter.presenter.ThingMatterMultipleFabricDevice`
- **Package**: `com.thingclips.sdk.matter.presenter`
- **Extends**: `com.thingclips.sdk.matter.presenter.bppdpdq`
- **Implements**: `IThingMatterMultipleFabricDevice`
- **Methods**: 130
- **Fields**: 108
- **Source**: `sdk\matter\presenter\ThingMatterMultipleFabricDevice.java`

**Key Methods**:
  - `C0157bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `C0159bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `C0158bdpdqbp()`
  - `onError()`
  - *(... and 120 more)*

---

### CertifiedUtil [HIGH]


- **Full Name**: `com.thingclips.sdk.matter.util.CertifiedUtil`
- **Package**: `com.thingclips.sdk.matter.util`
- **Implements**: `Runnable`
- **Methods**: 23
- **Fields**: 20
- **Source**: `sdk\matter\util\CertifiedUtil.java`

**Key Methods**:
  - `Handler()`
  - `C0170bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `DiscoveryBean()`
  - `bdpdqbp()`
  - `run()`
  - `C0170bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - *(... and 13 more)*

---

### bdqqbqd [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.bdqqbqd`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `ChipDeviceController.CompletionListener`
- **Methods**: 33
- **Fields**: 28
- **Source**: `thingclips\sdk\matterlib\bdqqbqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `RunnableC0175bdpdqbp()`
  - `run()`
  - `pdqppqb()`
  - `run()`
  - `bdpdqbp()`
  - `onDeviceAttestationCompleted()`
  - `bdqqbqd()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - *(... and 23 more)*

---

### C0006R [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.C0006R`
- **Package**: `com.thingclips.sdk.matterlib`
- **Methods**: 19
- **Fields**: 6213
- **Source**: `thingclips\sdk\matterlib\C0006R.java`

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

### dbbpbbb [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.dbbpbbb`
- **Package**: `com.thingclips.sdk.matterlib`
- **Extends**: `Business`
- **Methods**: 22
- **Fields**: 35
- **Source**: `thingclips\sdk\matterlib\dbbpbbb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `pdqppqb()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - *(... and 12 more)*

**Notable Strings**:
  - `"uuid"`
  - `"uuid"`

---

### dbpdpbp [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.dbpdpbp`
- **Package**: `com.thingclips.sdk.matterlib`
- **Methods**: 3
- **Fields**: 2
- **Source**: `thingclips\sdk\matterlib\dbpdpbp.java`

**Key Methods**:
  - `ConnectService()`
  - `dbpdpbp()`
  - `bdpdqbp()`

---

### dbppbbp [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.dbppbbp`
- **Package**: `com.thingclips.sdk.matterlib`
- **Extends**: `com.thingclips.sdk.matterlib.bdpdqbp`
- **Implements**: `IThingDataCallback<String>`
- **Methods**: 17
- **Fields**: 16
- **Source**: `thingclips\sdk\matterlib\dbppbbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `onError()`
  - `onSuccess()`
  - `dbppbbp()`
  - `pbbppqb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `onError()`
  - *(... and 7 more)*

---

### ddbdqbd [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.ddbdqbd`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `CountdownUtil.pdqppqb`
- **Methods**: 60
- **Fields**: 94
- **Source**: `thingclips\sdk\matterlib\ddbdqbd.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `HashMap()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pbpdpdp()`
  - `StringBuilder()`
  - `if()`
  - `onError()`
  - `bppdpdq()`
  - `onError()`
  - *(... and 50 more)*

**Notable Strings**:
  - `"readThingUuid error: "`

---

### dqdpbbd [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.dqdpbbd`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `ddqdbbd`
- **Methods**: 12
- **Fields**: 8
- **Source**: `thingclips\sdk\matterlib\dqdpbbd.java`

**Key Methods**:
  - `dqdpbbd()`
  - `Handler()`
  - `CopyOnWriteArraySet()`
  - `ConcurrentLinkedDeque()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `handleServiceBrowse()`
  - `handleServiceResolve()`
  - `pdqppqb()`
  - *(... and 2 more)*

---

### pbbppqb [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.pbbppqb`
- **Package**: `com.thingclips.sdk.matterlib`
- **Methods**: 7
- **Fields**: 4
- **Source**: `thingclips\sdk\matterlib\pbbppqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### pbddddb [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.pbddddb`
- **Package**: `com.thingclips.sdk.matterlib`
- **Methods**: 32
- **Fields**: 52
- **Source**: `thingclips\sdk\matterlib\pbddddb.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `bdpdqbp()`
  - `pbddddb()`
  - `pbddddb()`
  - `pppbppp()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `ChipDeviceController()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - *(... and 22 more)*

---

### pbpdbqp [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.pbpdbqp`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `Comparator<InetAddress>`
- **Methods**: 33
- **Fields**: 33
- **Source**: `thingclips\sdk\matterlib\pbpdbqp.java`

**Key Methods**:
  - `compare()`
  - `BigInteger()`
  - `BigInteger()`
  - `compare()`
  - `BigInteger()`
  - `bdpdqbp()`
  - `MatterDiscoveryInfo()`
  - `String()`
  - `if()`
  - `if()`
  - *(... and 23 more)*

---

### pbpdpdp [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.pbpdpdp`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `Runnable`
- **Methods**: 18
- **Fields**: 17
- **Source**: `thingclips\sdk\matterlib\pbpdpdp.java`

**Key Methods**:
  - `pbpdpdp()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `onSuccess()`
  - `onError()`
  - `pdqppqb()`
  - `run()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - *(... and 8 more)*

---

### pdbbqdp [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.pdbbqdp`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `Runnable`
- **Methods**: 86
- **Fields**: 93
- **Source**: `thingclips\sdk\matterlib\pdbbqdp.java`

**Key Methods**:
  - `C0177bdpdqbp()`
  - `onActiveSuccess()`
  - `onError()`
  - `bdpdqbp()`
  - `run()`
  - `C0177bdpdqbp()`
  - `bppdpdq()`
  - `onActiveSuccess()`
  - `onError()`
  - `onStep()`
  - *(... and 76 more)*

**Notable Strings**:
  - `" uuid："`
  - `" device uuid："`
  - `" device uuid："`
  - `"uuid"`
  - `"The uuid has arrived and has not listened to the addition of sub-device"`
  - *(... and 3 more)*

---

### pqpbdqq [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.pqpbdqq`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `NsdManager.DiscoveryListener`
- **Methods**: 15
- **Fields**: 11
- **Source**: `thingclips\sdk\matterlib\pqpbdqq.java`

**Key Methods**:
  - `pqpbdqq()`
  - `CopyOnWriteArraySet()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `onDiscoveryStarted()`
  - `onDiscoveryStopped()`
  - `onServiceFound()`
  - `onServiceLost()`
  - `onStartDiscoveryFailed()`
  - *(... and 5 more)*

---

### qbbdpbq [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.qbbdpbq`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `ServiceBrowser`
- **Methods**: 17
- **Fields**: 14
- **Source**: `thingclips\sdk\matterlib\qbbdpbq.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `run()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `onDiscoveryStarted()`
  - `onDiscoveryStopped()`
  - `onServiceFound()`
  - `onServiceLost()`
  - `onStartDiscoveryFailed()`
  - *(... and 7 more)*

---

### qbqqdqq [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.qbqqdqq`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `KeyValueStoreManager`
- **Methods**: 12
- **Fields**: 8
- **Source**: `thingclips\sdk\matterlib\qbqqdqq.java`

**Key Methods**:
  - `qbqqdqq()`
  - `qbqqdqq()`
  - `bppdpdq()`
  - `MMKVManager()`
  - `MMKVManager()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `delete()`
  - `get()`
  - `bppdpdq()`
  - *(... and 2 more)*

---

### qdddbpp [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.qdddbpp`
- **Package**: `com.thingclips.sdk.matterlib`
- **Methods**: 12
- **Fields**: 18
- **Source**: `thingclips\sdk\matterlib\qdddbpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `MMKVManager()`
  - `MMKVManager()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - *(... and 2 more)*

---

### qpqddqd [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.qpqddqd`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `IThingMatterDeviceCacheManager`
- **Methods**: 13
- **Fields**: 17
- **Source**: `thingclips\sdk\matterlib\qpqddqd.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `qpqddqd()`
  - `bdpdqbp()`
  - `addMatterDevice()`
  - `addMatterDevices()`
  - `getDevId()`
  - `getMatterDeviceBean()`
  - `remove()`
  - `removeCacheAndConnection()`
  - *(... and 3 more)*

---

### qqdbbpp [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.qqdbbpp`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `ReportCallback`
- **Methods**: 73
- **Fields**: 120
- **Source**: `thingclips\sdk\matterlib\qqdbbpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onReport()`
  - `JSONArray()`
  - `JSONObject()`
  - `a()`
  - `JSONObject()`
  - `toString()`
  - `C0185bdpdqbp()`
  - `onError()`
  - *(... and 63 more)*

**Notable Strings**:
  - `"readThingUuid error: "`
  - `"readThingUuid uuid: "`
  - `"Thing uuid or pid is empty."`
  - `"Thing uuid or pid is empty."`

---

### qqddbpb [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.qqddbpb`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `IMatterActivator`
- **Methods**: 13
- **Fields**: 20
- **Source**: `thingclips\sdk\matterlib\qqddbpb.java`

**Key Methods**:
  - `cancelActivator()`
  - `commissionDevice()`
  - `ConnectResult()`
  - `if()`
  - `qqpppdp()`
  - `connectDevice()`
  - `ddbdqbd()`
  - `continueCommissioningDevice()`
  - `parseSetupCode()`
  - `searchMatterDeviceAvailableWiFiList()`
  - *(... and 3 more)*

---

### qqpppdp [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.qqpppdp`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `IMatterActivatorListener`
- **Methods**: 84
- **Fields**: 124
- **Source**: `thingclips\sdk\matterlib\qqpppdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onChange()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `StringBuilder()`
  - `onError()`
  - `pbbppqb()`
  - `onConnectionFailure()`
  - *(... and 74 more)*

---

### qqqpdpb [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.qqqpdpb`
- **Package**: `com.thingclips.sdk.matterlib`
- **Extends**: `com.thingclips.sdk.matterlib.bdpdqbp`
- **Implements**: `IThingDataCallback<String>`
- **Methods**: 16
- **Fields**: 21
- **Source**: `thingclips\sdk\matterlib\qqqpdpb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `qqqpdpb()`
  - `pppbppp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pppbppp()`
  - `onError()`
  - `onSuccess()`
  - *(... and 6 more)*

---

### C0007R [HIGH]


- **Full Name**: `com.thingclips.sdk.matterlib.api.C0007R`
- **Package**: `com.thingclips.sdk.matterlib.api`
- **Methods**: 18
- **Fields**: 5989
- **Source**: `sdk\matterlib\api\C0007R.java`

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

### Lookup [HIGH]


- **Full Name**: `com.thingclips.sdk.mdns.Lookup`
- **Package**: `com.thingclips.sdk.mdns`
- **Extends**: `MulticastDNSLookupBase`
- **Methods**: 64
- **Fields**: 22
- **Source**: `thingclips\sdk\mdns\Lookup.java`

**Key Methods**:
  - `Domain()`
  - `equals()`
  - `getName()`
  - `hashCode()`
  - `isDefault()`
  - `isLegacy()`
  - `toString()`
  - `StringBuilder()`
  - `handleException()`
  - `receiveRecord()`
  - *(... and 54 more)*

---

### MulticastDNSLookupBase [HIGH]


- **Full Name**: `com.thingclips.sdk.mdns.MulticastDNSLookupBase`
- **Package**: `com.thingclips.sdk.mdns`
- **Implements**: `Closeable, Constants`
- **Methods**: 47
- **Fields**: 66
- **Source**: `thingclips\sdk\mdns\MulticastDNSLookupBase.java`

**Key Methods**:
  - `Comparator()`
  - `compare()`
  - `MulticastDNSLookupBase()`
  - `extractServiceInstances()`
  - `extractServiceInstances()`
  - `getDefaultQuerier()`
  - `MulticastDNSQuerier()`
  - `getDefaultSearchPath()`
  - `setDefaultQuerier()`
  - `setDefaultSearchPath()`
  - *(... and 37 more)*

---

### MulticastDNSQuerier [HIGH]


- **Full Name**: `com.thingclips.sdk.mdns.MulticastDNSQuerier`
- **Package**: `com.thingclips.sdk.mdns`
- **Implements**: `Querier`
- **Methods**: 56
- **Fields**: 82
- **Source**: `thingclips\sdk\mdns\MulticastDNSQuerier.java`

**Key Methods**:
  - `LinkedList()`
  - `ArrayList()`
  - `Resolution()`
  - `getResponse()`
  - `IOException()`
  - `getResults()`
  - `LinkedList()`
  - `LinkedList()`
  - `handleException()`
  - `hasResults()`
  - *(... and 46 more)*

---

### MulticastDNSService [HIGH]


- **Full Name**: `com.thingclips.sdk.mdns.MulticastDNSService`
- **Package**: `com.thingclips.sdk.mdns`
- **Extends**: `MulticastDNSLookupBase`
- **Implements**: `ResolverListener`
- **Methods**: 80
- **Fields**: 129
- **Source**: `thingclips\sdk\mdns\MulticastDNSService.java`

**Key Methods**:
  - `Register()`
  - `close()`
  - `register()`
  - `ArrayList()`
  - `IOException()`
  - `SRVRecord()`
  - `Name()`
  - `Update()`
  - `Name()`
  - `Name()`
  - *(... and 70 more)*

---

### ServiceInstance [HIGH]


- **Full Name**: `com.thingclips.sdk.mdns.ServiceInstance`
- **Package**: `com.thingclips.sdk.mdns`
- **Implements**: `Serializable`
- **Methods**: 47
- **Fields**: 39
- **Source**: `thingclips\sdk\mdns\ServiceInstance.java`

**Key Methods**:
  - `ServiceInstance()`
  - `parseTextRecords()`
  - `LinkedHashMap()`
  - `LinkedHashMap()`
  - `parseTextRecords()`
  - `parseTextRecords()`
  - `LinkedHashMap()`
  - `split()`
  - `ArrayList()`
  - `StringBuilder()`
  - *(... and 37 more)*

---

### ServiceName [HIGH]


- **Full Name**: `com.thingclips.sdk.mdns.ServiceName`
- **Package**: `com.thingclips.sdk.mdns`
- **Extends**: `Name`
- **Methods**: 29
- **Fields**: 70
- **Source**: `thingclips\sdk\mdns\ServiceName.java`

**Key Methods**:
  - `ArrayList()`
  - `BufferedReader()`
  - `ServiceName()`
  - `arrayEquals()`
  - `main()`
  - `Name()`
  - `ServiceName()`
  - `ServiceName()`
  - `StringBuilder()`
  - `getApplication()`
  - *(... and 19 more)*

---

### ServiceRegistrationException [HIGH]


- **Full Name**: `com.thingclips.sdk.mdns.ServiceRegistrationException`
- **Package**: `com.thingclips.sdk.mdns`
- **Extends**: `IOException`
- **Methods**: 7
- **Fields**: 5
- **Source**: `thingclips\sdk\mdns\ServiceRegistrationException.java`

**Key Methods**:
  - `ServiceRegistrationException()`
  - `getReason()`
  - `setReason()`
  - `toString()`
  - `ServiceRegistrationException()`
  - `ServiceRegistrationException()`
  - `ServiceRegistrationException()`

---

### NAPTRRecord [HIGH]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.NAPTRRecord`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Extends**: `Record`
- **Methods**: 18
- **Fields**: 8
- **Source**: `sdk\mdns\dnsjava\NAPTRRecord.java`

**Key Methods**:
  - `NAPTRRecord()`
  - `getAdditionalName()`
  - `getFlags()`
  - `getObject()`
  - `NAPTRRecord()`
  - `getOrder()`
  - `getPreference()`
  - `getRegexp()`
  - `getReplacement()`
  - `getService()`
  - *(... and 8 more)*

---

### ResolverConfig [HIGH]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.ResolverConfig`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Methods**: 50
- **Fields**: 75
- **Source**: `sdk\mdns\dnsjava\ResolverConfig.java`

**Key Methods**:
  - `ResolverConfig()`
  - `if()`
  - `addSearch()`
  - `addServer()`
  - `configureFromLists()`
  - `configureNdots()`
  - `find95()`
  - `File()`
  - `findAndroid()`
  - `ArrayList()`
  - *(... and 40 more)*

---

### bdpdqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.mqtt.bdpdqbp`
- **Package**: `com.thingclips.sdk.mqtt`
- **Extends**: `BroadcastReceiver`
- **Implements**: `MqttPingSender`
- **Methods**: 18
- **Fields**: 15
- **Source**: `thingclips\sdk\mqtt\bdpdqbp.java`

**Key Methods**:
  - `C0187bdpdqbp()`
  - `onFailure()`
  - `lock()`
  - `onSuccess()`
  - `lock()`
  - `C0186bdpdqbp()`
  - `onReceive()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `IllegalArgumentException()`
  - *(... and 8 more)*

---

### bqbppdq [HIGH]


- **Full Name**: `com.thingclips.sdk.mqtt.bqbppdq`
- **Package**: `com.thingclips.sdk.mqtt`
- **Implements**: `IMqttServer, IMqttMessageListener`
- **Methods**: 98
- **Fields**: 128
- **Source**: `thingclips\sdk\mqtt\bqbppdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `isDataUpdated()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `onError()`
  - `dpdbqdp()`
  - `getLocalKey()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - *(... and 88 more)*

---

### C0036R [HIGH]


- **Full Name**: `com.thingclips.sdk.mqtt.C0036R`
- **Package**: `com.thingclips.sdk.mqtt`
- **Methods**: 18
- **Fields**: 2847
- **Source**: `thingclips\sdk\mqtt\C0036R.java`

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

### pqpbdqq [HIGH]


- **Full Name**: `com.thingclips.sdk.mqtt.pqpbdqq`
- **Package**: `com.thingclips.sdk.mqtt`
- **Implements**: `pbpdbqp, pbddddb, IMqttActionListener, qdpppbq.bdpdqbp`
- **Methods**: 65
- **Fields**: 110
- **Source**: `thingclips\sdk\mqtt\pqpbdqq.java`

**Key Methods**:
  - `CopyOnWriteArrayList()`
  - `bdpdqbp()`
  - `connectComplete()`
  - `connectionLost()`
  - `deliveryComplete()`
  - `messageArrived()`
  - `pdqppqb()`
  - `connectFinish()`
  - `pqpbdqq()`
  - `HandlerThread()`
  - *(... and 55 more)*

---

### ThingOSBLE [HIGH]


- **Full Name**: `com.thingclips.sdk.p000os.ThingOSBLE`
- **Package**: `com.thingclips.sdk.p000os`
- **Methods**: 7
- **Fields**: 4
- **Source**: `thingclips\sdk\p000os\ThingOSBLE.java`

**Key Methods**:
  - `connectService()`
  - `gateway()`
  - `getThingCommRodCtrl()`
  - `manager()`
  - `qqqdqbb()`
  - `operator()`
  - `qqqqdqq()`

---

### ThingOSMQTT [HIGH]


- **Full Name**: `com.thingclips.sdk.p000os.ThingOSMQTT`
- **Package**: `com.thingclips.sdk.p000os`
- **Methods**: 5
- **Fields**: 7
- **Source**: `thingclips\sdk\p000os\ThingOSMQTT.java`

**Key Methods**:
  - `enableBackgroundConnect()`
  - `enableMqttBackgroundConnect()`
  - `getMqttChannelInstance()`
  - `getServerInstance()`
  - `getTransferInstance()`

---

### C0037R [HIGH]


- **Full Name**: `com.thingclips.sdk.personal.C0037R`
- **Package**: `com.thingclips.sdk.personal`
- **Methods**: 19
- **Fields**: 6213
- **Source**: `thingclips\sdk\personal\C0037R.java`

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

### bdpdqbp [HIGH]


- **Full Name**: `com.thingclips.sdk.personallib.bdpdqbp`
- **Package**: `com.thingclips.sdk.personallib`
- **Extends**: `SQLiteOpenHelper`
- **Methods**: 12
- **Fields**: 13
- **Source**: `thingclips\sdk\personallib\bdpdqbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `StringBuilder()`
  - `AtomicInteger()`
  - `bppdpdq()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onCreate()`
  - `onDowngrade()`
  - `onUpgrade()`
  - *(... and 2 more)*

---

### pbpdbqp [HIGH]


- **Full Name**: `com.thingclips.sdk.personallib.pbpdbqp`
- **Package**: `com.thingclips.sdk.personallib`
- **Extends**: `Business`
- **Methods**: 25
- **Fields**: 17
- **Source**: `thingclips\sdk\personallib\pbpdbqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `ApiParams()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - *(... and 15 more)*

---

### ThingRegionsPlugin [HIGH]


- **Full Name**: `com.thingclips.sdk.regions.ThingRegionsPlugin`
- **Package**: `com.thingclips.sdk.regions`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingRegionsPlugin`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\regions\ThingRegionsPlugin.java`

**Key Methods**:
  - `dependencies()`
  - `init()`

---

### C0038R [HIGH]


- **Full Name**: `com.thingclips.sdk.scene.C0038R`
- **Package**: `com.thingclips.sdk.scene`
- **Methods**: 19
- **Fields**: 6225
- **Source**: `thingclips\sdk\scene\C0038R.java`

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

### bppdpdq [HIGH]


- **Full Name**: `com.thingclips.sdk.scenelib.bppdpdq`
- **Package**: `com.thingclips.sdk.scenelib`
- **Extends**: `BaseModel`
- **Implements**: `OnThingGeoFenceStatusListener`
- **Methods**: 266
- **Fields**: 229
- **Source**: `thingclips\sdk\scenelib\bppdpdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFail()`
  - `StringBuilder()`
  - `onSuccess()`
  - `bdqqbqd()`
  - `onFailure()`
  - `onSuccess()`
  - `bpbbqdb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 256 more)*

---

### pdqppqb [HIGH]


- **Full Name**: `com.thingclips.sdk.scenelib.pdqppqb`
- **Package**: `com.thingclips.sdk.scenelib`
- **Extends**: `Business`
- **Methods**: 54
- **Fields**: 60
- **Source**: `thingclips\sdk\scenelib\pdqppqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `pbddddb()`
  - `pbpdbqp()`
  - `pbpdpdp()`
  - `pdqppqb()`
  - `pppbppp()`
  - `qddqppb()`
  - `ApiParams()`
  - *(... and 44 more)*

---

### pppbppp [HIGH]


- **Full Name**: `com.thingclips.sdk.scenelib.pppbppp`
- **Package**: `com.thingclips.sdk.scenelib`
- **Implements**: `IThingHomeScene`
- **Methods**: 36
- **Fields**: 8
- **Source**: `thingclips\sdk\scenelib\pppbppp.java`

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
  - `pdqppqb()`
  - *(... and 26 more)*

---

### pqdbppq [HIGH]


- **Full Name**: `com.thingclips.sdk.scenelib.pqdbppq`
- **Package**: `com.thingclips.sdk.scenelib`
- **Extends**: `BasePresenter`
- **Implements**: `Runnable`
- **Methods**: 34
- **Fields**: 55
- **Source**: `thingclips\sdk\scenelib\pqdbppq.java`

**Key Methods**:
  - `C0196bdpdqbp()`
  - `onSuccess()`
  - `ArrayList()`
  - `if()`
  - `onError()`
  - `RunnableC0195bdpdqbp()`
  - `run()`
  - `pbddddb()`
  - `C0196bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 24 more)*

---

### qpppdqb [HIGH]


- **Full Name**: `com.thingclips.sdk.scenelib.qpppdqb`
- **Package**: `com.thingclips.sdk.scenelib`
- **Implements**: `IThingHomeSceneManager, IDeviceMqttProtocolListener<MQ_401_SmartEnableUpdate>`
- **Methods**: 213
- **Fields**: 71
- **Source**: `thingclips\sdk\scenelib\qpppdqb.java`

**Key Methods**:
  - `ArrayList()`
  - `ArrayList()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `bdqqbqd()`
  - `onSuccess()`
  - `onError()`
  - `bpbbqdb()`
  - `onSuccess()`
  - *(... and 203 more)*

---

### SecuredPreferenceStore [HIGH]


- **Full Name**: `com.thingclips.sdk.security.SecuredPreferenceStore`
- **Package**: `com.thingclips.sdk.security`
- **Extends**: `Exception`
- **Implements**: `SharedPreferences`
- **Methods**: 61
- **Fields**: 60
- **Source**: `thingclips\sdk\security\SecuredPreferenceStore.java`

**Key Methods**:
  - `Editor()`
  - `apply()`
  - `commit()`
  - `putString()`
  - `putString()`
  - `putString()`
  - `putString()`
  - `HashSet()`
  - `onRecoveryRequired()`
  - `MigrationFailedException()`
  - *(... and 51 more)*

---

### bpbbqdb [HIGH]


- **Full Name**: `com.thingclips.sdk.user.bpbbqdb`
- **Package**: `com.thingclips.sdk.user`
- **Extends**: `BaseModel`
- **Implements**: `qqpdpbp`
- **Methods**: 7
- **Fields**: 6
- **Source**: `thingclips\sdk\user\bpbbqdb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `run()`
  - `bpbbqdb()`
  - `bdpdqbp()`
  - `logout()`

---

### C0046R [HIGH]


- **Full Name**: `com.thingclips.sdk.user.C0046R`
- **Package**: `com.thingclips.sdk.user`
- **Methods**: 18
- **Fields**: 2847
- **Source**: `thingclips\sdk\user\C0046R.java`

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

### pbpdbqp [HIGH]


- **Full Name**: `com.thingclips.sdk.user.pbpdbqp`
- **Package**: `com.thingclips.sdk.user`
- **Extends**: `Business`
- **Methods**: 12
- **Fields**: 17
- **Source**: `thingclips\sdk\user\pbpdbqp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `ApiParams()`
  - `pdqppqb()`
  - `ApiParams()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 2 more)*

---

### pdqppqb [HIGH]


- **Full Name**: `com.thingclips.sdk.user.pdqppqb`
- **Package**: `com.thingclips.sdk.user`
- **Implements**: `IUserCommonPlugin, IClearable`
- **Methods**: 12
- **Fields**: 8
- **Source**: `thingclips\sdk\user\pdqppqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `getCommonServices()`
  - `onDestroy()`
  - `updateTimeZone()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - *(... and 2 more)*

---

### pqdbppq [HIGH]


- **Full Name**: `com.thingclips.sdk.user.pqdbppq`
- **Package**: `com.thingclips.sdk.user`
- **Extends**: `Business`
- **Methods**: 111
- **Fields**: 119
- **Source**: `thingclips\sdk\user\pqdbppq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bpbbqdb()`
  - `ApiParams()`
  - `bppdpdq()`
  - `dpdbqdp()`
  - `ApiParams()`
  - `pbbppqb()`
  - `ApiParams()`
  - `pbddddb()`
  - `ApiParams()`
  - *(... and 101 more)*

---

### pqpbpqd [HIGH]


- **Full Name**: `com.thingclips.sdk.user.pqpbpqd`
- **Package**: `com.thingclips.sdk.user`
- **Extends**: `BaseModel`
- **Implements**: `Business.ResultListener<Region>`
- **Methods**: 31
- **Fields**: 29
- **Source**: `thingclips\sdk\user\pqpbpqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 21 more)*

---

### qpppdqb [HIGH]


- **Full Name**: `com.thingclips.sdk.user.qpppdqb`
- **Package**: `com.thingclips.sdk.user`
- **Implements**: `IThingUser`
- **Methods**: 90
- **Fields**: 28
- **Source**: `thingclips\sdk\user\qpppdqb.java`

**Key Methods**:
  - `sendVerifyCodeWithUserName()`
  - `pbpqqdp()`
  - `dqdbbqp()`
  - `qqpddqd()`
  - `dpdqppp()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onError()`
  - *(... and 80 more)*

---

### OptimusUtil [HIGH]


- **Full Name**: `com.thingclips.sdk.util.OptimusUtil`
- **Package**: `com.thingclips.sdk.util`
- **Extends**: `Business`
- **Methods**: 16
- **Fields**: 26
- **Source**: `thingclips\sdk\util\OptimusUtil.java`

**Key Methods**:
  - `reportLog()`
  - `EncryptApiParams()`
  - `syncRequest()`
  - `init()`
  - `run()`
  - `InvocationHandler()`
  - `invoke()`
  - `HashMap()`
  - `HashMap()`
  - `sendVersions()`
  - *(... and 6 more)*

---

### C0050R [HIGH]


- **Full Name**: `com.thingclips.smart.android.base.C0050R`
- **Package**: `com.thingclips.smart.android.base`
- **Methods**: 18
- **Fields**: 2847
- **Source**: `smart\android\base\C0050R.java`

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

### ThingSmartSdk [HIGH]


- **Full Name**: `com.thingclips.smart.android.base.ThingSmartSdk`
- **Package**: `com.thingclips.smart.android.base`
- **Methods**: 21
- **Fields**: 21
- **Source**: `smart\android\base\ThingSmartSdk.java`

**Key Methods**:
  - `ThingSmartSdk()`
  - `destroy()`
  - `getAppSecret()`
  - `getAppkey()`
  - `getApplication()`
  - `getEventBus()`
  - `getLatitude()`
  - `getLongitude()`
  - `getTtid()`
  - `init()`
  - *(... and 11 more)*

---

### MMKVManager [HIGH]


- **Full Name**: `com.thingclips.smart.android.base.mmkv.manager.MMKVManager`
- **Package**: `com.thingclips.smart.android.base.mmkv.manager`
- **Extends**: `Parcelable>`
- **Methods**: 43
- **Fields**: 69
- **Source**: `base\mmkv\manager\MMKVManager.java`

**Key Methods**:
  - `MMKVManager()`
  - `cleanCheckMask()`
  - `getReadWriteLock()`
  - `ReentrantReadWriteLock()`
  - `integrityCheck()`
  - `uploadException()`
  - `HashMap()`
  - `clear()`
  - `contains()`
  - `getActualSize()`
  - *(... and 33 more)*

---

### ApiUrlProvider [HIGH]


- **Full Name**: `com.thingclips.smart.android.base.provider.ApiUrlProvider`
- **Package**: `com.thingclips.smart.android.base.provider`
- **Implements**: `IApiUrlProvider`
- **Methods**: 65
- **Fields**: 81
- **Source**: `android\base\provider\ApiUrlProvider.java`

**Key Methods**:
  - `HashSet()`
  - `ApiUrlProvider()`
  - `getAispeechHttpsUrl()`
  - `getAtopUrl()`
  - `if()`
  - `if()`
  - `getCountryIOSCode()`
  - `getDefaultCountryData()`
  - `transforBean()`
  - `getDefaultDomainByRegion()`
  - *(... and 55 more)*

---

### PreferencesUtil [HIGH]


- **Full Name**: `com.thingclips.smart.android.base.utils.PreferencesUtil`
- **Package**: `com.thingclips.smart.android.base.utils`
- **Extends**: `Parcelable>`
- **Methods**: 38
- **Fields**: 37
- **Source**: `android\base\utils\PreferencesUtil.java`

**Key Methods**:
  - `clear()`
  - `getBoolean()`
  - `getBytes()`
  - `getMMKVManager()`
  - `getFloat()`
  - `getMMKVManager()`
  - `getGlobalPrefrencesKey()`
  - `getInt()`
  - `getMMKVManager()`
  - `getLong()`
  - *(... and 28 more)*

---

### ProcessUtils [HIGH]


- **Full Name**: `com.thingclips.smart.android.base.utils.ProcessUtils`
- **Package**: `com.thingclips.smart.android.base.utils`
- **Methods**: 2
- **Fields**: 6
- **Source**: `android\base\utils\ProcessUtils.java`

**Key Methods**:
  - `getProcessName()`
  - `getProcessNameFromActivityThread()`

---

### IThingBleManager [HIGH]


- **Full Name**: `com.thingclips.smart.android.ble.IThingBleManager`
- **Package**: `com.thingclips.smart.android.ble`
- **Methods**: 66
- **Fields**: 5
- **Source**: `smart\android\ble\IThingBleManager.java`

**Key Methods**:
  - `activeExtenModuleByBLEActived()`
  - `activeExtenModuleByBLEActived()`
  - `addScanLinkTaskIds()`
  - `bindSlaveDeviceToMaster()`
  - `cancelBleOta()`
  - `checkBleWifiDeviceReset()`
  - `clearBigDataChannelData()`
  - `clearBleDataCache()`
  - `connectBleDevice()`
  - `directConnectBleDevice()`
  - *(... and 56 more)*

---

### IThingBleOperator [HIGH]


- **Full Name**: `com.thingclips.smart.android.ble.IThingBleOperator`
- **Package**: `com.thingclips.smart.android.ble`
- **Methods**: 24
- **Fields**: 0
- **Source**: `smart\android\ble\IThingBleOperator.java`

**Key Methods**:
  - `addConnectHidListener()`
  - `clearLeCache()`
  - `closeBluetooth()`
  - `connectBleDevice()`
  - `createBond()`
  - `disconnectBleDevice()`
  - `getBondState()`
  - `getThingThirdProtocolSupport()`
  - `isBleSupported()`
  - `isBluetoothOpened()`
  - *(... and 14 more)*

---

### IThingThirdProtocolDelegate [HIGH]


- **Full Name**: `com.thingclips.smart.android.ble.IThingThirdProtocolDelegate`
- **Package**: `com.thingclips.smart.android.ble`
- **Methods**: 2
- **Fields**: 0
- **Source**: `smart\android\ble\IThingThirdProtocolDelegate.java`

**Key Methods**:
  - `beaconParse()`
  - `newThingBluetoothFlow()`

---

### IThingThirdProtocolSupport [HIGH]


- **Full Name**: `com.thingclips.smart.android.ble.IThingThirdProtocolSupport`
- **Package**: `com.thingclips.smart.android.ble`
- **Methods**: 5
- **Fields**: 0
- **Source**: `smart\android\ble\IThingThirdProtocolSupport.java`

**Key Methods**:
  - `addProtocolDelete()`
  - `getProtocolDelegateList()`
  - `getThingBleService()`
  - `removeProtocolDelete()`
  - `updateDps()`

---

### BluetoothBondStateBean [HIGH]


- **Full Name**: `com.thingclips.smart.android.ble.api.BluetoothBondStateBean`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 5
- **Source**: `android\ble\api\BluetoothBondStateBean.java`

**Key Methods**:
  - `toString()`

**Notable Strings**:
  - `"BluetoothBondStateBean pair = "`
  - `"，bluetoothName = "`

---

### BluetoothStateChangedListener [HIGH]


- **Full Name**: `com.thingclips.smart.android.ble.api.BluetoothStateChangedListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\BluetoothStateChangedListener.java`

**Key Methods**:
  - `onBluetoothStateChanged()`

---

### IThingBluetoothFlow [HIGH]


- **Full Name**: `com.thingclips.smart.android.ble.api.IThingBluetoothFlow`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 17
- **Fields**: 0
- **Source**: `android\ble\api\IThingBluetoothFlow.java`

**Key Methods**:
  - `activator()`
  - `connect()`
  - `deviceFirmwareUpgrade()`
  - `disconnectDevice()`
  - `getDeviceId()`
  - `getDeviceType()`
  - `getDeviceUuid()`
  - `isConnectAndPaired()`
  - `isInActivating()`
  - `queryDps()`
  - *(... and 7 more)*

---

### ConnectBuilder [HIGH]


- **Full Name**: `com.thingclips.smart.android.ble.connect.ConnectBuilder`
- **Package**: `com.thingclips.smart.android.ble.connect`
- **Methods**: 19
- **Fields**: 18
- **Source**: `android\ble\connect\ConnectBuilder.java`

**Key Methods**:
  - `ArrayList()`
  - `ArrayList()`
  - `addCommunicationService()`
  - `addNotificationService()`
  - `build()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `ConnectBuilder()`
  - `ConnectOptions()`
  - *(... and 9 more)*

---

### ConnectOptions [HIGH]


- **Full Name**: `com.thingclips.smart.android.ble.connect.ConnectOptions`
- **Package**: `com.thingclips.smart.android.ble.connect`
- **Methods**: 8
- **Fields**: 8
- **Source**: `android\ble\connect\ConnectOptions.java`

**Key Methods**:
  - `ConnectOptions()`
  - `getAddress()`
  - `getMtu()`
  - `getNotifyList()`
  - `getServiceList()`
  - `getTimeout()`
  - `ThingUUID()`
  - `ThingUUID()`

---

### IThingBleService [HIGH]


- **Full Name**: `com.thingclips.smart.android.ble.connect.api.IThingBleService`
- **Package**: `com.thingclips.smart.android.ble.connect.api`
- **Methods**: 5
- **Fields**: 0
- **Source**: `ble\connect\api\IThingBleService.java`

**Key Methods**:
  - `addRequest()`
  - `connectBleDevice()`
  - `disconnectBleDevice()`
  - `getConnectStatus()`
  - `readRemoteDeviceRssi()`

---

### XRequest [HIGH]


- **Full Name**: `com.thingclips.smart.android.ble.connect.request.XRequest`
- **Package**: `com.thingclips.smart.android.ble.connect.request`
- **Methods**: 30
- **Fields**: 20
- **Source**: `ble\connect\request\XRequest.java`

**Key Methods**:
  - `XRequest()`
  - `Handler()`
  - `splitByteByLength()`
  - `deliverError()`
  - `run()`
  - `deliverSuccess()`
  - `run()`
  - `forePlay()`
  - `getBack_code()`
  - `getCharacterUuid()`
  - *(... and 20 more)*

---

### WifiConnectHelper [HIGH]


- **Full Name**: `com.thingclips.smart.android.common.connecthelper.WifiConnectHelper`
- **Package**: `com.thingclips.smart.android.common.connecthelper`
- **Extends**: `ConnectivityManager.NetworkCallback`
- **Methods**: 34
- **Fields**: 33
- **Source**: `android\common\connecthelper\WifiConnectHelper.java`

**Key Methods**:
  - `SafeHandler()`
  - `C00621()`
  - `onAvailable()`
  - `onLost()`
  - `onUnavailable()`
  - `WifiConnectHelper()`
  - `SingleHolder()`
  - `connectWIFIWithWEPPassword()`
  - `WifiConfiguration()`
  - `connectWIFIWithWPAPassword()`
  - *(... and 24 more)*

---

### WifiScanManager [HIGH]


- **Full Name**: `com.thingclips.smart.android.common.scanhelper.WifiScanManager`
- **Package**: `com.thingclips.smart.android.common.scanhelper`
- **Implements**: `IWifiScanResult<List<ScanResult>>`
- **Methods**: 40
- **Fields**: 50
- **Source**: `android\common\scanhelper\WifiScanManager.java`

**Key Methods**:
  - `WifiScanManager()`
  - `SafeHandler()`
  - `ArrayList()`
  - `C00661()`
  - `onResult()`
  - `RunnableC00672()`
  - `run()`
  - `calculateSignalLevel()`
  - `checkWifiMixHide()`
  - `if()`
  - *(... and 30 more)*

---

### Coordinator [HIGH]


- **Full Name**: `com.thingclips.smart.android.common.task.Coordinator`
- **Package**: `com.thingclips.smart.android.common.task`
- **Extends**: `AsyncTask<Void`
- **Implements**: `RejectedExecutionHandler`
- **Methods**: 28
- **Fields**: 29
- **Source**: `android\common\task\Coordinator.java`

**Key Methods**:
  - `LinkedList()`
  - `LinkedBlockingQueue()`
  - `getOuterClass()`
  - `rejectedExecution()`
  - `StringBuilder()`
  - `RejectedExecutionException()`
  - `StandaloneTask()`
  - `toString()`
  - `getClass()`
  - `doInBackground()`
  - *(... and 18 more)*

---

### ThingExecutor [HIGH]


- **Full Name**: `com.thingclips.smart.android.common.task.ThingExecutor`
- **Package**: `com.thingclips.smart.android.common.task`
- **Implements**: `Runnable`
- **Methods**: 52
- **Fields**: 40
- **Source**: `android\common\task\ThingExecutor.java`

**Key Methods**:
  - `LinkedBlockingQueue()`
  - `RejectedExecutionHandler()`
  - `rejectedExecution()`
  - `LinkedBlockingQueue()`
  - `ThreadFactory()`
  - `AtomicInteger()`
  - `newThread()`
  - `Thread()`
  - `ThreadPoolExecutor()`
  - `ThreadFactory()`
  - *(... and 42 more)*

---

### ThreadPoolMonitor [HIGH]


- **Full Name**: `com.thingclips.smart.android.common.task.ThreadPoolMonitor`
- **Package**: `com.thingclips.smart.android.common.task`
- **Extends**: `ScheduledThreadPoolExecutor`
- **Implements**: `Callable<V>`
- **Methods**: 28
- **Fields**: 29
- **Source**: `android\common\task\ThreadPoolMonitor.java`

**Key Methods**:
  - `getTag()`
  - `getWorkQueue()`
  - `call()`
  - `MonitorCallable()`
  - `run()`
  - `MonitorRunnable()`
  - `ScheduledThreadPoolExecutorMonitor()`
  - `initWorkQueue()`
  - `getTag()`
  - `getWorkQueue()`
  - *(... and 18 more)*

---

### NetworkUtil [HIGH]


- **Full Name**: `com.thingclips.smart.android.common.utils.NetworkUtil`
- **Package**: `com.thingclips.smart.android.common.utils`
- **Extends**: `BroadcastReceiver`
- **Implements**: `ApnUriGetter`
- **Methods**: 26
- **Fields**: 84
- **Source**: `android\common\utils\NetworkUtil.java`

**Key Methods**:
  - `getUriList()`
  - `ConnectionChangeReceiver()`
  - `onReceive()`
  - `getUriList()`
  - `getMobileNetworkType()`
  - `getNetConnType()`
  - `getNetworkType()`
  - `getProxyInfo()`
  - `getSimState()`
  - `isMobile()`
  - *(... and 16 more)*

**Notable Strings**:
  - `"bluetooth"`

---

### NotificationHelper [HIGH]


- **Full Name**: `com.thingclips.smart.android.common.utils.NotificationHelper`
- **Package**: `com.thingclips.smart.android.common.utils`
- **Methods**: 24
- **Fields**: 41
- **Source**: `android\common\utils\NotificationHelper.java`

**Key Methods**:
  - `Params()`
  - `Params()`
  - `Builder()`
  - `build()`
  - `NotificationChannel()`
  - `if()`
  - `setAutoCancel()`
  - `setChannelId()`
  - `setChannelName()`
  - `setGroupId()`
  - *(... and 14 more)*

---

### ThingCommonUtil [HIGH]


- **Full Name**: `com.thingclips.smart.android.common.utils.ThingCommonUtil`
- **Package**: `com.thingclips.smart.android.common.utils`
- **Methods**: 34
- **Fields**: 41
- **Source**: `android\common\utils\ThingCommonUtil.java`

**Key Methods**:
  - `defaultZone()`
  - `getTimeZoneByRawOffset()`
  - `dip2px()`
  - `drawable2bytes()`
  - `ByteArrayOutputStream()`
  - `getAppVersionName()`
  - `getCountryCode()`
  - `getCountryNumberCodeByTimeZone()`
  - `getDisplayMetrics()`
  - `getLang()`
  - *(... and 24 more)*

---

### ThingUtil [HIGH]


- **Full Name**: `com.thingclips.smart.android.common.utils.ThingUtil`
- **Package**: `com.thingclips.smart.android.common.utils`
- **Methods**: 59
- **Fields**: 105
- **Source**: `android\common\utils\ThingUtil.java`

**Key Methods**:
  - `absoluteValue()`
  - `checkBvVersion()`
  - `checkHgwLastVersion()`
  - `checkHgwVersion()`
  - `checkPvLastVersion()`
  - `checkPvVersion()`
  - `checkServiceProcess()`
  - `checkServiceVersion()`
  - `compare()`
  - `IllegalArgumentException()`
  - *(... and 49 more)*

---

### WiFiUtil [HIGH]


- **Full Name**: `com.thingclips.smart.android.common.utils.WiFiUtil`
- **Package**: `com.thingclips.smart.android.common.utils`
- **Methods**: 45
- **Fields**: 95
- **Source**: `android\common\utils\WiFiUtil.java`

**Key Methods**:
  - `IsExsits()`
  - `checkWifiIsInScanResult()`
  - `connectNearNetwork()`
  - `HashMap()`
  - `enableNetwork()`
  - `createWifiConfig()`
  - `WifiConfiguration()`
  - `if()`
  - `if()`
  - `disableNetwork()`
  - *(... and 35 more)*

---

### CacheDelegate [HIGH]


- **Full Name**: `com.thingclips.smart.android.device.CacheDelegate`
- **Package**: `com.thingclips.smart.android.device`
- **Extends**: `ConcurrentHashMap<K`
- **Methods**: 17
- **Fields**: 47
- **Source**: `smart\android\device\CacheDelegate.java`

**Key Methods**:
  - `CacheConcurrentHashMap()`
  - `StringBuilder()`
  - `getDeviceCache()`
  - `clear()`
  - `containsKey()`
  - `get()`
  - `isEmpty()`
  - `keySet()`
  - `put()`
  - `putAll()`
  - *(... and 7 more)*

---

### ThingNetworkBinder [HIGH]


- **Full Name**: `com.thingclips.smart.android.device.ThingNetworkBinder`
- **Package**: `com.thingclips.smart.android.device`
- **Methods**: 14
- **Fields**: 23
- **Source**: `smart\android\device\ThingNetworkBinder.java`

**Key Methods**:
  - `ThingNetworkBinder()`
  - `Holder()`
  - `mo226e()`
  - `mo227i()`
  - `getNetworkByHandle()`
  - `findEthernetOr24GhzFrequency()`
  - `findNetworkByHandle()`
  - `getInstance()`
  - `m224le()`
  - `m225li()`
  - *(... and 4 more)*

---

### WiFiUtil [HIGH]


- **Full Name**: `com.thingclips.smart.android.device.utils.WiFiUtil`
- **Package**: `com.thingclips.smart.android.device.utils`
- **Methods**: 36
- **Fields**: 60
- **Source**: `android\device\utils\WiFiUtil.java`

**Key Methods**:
  - `IsExsits()`
  - `checkWifiIsInScanResult()`
  - `connectNearNetwork()`
  - `HashMap()`
  - `enableNetwork()`
  - `createWifiConfig()`
  - `WifiConfiguration()`
  - `if()`
  - `if()`
  - `disableNetwork()`
  - *(... and 26 more)*

---

### Default [HIGH]


- **Full Name**: `com.thingclips.smart.android.hardware.Default`
- **Package**: `com.thingclips.smart.android.hardware`
- **Extends**: `IInterface`
- **Implements**: `ITransferAidlInterface`
- **Methods**: 33
- **Fields**: 37
- **Source**: `smart\android\hardware\ITransferAidlInterface.java`

**Key Methods**:
  - `asBinder()`
  - `closeService()`
  - `getAppId()`
  - `gwOff()`
  - `gwOn()`
  - `hardwareLog()`
  - `parsePkgFrameProgress()`
  - `responseByBinary()`
  - `Proxy()`
  - `asBinder()`
  - *(... and 23 more)*

---

### Default [HIGH]


- **Full Name**: `com.thingclips.smart.android.hardware.Default`
- **Package**: `com.thingclips.smart.android.hardware`
- **Extends**: `IInterface`
- **Implements**: `ITransferServiceAidlInterface`
- **Methods**: 42
- **Fields**: 60
- **Source**: `smart\android\hardware\ITransferServiceAidlInterface.java`

**Key Methods**:
  - `addGw()`
  - `asBinder()`
  - `closeService()`
  - `controlByBinary()`
  - `deleteAllGw()`
  - `deleteGw()`
  - `getGw()`
  - `getServiceVersion()`
  - `queryGw()`
  - `registerCallback()`
  - *(... and 32 more)*

---

### Default [HIGH]


- **Full Name**: `com.thingclips.smart.android.hardware.Default`
- **Package**: `com.thingclips.smart.android.hardware`
- **Extends**: `IInterface`
- **Implements**: `IUDPBroadcastAidlInterface`
- **Methods**: 42
- **Fields**: 54
- **Source**: `smart\android\hardware\IUDPBroadcastAidlInterface.java`

**Key Methods**:
  - `asBinder()`
  - `closeService()`
  - `getServiceVersion()`
  - `registerCallback()`
  - `removeGwBean()`
  - `start()`
  - `startListenUDP()`
  - `startListenUDPWithNetwork()`
  - `stop()`
  - `stopListenUDP()`
  - *(... and 32 more)*

---

### HgwBean [HIGH]


- **Full Name**: `com.thingclips.smart.android.hardware.bean.HgwBean`
- **Package**: `com.thingclips.smart.android.hardware.bean`
- **Implements**: `Parcelable`
- **Methods**: 46
- **Fields**: 21
- **Source**: `android\hardware\bean\HgwBean.java`

**Key Methods**:
  - `createFromParcel()`
  - `HgwBean()`
  - `newArray()`
  - `HgwBean()`
  - `describeContents()`
  - `equals()`
  - `getAblilty()`
  - `getActive()`
  - `getApConfigType()`
  - `getDevConfigAttribute()`
  - *(... and 36 more)*

**Notable Strings**:
  - `"', devConfigAttribute="`

---

### DevTransferService [HIGH]


- **Full Name**: `com.thingclips.smart.android.hardware.service.DevTransferService`
- **Package**: `com.thingclips.smart.android.hardware.service`
- **Extends**: `Service`
- **Implements**: `Runnable`
- **Methods**: 62
- **Fields**: 82
- **Source**: `android\hardware\service\DevTransferService.java`

**Key Methods**:
  - `addGw()`
  - `closeService()`
  - `ArrayList()`
  - `ArrayList()`
  - `controlByBinary()`
  - `deleteAllGw()`
  - `deleteGw()`
  - `getGw()`
  - `getServiceVersion()`
  - `queryGw()`
  - *(... and 52 more)*

---

### GwBroadcastMonitorService [HIGH]


- **Full Name**: `com.thingclips.smart.android.hardware.service.GwBroadcastMonitorService`
- **Package**: `com.thingclips.smart.android.hardware.service`
- **Extends**: `Service`
- **Implements**: `PackageCallback`
- **Methods**: 39
- **Fields**: 42
- **Source**: `android\hardware\service\GwBroadcastMonitorService.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `Object()`
  - `closeService()`
  - `ArrayList()`
  - `getServiceVersion()`
  - `registerCallback()`
  - `removeGwBean()`
  - `start()`
  - `startListenUDP()`
  - `startListenUDPWithNetwork()`
  - *(... and 29 more)*

---

### Business [HIGH]


- **Full Name**: `com.thingclips.smart.android.network.Business`
- **Package**: `com.thingclips.smart.android.network`
- **Extends**: `RequestTask<JSONObject>`
- **Implements**: `Callback`
- **Methods**: 158
- **Fields**: 129
- **Source**: `smart\android\network\Business.java`

**Key Methods**:
  - `C00941()`
  - `onParser()`
  - `method()`
  - `C00952()`
  - `onParser()`
  - `method()`
  - `C00963()`
  - `onParser()`
  - `method()`
  - `C00974()`
  - *(... and 148 more)*

---

### C0104R [HIGH]


- **Full Name**: `com.thingclips.smart.android.network.C0104R`
- **Package**: `com.thingclips.smart.android.network`
- **Methods**: 15
- **Fields**: 1751
- **Source**: `smart\android\network\C0104R.java`

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

### QuicBusiness [HIGH]


- **Full Name**: `com.thingclips.smart.android.network.QuicBusiness`
- **Package**: `com.thingclips.smart.android.network`
- **Implements**: `QuicRequestFinishedListener`
- **Methods**: 13
- **Fields**: 73
- **Source**: `smart\android\network\QuicBusiness.java`

**Key Methods**:
  - `SimpleRequestFinishedListener()`
  - `onRequestFinished()`
  - `businessLog()`
  - `initEngine()`
  - `initEngine()`
  - `requestByCronet()`
  - `SimpleRequestFinishedListener()`
  - `syncRequestByCronet()`
  - `BusinessResult()`
  - `SimpleRequestFinishedListener()`
  - *(... and 3 more)*

---

### ThingApiParams [HIGH]


- **Full Name**: `com.thingclips.smart.android.network.ThingApiParams`
- **Package**: `com.thingclips.smart.android.network`
- **Implements**: `OKHttpBusinessRequest.ApiRequest`
- **Methods**: 87
- **Fields**: 96
- **Source**: `smart\android\network\ThingApiParams.java`

**Key Methods**:
  - `ThingApiParams()`
  - `checkAPIName()`
  - `getDevaultEtVersion()`
  - `isSpRequest()`
  - `downgradeToHttp()`
  - `getApiChannel()`
  - `getApiName()`
  - `getApiVersion()`
  - `getBusinessParams()`
  - `getCommonParams()`
  - *(... and 77 more)*

---

### ThingSmartNetWork [HIGH]


- **Full Name**: `com.thingclips.smart.android.network.ThingSmartNetWork`
- **Package**: `com.thingclips.smart.android.network`
- **Methods**: 118
- **Fields**: 194
- **Source**: `smart\android\network\ThingSmartNetWork.java`

**Key Methods**:
  - `HashMap()`
  - `ThingSmartNetWorkConfig()`
  - `addHttpBuilder()`
  - `ThingCertificatePinner()`
  - `ArrayList()`
  - `apNetBindEnable()`
  - `autoPlugPlay()`
  - `cancelAllNetwork()`
  - `certCheck()`
  - `closePSKConfig()`
  - *(... and 108 more)*

---

### FusionBusiness [HIGH]


- **Full Name**: `com.thingclips.smart.android.network.fusion.FusionBusiness`
- **Package**: `com.thingclips.smart.android.network.fusion`
- **Implements**: `Runnable, Callback, SimpleResponseCallback`
- **Methods**: 64
- **Fields**: 81
- **Source**: `android\network\fusion\FusionBusiness.java`

**Key Methods**:
  - `onFailure()`
  - `onSuccess()`
  - `FusionBusiness()`
  - `Handler()`
  - `Handler()`
  - `decryptResponse()`
  - `RuntimeException()`
  - `increaseQuicErrorCount()`
  - `verifyResponseResult()`
  - `asyncArrayList()`
  - *(... and 54 more)*

---

### HighwayBusiness [HIGH]


- **Full Name**: `com.thingclips.smart.android.network.highway.HighwayBusiness`
- **Package**: `com.thingclips.smart.android.network.highway`
- **Implements**: `Runnable, Callback, SimpleResponseCallback`
- **Methods**: 100
- **Fields**: 120
- **Source**: `android\network\highway\HighwayBusiness.java`

**Key Methods**:
  - `onTokenRefreshFailed()`
  - `onTokenRefreshed()`
  - `onFailure()`
  - `onSuccess()`
  - `getAccessToken()`
  - `HighwayBusiness()`
  - `Handler()`
  - `Handler()`
  - `decryptResponse()`
  - `RuntimeException()`
  - *(... and 90 more)*

---

### DomainChecker [HIGH]


- **Full Name**: `com.thingclips.smart.android.network.http.dns.DomainChecker`
- **Package**: `com.thingclips.smart.android.network.http.dns`
- **Methods**: 4
- **Fields**: 10
- **Source**: `network\http\dns\DomainChecker.java`

**Key Methods**:
  - `DomainChecker()`
  - `getInstance()`
  - `isDomainLegal()`
  - `DomainChecker()`

---

### CertPinRefresher [HIGH]


- **Full Name**: `com.thingclips.smart.android.network.http.pin.CertPinRefresher`
- **Package**: `com.thingclips.smart.android.network.http.pin`
- **Methods**: 23
- **Fields**: 40
- **Source**: `network\http\pin\CertPinRefresher.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`
  - `decryptData()`
  - `getInstance()`
  - `CertPinRefresher()`
  - `requestCerts()`
  - `JSONObject()`
  - `requestCertsDns2()`
  - `JSONObject()`
  - `statRefreshCerts()`
  - *(... and 13 more)*

---

### QuicUtil [HIGH]


- **Full Name**: `com.thingclips.smart.android.network.quic.QuicUtil`
- **Package**: `com.thingclips.smart.android.network.quic`
- **Methods**: 4
- **Fields**: 21
- **Source**: `android\network\quic\QuicUtil.java`

**Key Methods**:
  - `httpEnable()`
  - `isPackageMatched()`
  - `isQuicSupport()`
  - `mqttEnable()`

---

### ECDHEngine [HIGH]


- **Full Name**: `com.thingclips.smart.android.network.util.ECDHEngine`
- **Package**: `com.thingclips.smart.android.network.util`
- **Methods**: 10
- **Fields**: 23
- **Source**: `android\network\util\ECDHEngine.java`

**Key Methods**:
  - `decodeECPoint()`
  - `ECNamedCurveSpec()`
  - `decodePoint()`
  - `ecdhKey()`
  - `generateKeyPair()`
  - `KeyEntity()`
  - `String()`
  - `String()`
  - `hmacSha256()`
  - `String()`

---

### OkHttpDownloader [HIGH]


- **Full Name**: `com.thingclips.smart.android.network.util.OkHttpDownloader`
- **Package**: `com.thingclips.smart.android.network.util`
- **Implements**: `IDownloader`
- **Methods**: 33
- **Fields**: 49
- **Source**: `android\network\util\OkHttpDownloader.java`

**Key Methods**:
  - `OkHttpDownloader()`
  - `cancelCall()`
  - `checkDownloadEnvironment()`
  - `File()`
  - `StatFs()`
  - `copy()`
  - `BufferedInputStream()`
  - `downloadError()`
  - `if()`
  - `downloadSuccess()`
  - *(... and 23 more)*

---

### ThingHighwayUtil [HIGH]


- **Full Name**: `com.thingclips.smart.android.network.util.ThingHighwayUtil`
- **Package**: `com.thingclips.smart.android.network.util`
- **Methods**: 33
- **Fields**: 47
- **Source**: `android\network\util\ThingHighwayUtil.java`

**Key Methods**:
  - `MMKVManager()`
  - `cleanToken()`
  - `encryptRequest()`
  - `String()`
  - `generateHighwaySignature()`
  - `HashMap()`
  - `StringBuilder()`
  - `generateNonce()`
  - `getAccessToken()`
  - `getApiVersion()`
  - *(... and 23 more)*

---

### User [HIGH]


- **Full Name**: `com.thingclips.smart.android.user.bean.User`
- **Package**: `com.thingclips.smart.android.user.bean`
- **Implements**: `Parcelable, Cloneable`
- **Methods**: 52
- **Fields**: 24
- **Source**: `android\user\bean\User.java`

**Key Methods**:
  - `createFromParcel()`
  - `User()`
  - `newArray()`
  - `User()`
  - `clone()`
  - `describeContents()`
  - `getDataVersion()`
  - `getDomain()`
  - `getEcode()`
  - `getEmail()`
  - *(... and 42 more)*

---

### ComputationScheduler [HIGH]


- **Full Name**: `com.thingclips.smart.asynclib.schedulers.ComputationScheduler`
- **Package**: `com.thingclips.smart.asynclib.schedulers`
- **Implements**: `Scheduler`
- **Methods**: 8
- **Fields**: 3
- **Source**: `smart\asynclib\schedulers\ComputationScheduler.java`

**Key Methods**:
  - `ComputationScheduler()`
  - `PriorityThreadPool()`
  - `CustomThreadFactory()`
  - `execute()`
  - `executeDelay()`
  - `getExecutor()`
  - `getPriorityExecutor()`
  - `getScheduledExecutor()`

---

### IOScheduler [HIGH]


- **Full Name**: `com.thingclips.smart.asynclib.schedulers.IOScheduler`
- **Package**: `com.thingclips.smart.asynclib.schedulers`
- **Implements**: `Scheduler`
- **Methods**: 14
- **Fields**: 11
- **Source**: `smart\asynclib\schedulers\IOScheduler.java`

**Key Methods**:
  - `IOScheduler()`
  - `CachedWorkerPool()`
  - `execute()`
  - `executeDelay()`
  - `offerForInvoke()`
  - `wrap()`
  - `wrap()`
  - `wrap()`
  - `IOWrapperTask()`
  - `wrap()`
  - *(... and 4 more)*

---

### ThingScheduleExecutorService [HIGH]


- **Full Name**: `com.thingclips.smart.asynclib.schedulers.ThingScheduleExecutorService`
- **Package**: `com.thingclips.smart.asynclib.schedulers`
- **Extends**: `Callable<T>>`
- **Implements**: `ExecutorService`
- **Methods**: 17
- **Fields**: 13
- **Source**: `smart\asynclib\schedulers\ThingScheduleExecutorService.java`

**Key Methods**:
  - `ThingScheduleExecutorService()`
  - `assertNotNull()`
  - `IllegalArgumentException()`
  - `get()`
  - `awaitTermination()`
  - `execute()`
  - `invokeAll()`
  - `invokeAny()`
  - `isShutdown()`
  - `isTerminated()`
  - *(... and 7 more)*

---

### ThreadEnv [HIGH]


- **Full Name**: `com.thingclips.smart.asynclib.schedulers.ThreadEnv`
- **Package**: `com.thingclips.smart.asynclib.schedulers`
- **Methods**: 23
- **Fields**: 10
- **Source**: `smart\asynclib\schedulers\ThreadEnv.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `computation()`
  - `ComputationScheduler()`
  - `computationExecutor()`
  - `customIOExecutorService()`
  - `ThingScheduleExecutorService()`
  - `customPriorityExecutorService()`
  - `PriorityThreadPool()`
  - `getGlobalThreadLooper()`
  - `getShareLooper()`
  - *(... and 13 more)*

---

### CachedWorkerPool [HIGH]


- **Full Name**: `com.thingclips.smart.asynclib.schedulers.io.CachedWorkerPool`
- **Package**: `com.thingclips.smart.asynclib.schedulers.io`
- **Implements**: `Runnable`
- **Methods**: 26
- **Fields**: 35
- **Source**: `asynclib\schedulers\io\CachedWorkerPool.java`

**Key Methods**:
  - `Object()`
  - `ConcurrentHashMap()`
  - `AtomicBoolean()`
  - `AtomicInteger()`
  - `CachedWorkerPool()`
  - `AtomicInteger()`
  - `getAllActivePool()`
  - `HashSet()`
  - `register()`
  - `CustomThreadFactory()`
  - *(... and 16 more)*

---

### PriorityThreadPool [HIGH]


- **Full Name**: `com.thingclips.smart.asynclib.threadpool.PriorityThreadPool`
- **Package**: `com.thingclips.smart.asynclib.threadpool`
- **Extends**: `ThreadPoolExecutor`
- **Implements**: `Comparator<Runnable>`
- **Methods**: 31
- **Fields**: 21
- **Source**: `smart\asynclib\threadpool\PriorityThreadPool.java`

**Key Methods**:
  - `Object()`
  - `CustomComparator()`
  - `compare()`
  - `PriorityThreadPool()`
  - `PriorityBlockingQueue()`
  - `CustomThreadFactory()`
  - `RejectedExecutionHandler()`
  - `rejectedExecution()`
  - `AtomicBoolean()`
  - `AtomicInteger()`
  - *(... and 21 more)*

---

### ThingAudioRecord [HIGH]


- **Full Name**: `com.thingclips.smart.audioengine.bean.ThingAudioRecord`
- **Package**: `com.thingclips.smart.audioengine.bean`
- **Extends**: `Thread`
- **Methods**: 13
- **Fields**: 31
- **Source**: `smart\audioengine\bean\ThingAudioRecord.java`

**Key Methods**:
  - `ReentrantLock()`
  - `AudioRecordThread()`
  - `joinThread()`
  - `run()`
  - `ThingAudioRecord()`
  - `Destroy()`
  - `InitRecording()`
  - `AudioRecord()`
  - `StartRecording()`
  - `AudioRecordThread()`
  - *(... and 3 more)*

---

### ThingBlueServicePlugin [HIGH]


- **Full Name**: `com.thingclips.smart.ble.bs.ThingBlueServicePlugin`
- **Package**: `com.thingclips.smart.ble.bs`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingBlueServicePlugin`
- **Methods**: 9
- **Fields**: 0
- **Source**: `smart\ble\bs\ThingBlueServicePlugin.java`

**Key Methods**:
  - `dependencies()`
  - `getBeaconFilterManager()`
  - `getBleConnectService()`
  - `dbbbppp()`
  - `getBleFittingsManager()`
  - `getThingBleGateway()`
  - `ppbqqdd()`
  - `init()`
  - `onDestroy()`

---

### BeaconScanFilterReceiver [HIGH]


- **Full Name**: `com.thingclips.smart.ble.bs.beacon.BeaconScanFilterReceiver`
- **Package**: `com.thingclips.smart.ble.bs.beacon`
- **Extends**: `BroadcastReceiver`
- **Methods**: 9
- **Fields**: 19
- **Source**: `ble\bs\beacon\BeaconScanFilterReceiver.java`

**Key Methods**:
  - `bdpdqbp()`
  - `LinkedList()`
  - `StringBuilder()`
  - `bppdpdq()`
  - `StringBuilder()`
  - `onReceive()`
  - `pdqppqb()`
  - `qddqppb()`
  - `StringBuilder()`

---

### ThingOSBlueService [HIGH]


- **Full Name**: `com.thingclips.smart.ble.bs.p003os.ThingOSBlueService`
- **Package**: `com.thingclips.smart.ble.bs.p003os`
- **Methods**: 3
- **Fields**: 0
- **Source**: `ble\bs\p003os\ThingOSBlueService.java`

**Key Methods**:
  - `gateway()`
  - `ppbqqdd()`
  - `getBlueServiceManager()`

---

### IThingBleConnectService [HIGH]


- **Full Name**: `com.thingclips.smart.bluet.api.IThingBleConnectService`
- **Package**: `com.thingclips.smart.bluet.api`
- **Methods**: 7
- **Fields**: 0
- **Source**: `smart\bluet\api\IThingBleConnectService.java`

**Key Methods**:
  - `addContinuousConnectDevice()`
  - `displayDeviceList()`
  - `enterDeviceConsole()`
  - `exitDeviceConsole()`
  - `onApplicationCreate()`
  - `removeContinuousConnectDevice()`
  - `takeConnectToDevice()`

---

### IThingBlueServicePlugin [HIGH]


- **Full Name**: `com.thingclips.smart.bluet.api.IThingBlueServicePlugin`
- **Package**: `com.thingclips.smart.bluet.api`
- **Methods**: 5
- **Fields**: 0
- **Source**: `smart\bluet\api\IThingBlueServicePlugin.java`

**Key Methods**:
  - `getBeaconFilterManager()`
  - `getBleConnectService()`
  - `getBleFittingsManager()`
  - `getThingBleGateway()`
  - `onDestroy()`

---

### C0153R [HIGH]


- **Full Name**: `com.thingclips.smart.bluetooth.C0153R`
- **Package**: `com.thingclips.smart.bluetooth`
- **Methods**: 19
- **Fields**: 6213
- **Source**: `thingclips\smart\bluetooth\C0153R.java`

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

### ThingMatterPlugin [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matter.ThingMatterPlugin`
- **Package**: `com.thingclips.sdk.matter`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingMatterDevicePlugin`
- **Methods**: 24
- **Fields**: 2
- **Source**: `thingclips\sdk\matter\ThingMatterPlugin.java`

**Key Methods**:
  - `bdpdqbp()`
  - `logoutSuccess()`
  - `bppdpdq()`
  - `onCancelAccountSuccess()`
  - `pdqppqb()`
  - `loginSuccess()`
  - `dependencies()`
  - `getDiscoveryActivatorInstance()`
  - `dqqbdqb()`
  - `getFabricManager()`
  - *(... and 14 more)*

---

### IMatterActivator [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matter.activator.IMatterActivator`
- **Package**: `com.thingclips.sdk.matter.activator`
- **Methods**: 7
- **Fields**: 0
- **Source**: `sdk\matter\activator\IMatterActivator.java`

**Key Methods**:
  - `cancelActivator()`
  - `commissionDevice()`
  - `connectDevice()`
  - `continueCommissioningDevice()`
  - `parseSetupCode()`
  - `searchMatterDeviceAvailableWiFiList()`
  - `startDiscover()`

---

### SetupPayload [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matter.activator.SetupPayload`
- **Package**: `com.thingclips.sdk.matter.activator`
- **Implements**: `Serializable`
- **Methods**: 6
- **Fields**: 13
- **Source**: `sdk\matter\activator\SetupPayload.java`

**Key Methods**:
  - `HashSet()`
  - `toString()`
  - `StringBuilder()`
  - `setGwId()`
  - `toString()`
  - `StringBuilder()`

---

### IMatterNsdDiscoverListener [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matter.api.IMatterNsdDiscoverListener`
- **Package**: `com.thingclips.sdk.matter.api`
- **Extends**: `Serializable`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\matter\api\IMatterNsdDiscoverListener.java`

**Key Methods**:
  - `matterDnsDiscover()`
  - `onError()`

---

### MatterErrorCode [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matter.config.MatterErrorCode`
- **Package**: `com.thingclips.sdk.matter.config`
- **Methods**: 0
- **Fields**: 61
- **Source**: `sdk\matter\config\MatterErrorCode.java`

---

### DiscoveryBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matter.discover.bean.DiscoveryBean`
- **Package**: `com.thingclips.sdk.matter.discover.bean`
- **Methods**: 13
- **Fields**: 7
- **Source**: `matter\discover\bean\DiscoveryBean.java`

**Key Methods**:
  - `getDeviceType()`
  - `getDiscoveryDiscriminator()`
  - `getMsv()`
  - `getParseObject()`
  - `isThingMatter()`
  - `setDeviceType()`
  - `setDiscoveryDiscriminator()`
  - `setDiscoveryType()`
  - `setMsv()`
  - `setParseObject()`
  - *(... and 3 more)*

---

### IndicationReceived [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matter.discover.ble.bean.IndicationReceived`
- **Package**: `com.thingclips.sdk.matter.discover.ble.bean`
- **Implements**: `Runnable`
- **Methods**: 5
- **Fields**: 2
- **Source**: `discover\ble\bean\IndicationReceived.java`

**Key Methods**:
  - `handleIndication()`
  - `registerListener()`
  - `run()`
  - `startHandleIndication()`
  - `unregisterListener()`

---

### ThingMatterLeBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matter.discover.ble.bean.ThingMatterLeBean`
- **Package**: `com.thingclips.sdk.matter.discover.ble.bean`
- **Implements**: `Serializable`
- **Methods**: 10
- **Fields**: 5
- **Source**: `discover\ble\bean\ThingMatterLeBean.java`

**Key Methods**:
  - `getDeviceType()`
  - `getMsv()`
  - `isBLEGateway()`
  - `isThingMatter()`
  - `setBleGateway()`
  - `setDeviceType()`
  - `setMsv()`
  - `setThingMatter()`
  - `toString()`
  - `StringBuilder()`

---

### bdpdqbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matter.presenter.bdpdqbp`
- **Package**: `com.thingclips.sdk.matter.presenter`
- **Extends**: `ChipClusters.BaseChipCluster>>`
- **Implements**: `ConnectedDeviceCallback`
- **Methods**: 36
- **Fields**: 14
- **Source**: `sdk\matter\presenter\bdpdqbp.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `bdpdqbp()`
  - `Object()`
  - `C0162bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`
  - *(... and 26 more)*

---

### bdpdqbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matter.presenter.bdpdqbp`
- **Package**: `com.thingclips.sdk.matter.presenter`
- **Implements**: `ChipDeviceController.NOCChainIssuer`
- **Methods**: 7
- **Fields**: 17
- **Source**: `sdk\matter\presenter\MatterNocChainIssuer.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `getCats()`
  - `onNOCChainGenerationNeeded()`
  - `setCats()`
  - `shouldNotUseCat()`
  - `shouldUseCat()`

---

### bdpdqbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matter.presenter.bdpdqbp`
- **Package**: `com.thingclips.sdk.matter.presenter`
- **Extends**: `Handler`
- **Implements**: `IThingResultCallback<Integer>`
- **Methods**: 11
- **Fields**: 15
- **Source**: `sdk\matter\presenter\PaseConnectionKeeper.java`

**Key Methods**:
  - `C0156bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `if()`
  - `C0156bdpdqbp()`
  - `init()`
  - `bdpdqbp()`
  - `startKeeper()`
  - *(... and 1 more)*

---

### ResolvingTask [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matter.presenter.connect.bean.ResolvingTask`
- **Package**: `com.thingclips.sdk.matter.presenter.connect.bean`
- **Implements**: `Runnable`
- **Methods**: 5
- **Fields**: 4
- **Source**: `presenter\connect\bean\ResolvingTask.java`

**Key Methods**:
  - `ResolvingTask()`
  - `equals()`
  - `hashCode()`
  - `run()`
  - `toString()`

---

### MatterFabricAttributeBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matter.presenter.pipeline.bean.MatterFabricAttributeBean`
- **Package**: `com.thingclips.sdk.matter.presenter.pipeline.bean`
- **Implements**: `Serializable`
- **Methods**: 17
- **Fields**: 8
- **Source**: `presenter\pipeline\bean\MatterFabricAttributeBean.java`

**Key Methods**:
  - `getCurrentFabricIndex()`
  - `getFabricInfoList()`
  - `getOperationalFabricInfo()`
  - `getSsidName()`
  - `getSupportedFabrics()`
  - `getSupportedFabricsUsed()`
  - `isMultiModeDev()`
  - `isWindowStatus()`
  - `setCurrentFabricIndex()`
  - `setFabricInfoList()`
  - *(... and 7 more)*

---

### bdpdqbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matter.util.bdpdqbp`
- **Package**: `com.thingclips.sdk.matter.util`
- **Extends**: `TimerTask`
- **Implements**: `Runnable`
- **Methods**: 14
- **Fields**: 8
- **Source**: `sdk\matter\util\CountdownUtil.java`

**Key Methods**:
  - `RunnableC0171bdpdqbp()`
  - `run()`
  - `bdpdqbp()`
  - `run()`
  - `bdpdqbp()`
  - `cancelTimer()`
  - `getTimer()`
  - `Timer()`
  - `startTimeoutTimer()`
  - `isTimeout()`
  - *(... and 4 more)*

---

### bdpdqbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matterlib.bdpdqbp`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `pbbppqb.bdpdqbp`
- **Methods**: 31
- **Fields**: 52
- **Source**: `thingclips\sdk\matterlib\bdpdqbp.java`

**Key Methods**:
  - `C0172bdpdqbp()`
  - `bdpdqbp()`
  - `if()`
  - `RunnableC0173bdpdqbp()`
  - `run()`
  - `RunnableC0174pdqppqb()`
  - `run()`
  - `pdqppqb()`
  - `onSuccess()`
  - `onError()`
  - *(... and 21 more)*

---

### bpqqdpq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matterlib.bpqqdpq`
- **Package**: `com.thingclips.sdk.matterlib`
- **Methods**: 7
- **Fields**: 8
- **Source**: `thingclips\sdk\matterlib\bpqqdpq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### bqbdbqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matterlib.bqbdbqb`
- **Package**: `com.thingclips.sdk.matterlib`
- **Methods**: 9
- **Fields**: 27
- **Source**: `thingclips\sdk\matterlib\bqbdbqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `CopyOnWriteArraySet()`
  - `SetupPayload()`
  - `bdpdqbp()`
  - `HashMap()`
  - `MatterQrCodeInfo()`

---

### bqbppdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matterlib.bqbppdq`
- **Package**: `com.thingclips.sdk.matterlib`
- **Methods**: 2
- **Fields**: 5
- **Source**: `thingclips\sdk\matterlib\bqbppdq.java`

**Key Methods**:
  - `bqbppdq()`
  - `toString()`

---

### dpdbqdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matterlib.dpdbqdp`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `pbpqqdp`
- **Methods**: 57
- **Fields**: 58
- **Source**: `thingclips\sdk\matterlib\dpdbqdp.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `bdpdqbp()`
  - `run()`
  - `pdqppqb()`
  - `run()`
  - `bppdpdq()`
  - `onError()`
  - *(... and 47 more)*

---

### ppdpppq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matterlib.ppdpppq`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `IThingDataCallback<OpenFabricInfo>`
- **Methods**: 82
- **Fields**: 60
- **Source**: `thingclips\sdk\matterlib\ppdpppq.java`

**Key Methods**:
  - `dbbpbbb()`
  - `C0179bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `C0179bdpdqbp()`
  - `onError()`
  - `bpbbqdb()`
  - `onFailure()`
  - *(... and 72 more)*

---

### pqdbppq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matterlib.pqdbppq`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `pbpqqdp`
- **Methods**: 36
- **Fields**: 31
- **Source**: `thingclips\sdk\matterlib\pqdbppq.java`

**Key Methods**:
  - `C0182bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `C0181bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `C0180bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `pdqppqb()`
  - *(... and 26 more)*

---

### pqdqqbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matterlib.pqdqqbd`
- **Package**: `com.thingclips.sdk.matterlib`
- **Extends**: `BleManager`
- **Methods**: 3
- **Fields**: 0
- **Source**: `thingclips\sdk\matterlib\pqdqqbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `pdqppqb()`

---

### pqpbpqd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matterlib.pqpbpqd`
- **Package**: `com.thingclips.sdk.matterlib`
- **Methods**: 4
- **Fields**: 13
- **Source**: `thingclips\sdk\matterlib\pqpbpqd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `BufferedReader()`
  - `pdqppqb()`

---

### qddqppb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matterlib.qddqppb`
- **Package**: `com.thingclips.sdk.matterlib`
- **Extends**: `BasePresenter`
- **Implements**: `IThingActivator, ICheckDevActiveStatusByTokenListener`
- **Methods**: 20
- **Fields**: 22
- **Source**: `thingclips\sdk\matterlib\qddqppb.java`

**Key Methods**:
  - `Handler()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `handleMessage()`
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `pdqppqb()`
  - `onSuccess()`
  - `onError()`
  - *(... and 10 more)*

---

### qdpppbq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matterlib.qdpppbq`
- **Package**: `com.thingclips.sdk.matterlib`
- **Methods**: 2
- **Fields**: 7
- **Source**: `thingclips\sdk\matterlib\qdpppbq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`

**Notable Strings**:
  - `"android.permission.BLUETOOTH_CONNECT"`
  - `"android.permission.BLUETOOTH_SCAN"`
  - `"android.permission.BLUETOOTH_ADVERTISE"`

---

### qpbpqpq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matterlib.qpbpqpq`
- **Package**: `com.thingclips.sdk.matterlib`
- **Methods**: 0
- **Fields**: 19
- **Source**: `thingclips\sdk\matterlib\qpbpqpq.java`

---

### qppddqq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matterlib.qppddqq`
- **Package**: `com.thingclips.sdk.matterlib`
- **Extends**: `com.thingclips.sdk.matterlib.bdpdqbp`
- **Implements**: `GetConnectedDeviceCallbackJni.GetConnectedDeviceCallback`
- **Methods**: 51
- **Fields**: 56
- **Source**: `thingclips\sdk\matterlib\qppddqq.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `RunnableC0184bdpdqbp()`
  - `run()`
  - `pdqppqb()`
  - `run()`
  - `C0183bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `ArrayList()`
  - `HashMap()`
  - *(... and 41 more)*

---

### qpqbppd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matterlib.qpqbppd`
- **Package**: `com.thingclips.sdk.matterlib`
- **Extends**: `com.thingclips.sdk.matter.presenter.bppdpdq`
- **Implements**: `IThingMatterOperation`
- **Methods**: 15
- **Fields**: 16
- **Source**: `thingclips\sdk\matterlib\qpqbppd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onSuccess()`
  - `onError()`
  - `pdqppqb()`
  - `onSuccess()`
  - `onError()`
  - `qpqbppd()`
  - `JSONArray()`
  - `processResult()`
  - `publishNextCommandInPipeline()`
  - *(... and 5 more)*

---

### qqpdpbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.matterlib.qqpdpbp`
- **Package**: `com.thingclips.sdk.matterlib`
- **Methods**: 2
- **Fields**: 0
- **Source**: `thingclips\sdk\matterlib\qqpdpbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### Browse [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.Browse`
- **Package**: `com.thingclips.sdk.mdns`
- **Extends**: `MulticastDNSLookupBase`
- **Implements**: `ResolverListener, Runnable`
- **Methods**: 33
- **Fields**: 33
- **Source**: `thingclips\sdk\mdns\Browse.java`

**Key Methods**:
  - `BrowseOperation()`
  - `answersQuery()`
  - `close()`
  - `getQueries()`
  - `handleException()`
  - `matchesBrowse()`
  - `receiveMessage()`
  - `registerListener()`
  - `run()`
  - `StringBuilder()`
  - *(... and 23 more)*

---

### Constants [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.Constants`
- **Package**: `com.thingclips.sdk.mdns`
- **Methods**: 0
- **Fields**: 21
- **Source**: `thingclips\sdk\mdns\Constants.java`

---

### DNSSDListener [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.DNSSDListener`
- **Package**: `com.thingclips.sdk.mdns`
- **Methods**: 4
- **Fields**: 0
- **Source**: `thingclips\sdk\mdns\DNSSDListener.java`

**Key Methods**:
  - `handleException()`
  - `receiveMessage()`
  - `serviceDiscovered()`
  - `serviceRemoved()`

---

### MulticastDNSCache [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.MulticastDNSCache`
- **Package**: `com.thingclips.sdk.mdns`
- **Extends**: `Cache`
- **Implements**: `Closeable`
- **Methods**: 59
- **Fields**: 82
- **Source**: `thingclips\sdk\mdns\MulticastDNSCache.java`

**Key Methods**:
  - `begin()`
  - `check()`
  - `end()`
  - `expired()`
  - `isOperational()`
  - `ElementHelper()`
  - `compareCredibility()`
  - `expired()`
  - `getCredibility()`
  - `getElement()`
  - *(... and 49 more)*

---

### MulticastDNSMulticastOnlyQuerier [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.MulticastDNSMulticastOnlyQuerier`
- **Package**: `com.thingclips.sdk.mdns`
- **Implements**: `Querier, PacketListener`
- **Methods**: 85
- **Fields**: 115
- **Source**: `thingclips\sdk\mdns\MulticastDNSMulticastOnlyQuerier.java`

**Key Methods**:
  - `Cacher()`
  - `handleException()`
  - `receiveMessage()`
  - `if()`
  - `ListenerWrapper()`
  - `equals()`
  - `handleException()`
  - `hashCode()`
  - `receiveMessage()`
  - `MulticastDNSResponder()`
  - *(... and 75 more)*

---

### Querier [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.Querier`
- **Package**: `com.thingclips.sdk.mdns`
- **Extends**: `Resolver`
- **Methods**: 9
- **Fields**: 4
- **Source**: `thingclips\sdk\mdns\Querier.java`

**Key Methods**:
  - `broadcast()`
  - `getMulticastDomains()`
  - `isIPv4()`
  - `isIPv6()`
  - `isOperational()`
  - `registerListener()`
  - `setRetryWaitTime()`
  - `setRetryWaitTime()`
  - `unregisterListener()`

---

### Cache [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.Cache`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Extends**: `LinkedHashMap`
- **Implements**: `Element`
- **Methods**: 79
- **Fields**: 73
- **Source**: `sdk\mdns\dnsjava\Cache.java`

**Key Methods**:
  - `CacheMap()`
  - `getMaxSize()`
  - `removeEldestEntry()`
  - `setMaxSize()`
  - `compareCredibility()`
  - `expired()`
  - `getType()`
  - `NegativeElement()`
  - `compareCredibility()`
  - `expired()`
  - *(... and 69 more)*

---

### Client [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.Client`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Methods**: 7
- **Fields**: 8
- **Source**: `sdk\mdns\dnsjava\Client.java`

**Key Methods**:
  - `Client()`
  - `blockUntil()`
  - `SocketTimeoutException()`
  - `SocketTimeoutException()`
  - `setPacketLogger()`
  - `verboseLog()`
  - `cleanup()`

---

### Compression [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.Compression`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Methods**: 4
- **Fields**: 12
- **Source**: `sdk\mdns\dnsjava\Compression.java`

**Key Methods**:
  - `Entry()`
  - `add()`
  - `Entry()`
  - `get()`

---

### DNSSEC [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.DNSSEC`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Extends**: `Exception`
- **Methods**: 162
- **Fields**: 136
- **Source**: `sdk\mdns\dnsjava\DNSSEC.java`

**Key Methods**:
  - `ECKeyInfo()`
  - `ECKeyInfo()`
  - `ECKeyInfo()`
  - `Mnemonic()`
  - `Algorithm()`
  - `string()`
  - `value()`
  - `DNSSECException()`
  - `ECKeyInfo()`
  - `BigInteger()`
  - *(... and 152 more)*

---

### ExtendedResolver [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.ExtendedResolver`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Implements**: `Resolver`
- **Methods**: 35
- **Fields**: 45
- **Source**: `sdk\mdns\dnsjava\ExtendedResolver.java`

**Key Methods**:
  - `Resolution()`
  - `handleException()`
  - `if()`
  - `RuntimeException()`
  - `receiveMessage()`
  - `send()`
  - `start()`
  - `Object()`
  - `IllegalStateException()`
  - `startAsync()`
  - *(... and 25 more)*

---

### GPOSRecord [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.GPOSRecord`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Extends**: `Record`
- **Methods**: 22
- **Fields**: 5
- **Source**: `sdk\mdns\dnsjava\GPOSRecord.java`

**Key Methods**:
  - `GPOSRecord()`
  - `validate()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `getAltitude()`
  - `getAltitudeString()`
  - `getLatitude()`
  - `getLatitudeString()`
  - `getLongitude()`
  - `getLongitudeString()`
  - *(... and 12 more)*

---

### Header [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.Header`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Implements**: `Cloneable`
- **Methods**: 42
- **Fields**: 30
- **Source**: `sdk\mdns\dnsjava\Header.java`

**Key Methods**:
  - `Random()`
  - `Header()`
  - `checkFlag()`
  - `IllegalArgumentException()`
  - `init()`
  - `setFlag()`
  - `validFlag()`
  - `clone()`
  - `Header()`
  - `decCount()`
  - *(... and 32 more)*

---

### LOCRecord [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.LOCRecord`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Extends**: `Record`
- **Methods**: 29
- **Fields**: 37
- **Source**: `sdk\mdns\dnsjava\LOCRecord.java`

**Key Methods**:
  - `DecimalFormat()`
  - `DecimalFormat()`
  - `LOCRecord()`
  - `parseDouble()`
  - `parseFixedPoint()`
  - `NumberFormatException()`
  - `parseLOCformat()`
  - `WireParseException()`
  - `parsePosition()`
  - `if()`
  - *(... and 19 more)*

---

### Lookup [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.Lookup`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Methods**: 49
- **Fields**: 61
- **Source**: `sdk\mdns\dnsjava\Lookup.java`

**Key Methods**:
  - `Lookup()`
  - `IllegalArgumentException()`
  - `checkDone()`
  - `StringBuffer()`
  - `IllegalStateException()`
  - `follow()`
  - `ArrayList()`
  - `getDefaultCache()`
  - `Cache()`
  - `getDefaultResolver()`
  - *(... and 39 more)*

---

### Master [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.Master`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Methods**: 32
- **Fields**: 57
- **Source**: `sdk\mdns\dnsjava\Master.java`

**Key Methods**:
  - `Master()`
  - `RelativeNameException()`
  - `Tokenizer()`
  - `endGenerate()`
  - `nextGenerated()`
  - `parseName()`
  - `parseTTLClassAndType()`
  - `parseUInt32()`
  - `startGenerate()`
  - `Generator()`
  - *(... and 22 more)*

---

### Message [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.Message`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Implements**: `Cloneable`
- **Methods**: 52
- **Fields**: 92
- **Source**: `sdk\mdns\dnsjava\Message.java`

**Key Methods**:
  - `Message()`
  - `newQuery()`
  - `Message()`
  - `newUpdate()`
  - `Update()`
  - `sameSet()`
  - `sectionToWire()`
  - `addRecord()`
  - `LinkedList()`
  - `clone()`
  - *(... and 42 more)*

---

### MINFORecord [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.MINFORecord`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Extends**: `Record`
- **Methods**: 13
- **Fields**: 4
- **Source**: `sdk\mdns\dnsjava\MINFORecord.java`

**Key Methods**:
  - `MINFORecord()`
  - `getErrorAddress()`
  - `getObject()`
  - `MINFORecord()`
  - `getResponsibleAddress()`
  - `rdataFromString()`
  - `rrFromWire()`
  - `Name()`
  - `Name()`
  - `rrToString()`
  - *(... and 3 more)*

---

### Name [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.Name`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Implements**: `Comparable, Serializable`
- **Methods**: 93
- **Fields**: 170
- **Source**: `sdk\mdns\dnsjava\Name.java`

**Key Methods**:
  - `DecimalFormat()`
  - `Name()`
  - `Name()`
  - `Name()`
  - `Name()`
  - `append()`
  - `IllegalStateException()`
  - `NameTooLongException()`
  - `IllegalStateException()`
  - `appendFromString()`
  - *(... and 83 more)*

---

### Options [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.Options`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Methods**: 12
- **Fields**: 12
- **Source**: `sdk\mdns\dnsjava\Options.java`

**Key Methods**:
  - `Options()`
  - `check()`
  - `clear()`
  - `intValue()`
  - `refresh()`
  - `StringTokenizer()`
  - `set()`
  - `HashMap()`
  - `unset()`
  - `value()`
  - *(... and 2 more)*

---

### OPTRecord [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.OPTRecord`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Extends**: `Record`
- **Methods**: 21
- **Fields**: 10
- **Source**: `sdk\mdns\dnsjava\OPTRecord.java`

**Key Methods**:
  - `OPTRecord()`
  - `equals()`
  - `getExtendedRcode()`
  - `getFlags()`
  - `getObject()`
  - `OPTRecord()`
  - `getOptions()`
  - `getPayloadSize()`
  - `getVersion()`
  - `rdataFromString()`
  - *(... and 11 more)*

---

### Record [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.Record`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Implements**: `Cloneable, Comparable, Serializable`
- **Methods**: 94
- **Fields**: 66
- **Source**: `sdk\mdns\dnsjava\Record.java`

**Key Methods**:
  - `DecimalFormat()`
  - `Record()`
  - `byteArrayFromString()`
  - `ByteArrayOutputStream()`
  - `TextParseException()`
  - `if()`
  - `TextParseException()`
  - `if()`
  - `TextParseException()`
  - `TextParseException()`
  - *(... and 84 more)*

---

### ResolveThread [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.ResolveThread`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Extends**: `Thread`
- **Methods**: 2
- **Fields**: 4
- **Source**: `sdk\mdns\dnsjava\ResolveThread.java`

**Key Methods**:
  - `ResolveThread()`
  - `run()`

---

### RRset [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.RRset`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Implements**: `Serializable`
- **Methods**: 34
- **Fields**: 15
- **Source**: `sdk\mdns\dnsjava\RRset.java`

**Key Methods**:
  - `RRset()`
  - `ArrayList()`
  - `iterator()`
  - `if()`
  - `ArrayList()`
  - `iteratorToString()`
  - `StringBuffer()`
  - `safeAddRR()`
  - `if()`
  - `addRR()`
  - *(... and 24 more)*

---

### SimpleResolver [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.SimpleResolver`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Implements**: `Resolver`
- **Methods**: 40
- **Fields**: 40
- **Source**: `sdk\mdns\dnsjava\SimpleResolver.java`

**Key Methods**:
  - `SimpleResolver()`
  - `InetSocketAddress()`
  - `applyEDNS()`
  - `maxUDPSize()`
  - `parseMessage()`
  - `Message()`
  - `WireParseException()`
  - `sendAXFR()`
  - `Message()`
  - `WireParseException()`
  - *(... and 30 more)*

---

### SMIMEARecord [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.SMIMEARecord`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Extends**: `Record`
- **Methods**: 16
- **Fields**: 15
- **Source**: `sdk\mdns\dnsjava\SMIMEARecord.java`

**Key Methods**:
  - `CertificateUsage()`
  - `MatchingType()`
  - `Selector()`
  - `SMIMEARecord()`
  - `getCertificateAssociationData()`
  - `getCertificateUsage()`
  - `getMatchingType()`
  - `getObject()`
  - `SMIMEARecord()`
  - `getSelector()`
  - *(... and 6 more)*

---

### TCPClient [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.TCPClient`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Extends**: `Client`
- **Methods**: 15
- **Fields**: 21
- **Source**: `sdk\mdns\dnsjava\TCPClient.java`

**Key Methods**:
  - `TCPClient()`
  - `_recv()`
  - `EOFException()`
  - `SocketTimeoutException()`
  - `sendrecv()`
  - `TCPClient()`
  - `bind()`
  - `connect()`
  - `if()`
  - `recv()`
  - *(... and 5 more)*

---

### TLSARecord [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.TLSARecord`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Extends**: `Record`
- **Methods**: 16
- **Fields**: 15
- **Source**: `sdk\mdns\dnsjava\TLSARecord.java`

**Key Methods**:
  - `CertificateUsage()`
  - `MatchingType()`
  - `Selector()`
  - `TLSARecord()`
  - `getCertificateAssociationData()`
  - `getCertificateUsage()`
  - `getMatchingType()`
  - `getObject()`
  - `TLSARecord()`
  - `getSelector()`
  - *(... and 6 more)*

---

### TSIG [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.TSIG`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Methods**: 49
- **Fields**: 76
- **Source**: `sdk\mdns\dnsjava\TSIG.java`

**Key Methods**:
  - `StreamVerifier()`
  - `verify()`
  - `DNSOutput()`
  - `DNSOutput()`
  - `DNSOutput()`
  - `HashMap()`
  - `TSIG()`
  - `SecretKeySpec()`
  - `algorithmToName()`
  - `IllegalArgumentException()`
  - *(... and 39 more)*

---

### TypeBitmap [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.TypeBitmap`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Implements**: `Serializable`
- **Methods**: 16
- **Fields**: 26
- **Source**: `sdk\mdns\dnsjava\TypeBitmap.java`

**Key Methods**:
  - `TypeBitmap()`
  - `TreeSet()`
  - `mapToWire()`
  - `contains()`
  - `empty()`
  - `toArray()`
  - `toString()`
  - `StringBuffer()`
  - `toWire()`
  - `TreeSet()`
  - *(... and 6 more)*

---

### UDPClient [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.UDPClient`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Extends**: `Client`
- **Methods**: 16
- **Fields**: 18
- **Source**: `sdk\mdns\dnsjava\UDPClient.java`

**Key Methods**:
  - `SecureRandom()`
  - `Thread()`
  - `run()`
  - `UDPClient()`
  - `bind_random()`
  - `InetSocketAddress()`
  - `InetSocketAddress()`
  - `sendrecv()`
  - `UDPClient()`
  - `bind()`
  - *(... and 6 more)*

---

### WireParseException [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.WireParseException`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Extends**: `IOException`
- **Methods**: 3
- **Fields**: 0
- **Source**: `sdk\mdns\dnsjava\WireParseException.java`

**Key Methods**:
  - `WireParseException()`
  - `WireParseException()`
  - `WireParseException()`

---

### WKSRecord [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.WKSRecord`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Extends**: `Record`
- **Methods**: 23
- **Fields**: 146
- **Source**: `sdk\mdns\dnsjava\WKSRecord.java`

**Key Methods**:
  - `Mnemonic()`
  - `Protocol()`
  - `string()`
  - `value()`
  - `Mnemonic()`
  - `Service()`
  - `string()`
  - `value()`
  - `WKSRecord()`
  - `getAddress()`
  - *(... and 13 more)*

---

### Zone [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.dnsjava.Zone`
- **Package**: `com.thingclips.sdk.mdns.dnsjava`
- **Implements**: `Serializable`
- **Methods**: 64
- **Fields**: 84
- **Source**: `sdk\mdns\dnsjava\Zone.java`

**Key Methods**:
  - `ZoneIterator()`
  - `if()`
  - `hasNext()`
  - `next()`
  - `NoSuchElementException()`
  - `remove()`
  - `UnsupportedOperationException()`
  - `Zone()`
  - `TreeMap()`
  - `Master()`
  - *(... and 54 more)*

---

### DatagramProcessor [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.net.DatagramProcessor`
- **Package**: `com.thingclips.sdk.mdns.net`
- **Extends**: `NetworkProcessor`
- **Methods**: 17
- **Fields**: 24
- **Source**: `sdk\mdns\net\DatagramProcessor.java`

**Key Methods**:
  - `DatagramProcessor()`
  - `MulticastSocket()`
  - `DatagramSocket()`
  - `close()`
  - `finalize()`
  - `getMaxPayloadSize()`
  - `getTTL()`
  - `isLoopbackModeDisabled()`
  - `isMulticast()`
  - `isOperational()`
  - *(... and 7 more)*

---

### NetworkProcessor [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.net.NetworkProcessor`
- **Package**: `com.thingclips.sdk.mdns.net`
- **Implements**: `Runnable, Closeable`
- **Methods**: 17
- **Fields**: 27
- **Source**: `sdk\mdns\net\NetworkProcessor.java`

**Key Methods**:
  - `PacketRunner()`
  - `run()`
  - `NetworkProcessor()`
  - `close()`
  - `getAddress()`
  - `getInterfaceAddress()`
  - `getMTU()`
  - `getPort()`
  - `isIPv4()`
  - `isIPv6()`
  - *(... and 7 more)*

---

### UnicastProcessor [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.net.UnicastProcessor`
- **Package**: `com.thingclips.sdk.mdns.net`
- **Extends**: `NetworkProcessor`
- **Implements**: `Runnable`
- **Methods**: 10
- **Fields**: 16
- **Source**: `sdk\mdns\net\UnicastProcessor.java`

**Key Methods**:
  - `dataReceived()`
  - `UnicastRunner()`
  - `UnicastProcessor()`
  - `HashMap()`
  - `HashMap()`
  - `close()`
  - `run()`
  - `IOException()`
  - `Packet()`
  - `send()`

---

### ExecutionTimer [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.utils.ExecutionTimer`
- **Package**: `com.thingclips.sdk.mdns.utils`
- **Methods**: 6
- **Fields**: 7
- **Source**: `sdk\mdns\utils\ExecutionTimer.java`

**Key Methods**:
  - `ExecutionTimer()`
  - `Stack()`
  - `_start()`
  - `_took()`
  - `start()`
  - `took()`

---

### Executors [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.utils.Executors`
- **Package**: `com.thingclips.sdk.mdns.utils`
- **Methods**: 27
- **Fields**: 55
- **Source**: `sdk\mdns\utils\Executors.java`

**Key Methods**:
  - `Executors()`
  - `ThreadFactory()`
  - `newThread()`
  - `Thread()`
  - `ThreadPoolExecutor()`
  - `ThreadFactory()`
  - `newThread()`
  - `Thread()`
  - `RejectedExecutionHandler()`
  - `rejectedExecution()`
  - *(... and 17 more)*

---

### ListenerProcessor [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.utils.ListenerProcessor`
- **Package**: `com.thingclips.sdk.mdns.utils`
- **Extends**: `Exception`
- **Implements**: `Closeable`
- **Methods**: 11
- **Fields**: 31
- **Source**: `sdk\mdns\utils\ListenerProcessor.java`

**Key Methods**:
  - `Dispatcher()`
  - `invoke()`
  - `ListenerProcessor()`
  - `IllegalArgumentException()`
  - `LinkedHashSet()`
  - `Stack()`
  - `close()`
  - `getDispatcher()`
  - `Dispatcher()`
  - `registerListener()`
  - *(... and 1 more)*

---

### Misc [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.utils.Misc`
- **Package**: `com.thingclips.sdk.mdns.utils`
- **Methods**: 12
- **Fields**: 17
- **Source**: `sdk\mdns\utils\Misc.java`

**Key Methods**:
  - `close()`
  - `getLogger()`
  - `getLogger()`
  - `setGlobalLogLevel()`
  - `throwableToString()`
  - `StringWriter()`
  - `trimTrailingDot()`
  - `unescape()`
  - `StringBuilder()`
  - `if()`
  - *(... and 2 more)*

---

### Wait [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mdns.utils.Wait`
- **Package**: `com.thingclips.sdk.mdns.utils`
- **Methods**: 3
- **Fields**: 4
- **Source**: `sdk\mdns\utils\Wait.java`

**Key Methods**:
  - `forResponse()`
  - `waitTill()`
  - `forResponse()`

---

### bqbdbqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mqtt.bqbdbqb`
- **Package**: `com.thingclips.sdk.mqtt`
- **Methods**: 0
- **Fields**: 44
- **Source**: `thingclips\sdk\mqtt\bqbdbqb.java`

---

### dbpdpbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mqtt.dbpdpbp`
- **Package**: `com.thingclips.sdk.mqtt`
- **Extends**: `qqddbpb`
- **Methods**: 6
- **Fields**: 16
- **Source**: `thingclips\sdk\mqtt\dbpdpbp.java`

**Key Methods**:
  - `dbpdpbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qbpppdb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mqtt.qbpppdb`
- **Package**: `com.thingclips.sdk.mqtt`
- **Extends**: `qqddbpb`
- **Methods**: 6
- **Fields**: 16
- **Source**: `thingclips\sdk\mqtt\qbpppdb.java`

**Key Methods**:
  - `qbpppdb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### qdpppbq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mqtt.qdpppbq`
- **Package**: `com.thingclips.sdk.mqtt`
- **Implements**: `NetWorkStatusEvent, ForeGroundStatusEvent`
- **Methods**: 7
- **Fields**: 8
- **Source**: `thingclips\sdk\mqtt\qdpppbq.java`

**Key Methods**:
  - `deviceStatusOk()`
  - `qdpppbq()`
  - `bdpdqbp()`
  - `onEvent()`
  - `pdqppqb()`
  - `onEvent()`
  - `bdpdqbp()`

---

### qpqbppd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mqtt.qpqbppd`
- **Package**: `com.thingclips.sdk.mqtt`
- **Extends**: `SSLSocketFactory`
- **Methods**: 18
- **Fields**: 7
- **Source**: `thingclips\sdk\mqtt\qpqbppd.java`

**Key Methods**:
  - `qpqbppd()`
  - `bdpdqbp()`
  - `createSocket()`
  - `bdpdqbp()`
  - `getDefaultCipherSuites()`
  - `getSupportedCipherSuites()`
  - `createSocket()`
  - `bdpdqbp()`
  - `createSocket()`
  - `bdpdqbp()`
  - *(... and 8 more)*

---

### qqpppdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mqtt.qqpppdp`
- **Package**: `com.thingclips.sdk.mqtt`
- **Implements**: `IMqttToken`
- **Methods**: 26
- **Fields**: 20
- **Source**: `thingclips\sdk\mqtt\qqpppdp.java`

**Key Methods**:
  - `qqpppdp()`
  - `getActionCallback()`
  - `getClient()`
  - `getConnectMonitor()`
  - `getException()`
  - `getGrantedQos()`
  - `getMessageId()`
  - `getResponse()`
  - `getSessionPresent()`
  - `getTopics()`
  - *(... and 16 more)*

---

### ThingMqttPlugin [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mqtt.ThingMqttPlugin`
- **Package**: `com.thingclips.sdk.mqtt`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingMqttPlugin`
- **Methods**: 3
- **Fields**: 0
- **Source**: `thingclips\sdk\mqtt\ThingMqttPlugin.java`

**Key Methods**:
  - `dependencies()`
  - `getMqttServerInstance()`
  - `init()`

---

### MqttConfigBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mqttmanager.bean.MqttConfigBean`
- **Package**: `com.thingclips.sdk.mqttmanager.bean`
- **Methods**: 32
- **Fields**: 24
- **Source**: `sdk\mqttmanager\bean\MqttConfigBean.java`

**Key Methods**:
  - `ArrayList()`
  - `ArrayList()`
  - `isQuic()`
  - `isSsl()`
  - `toString()`
  - `StringBuilder()`
  - `getClientId()`
  - `getKeepAlive()`
  - `getMaxInflight()`
  - `getQos()`
  - *(... and 22 more)*

---

### bdpdqbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.mqttmanager.model.bdpdqbp`
- **Package**: `com.thingclips.sdk.mqttmanager.model`
- **Implements**: `pqdbppq`
- **Methods**: 48
- **Fields**: 46
- **Source**: `sdk\mqttmanager\model\bdpdqbp.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `C0188bdpdqbp()`
  - `verify()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - *(... and 38 more)*

---

### qddqppb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.network.qddqppb`
- **Package**: `com.thingclips.sdk.network`
- **Methods**: 5
- **Fields**: 28
- **Source**: `thingclips\sdk\network\qddqppb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `if()`
  - `JSONObject()`

---

### ThingApiSignManager [MEDIUM]


- **Full Name**: `com.thingclips.sdk.network.ThingApiSignManager`
- **Package**: `com.thingclips.sdk.network`
- **Methods**: 10
- **Fields**: 14
- **Source**: `thingclips\sdk\network\ThingApiSignManager.java`

**Key Methods**:
  - `generateSignature()`
  - `generateSignatureSdk()`
  - `generateSignatureSdk()`
  - `LinkedList()`
  - `StringBuilder()`
  - `getRequestKeyBySorted()`
  - `LinkedList()`
  - `getUrlWithQueryString()`
  - `postDataMD5Hex()`
  - `swapSignString()`

---

### ThingNetworkSecurity [MEDIUM]


- **Full Name**: `com.thingclips.sdk.network.ThingNetworkSecurity`
- **Package**: `com.thingclips.sdk.network`
- **Methods**: 9
- **Fields**: 8
- **Source**: `thingclips\sdk\network\ThingNetworkSecurity.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `computeDigest()`
  - `doCommandNative()`
  - `encryptPostData()`
  - `genKey()`
  - `getChKey()`
  - `getContext()`
  - `getEncryptoKey()`
  - `initJNI()`

---

### ThingOtaPlugin [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ota.ThingOtaPlugin`
- **Package**: `com.thingclips.sdk.ota`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingOtaPlugin`
- **Methods**: 4
- **Fields**: 0
- **Source**: `thingclips\sdk\ota\ThingOtaPlugin.java`

**Key Methods**:
  - `dependencies()`
  - `init()`
  - `newOTAInstance()`
  - `newOTAInstance()`

---

### ThingOtaServicePlugin [MEDIUM]


- **Full Name**: `com.thingclips.sdk.ota_service.ThingOtaServicePlugin`
- **Package**: `com.thingclips.sdk.ota_service`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingOtaServicePlugin`
- **Methods**: 4
- **Fields**: 0
- **Source**: `thingclips\sdk\ota_service\ThingOtaServicePlugin.java`

**Key Methods**:
  - `dependencies()`
  - `init()`
  - `newOTAServiceInstance()`
  - `qdddqdp()`

---

### ThingOSActivator [MEDIUM]


- **Full Name**: `com.thingclips.sdk.p000os.ThingOSActivator`
- **Package**: `com.thingclips.sdk.p000os`
- **Methods**: 2
- **Fields**: 4
- **Source**: `thingclips\sdk\p000os\ThingOSActivator.java`

**Key Methods**:
  - `activator()`
  - `deviceActivator()`

---

### ThingOSDevice [MEDIUM]


- **Full Name**: `com.thingclips.sdk.p000os.ThingOSDevice`
- **Package**: `com.thingclips.sdk.p000os`
- **Methods**: 12
- **Fields**: 24
- **Source**: `thingclips\sdk\p000os\ThingOSDevice.java`

**Key Methods**:
  - `closeService()`
  - `getBatchExecutionManager()`
  - `getDataInstance()`
  - `getDeviceBean()`
  - `getDeviceOperator()`
  - `getRequestInstance()`
  - `getWifiBackupManager()`
  - `getWifiSwitchManager()`
  - `newDeviceInstance()`
  - `newGatewayInstance()`
  - *(... and 2 more)*

---

### ThingOSGroup [MEDIUM]


- **Full Name**: `com.thingclips.sdk.p000os.ThingOSGroup`
- **Package**: `com.thingclips.sdk.p000os`
- **Methods**: 6
- **Fields**: 14
- **Source**: `thingclips\sdk\p000os\ThingOSGroup.java`

**Key Methods**:
  - `getGroupBean()`
  - `newGroupInstance()`
  - `newWifiGroupInstance()`
  - `newZigbeeGroupInstance()`
  - `newWifiGroupInstance()`
  - `newZigbeeGroupInstance()`

---

### ThingOSMultiControl [MEDIUM]


- **Full Name**: `com.thingclips.sdk.p000os.ThingOSMultiControl`
- **Package**: `com.thingclips.sdk.p000os`
- **Methods**: 1
- **Fields**: 3
- **Source**: `thingclips\sdk\p000os\ThingOSMultiControl.java`

**Key Methods**:
  - `getDeviceMultiControlInstance()`

---

### ThingOSScene [MEDIUM]


- **Full Name**: `com.thingclips.sdk.p000os.ThingOSScene`
- **Package**: `com.thingclips.sdk.p000os`
- **Methods**: 2
- **Fields**: 5
- **Source**: `thingclips\sdk\p000os\ThingOSScene.java`

**Key Methods**:
  - `getSceneManagerInstance()`
  - `newSceneInstance()`

---

### ThingOSTimer [MEDIUM]


- **Full Name**: `com.thingclips.sdk.p000os.ThingOSTimer`
- **Package**: `com.thingclips.sdk.p000os`
- **Methods**: 1
- **Fields**: 2
- **Source**: `thingclips\sdk\p000os\ThingOSTimer.java`

**Key Methods**:
  - `getTimerInstance()`

---

### ThingOSUser [MEDIUM]


- **Full Name**: `com.thingclips.sdk.p000os.ThingOSUser`
- **Package**: `com.thingclips.sdk.p000os`
- **Methods**: 1
- **Fields**: 2
- **Source**: `thingclips\sdk\p000os\ThingOSUser.java`

**Key Methods**:
  - `getUserInstance()`

---

### C0049R [MEDIUM]


- **Full Name**: `com.thingclips.sdk.p001yu.api.C0049R`
- **Package**: `com.thingclips.sdk.p001yu.api`
- **Methods**: 17
- **Fields**: 5916
- **Source**: `sdk\p001yu\api\C0049R.java`

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
  - *(... and 7 more)*

---

### IYuChannel [MEDIUM]


- **Full Name**: `com.thingclips.sdk.p001yu.api.IYuChannel`
- **Package**: `com.thingclips.sdk.p001yu.api`
- **Methods**: 6
- **Fields**: 0
- **Source**: `sdk\p001yu\api\IYuChannel.java`

**Key Methods**:
  - `getStatus()`
  - `onlineStatusChanged()`
  - `release()`
  - `report()`
  - `send()`
  - `start()`

---

### ThingPersonalPlugin [MEDIUM]


- **Full Name**: `com.thingclips.sdk.personal.ThingPersonalPlugin`
- **Package**: `com.thingclips.sdk.personal`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingPersonalCenterPlugin`
- **Methods**: 5
- **Fields**: 0
- **Source**: `thingclips\sdk\personal\ThingPersonalPlugin.java`

**Key Methods**:
  - `dependencies()`
  - `getMessageInstance()`
  - `getPushInstance()`
  - `getThingFeekback()`
  - `init()`

---

### bpbbqdb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.personallib.bpbbqdb`
- **Package**: `com.thingclips.sdk.personallib`
- **Implements**: `IThingPush, IDeviceMqttProtocolListener`
- **Methods**: 57
- **Fields**: 36
- **Source**: `thingclips\sdk\personallib\bpbbqdb.java`

**Key Methods**:
  - `dpdbqdp()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 47 more)*

---

### bppdpdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.personallib.bppdpdq`
- **Package**: `com.thingclips.sdk.personallib`
- **Methods**: 11
- **Fields**: 35
- **Source**: `thingclips\sdk\personallib\bppdpdq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `ContentValues()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `FeedbackMsgBean()`
  - *(... and 1 more)*

---

### dpdbqdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.personallib.dpdbqdp`
- **Package**: `com.thingclips.sdk.personallib`
- **Extends**: `Business`
- **Implements**: `Business.ResultListener<JSONObject>`
- **Methods**: 12
- **Fields**: 18
- **Source**: `thingclips\sdk\personallib\dpdbqdp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - *(... and 2 more)*

---

### pbbppqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.personallib.pbbppqb`
- **Package**: `com.thingclips.sdk.personallib`
- **Implements**: `IThingFeedback`
- **Methods**: 5
- **Fields**: 4
- **Source**: `thingclips\sdk\personallib\pbbppqb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pbbppqb()`
  - `getFeedbackManager()`
  - `getFeedbackMsg()`
  - `pbddddb()`

---

### pdqppqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.personallib.pdqppqb`
- **Package**: `com.thingclips.sdk.personallib`
- **Methods**: 1
- **Fields**: 8
- **Source**: `thingclips\sdk\personallib\pdqppqb.java`

**Key Methods**:
  - `feedback()`

---

### pppbppp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.personallib.pppbppp`
- **Package**: `com.thingclips.sdk.personallib`
- **Extends**: `BaseModel`
- **Implements**: `Business.ResultListener<FeedbackMsgListBean>`
- **Methods**: 22
- **Fields**: 18
- **Source**: `thingclips\sdk\personallib\pppbppp.java`

**Key Methods**:
  - `RunnableC0190bdpdqbp()`
  - `run()`
  - `RunnableC0189bdpdqbp()`
  - `run()`
  - `Handler()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - *(... and 12 more)*

---

### pqdbppq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.personallib.pqdbppq`
- **Package**: `com.thingclips.sdk.personallib`
- **Extends**: `Business`
- **Methods**: 10
- **Fields**: 12
- **Source**: `thingclips\sdk\personallib\pqdbppq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `ApiParams()`
  - `onDestroy()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `ApiParams()`

---

### qpppdqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.personallib.qpppdqb`
- **Package**: `com.thingclips.sdk.personallib`
- **Implements**: `IThingFeedbackManager`
- **Methods**: 16
- **Fields**: 9
- **Source**: `thingclips\sdk\personallib\qpppdqb.java`

**Key Methods**:
  - `pbpdbqp()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 6 more)*

---

### qqpdpbp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.personallib.qqpdpbp`
- **Package**: `com.thingclips.sdk.personallib`
- **Implements**: `IThingMessage`
- **Methods**: 111
- **Fields**: 89
- **Source**: `thingclips\sdk\personallib\qqpdpbp.java`

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
  - *(... and 101 more)*

---

### ThingScenePlugin [MEDIUM]


- **Full Name**: `com.thingclips.sdk.scene.ThingScenePlugin`
- **Package**: `com.thingclips.sdk.scene`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingScenePlugin`
- **Methods**: 5
- **Fields**: 0
- **Source**: `thingclips\sdk\scene\ThingScenePlugin.java`

**Key Methods**:
  - `dependencies()`
  - `getSceneManagerInstance()`
  - `init()`
  - `newSceneInstance()`
  - `onDestroy()`

---

### CovertCompatUtil [MEDIUM]


- **Full Name**: `com.thingclips.sdk.scene.utils.CovertCompatUtil`
- **Package**: `com.thingclips.sdk.scene.utils`
- **Methods**: 62
- **Fields**: 93
- **Source**: `sdk\scene\utils\CovertCompatUtil.java`

**Key Methods**:
  - `actionDeviceDataPointDetailListToFunctionDataPointList()`
  - `ArrayList()`
  - `FunctionDataPoint()`
  - `actionDeviceDataPointListToFunctionList()`
  - `ArrayList()`
  - `FunctionListBean()`
  - `actionDeviceGroupToSceneTaskGroupDevice()`
  - `SceneTaskGroupDevice()`
  - `HashMap()`
  - `HashMap()`
  - *(... and 52 more)*

---

### dpdbqdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.scenelib.dpdbqdp`
- **Package**: `com.thingclips.sdk.scenelib`
- **Implements**: `Runnable`
- **Methods**: 14
- **Fields**: 11
- **Source**: `thingclips\sdk\scenelib\dpdbqdp.java`

**Key Methods**:
  - `C0193bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `run()`
  - `CountDownLatch()`
  - `C0193bdpdqbp()`
  - `HashMap()`
  - `dpdbqdp()`
  - `bdpdqbp()`
  - *(... and 4 more)*

---

### pbddddb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.scenelib.pbddddb`
- **Package**: `com.thingclips.sdk.scenelib`
- **Implements**: `IDeviceMqttProtocolListener<MQ_205_AddZigbeeSceneBean>`
- **Methods**: 23
- **Fields**: 31
- **Source**: `thingclips\sdk\scenelib\pbddddb.java`

**Key Methods**:
  - `Handler()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `handleMessage()`
  - `LocalSceneResultBean()`
  - `HashMap()`
  - `pdqppqb()`
  - *(... and 13 more)*

---

### pbpdpdp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.scenelib.pbpdpdp`
- **Package**: `com.thingclips.sdk.scenelib`
- **Extends**: `BasePresenter`
- **Implements**: `IThingZigBeeLocalScene`
- **Methods**: 30
- **Fields**: 20
- **Source**: `thingclips\sdk\scenelib\pbpdpdp.java`

**Key Methods**:
  - `ArrayList()`
  - `HashMap()`
  - `bdpdqbp()`
  - `onLocalSceneConfigSuccess()`
  - `bppdpdq()`
  - `onLocalSceneConfigSuccess()`
  - `pdqppqb()`
  - `onLocalSceneConfigSuccess()`
  - `qddqppb()`
  - `onLocalSceneConfigSuccess()`
  - *(... and 20 more)*

---

### qddqppb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.scenelib.qddqppb`
- **Package**: `com.thingclips.sdk.scenelib`
- **Extends**: `TypeReference<LinkedHashMap<String`
- **Implements**: `IDevListener`
- **Methods**: 20
- **Fields**: 25
- **Source**: `thingclips\sdk\scenelib\qddqppb.java`

**Key Methods**:
  - `Handler()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `handleMessage()`
  - `qddqppb()`
  - `ArrayList()`
  - *(... and 10 more)*

---

### EncryptionManager [MEDIUM]


- **Full Name**: `com.thingclips.sdk.security.EncryptionManager`
- **Package**: `com.thingclips.sdk.security`
- **Extends**: `GeneralSecurityException`
- **Methods**: 56
- **Fields**: 63
- **Source**: `thingclips\sdk\security\EncryptionManager.java`

**Key Methods**:
  - `InvalidMacException()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `bdpdqbp()`
  - *(... and 46 more)*

---

### SecuredStore [MEDIUM]


- **Full Name**: `com.thingclips.sdk.security.SecuredStore`
- **Package**: `com.thingclips.sdk.security`
- **Methods**: 8
- **Fields**: 14
- **Source**: `thingclips\sdk\security\SecuredStore.java`

**Key Methods**:
  - `getBitshiftingKey()`
  - `getSecurityKey()`
  - `JSONObject()`
  - `init()`
  - `pppbppp()`
  - `isInited()`
  - `securityUserKey()`
  - `getSecurityKey()`

---

### ThingTimerPlugin [MEDIUM]


- **Full Name**: `com.thingclips.sdk.timer.ThingTimerPlugin`
- **Package**: `com.thingclips.sdk.timer`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingTimerPlugin`
- **Methods**: 5
- **Fields**: 0
- **Source**: `thingclips\sdk\timer\ThingTimerPlugin.java`

**Key Methods**:
  - `dependencies()`
  - `getInstance()`
  - `getThingSmartTimer()`
  - `getTimerInstance()`
  - `init()`

---

### DpTimerBean [MEDIUM]


- **Full Name**: `com.thingclips.sdk.timer.bean.DpTimerBean`
- **Package**: `com.thingclips.sdk.timer.bean`
- **Methods**: 16
- **Fields**: 11
- **Source**: `sdk\timer\bean\DpTimerBean.java`

**Key Methods**:
  - `getAliasName()`
  - `getDate()`
  - `getDpId()`
  - `getDps()`
  - `getLoops()`
  - `getStatus()`
  - `getTime()`
  - `isAppPush()`
  - `isEnabled()`
  - `setAliasName()`
  - *(... and 6 more)*

---

### bppdpdq [MEDIUM]


- **Full Name**: `com.thingclips.sdk.user.bppdpdq`
- **Package**: `com.thingclips.sdk.user`
- **Implements**: `IUser, IClearable`
- **Methods**: 11
- **Fields**: 3
- **Source**: `thingclips\sdk\user\bppdpdq.java`

**Key Methods**:
  - `bppdpdq()`
  - `bppdpdq()`
  - `bdpdqbp()`
  - `getUser()`
  - `isLogin()`
  - `onDestroy()`
  - `removeUser()`
  - `saveUser()`
  - `bppdpdq()`
  - `bpqqdpq()`
  - *(... and 1 more)*

---

### dqdbbqp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.user.dqdbbqp`
- **Package**: `com.thingclips.sdk.user`
- **Extends**: `com.thingclips.sdk.user.bpbbqdb`
- **Implements**: `Business.ResultListener<TokenBean>`
- **Methods**: 237
- **Fields**: 183
- **Source**: `thingclips\sdk\user\dqdbbqp.java`

**Key Methods**:
  - `C0200bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `C0200bdpdqbp()`
  - `bdqqbqd()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 227 more)*

---

### dqdpbbd [MEDIUM]


- **Full Name**: `com.thingclips.sdk.user.dqdpbbd`
- **Package**: `com.thingclips.sdk.user`
- **Implements**: `IClearable`
- **Methods**: 17
- **Fields**: 11
- **Source**: `thingclips\sdk\user\dqdpbbd.java`

**Key Methods**:
  - `pbpdbqp()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 7 more)*

---

### pbbppqb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.user.pbbppqb`
- **Package**: `com.thingclips.sdk.user`
- **Implements**: `IUserHighwayPlugin, IClearable`
- **Methods**: 6
- **Fields**: 2
- **Source**: `thingclips\sdk\user\pbbppqb.java`

**Key Methods**:
  - `pbbppqb()`
  - `bdpdqbp()`
  - `onDestroy()`
  - `requestHighwayToken()`
  - `pbbppqb()`
  - `qqdbbpp()`

---

### pbddddb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.user.pbddddb`
- **Package**: `com.thingclips.sdk.user`
- **Implements**: `IUserRegionPlugin, IClearable`
- **Methods**: 6
- **Fields**: 2
- **Source**: `thingclips\sdk\user\pbddddb.java`

**Key Methods**:
  - `pbddddb()`
  - `bdpdqbp()`
  - `getRegionListWithCountryCode()`
  - `onDestroy()`
  - `pbddddb()`
  - `pqpbpqd()`

---

### pppbppp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.user.pppbppp`
- **Package**: `com.thingclips.sdk.user`
- **Implements**: `IUserGeneralBusiness, IClearable`
- **Methods**: 8
- **Fields**: 3
- **Source**: `thingclips\sdk\user\pppbppp.java`

**Key Methods**:
  - `pppbppp()`
  - `bdpdqbp()`
  - `bindMobile()`
  - `onDestroy()`
  - `sendBindVerifyCode()`
  - `sendBindVerifyCodeByTicket()`
  - `pppbppp()`
  - `dqdpbbd()`

---

### qddqppb [MEDIUM]


- **Full Name**: `com.thingclips.sdk.user.qddqppb`
- **Package**: `com.thingclips.sdk.user`
- **Implements**: `IUserDomainPlugin, IClearable`
- **Methods**: 10
- **Fields**: 3
- **Source**: `thingclips\sdk\user\qddqppb.java`

**Key Methods**:
  - `qddqppb()`
  - `qddqppb()`
  - `bdpdqbp()`
  - `onDestroy()`
  - `queryAllBizDomains()`
  - `queryAllBizDomainsFromCache()`
  - `queryDomainByBizCodeAndKey()`
  - `queryDomainByBizCodeAndKeyFromCache()`
  - `qddqppb()`
  - `pqpbpqd()`

---

### qqdbbpp [MEDIUM]


- **Full Name**: `com.thingclips.sdk.user.qqdbbpp`
- **Package**: `com.thingclips.sdk.user`
- **Implements**: `IClearable`
- **Methods**: 6
- **Fields**: 4
- **Source**: `thingclips\sdk\user\qqdbbpp.java`

**Key Methods**:
  - `pbpdbqp()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `onDestroy()`

---

### ThingBaseUserPlugin [MEDIUM]


- **Full Name**: `com.thingclips.sdk.user.ThingBaseUserPlugin`
- **Package**: `com.thingclips.sdk.user`
- **Extends**: `AbstractComponentService`
- **Implements**: `IBaseUser`
- **Methods**: 11
- **Fields**: 13
- **Source**: `thingclips\sdk\user\ThingBaseUserPlugin.java`

**Key Methods**:
  - `getUser()`
  - `dependencies()`
  - `getDomain()`
  - `getEcode()`
  - `getPartnerIdentity()`
  - `getSid()`
  - `getUid()`
  - `init()`
  - `isLogin()`
  - `phoneCode()`
  - *(... and 1 more)*

---

### ThingUserAggregationManager [MEDIUM]


- **Full Name**: `com.thingclips.sdk.user.ThingUserAggregationManager`
- **Package**: `com.thingclips.sdk.user`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingUserAggregationPlugin`
- **Methods**: 7
- **Fields**: 0
- **Source**: `thingclips\sdk\user\ThingUserAggregationManager.java`

**Key Methods**:
  - `dependencies()`
  - `getUserCommonManager()`
  - `getUserCoreManager()`
  - `getUserDomainManager()`
  - `getUserHighwayManager()`
  - `getUserRegionManager()`
  - `init()`

---

### ThingUserDecoratorPlugin [MEDIUM]


- **Full Name**: `com.thingclips.sdk.user.ThingUserDecoratorPlugin`
- **Package**: `com.thingclips.sdk.user`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingUserPlugin`
- **Methods**: 13
- **Fields**: 1
- **Source**: `thingclips\sdk\user\ThingUserDecoratorPlugin.java`

**Key Methods**:
  - `getListenerPlugin()`
  - `dependencies()`
  - `getCancelAccountListeners()`
  - `getListenerPlugin()`
  - `getLoginSuccessListeners()`
  - `getListenerPlugin()`
  - `getLogoutSuccessListeners()`
  - `getListenerPlugin()`
  - `getUserInstance()`
  - `init()`
  - *(... and 3 more)*

---

### ThingUserListenerPlugin [MEDIUM]


- **Full Name**: `com.thingclips.sdk.user.ThingUserListenerPlugin`
- **Package**: `com.thingclips.sdk.user`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingUserListenerPlugin`
- **Methods**: 11
- **Fields**: 3
- **Source**: `thingclips\sdk\user\ThingUserListenerPlugin.java`

**Key Methods**:
  - `ArrayList()`
  - `ArrayList()`
  - `ArrayList()`
  - `dependencies()`
  - `getCancelAccountListeners()`
  - `getLoginSuccessListeners()`
  - `getLogoutSuccessListeners()`
  - `init()`
  - `registerCancelAccountListener()`
  - `registerLoginSuccessListener()`
  - *(... and 1 more)*

---

### IUser [MEDIUM]


- **Full Name**: `com.thingclips.sdk.user.model.IUser`
- **Package**: `com.thingclips.sdk.user.model`
- **Methods**: 4
- **Fields**: 0
- **Source**: `sdk\user\model\IUser.java`

**Key Methods**:
  - `getUser()`
  - `isLogin()`
  - `removeUser()`
  - `saveUser()`

---

### ApiParams [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.base.ApiParams`
- **Package**: `com.thingclips.smart.android.base`
- **Extends**: `ThingApiParams`
- **Methods**: 9
- **Fields**: 8
- **Source**: `smart\android\base\ApiParams.java`

**Key Methods**:
  - `ApiParams()`
  - `getEcode()`
  - `getRequestBody()`
  - `getSession()`
  - `getUrlParams()`
  - `initUrlParams()`
  - `setBizDM()`
  - `setCtId()`
  - `ApiParams()`

---

### NetworkBroadcastReceiver [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.base.broadcast.NetworkBroadcastReceiver`
- **Package**: `com.thingclips.smart.android.base.broadcast`
- **Extends**: `BroadcastReceiver`
- **Methods**: 6
- **Fields**: 4
- **Source**: `android\base\broadcast\NetworkBroadcastReceiver.java`

**Key Methods**:
  - `NetworkBroadcastReceiver()`
  - `InstanceHolder()`
  - `registerReceiver()`
  - `IntentFilter()`
  - `unregisterReceiver()`
  - `onReceive()`

---

### NetWorkStatusEventModel [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.base.event.NetWorkStatusEventModel`
- **Package**: `com.thingclips.smart.android.base.event`
- **Methods**: 3
- **Fields**: 1
- **Source**: `android\base\event\NetWorkStatusEventModel.java`

**Key Methods**:
  - `NetWorkStatusEventModel()`
  - `isAvailable()`
  - `setIsAvailable()`

---

### ThingEventBus [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.base.event.ThingEventBus`
- **Package**: `com.thingclips.smart.android.base.event`
- **Methods**: 7
- **Fields**: 2
- **Source**: `android\base\event\ThingEventBus.java`

**Key Methods**:
  - `ThingEventBus()`
  - `post()`
  - `register()`
  - `registerSticky()`
  - `unregister()`
  - `register()`
  - `registerSticky()`

---

### DomainHelper [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.base.provider.DomainHelper`
- **Package**: `com.thingclips.smart.android.base.provider`
- **Methods**: 8
- **Fields**: 20
- **Source**: `android\base\provider\DomainHelper.java`

**Key Methods**:
  - `loadDomainsFormAssets()`
  - `String()`
  - `IllegalArgumentException()`
  - `HashMap()`
  - `RuntimeException()`
  - `RuntimeException()`
  - `parseDomainsConfig()`
  - `setSslPinningUrls()`

---

### UserPreferenceUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.base.utils.UserPreferenceUtil`
- **Package**: `com.thingclips.smart.android.base.utils`
- **Methods**: 14
- **Fields**: 18
- **Source**: `android\base\utils\UserPreferenceUtil.java`

**Key Methods**:
  - `ReentrantReadWriteLock()`
  - `clear()`
  - `getMMKV()`
  - `if()`
  - `getString()`
  - `migrateDir()`
  - `StringBuilder()`
  - `File()`
  - `File()`
  - `File()`
  - *(... and 4 more)*

---

### IThingBleCommRodCtrl [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.IThingBleCommRodCtrl`
- **Package**: `com.thingclips.smart.android.ble`
- **Methods**: 8
- **Fields**: 0
- **Source**: `smart\android\ble\IThingBleCommRodCtrl.java`

**Key Methods**:
  - `connect()`
  - `destroy()`
  - `disconnect()`
  - `isConnected()`
  - `publishDps()`
  - `reConnect()`
  - `registerDevListener()`
  - `registerSchemaListener()`

---

### IThingBleController [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.IThingBleController`
- **Package**: `com.thingclips.smart.android.ble`
- **Methods**: 16
- **Fields**: 0
- **Source**: `smart\android\ble\IThingBleController.java`

**Key Methods**:
  - `activator()`
  - `activator()`
  - `disconnectDevice()`
  - `getDeviceInfo()`
  - `getDeviceSecurityFlag()`
  - `getDeviceSecurityLevel()`
  - `preConnect()`
  - `registerBleConnectStatusChange()`
  - `registerMultiModeDevStatusListener()`
  - `revChannel()`
  - *(... and 6 more)*

---

### IThingDeviceConnectManager [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.IThingDeviceConnectManager`
- **Package**: `com.thingclips.smart.android.ble`
- **Methods**: 2
- **Fields**: 0
- **Source**: `smart\android\ble\IThingDeviceConnectManager.java`

**Key Methods**:
  - `connectDeviceWithCallback()`
  - `disconnectDevice()`

---

### IThingFittings [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.IThingFittings`
- **Package**: `com.thingclips.smart.android.ble`
- **Methods**: 4
- **Fields**: 0
- **Source**: `smart\android\ble\IThingFittings.java`

**Key Methods**:
  - `handleFittingsData()`
  - `registerFittingsListener()`
  - `sendFittingsData()`
  - `unregisterFittingsListener()`

---

### IThingLEAudioManager [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.IThingLEAudioManager`
- **Package**: `com.thingclips.smart.android.ble`
- **Methods**: 12
- **Fields**: 0
- **Source**: `smart\android\ble\IThingLEAudioManager.java`

**Key Methods**:
  - `getLEAudioAuthorizationToken()`
  - `publishLEAudioAlarmClockSettings()`
  - `publishLEAudioCommonCommand()`
  - `publishLEAudioEndpoint()`
  - `publishLEAudioProvideSpeech()`
  - `publishLEAudioResult()`
  - `publishLEAudioSpeechState()`
  - `publishLEAudioStartSpeech()`
  - `publishLEAudioStopSpeech()`
  - `publishLEAudioTokenDelivery()`
  - *(... and 2 more)*

---

### ActivateBLEDeviceListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.ActivateBLEDeviceListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 3
- **Fields**: 0
- **Source**: `android\ble\api\ActivateBLEDeviceListener.java`

**Key Methods**:
  - `onActivateFail()`
  - `onActivateSuccess()`
  - `onFinish()`

---

### AddGwSubDeviceListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.AddGwSubDeviceListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 4
- **Fields**: 0
- **Source**: `android\ble\api\AddGwSubDeviceListener.java`

**Key Methods**:
  - `onAddFail()`
  - `onAddSuccess()`
  - `onError()`
  - `onFinish()`

---

### BeaconAuthBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.BeaconAuthBean`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 16
- **Fields**: 20
- **Source**: `android\ble\api\BeaconAuthBean.java`

**Key Methods**:
  - `getCmd()`
  - `getDevId()`
  - `getGroup()`
  - `getMac()`
  - `getS1()`
  - `getType()`
  - `isResult()`
  - `setCmd()`
  - `setDevId()`
  - `setGroup()`
  - *(... and 6 more)*

---

### BleConnectStatusListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.BleConnectStatusListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 3
- **Source**: `android\ble\api\BleConnectStatusListener.java`

**Key Methods**:
  - `onConnectStatusChanged()`

---

### BleControllerBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.BleControllerBean`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 0
- **Fields**: 18
- **Source**: `android\ble\api\BleControllerBean.java`

---

### BleControllerUpdateBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.BleControllerUpdateBean`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 0
- **Fields**: 5
- **Source**: `android\ble\api\BleControllerUpdateBean.java`

---

### BleLogCallback [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.BleLogCallback`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\BleLogCallback.java`

**Key Methods**:
  - `onLogPrint()`

---

### BleRssiListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.BleRssiListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\BleRssiListener.java`

**Key Methods**:
  - `onResult()`

---

### BleScanResponse [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.BleScanResponse`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\BleScanResponse.java`

**Key Methods**:
  - `onResult()`

---

### BleWiFiDeviceBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.BleWiFiDeviceBean`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 0
- **Fields**: 22
- **Source**: `android\ble\api\BleWiFiDeviceBean.java`

---

### ChannelDataConstants [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.ChannelDataConstants`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 0
- **Fields**: 10
- **Source**: `android\ble\api\ChannelDataConstants.java`

---

### CheckResultBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.CheckResultBean`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 6
- **Fields**: 3
- **Source**: `android\ble\api\CheckResultBean.java`

**Key Methods**:
  - `getBusinessCode()`
  - `getEncryptedKey()`
  - `getRandom()`
  - `setBusinessCode()`
  - `setEncryptedKey()`
  - `setRandom()`

---

### CombosFlagCapability [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.CombosFlagCapability`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 0
- **Fields**: 3
- **Source**: `android\ble\api\CombosFlagCapability.java`

---

### ConfigErrorBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.ConfigErrorBean`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 0
- **Fields**: 6
- **Source**: `android\ble\api\ConfigErrorBean.java`

---

### DataChannelListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.DataChannelListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\ble\api\DataChannelListener.java`

**Key Methods**:
  - `onFail()`
  - `onSuccess()`

---

### DataCustom2ChannelListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.DataCustom2ChannelListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Extends**: `DataCustomChannelListener`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\ble\api\DataCustom2ChannelListener.java`

**Key Methods**:
  - `onDpsReceived()`
  - `onUploadProgress()`

---

### DataCustomChannelListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.DataCustomChannelListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Implements**: `DataChannelListener`
- **Methods**: 3
- **Fields**: 0
- **Source**: `android\ble\api\DataCustomChannelListener.java`

**Key Methods**:
  - `onDataFinish()`
  - `onProgress()`
  - `onSuccess()`

---

### DeviceDataBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.DeviceDataBean`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 10
- **Fields**: 5
- **Source**: `android\ble\api\DeviceDataBean.java`

**Key Methods**:
  - `getData()`
  - `getFlag()`
  - `getPacketMaxSize()`
  - `getSub_cmd()`
  - `setData()`
  - `setFlag()`
  - `setPacketMaxSize()`
  - `setSub_cmd()`
  - `toString()`
  - `StringBuilder()`

---

### DevIotDataBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.DevIotDataBean`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 8
- **Fields**: 4
- **Source**: `android\ble\api\DevIotDataBean.java`

**Key Methods**:
  - `getData()`
  - `getPacketMaxSize()`
  - `getSubCmd()`
  - `getType()`
  - `setData()`
  - `setPacketMaxSize()`
  - `setSubCmd()`
  - `setType()`

---

### ExtModuleStatusListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.ExtModuleStatusListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\ExtModuleStatusListener.java`

**Key Methods**:
  - `onExtModuleStatusChange()`

---

### IBleThroughDataListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.IBleThroughDataListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\IBleThroughDataListener.java`

**Key Methods**:
  - `onDataReceive()`

---

### ICommRodSchemaListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.ICommRodSchemaListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\ICommRodSchemaListener.java`

**Key Methods**:
  - `updateSchemaMap()`

---

### IGetCustomHomeWeather [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.IGetCustomHomeWeather`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\IGetCustomHomeWeather.java`

**Key Methods**:
  - `getHomeWeather()`

---

### IGetCustomLocationWeather [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.IGetCustomLocationWeather`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\IGetCustomLocationWeather.java`

**Key Methods**:
  - `getLocationWeather()`

---

### IGetHomeWeather [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.IGetHomeWeather`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\IGetHomeWeather.java`

**Key Methods**:
  - `getHomeWeather()`

---

### IGetLocationWeather [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.IGetLocationWeather`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\IGetLocationWeather.java`

**Key Methods**:
  - `getLocationWeather()`

---

### IGetWeather [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.IGetWeather`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\ble\api\IGetWeather.java`

**Key Methods**:
  - `getCurrentLocationWeather()`
  - `getHomeLocationWeather()`

---

### IThingBleConfigListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.IThingBleConfigListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\ble\api\IThingBleConfigListener.java`

**Key Methods**:
  - `onFail()`
  - `onSuccess()`

---

### IThingBleGateway [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.IThingBleGateway`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 8
- **Fields**: 0
- **Source**: `android\ble\api\IThingBleGateway.java`

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

### LeConnectResponse [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.LeConnectResponse`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\LeConnectResponse.java`

**Key Methods**:
  - `onConnnectResult()`

---

### LeConnectStatusResponse [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.LeConnectStatusResponse`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\LeConnectStatusResponse.java`

**Key Methods**:
  - `onConnectStatusChanged()`

---

### LeScanSetting [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.LeScanSetting`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 15
- **Fields**: 15
- **Source**: `android\ble\api\LeScanSetting.java`

**Key Methods**:
  - `ArrayList()`
  - `addScanType()`
  - `build()`
  - `LeScanSetting()`
  - `IllegalArgumentException()`
  - `setNeedMatchUUID()`
  - `setRepeatFilter()`
  - `setTimeout()`
  - `setUUID()`
  - `getScanTypeList()`
  - *(... and 5 more)*

---

### LocalDataModel [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.LocalDataModel`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 0
- **Fields**: 2
- **Source**: `android\ble\api\LocalDataModel.java`

---

### OnBleActivatorListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.OnBleActivatorListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\ble\api\OnBleActivatorListener.java`

**Key Methods**:
  - `onConfigSuccess()`
  - `onError()`

---

### OnBleConnectListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.OnBleConnectListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\ble\api\OnBleConnectListener.java`

**Key Methods**:
  - `onFailure()`
  - `onSuccess()`

---

### OnBleDataTransferListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.OnBleDataTransferListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\OnBleDataTransferListener.java`

**Key Methods**:
  - `onReceive()`

---

### OnBleIoTChannelListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.OnBleIoTChannelListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\OnBleIoTChannelListener.java`

**Key Methods**:
  - `onReceive()`

---

### OnBleMultiModeDevStatusListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.OnBleMultiModeDevStatusListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\OnBleMultiModeDevStatusListener.java`

**Key Methods**:
  - `onActivatorStatusChanged()`

---

### OnBleRevChannelListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.OnBleRevChannelListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\ble\api\OnBleRevChannelListener.java`

**Key Methods**:
  - `onFailure()`
  - `onSuccess()`

---

### OnBleSendChannelListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.OnBleSendChannelListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\ble\api\OnBleSendChannelListener.java`

**Key Methods**:
  - `onFailure()`
  - `onSuccess()`

---

### OnBleToDeviceListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.OnBleToDeviceListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `android\ble\api\OnBleToDeviceListener.java`

**Key Methods**:
  - `onReceive()`

---

### OnBleUpgradeListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.OnBleUpgradeListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 3
- **Fields**: 0
- **Source**: `android\ble\api\OnBleUpgradeListener.java`

**Key Methods**:
  - `onFail()`
  - `onSuccess()`
  - `onUpgrade()`

---

### OnDataLocalProcessingListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.OnDataLocalProcessingListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\ble\api\OnDataLocalProcessingListener.java`

**Key Methods**:
  - `filterLocalProcessingData()`
  - `isBigDataLocalProcess()`

---

### OnDeviceAttributeListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.OnDeviceAttributeListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\ble\api\OnDeviceAttributeListener.java`

**Key Methods**:
  - `onError()`
  - `onReceive()`

---

### OnMultiModeActivatorStatusListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.OnMultiModeActivatorStatusListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Implements**: `OnBleMultiModeDevStatusListener`
- **Methods**: 3
- **Fields**: 1
- **Source**: `android\ble\api\OnMultiModeActivatorStatusListener.java`

**Key Methods**:
  - `onActivatorStatusChanged()`
  - `DeviceActivatorStatus()`
  - `onActivatorStatusChanged()`

---

### OnThirdConnectListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.OnThirdConnectListener`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 3
- **Fields**: 0
- **Source**: `android\ble\api\OnThirdConnectListener.java`

**Key Methods**:
  - `onConnectError()`
  - `onConnectedSuccess()`
  - `onDisconnect()`

---

### ResetErrorCode [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.ResetErrorCode`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 0
- **Fields**: 5
- **Source**: `android\ble\api\ResetErrorCode.java`

---

### ScanDeviceBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.ScanDeviceBean`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 36
- **Fields**: 18
- **Source**: `android\ble\api\ScanDeviceBean.java`

**Key Methods**:
  - `getAddress()`
  - `getConfigType()`
  - `getData()`
  - `getDeviceType()`
  - `getFlag()`
  - `getId()`
  - `getIsbind()`
  - `getMac()`
  - `getName()`
  - `getPidRaw()`
  - *(... and 26 more)*

**Notable Strings**:
  - `"', uuid='"`

---

### ThingBleScanResponse [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.ThingBleScanResponse`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Extends**: `BleScanResponse`
- **Methods**: 2
- **Fields**: 2
- **Source**: `android\ble\api\ThingBleScanResponse.java`

**Key Methods**:
  - `onScanStart()`
  - `onScanStop()`

---

### ThirdBleScanDeviceBuilder [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.ThirdBleScanDeviceBuilder`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 25
- **Fields**: 30
- **Source**: `android\ble\api\ThirdBleScanDeviceBuilder.java`

**Key Methods**:
  - `build()`
  - `RuntimeException()`
  - `RuntimeException()`
  - `RuntimeException()`
  - `ThirdBleScanDeviceBuilder()`
  - `setAddress()`
  - `setBindStatus()`
  - `setCustomData()`
  - `setName()`
  - `setProductId()`
  - *(... and 15 more)*

**Notable Strings**:
  - `"uuid is empty"`

---

### WatchWeatherBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.WatchWeatherBean`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Methods**: 10
- **Fields**: 5
- **Source**: `android\ble\api\WatchWeatherBean.java`

**Key Methods**:
  - `getConditionNum()`
  - `getTemp()`
  - `getTempHigh()`
  - `getTempLow()`
  - `setConditionNum()`
  - `setTemp()`
  - `setTempHigh()`
  - `setTempLow()`
  - `toString()`
  - `StringBuilder()`

---

### WiFiInfo [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.WiFiInfo`
- **Package**: `com.thingclips.smart.android.ble.api`
- **Implements**: `Serializable`
- **Methods**: 6
- **Fields**: 3
- **Source**: `android\ble\api\WiFiInfo.java`

**Key Methods**:
  - `getRssi()`
  - `getSec()`
  - `getSsid()`
  - `setRssi()`
  - `setSec()`
  - `setSsid()`

---

### AudioCommnonResponse [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.audio.AudioCommnonResponse`
- **Package**: `com.thingclips.smart.android.ble.api.audio`
- **Methods**: 4
- **Fields**: 2
- **Source**: `ble\api\audio\AudioCommnonResponse.java`

**Key Methods**:
  - `getStatus()`
  - `getSubCmd()`
  - `setStatus()`
  - `setSubCmd()`

---

### AudioCommonCommand [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.audio.AudioCommonCommand`
- **Package**: `com.thingclips.smart.android.ble.api.audio`
- **Methods**: 9
- **Fields**: 4
- **Source**: `ble\api\audio\AudioCommonCommand.java`

**Key Methods**:
  - `AudioCommonCommand()`
  - `buildClearCommand()`
  - `AudioCommonCommand()`
  - `buildNotifyCommand()`
  - `AudioCommonCommand()`
  - `getData()`
  - `getSubCmd()`
  - `setData()`
  - `setSubCmd()`

---

### AudioNoramlResult [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.audio.AudioNoramlResult`
- **Package**: `com.thingclips.smart.android.ble.api.audio`
- **Extends**: `LEAudioResult`
- **Methods**: 3
- **Fields**: 1
- **Source**: `ble\api\audio\AudioNoramlResult.java`

**Key Methods**:
  - `AudioNoramlResult()`
  - `getAudioData()`
  - `setAudioData()`

---

### AudioTokenBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.audio.AudioTokenBean`
- **Package**: `com.thingclips.smart.android.ble.api.audio`
- **Methods**: 0
- **Fields**: 5
- **Source**: `ble\api\audio\AudioTokenBean.java`

---

### CalendarResult [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.audio.CalendarResult`
- **Package**: `com.thingclips.smart.android.ble.api.audio`
- **Extends**: `LEAudioResult`
- **Methods**: 11
- **Fields**: 5
- **Source**: `ble\api\audio\CalendarResult.java`

**Key Methods**:
  - `getLeftText()`
  - `getRightText()`
  - `setLeftText()`
  - `setRightText()`
  - `CalendarResult()`
  - `getMainTitle()`
  - `getSubTitle()`
  - `getTodoListData()`
  - `setMainTitle()`
  - `setSubTitle()`
  - *(... and 1 more)*

---

### LEAudioAlarmClockRequest [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.audio.LEAudioAlarmClockRequest`
- **Package**: `com.thingclips.smart.android.ble.api.audio`
- **Methods**: 18
- **Fields**: 23
- **Source**: `ble\api\audio\LEAudioAlarmClockRequest.java`

**Key Methods**:
  - `build()`
  - `LEAudioAlarmClockRequest()`
  - `setCmd()`
  - `setLoopCount()`
  - `setLoopCountPauseTime()`
  - `setMd5Token()`
  - `setReminderText()`
  - `setTime()`
  - `setType()`
  - `LEAudioAlarmClockRequest()`
  - *(... and 8 more)*

---

### LEAudioRequest [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.audio.LEAudioRequest`
- **Package**: `com.thingclips.smart.android.ble.api.audio`
- **Methods**: 19
- **Fields**: 17
- **Source**: `ble\api\audio\LEAudioRequest.java`

**Key Methods**:
  - `LEAudioRequest()`
  - `createEndPointRequest()`
  - `LEAudioRequest()`
  - `createProvideSpeechRequest()`
  - `LEAudioRequest()`
  - `createSpeechStateRequest()`
  - `LEAudioRequest()`
  - `createStartSpeechRequest()`
  - `LEAudioRequest()`
  - `createStopRequest()`
  - *(... and 9 more)*

---

### LEAudioResult [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.audio.LEAudioResult`
- **Package**: `com.thingclips.smart.android.ble.api.audio`
- **Methods**: 1
- **Fields**: 4
- **Source**: `ble\api\audio\LEAudioResult.java`

**Key Methods**:
  - `getType()`

---

### OnLEAudioStatusListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.audio.OnLEAudioStatusListener`
- **Package**: `com.thingclips.smart.android.ble.api.audio`
- **Methods**: 5
- **Fields**: 0
- **Source**: `ble\api\audio\OnLEAudioStatusListener.java`

**Key Methods**:
  - `onLEAudioEndpointSpeech()`
  - `onLEAudioProvideSpeech()`
  - `onLEAudioStartSpeech()`
  - `onLEAudioStopSpeech()`
  - `onReceiveAudioData()`

---

### ThingLEAudioDataArgs [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.audio.ThingLEAudioDataArgs`
- **Package**: `com.thingclips.smart.android.ble.api.audio`
- **Methods**: 4
- **Fields**: 1
- **Source**: `ble\api\audio\ThingLEAudioDataArgs.java`

**Key Methods**:
  - `ThingLEAudioDataArgs()`
  - `getAudioData()`
  - `setAudioData()`
  - `setFormat()`

---

### ThingLEAudioEnum [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.audio.ThingLEAudioEnum`
- **Package**: `com.thingclips.smart.android.ble.api.audio`
- **Methods**: 1
- **Fields**: 5
- **Source**: `ble\api\audio\ThingLEAudioEnum.java`

**Key Methods**:
  - `valueOf()`

---

### ThingLEAudioProvideArgs [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.audio.ThingLEAudioProvideArgs`
- **Package**: `com.thingclips.smart.android.ble.api.audio`
- **Methods**: 6
- **Fields**: 2
- **Source**: `ble\api\audio\ThingLEAudioProvideArgs.java`

**Key Methods**:
  - `ThingLEAudioProvideArgs()`
  - `getAudioProfile()`
  - `getDialogId()`
  - `setAudioProfile()`
  - `setDialogId()`
  - `setFormat()`

---

### ThingLEAudioStartArgs [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.audio.ThingLEAudioStartArgs`
- **Package**: `com.thingclips.smart.android.ble.api.audio`
- **Methods**: 10
- **Fields**: 4
- **Source**: `ble\api\audio\ThingLEAudioStartArgs.java`

**Key Methods**:
  - `ThingLEAudioStartArgs()`
  - `getAudioProfile()`
  - `getDialogId()`
  - `getPlayVoice()`
  - `getSuppressEarcon()`
  - `setAudioProfile()`
  - `setDialogId()`
  - `setFormat()`
  - `setPlayVoice()`
  - `setSuppressEarcon()`

---

### WeatherResult [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.api.audio.WeatherResult`
- **Package**: `com.thingclips.smart.android.ble.api.audio`
- **Extends**: `LEAudioResult`
- **Methods**: 27
- **Fields**: 15
- **Source**: `ble\api\audio\WeatherResult.java`

**Key Methods**:
  - `getCurrentTemperature()`
  - `getDate()`
  - `getDay()`
  - `getDescription()`
  - `getMaxTemperature()`
  - `getMinTemperature()`
  - `getTtsContent()`
  - `getWeatherType()`
  - `setCurrentTemperature()`
  - `setDate()`
  - *(... and 17 more)*

---

### BatchBeaconActivatorBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.bean.BatchBeaconActivatorBean`
- **Package**: `com.thingclips.smart.android.ble.bean`
- **Methods**: 9
- **Fields**: 7
- **Source**: `android\ble\bean\BatchBeaconActivatorBean.java`

**Key Methods**:
  - `BatchBeaconActivatorBean()`
  - `build()`
  - `setHomeId()`
  - `setScanDeviceList()`
  - `setTimeout()`
  - `getDeviceBeanList()`
  - `getHomeId()`
  - `getTimeout()`
  - `BatchBeaconActivatorBean()`

---

### BeaconBatchCheckBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.bean.BeaconBatchCheckBean`
- **Package**: `com.thingclips.smart.android.ble.bean`
- **Methods**: 12
- **Fields**: 6
- **Source**: `android\ble\bean\BeaconBatchCheckBean.java`

**Key Methods**:
  - `getErrorCode()`
  - `getFlag()`
  - `getMac()`
  - `getS2()`
  - `getType()`
  - `isSuccess()`
  - `setErrorCode()`
  - `setFlag()`
  - `setMac()`
  - `setS2()`
  - *(... and 2 more)*

---

### BleOTABean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.bean.BleOTABean`
- **Package**: `com.thingclips.smart.android.ble.bean`
- **Methods**: 19
- **Fields**: 9
- **Source**: `android\ble\bean\BleOTABean.java`

**Key Methods**:
  - `BleOTABean()`
  - `getAccessoriesPid()`
  - `getBinPackagePath()`
  - `getDevId()`
  - `getNodeId()`
  - `getPid()`
  - `getType()`
  - `getUuid()`
  - `getVersion()`
  - `setAccessoriesPid()`
  - *(... and 9 more)*

**Notable Strings**:
  - `"BleOTABean{uuid='"`

---

### CheckDeviceSetting [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.bean.CheckDeviceSetting`
- **Package**: `com.thingclips.smart.android.ble.bean`
- **Methods**: 6
- **Fields**: 8
- **Source**: `android\ble\bean\CheckDeviceSetting.java`

**Key Methods**:
  - `build()`
  - `CheckDeviceSetting()`
  - `setPacket()`
  - `setShortChain()`
  - `getPacket()`
  - `getShortChain()`

---

### QueryWifiSetting [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.bean.QueryWifiSetting`
- **Package**: `com.thingclips.smart.android.ble.bean`
- **Methods**: 10
- **Fields**: 9
- **Source**: `android\ble\bean\QueryWifiSetting.java`

**Key Methods**:
  - `build()`
  - `IllegalArgumentException()`
  - `QueryWifiSetting()`
  - `setSize()`
  - `setTimeout()`
  - `setUuid()`
  - `getSize()`
  - `getTimeout()`
  - `getUuid()`
  - `QueryWifiSetting()`

---

### ResetBleSetting [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.bean.ResetBleSetting`
- **Package**: `com.thingclips.smart.android.ble.bean`
- **Methods**: 8
- **Fields**: 11
- **Source**: `android\ble\bean\ResetBleSetting.java`

**Key Methods**:
  - `build()`
  - `ResetBleSetting()`
  - `setEncryptedKey()`
  - `setPacket()`
  - `setRandom()`
  - `getEncryptedKey()`
  - `getPacket()`
  - `getRandom()`

---

### ScanReq [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.bean.ScanReq`
- **Package**: `com.thingclips.smart.android.ble.bean`
- **Methods**: 21
- **Fields**: 19
- **Source**: `android\ble\bean\ScanReq.java`

**Key Methods**:
  - `build()`
  - `ScanReq()`
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

### ThirdConnectErrorBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.bean.ThirdConnectErrorBean`
- **Package**: `com.thingclips.smart.android.ble.bean`
- **Methods**: 0
- **Fields**: 6
- **Source**: `android\ble\bean\ThirdConnectErrorBean.java`

---

### ThirdConnectInfoBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.bean.ThirdConnectInfoBean`
- **Package**: `com.thingclips.smart.android.ble.bean`
- **Methods**: 1
- **Fields**: 9
- **Source**: `android\ble\bean\ThirdConnectInfoBean.java`

**Key Methods**:
  - `ExInfo()`

---

### ThirdConstant [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.bean.ThirdConstant`
- **Package**: `com.thingclips.smart.android.ble.bean`
- **Methods**: 0
- **Fields**: 3
- **Source**: `android\ble\bean\ThirdConstant.java`

---

### ThirdDpsUpdate [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.bean.ThirdDpsUpdate`
- **Package**: `com.thingclips.smart.android.ble.bean`
- **Methods**: 6
- **Fields**: 5
- **Source**: `android\ble\bean\ThirdDpsUpdate.java`

**Key Methods**:
  - `ThirdDpsUpdate()`
  - `getDpsMap()`
  - `getDpsTime()`
  - `isUpdateDpsToCache()`
  - `isUpdateDpsToCloud()`
  - `isUpdateDpsToLocal()`

---

### BleConnectBuilder [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.builder.BleConnectBuilder`
- **Package**: `com.thingclips.smart.android.ble.builder`
- **Methods**: 12
- **Fields**: 15
- **Source**: `android\ble\builder\BleConnectBuilder.java`

**Key Methods**:
  - `getDevId()`
  - `getExtInfo()`
  - `getLevel()`
  - `getScanTimeout()`
  - `isAutoConnect()`
  - `isDirectConnect()`
  - `setAutoConnect()`
  - `setDevId()`
  - `setDirectConnect()`
  - `setExtInfo()`
  - *(... and 2 more)*

---

### BlueConnectParam [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.builder.BlueConnectParam`
- **Package**: `com.thingclips.smart.android.ble.builder`
- **Methods**: 11
- **Fields**: 14
- **Source**: `android\ble\builder\BlueConnectParam.java`

**Key Methods**:
  - `BlueConnectParam()`
  - `build()`
  - `setConnectType()`
  - `setDevId()`
  - `setSourceType()`
  - `setTimeoutMillis()`
  - `getConnectTimeoutMillis()`
  - `getConnectType()`
  - `getDevId()`
  - `getSourceType()`
  - *(... and 1 more)*

---

### ConnectResponse [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.connect.api.ConnectResponse`
- **Package**: `com.thingclips.smart.android.ble.connect.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `ble\connect\api\ConnectResponse.java`

**Key Methods**:
  - `onConnectError()`
  - `onConnectSuccess()`

---

### INotifyDelegate [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.connect.api.INotifyDelegate`
- **Package**: `com.thingclips.smart.android.ble.connect.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `ble\connect\api\INotifyDelegate.java`

**Key Methods**:
  - `onFrameReceived()`

---

### OnBleConnectStatusChangeListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.connect.api.OnBleConnectStatusChangeListener`
- **Package**: `com.thingclips.smart.android.ble.connect.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `ble\connect\api\OnBleConnectStatusChangeListener.java`

**Key Methods**:
  - `onStatusChanged()`

---

### ReadRemoteRssiCallback [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.connect.api.ReadRemoteRssiCallback`
- **Package**: `com.thingclips.smart.android.ble.connect.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `ble\connect\api\ReadRemoteRssiCallback.java`

**Key Methods**:
  - `onResult()`

---

### XResponse [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.connect.request.XResponse`
- **Package**: `com.thingclips.smart.android.ble.connect.request`
- **Methods**: 2
- **Fields**: 0
- **Source**: `ble\connect\request\XResponse.java`

**Key Methods**:
  - `onCommandSuccess()`
  - `onError()`

---

### BleConnectAbility [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.enums.BleConnectAbility`
- **Package**: `com.thingclips.smart.android.ble.enums`
- **Methods**: 0
- **Fields**: 3
- **Source**: `android\ble\enums\BleConnectAbility.java`

---

### InnerScanResponse [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.scanner.InnerScanResponse`
- **Package**: `com.thingclips.smart.android.ble.scanner`
- **Methods**: 4
- **Fields**: 0
- **Source**: `android\ble\scanner\InnerScanResponse.java`

**Key Methods**:
  - `onDeviceFounded()`
  - `onScanCancel()`
  - `onScanStart()`
  - `onScanStop()`

---

### IThingInnerScanner [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.ble.scanner.IThingInnerScanner`
- **Package**: `com.thingclips.smart.android.ble.scanner`
- **Methods**: 2
- **Fields**: 0
- **Source**: `android\ble\scanner\IThingInnerScanner.java`

**Key Methods**:
  - `addScanRequest()`
  - `removeScanRequest()`

---

### ThingIPCSdk [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.camera.sdk.ThingIPCSdk`
- **Package**: `com.thingclips.smart.android.camera.sdk`
- **Methods**: 11
- **Fields**: 23
- **Source**: `android\camera\sdk\ThingIPCSdk.java`

**Key Methods**:
  - `P2PBuilder()`
  - `createIPCDpHelper()`
  - `getCameraInstance()`
  - `getCloud()`
  - `getDoorbell()`
  - `getHomeProxy()`
  - `getMessage()`
  - `getP2P()`
  - `getPTZInstance()`
  - `getTool()`
  - *(... and 1 more)*

---

### ICameraStatEvent [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.camera.sdk.api.ICameraStatEvent`
- **Package**: `com.thingclips.smart.android.camera.sdk.api`
- **Methods**: 14
- **Fields**: 0
- **Source**: `camera\sdk\api\ICameraStatEvent.java`

**Key Methods**:
  - `getClientTraceId()`
  - `getConnectTraceId()`
  - `sendAPMLog()`
  - `sendAPMLog()`
  - `sendCameraLog()`
  - `sendConnectFullLinkLog()`
  - `sendFullLinkLog()`
  - `sendFullLinkStartLog()`
  - `sendIPCExtraDataLog()`
  - `sendIPCSDKVisionLog()`
  - *(... and 4 more)*

---

### ILog [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.camera.sdk.api.ILog`
- **Package**: `com.thingclips.smart.android.camera.sdk.api`
- **Methods**: 7
- **Fields**: 0
- **Source**: `camera\sdk\api\ILog.java`

**Key Methods**:
  - `m146d()`
  - `m147e()`
  - `m148e()`
  - `m149i()`
  - `setLogEnabled()`
  - `m150v()`
  - `m151w()`

---

### IThingCameraMessage [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.camera.sdk.api.IThingCameraMessage`
- **Package**: `com.thingclips.smart.android.camera.sdk.api`
- **Methods**: 10
- **Fields**: 0
- **Source**: `camera\sdk\api\IThingCameraMessage.java`

**Key Methods**:
  - `deleteMotionMessageList()`
  - `destroy()`
  - `getAlarmDetectionMessageList()`
  - `getAlarmDetectionMessageList()`
  - `getAlarmDetectionMessageList()`
  - `getMessageAITags()`
  - `getVideoCheckServiceUrl()`
  - `queryAlarmDetectionClassify()`
  - `queryMotionDaysByMonth()`
  - `queryMotionDaysByMonth()`

---

### IThingIPCCore [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.camera.sdk.api.IThingIPCCore`
- **Package**: `com.thingclips.smart.android.camera.sdk.api`
- **Methods**: 10
- **Fields**: 0
- **Source**: `camera\sdk\api\IThingIPCCore.java`

**Key Methods**:
  - `createCameraP2P()`
  - `createNvrP2P()`
  - `deInit()`
  - `destroyNvrP2P()`
  - `getBuilderInstance()`
  - `getCameraConfig()`
  - `getP2PType()`
  - `isIPCDevice()`
  - `isLowPowerDevice()`
  - `setLogEnabled()`

---

### CollectionPointBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.camera.sdk.bean.CollectionPointBean`
- **Package**: `com.thingclips.smart.android.camera.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 14
- **Fields**: 7
- **Source**: `camera\sdk\bean\CollectionPointBean.java`

**Key Methods**:
  - `getDevId()`
  - `getEncryption()`
  - `getId()`
  - `getMpId()`
  - `getName()`
  - `getPic()`
  - `getPos()`
  - `setDevId()`
  - `setEncryption()`
  - `setId()`
  - *(... and 4 more)*

---

### RunnableC0064b [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.common.connecthelper.RunnableC0064b`
- **Package**: `com.thingclips.smart.android.common.connecthelper`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 4
- **Source**: `android\common\connecthelper\RunnableC0064b.java`

**Key Methods**:
  - `run()`

---

### RunnableC0070a [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.common.scanhelper.RunnableC0070a`
- **Package**: `com.thingclips.smart.android.common.scanhelper`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 6
- **Source**: `android\common\scanhelper\RunnableC0070a.java`

**Key Methods**:
  - `run()`

---

### WifiScanRequest [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.common.scanhelper.WifiScanRequest`
- **Package**: `com.thingclips.smart.android.common.scanhelper`
- **Methods**: 9
- **Fields**: 9
- **Source**: `android\common\scanhelper\WifiScanRequest.java`

**Key Methods**:
  - `checkReceiverAndResult()`
  - `BroadcastReceiver()`
  - `onReceive()`
  - `onResult()`
  - `startScan()`
  - `startScanRequest()`
  - `IntentFilter()`
  - `startScan()`
  - `stopScan()`

---

### SafeAsyncTask [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.common.task.SafeAsyncTask`
- **Package**: `com.thingclips.smart.android.common.task`
- **Extends**: `AsyncTask<Params`
- **Methods**: 5
- **Fields**: 1
- **Source**: `android\common\task\SafeAsyncTask.java`

**Key Methods**:
  - `SafeAsyncTask()`
  - `execute()`
  - `init()`
  - `onPostExecute()`
  - `onResult()`

---

### SaturativeExecutor [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.common.task.SaturativeExecutor`
- **Package**: `com.thingclips.smart.android.common.task`
- **Extends**: `ThreadPoolExecutor`
- **Implements**: `Runnable`
- **Methods**: 27
- **Fields**: 42
- **Source**: `android\common\task\SaturativeExecutor.java`

**Key Methods**:
  - `ThreadFactory()`
  - `AtomicInteger()`
  - `newThread()`
  - `Thread()`
  - `AtomicInteger()`
  - `CountedTask()`
  - `run()`
  - `SaturationAwareBlockingQueue()`
  - `add()`
  - `IllegalStateException()`
  - *(... and 17 more)*

---

### AesGcmUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.common.utils.AesGcmUtil`
- **Package**: `com.thingclips.smart.android.common.utils`
- **Methods**: 11
- **Fields**: 20
- **Source**: `android\common\utils\AesGcmUtil.java`

**Key Methods**:
  - `decryptBytes2Bytes()`
  - `SecretKeySpec()`
  - `GCMParameterSpec()`
  - `decryptBytesAppendedNonce2Bytes()`
  - `decryptBytes2Bytes()`
  - `encryptBytes2Bytes()`
  - `SecretKeySpec()`
  - `GCMParameterSpec()`
  - `encryptBytes2BytesAppendNonce()`
  - `generateRandomNonce()`
  - *(... and 1 more)*

---

### C0078L [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.common.utils.C0078L`
- **Package**: `com.thingclips.smart.android.common.utils`
- **Methods**: 36
- **Fields**: 46
- **Source**: `android\common\utils\C0078L.java`

**Key Methods**:
  - `StringBuffer()`
  - `Holder()`
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `getInstance()`
  - `log()`
  - `run()`
  - `m213d()`
  - `m215e()`
  - `getLogStatus()`
  - *(... and 26 more)*

---

### CRC32Utils [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.common.utils.CRC32Utils`
- **Package**: `com.thingclips.smart.android.common.utils`
- **Methods**: 2
- **Fields**: 6
- **Source**: `android\common\utils\CRC32Utils.java`

**Key Methods**:
  - `crc32()`
  - `getChecksum()`

---

### FileUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.common.utils.FileUtil`
- **Package**: `com.thingclips.smart.android.common.utils`
- **Methods**: 18
- **Fields**: 28
- **Source**: `android\common\utils\FileUtil.java`

**Key Methods**:
  - `delete()`
  - `deleteFileSafely()`
  - `File()`
  - `fileExists()`
  - `File()`
  - `isExists()`
  - `readFile()`
  - `RandomAccessFile()`
  - `readFileByLine()`
  - `RandomAccessFile()`
  - *(... and 8 more)*

---

### MD5Util [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.common.utils.MD5Util`
- **Package**: `com.thingclips.smart.android.common.utils`
- **Methods**: 15
- **Fields**: 14
- **Source**: `android\common\utils\MD5Util.java`

**Key Methods**:
  - `computeMD5Hash()`
  - `BufferedInputStream()`
  - `IllegalStateException()`
  - `getHmacMd5Str()`
  - `SecretKeySpec()`
  - `StringBuilder()`
  - `md5AsBase64()`
  - `md5AsBase64For16()`
  - `md5AsBase64()`
  - `md5AsBase64()`
  - *(... and 5 more)*

---

### SHA256Util [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.common.utils.SHA256Util`
- **Package**: `com.thingclips.smart.android.common.utils`
- **Methods**: 8
- **Fields**: 7
- **Source**: `android\common\utils\SHA256Util.java`

**Key Methods**:
  - `getBase64Hash()`
  - `String()`
  - `getHash()`
  - `getHash()`
  - `sha256()`
  - `getHash()`
  - `sha256()`
  - `sha256()`

---

### INetWorkCallback [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.common.utils.callback.INetWorkCallback`
- **Package**: `com.thingclips.smart.android.common.utils.callback`
- **Methods**: 2
- **Fields**: 1
- **Source**: `common\utils\callback\INetWorkCallback.java`

**Key Methods**:
  - `onAvailable()`
  - `onUnavailable()`

---

### ThingNetworkApi [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.ThingNetworkApi`
- **Package**: `com.thingclips.smart.android.device`
- **Methods**: 36
- **Fields**: 0
- **Source**: `smart\android\device\ThingNetworkApi.java`

**Key Methods**:
  - `ReadOverTlsChannel()`
  - `asyncSendOverTlsChannel()`
  - `bindNetworkInterface()`
  - `checkOnline()`
  - `closeAllConnection()`
  - `closeDevice()`
  - `closeTlsChannel()`
  - `connectApDevice()`
  - `connectDevice()`
  - `connectDeviceWithKey()`
  - *(... and 26 more)*

---

### ThingNetworkInterface [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.ThingNetworkInterface`
- **Package**: `com.thingclips.smart.android.device`
- **Implements**: `IDeviceConnCallback, IApConfigTcpCallback`
- **Methods**: 66
- **Fields**: 23
- **Source**: `smart\android\device\ThingNetworkInterface.java`

**Key Methods**:
  - `getProtocolVersion()`
  - `getVersion()`
  - `ThingNetworkInterface()`
  - `SingletonHolder()`
  - `OnLinkCloseCallback()`
  - `OnResponseDataCallback()`
  - `OnResponseExceptionCallback()`
  - `OnSmartUDPDataCallback()`
  - `if()`
  - `ReadOverTlsChannel()`
  - *(... and 56 more)*

---

### ThingSmartLink [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.ThingSmartLink`
- **Package**: `com.thingclips.smart.android.device`
- **Methods**: 2
- **Fields**: 0
- **Source**: `smart\android\device\ThingSmartLink.java`

**Key Methods**:
  - `sendStatusStop()`
  - `smartLink()`

---

### IThingDeviceMultiControl [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.api.IThingDeviceMultiControl`
- **Package**: `com.thingclips.smart.android.device.api`
- **Methods**: 8
- **Fields**: 0
- **Source**: `android\device\api\IThingDeviceMultiControl.java`

**Key Methods**:
  - `disableMultiControl()`
  - `enableMultiControl()`
  - `getDeviceDpInfoList()`
  - `getDeviceDpLinkRelation()`
  - `getMultiControlDeviceList()`
  - `queryLinkInfoByDp()`
  - `saveDeviceMultiControl()`
  - `saveDeviceMultiControl()`

---

### AlarmTimerBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.AlarmTimerBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Implements**: `Parcelable`
- **Methods**: 23
- **Fields**: 21
- **Source**: `android\device\bean\AlarmTimerBean.java`

**Key Methods**:
  - `createFromParcel()`
  - `AlarmTimerBean()`
  - `newArray()`
  - `describeContents()`
  - `getAliasName()`
  - `getGroupId()`
  - `getId()`
  - `getLoops()`
  - `getStatus()`
  - `getTime()`
  - *(... and 13 more)*

---

### ArraySchemaBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.ArraySchemaBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 3
- **Source**: `android\device\bean\ArraySchemaBean.java`

**Key Methods**:
  - `getElementTypeSpec()`
  - `getMaxSize()`
  - `setElementTypeSpec()`
  - `setMaxSize()`

---

### BitmapSchemaBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.BitmapSchemaBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 3
- **Source**: `android\device\bean\BitmapSchemaBean.java`

**Key Methods**:
  - `getLabel()`
  - `getMaxlen()`
  - `setLabel()`
  - `setMaxlen()`

---

### BoolSchemaBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.BoolSchemaBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Implements**: `Serializable`
- **Methods**: 0
- **Fields**: 1
- **Source**: `android\device\bean\BoolSchemaBean.java`

---

### CommonSpecParamsBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.CommonSpecParamsBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 2
- **Source**: `android\device\bean\CommonSpecParamsBean.java`

**Key Methods**:
  - `getCode()`
  - `getTypeSpec()`
  - `setCode()`
  - `setTypeSpec()`

---

### DateSchemaBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.DateSchemaBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Implements**: `Serializable`
- **Methods**: 2
- **Fields**: 5
- **Source**: `android\device\bean\DateSchemaBean.java`

**Key Methods**:
  - `getMaxlen()`
  - `getMinLen()`

---

### DeviceMultiControlRelationBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.DeviceMultiControlRelationBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Methods**: 56
- **Fields**: 28
- **Source**: `android\device\bean\DeviceMultiControlRelationBean.java`

**Key Methods**:
  - `getDpId()`
  - `getName()`
  - `setDpId()`
  - `setName()`
  - `getDevId()`
  - `getDevName()`
  - `getDpId()`
  - `getDpName()`
  - `getId()`
  - `getMultiControlId()`
  - *(... and 46 more)*

---

### DevLocationBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.DevLocationBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Implements**: `Parcelable`
- **Methods**: 21
- **Fields**: 8
- **Source**: `android\device\bean\DevLocationBean.java`

**Key Methods**:
  - `createFromParcel()`
  - `DevLocationBean()`
  - `newArray()`
  - `DevLocationBean()`
  - `describeContents()`
  - `getDevId()`
  - `getGwId()`
  - `getLat()`
  - `getLon()`
  - `getLower()`
  - *(... and 11 more)*

---

### EnumSchemaBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.EnumSchemaBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Implements**: `Serializable`
- **Methods**: 2
- **Fields**: 2
- **Source**: `android\device\bean\EnumSchemaBean.java`

**Key Methods**:
  - `getRange()`
  - `setRange()`

---

### MultiControlBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.MultiControlBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Methods**: 16
- **Fields**: 8
- **Source**: `android\device\bean\MultiControlBean.java`

**Key Methods**:
  - `getDevId()`
  - `getDpId()`
  - `getId()`
  - `isEnable()`
  - `setDevId()`
  - `setDpId()`
  - `setEnable()`
  - `setId()`
  - `getGroupDetail()`
  - `getGroupName()`
  - *(... and 6 more)*

---

### MultiControlLinkBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.MultiControlLinkBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Methods**: 44
- **Fields**: 22
- **Source**: `android\device\bean\MultiControlLinkBean.java`

**Key Methods**:
  - `getDatapoints()`
  - `getDevId()`
  - `getDevName()`
  - `getDpId()`
  - `getDpName()`
  - `getId()`
  - `getMultiControlId()`
  - `getStatus()`
  - `isEnabled()`
  - `setDatapoints()`
  - *(... and 34 more)*

---

### SchemaBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.SchemaBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Implements**: `Serializable`
- **Methods**: 20
- **Fields**: 10
- **Source**: `android\device\bean\SchemaBean.java`

**Key Methods**:
  - `getCode()`
  - `getExtContent()`
  - `getIconname()`
  - `getId()`
  - `getMode()`
  - `getName()`
  - `getPassive()`
  - `getProperty()`
  - `getSchemaType()`
  - `getType()`
  - *(... and 10 more)*

---

### StringSchemaBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.StringSchemaBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Implements**: `Serializable`
- **Methods**: 2
- **Fields**: 2
- **Source**: `android\device\bean\StringSchemaBean.java`

**Key Methods**:
  - `getMaxlen()`
  - `setMaxlen()`

---

### StructPropertyBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.StructPropertyBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 2
- **Source**: `android\device\bean\StructPropertyBean.java`

**Key Methods**:
  - `getName()`
  - `getTypeSpec()`
  - `setName()`
  - `setTypeSpec()`

---

### StructSchemaBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.StructSchemaBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Implements**: `Serializable`
- **Methods**: 2
- **Fields**: 2
- **Source**: `android\device\bean\StructSchemaBean.java`

**Key Methods**:
  - `getProperties()`
  - `setProperties()`

---

### UpgradeInfoBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.UpgradeInfoBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Implements**: `Serializable`
- **Methods**: 42
- **Fields**: 31
- **Source**: `android\device\bean\UpgradeInfoBean.java`

**Key Methods**:
  - `getAutoSwitch()`
  - `getCanUpgrade()`
  - `getControlType()`
  - `getCurrentVersion()`
  - `getDesc()`
  - `getDevType()`
  - `getDownloadingDesc()`
  - `getFileSize()`
  - `getFirmwareDeployTime()`
  - `getLastUpgradeTime()`
  - *(... and 32 more)*

---

### ValueSchemaBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.bean.ValueSchemaBean`
- **Package**: `com.thingclips.smart.android.device.bean`
- **Implements**: `Serializable`
- **Methods**: 10
- **Fields**: 6
- **Source**: `android\device\bean\ValueSchemaBean.java`

**Key Methods**:
  - `getMax()`
  - `getMin()`
  - `getScale()`
  - `getStep()`
  - `getUnit()`
  - `setMax()`
  - `setMin()`
  - `setScale()`
  - `setStep()`
  - `setUnit()`

---

### ThingActivityLifecycleCallback [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.utils.ThingActivityLifecycleCallback`
- **Package**: `com.thingclips.smart.android.device.utils`
- **Methods**: 13
- **Fields**: 9
- **Source**: `android\device\utils\ThingActivityLifecycleCallback.java`

**Key Methods**:
  - `ThingActivityLifecycleCallback()`
  - `onActivityCreated()`
  - `onActivityDestroyed()`
  - `onActivityPaused()`
  - `onActivityResumed()`
  - `run()`
  - `onActivitySaveInstanceState()`
  - `onActivityStarted()`
  - `onActivityStopped()`
  - `run()`
  - *(... and 3 more)*

---

### ThingBleUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.device.utils.ThingBleUtil`
- **Package**: `com.thingclips.smart.android.device.utils`
- **Methods**: 3
- **Fields**: 4
- **Source**: `android\device\utils\ThingBleUtil.java`

**Key Methods**:
  - `convertMac()`
  - `StringBuilder()`
  - `parseBleDeviceCapability()`

---

### Default [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.hardware.Default`
- **Package**: `com.thingclips.smart.android.hardware`
- **Extends**: `IInterface`
- **Implements**: `IUDPMonitorAidlInterface`
- **Methods**: 24
- **Fields**: 28
- **Source**: `smart\android\hardware\IUDPMonitorAidlInterface.java`

**Key Methods**:
  - `asBinder()`
  - `closeService()`
  - `getAppId()`
  - `onConfigResult()`
  - `update()`
  - `Proxy()`
  - `asBinder()`
  - `closeService()`
  - `getAppId()`
  - `getInterfaceDescriptor()`
  - *(... and 14 more)*

---

### HomeSdkConfigWrapper [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.HomeSdkConfigWrapper`
- **Package**: `com.thingclips.smart.android.network`
- **Implements**: `IHomeSdkConfig`
- **Methods**: 42
- **Fields**: 39
- **Source**: `smart\android\network\HomeSdkConfigWrapper.java`

**Key Methods**:
  - `HomeSdkConfigWrapper()`
  - `apNetBindEnable()`
  - `autoPlugPlay()`
  - `closePSKConfig()`
  - `configNotify()`
  - `configThreadPoolStrategy()`
  - `dpReportEnabled()`
  - `getApiAllTimeEventSwitch()`
  - `getAutoReconnectCount()`
  - `getBatchPairVersion()`
  - *(... and 32 more)*

---

### IApiUrlProvider [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.IApiUrlProvider`
- **Package**: `com.thingclips.smart.android.network`
- **Methods**: 21
- **Fields**: 0
- **Source**: `smart\android\network\IApiUrlProvider.java`

**Key Methods**:
  - `downgradeToHttp()`
  - `enableQuic()`
  - `getAllPinningUrls()`
  - `getApiUrl()`
  - `getApiUrlByCountryCode()`
  - `getAudioUrl()`
  - `getDns2ServerConfig()`
  - `getDnsServerConfig()`
  - `getEncrptUrl()`
  - `getGwApiUrl()`
  - *(... and 11 more)*

---

### TokenBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.bean.TokenBean`
- **Package**: `com.thingclips.smart.android.network.bean`
- **Implements**: `Serializable`
- **Methods**: 8
- **Fields**: 4
- **Source**: `android\network\bean\TokenBean.java`

**Key Methods**:
  - `getAccessToken()`
  - `getExpireTime()`
  - `getRefreshToken()`
  - `getUid()`
  - `setAccessToken()`
  - `setExpireTime()`
  - `setRefreshToken()`
  - `setUid()`

---

### FusionApiParams [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.fusion.FusionApiParams`
- **Package**: `com.thingclips.smart.android.network.fusion`
- **Extends**: `ThingApiParams`
- **Methods**: 9
- **Fields**: 12
- **Source**: `android\network\fusion\FusionApiParams.java`

**Key Methods**:
  - `FusionApiParams()`
  - `getBodyParams()`
  - `getFusionRequestBody()`
  - `ConcurrentHashMap()`
  - `getHeaderParams()`
  - `getQueryParams()`
  - `setBodyParams()`
  - `setHeaderParams()`
  - `setQueryParams()`

---

### AssetsConfig [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.http.AssetsConfig`
- **Package**: `com.thingclips.smart.android.network.http`
- **Methods**: 15
- **Fields**: 24
- **Source**: `android\network\http\AssetsConfig.java`

**Key Methods**:
  - `AssetsConfig()`
  - `Holder()`
  - `getConfigObj()`
  - `ByteArrayOutputStream()`
  - `String()`
  - `getConfigObj()`
  - `getInstance()`
  - `getCert()`
  - `getRegion()`
  - `isFileExist()`
  - *(... and 5 more)*

---

### HttpEventListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.http.HttpEventListener`
- **Package**: `com.thingclips.smart.android.network.http`
- **Extends**: `EventListener`
- **Implements**: `EventListener.Factory`
- **Methods**: 51
- **Fields**: 61
- **Source**: `android\network\http\HttpEventListener.java`

**Key Methods**:
  - `HttpEventListenerFactory()`
  - `isIpByTime()`
  - `parseApi()`
  - `proxyStatus()`
  - `recordEventLog()`
  - `refreshConncetLookup()`
  - `callEnd()`
  - `callFailed()`
  - `callStart()`
  - `connectEnd()`
  - *(... and 41 more)*

---

### ThingOKHttpDNS [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.http.dns.ThingOKHttpDNS`
- **Package**: `com.thingclips.smart.android.network.http.dns`
- **Implements**: `Dns`
- **Methods**: 12
- **Fields**: 16
- **Source**: `network\http\dns\ThingOKHttpDNS.java`

**Key Methods**:
  - `getInstance()`
  - `ThingOKHttpDNS()`
  - `lookup()`
  - `ArrayList()`
  - `refreshLookup()`
  - `Callback()`
  - `onFailure()`
  - `onResponse()`
  - `requestHostsIpsInNetWork()`
  - `HashMap()`
  - *(... and 2 more)*

---

### ThingDNSCacheManager [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.http.dns.cache.ThingDNSCacheManager`
- **Package**: `com.thingclips.smart.android.network.http.dns.cache`
- **Methods**: 7
- **Fields**: 11
- **Source**: `http\dns\cache\ThingDNSCacheManager.java`

**Key Methods**:
  - `getInstance()`
  - `ThingDNSCacheManager()`
  - `lookUpIps()`
  - `HashMap()`
  - `saveToCache()`
  - `HashMap()`
  - `HashMap()`

---

### ThingHostValidationChecker [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.http.dns.cache.ThingHostValidationChecker`
- **Package**: `com.thingclips.smart.android.network.http.dns.cache`
- **Methods**: 2
- **Fields**: 2
- **Source**: `http\dns\cache\ThingHostValidationChecker.java`

**Key Methods**:
  - `isDomainAvailable()`
  - `setDomainUnavailable()`

---

### ThingDnsManager [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.http.dns.manager.ThingDnsManager`
- **Package**: `com.thingclips.smart.android.network.http.dns.manager`
- **Methods**: 16
- **Fields**: 23
- **Source**: `http\dns\manager\ThingDnsManager.java`

**Key Methods**:
  - `ThingDefaultHostResolveStrategy()`
  - `getInstance()`
  - `ThingDnsManager()`
  - `downgradeDomain()`
  - `lookup()`
  - `ArrayList()`
  - `UnknownHostException()`
  - `lookupAndSelectOneWithRandom()`
  - `lookupInCache()`
  - `ArrayList()`
  - *(... and 6 more)*

---

### DNSStatUtils [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.http.dns.stat.DNSStatUtils`
- **Package**: `com.thingclips.smart.android.network.http.dns.stat`
- **Methods**: 6
- **Fields**: 7
- **Source**: `http\dns\stat\DNSStatUtils.java`

**Key Methods**:
  - `dnsDowngrade()`
  - `dnsRequestError()`
  - `HashMap()`
  - `dnsRequestStartStat()`
  - `dnsRequestSuccess()`
  - `HashMap()`

---

### ThingDefaultHostResolveStrategy [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.http.dns.strategy.ThingDefaultHostResolveStrategy`
- **Package**: `com.thingclips.smart.android.network.http.dns.strategy`
- **Methods**: 27
- **Fields**: 68
- **Source**: `http\dns\strategy\ThingDefaultHostResolveStrategy.java`

**Key Methods**:
  - `checkIfMatchRequestConditions()`
  - `ArrayList()`
  - `if()`
  - `if()`
  - `checkIfWithInfTTL()`
  - `parseDNSResponse()`
  - `HttpDnsBean()`
  - `lookup()`
  - `UnknownHostException()`
  - `StringBuilder()`
  - *(... and 17 more)*

---

### ThingCertificatePinner [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.http.pin.ThingCertificatePinner`
- **Package**: `com.thingclips.smart.android.network.http.pin`
- **Methods**: 26
- **Fields**: 38
- **Source**: `network\http\pin\ThingCertificatePinner.java`

**Key Methods**:
  - `cacheCersExists()`
  - `certCheck()`
  - `checkCertValidity()`
  - `checkExpireTimeAllowed()`
  - `createPublicKeyPins()`
  - `ArrayList()`
  - `PublicKeyPinInfo()`
  - `HashSet()`
  - `Date()`
  - `downgrade()`
  - *(... and 16 more)*

---

### IThingSmartQuicManager [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.quic.IThingSmartQuicManager`
- **Package**: `com.thingclips.smart.android.network.quic`
- **Methods**: 6
- **Fields**: 0
- **Source**: `android\network\quic\IThingSmartQuicManager.java`

**Key Methods**:
  - `addRequestFinishedListener()`
  - `clear()`
  - `enable()`
  - `initEngine()`
  - `openConnection()`
  - `request()`

---

### ThingSmartNetWorkConfig [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.request.ThingSmartNetWorkConfig`
- **Package**: `com.thingclips.smart.android.network.request`
- **Methods**: 12
- **Fields**: 9
- **Source**: `android\network\request\ThingSmartNetWorkConfig.java`

**Key Methods**:
  - `ThingSmartNetWorkConfig()`
  - `getBusinessExecutor()`
  - `getNetWorkExecutor()`
  - `isSupportSSLPinning()`
  - `Builder()`
  - `build()`
  - `ThingSmartNetWorkConfig()`
  - `businessExecutor()`
  - `netWorkExecutor()`
  - `supportSSLPinning()`
  - *(... and 2 more)*

---

### ThingSmartNetWorkExecutorManager [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.request.ThingSmartNetWorkExecutorManager`
- **Package**: `com.thingclips.smart.android.network.request`
- **Methods**: 2
- **Fields**: 3
- **Source**: `android\network\request\ThingSmartNetWorkExecutorManager.java`

**Key Methods**:
  - `getBusinessExecutor()`
  - `getNetWorkExcuter()`

---

### AESCBCUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.util.AESCBCUtil`
- **Package**: `com.thingclips.smart.android.network.util`
- **Methods**: 8
- **Fields**: 9
- **Source**: `android\network\util\AESCBCUtil.java`

**Key Methods**:
  - `decrypt()`
  - `IvParameterSpec()`
  - `SecretKeySpec()`
  - `String()`
  - `encrypt()`
  - `IvParameterSpec()`
  - `SecretKeySpec()`
  - `String()`

---

### AESCTRUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.util.AESCTRUtil`
- **Package**: `com.thingclips.smart.android.network.util`
- **Methods**: 8
- **Fields**: 14
- **Source**: `android\network\util\AESCTRUtil.java`

**Key Methods**:
  - `decrypt()`
  - `IvParameterSpec()`
  - `SecretKeySpec()`
  - `String()`
  - `encrypt()`
  - `IvParameterSpec()`
  - `SecretKeySpec()`
  - `String()`

---

### FusionUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.util.FusionUtil`
- **Package**: `com.thingclips.smart.android.network.util`
- **Extends**: `ThingHighwayUtil`
- **Methods**: 17
- **Fields**: 19
- **Source**: `android\network\util\FusionUtil.java`

**Key Methods**:
  - `addXInParams()`
  - `generateFusionSignature()`
  - `StringBuilder()`
  - `getBodyEncryptData()`
  - `getBodyParams()`
  - `getHeaderParams()`
  - `HashMap()`
  - `transferHeaderKeys()`
  - `getQueryEncryptData()`
  - `getQueryParams()`
  - *(... and 7 more)*

---

### ParseHelper [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.util.ParseHelper`
- **Package**: `com.thingclips.smart.android.network.util`
- **Methods**: 27
- **Fields**: 49
- **Source**: `android\network\util\ParseHelper.java`

**Key Methods**:
  - `parse2ArrayList()`
  - `parse2ArrayList()`
  - `parse2ArrayLists()`
  - `parse2ArrayLists()`
  - `parse2HashMap()`
  - `parse2HashMap()`
  - `parse2PageList()`
  - `parse2PageList()`
  - `parser()`
  - `responseByteToString()`
  - *(... and 17 more)*

---

### ThingNetGzipHelper [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.util.ThingNetGzipHelper`
- **Package**: `com.thingclips.smart.android.network.util`
- **Methods**: 12
- **Fields**: 37
- **Source**: `android\network\util\ThingNetGzipHelper.java`

**Key Methods**:
  - `decompress()`
  - `ByteArrayInputStream()`
  - `GZIPInputStream()`
  - `ByteArrayOutputStream()`
  - `decompress2()`
  - `ByteArrayInputStream()`
  - `GZIPInputStream()`
  - `ByteArrayOutputStream()`
  - `formatRoundToTwoDecimal()`
  - `isGzip()`
  - *(... and 2 more)*

---

### TLSSocketFactory [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.network.util.TLSSocketFactory`
- **Package**: `com.thingclips.smart.android.network.util`
- **Extends**: `SSLSocketFactory`
- **Methods**: 16
- **Fields**: 8
- **Source**: `android\network\util\TLSSocketFactory.java`

**Key Methods**:
  - `TLSSocketFactory()`
  - `enableTLSOnSocket()`
  - `getSupportedProtocols()`
  - `ArrayList()`
  - `createSocket()`
  - `enableTLSOnSocket()`
  - `getDefaultCipherSuites()`
  - `getSupportedCipherSuites()`
  - `createSocket()`
  - `enableTLSOnSocket()`
  - *(... and 6 more)*

---

### CommonConfigBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.user.bean.CommonConfigBean`
- **Package**: `com.thingclips.smart.android.user.bean`
- **Methods**: 30
- **Fields**: 15
- **Source**: `android\user\bean\CommonConfigBean.java`

**Key Methods**:
  - `getFaq()`
  - `getJudge_url()`
  - `getMethod_url()`
  - `getNetwork_failure()`
  - `getNot_receive_email_url()`
  - `getNot_receive_message_url()`
  - `getPrivacy()`
  - `getRouter_help()`
  - `getScenes_validscope_url()`
  - `getSearch_failure_url()`
  - *(... and 20 more)*

---

### Domain [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.user.bean.Domain`
- **Package**: `com.thingclips.smart.android.user.bean`
- **Implements**: `Parcelable, Cloneable`
- **Methods**: 47
- **Fields**: 26
- **Source**: `android\user\bean\Domain.java`

**Key Methods**:
  - `createFromParcel()`
  - `Domain()`
  - `newArray()`
  - `Domain()`
  - `describeContents()`
  - `getAispeechHttpsUrl()`
  - `getAispeechQuicUrl()`
  - `getDns2Url()`
  - `getDnsIps()`
  - `getDnsUrl()`
  - *(... and 37 more)*

---

### Region [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.user.bean.Region`
- **Package**: `com.thingclips.smart.android.user.bean`
- **Implements**: `Serializable`
- **Methods**: 8
- **Fields**: 4
- **Source**: `android\user\bean\Region.java`

**Key Methods**:
  - `getName()`
  - `getServer()`
  - `setName()`
  - `setServer()`
  - `getDefaultServer()`
  - `getServers()`
  - `setDefaultServer()`
  - `setServers()`

---

### UserToB [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.user.bean.UserToB`
- **Package**: `com.thingclips.smart.android.user.bean`
- **Implements**: `Parcelable, Cloneable`
- **Methods**: 13
- **Fields**: 4
- **Source**: `android\user\bean\UserToB.java`

**Key Methods**:
  - `createFromParcel()`
  - `UserToB()`
  - `newArray()`
  - `UserToB()`
  - `describeContents()`
  - `getGmtDelJobCreate()`
  - `isAsInitialPassword()`
  - `isHasDelJob()`
  - `setAsInitialPassword()`
  - `setGmtDelJobCreate()`
  - *(... and 3 more)*

---

### WhiteList [MEDIUM]


- **Full Name**: `com.thingclips.smart.android.user.bean.WhiteList`
- **Package**: `com.thingclips.smart.android.user.bean`
- **Implements**: `Serializable`
- **Methods**: 2
- **Fields**: 1
- **Source**: `android\user\bean\WhiteList.java`

**Key Methods**:
  - `getCountryCodes()`
  - `setCountryCodes()`

---

### Async [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.Async`
- **Package**: `com.thingclips.smart.asynclib`
- **Extends**: `R>`
- **Methods**: 39
- **Fields**: 9
- **Source**: `thingclips\smart\asynclib\Async.java`

**Key Methods**:
  - `Async()`
  - `action()`
  - `create()`
  - `create()`
  - `createThreadHandler()`
  - `createThreadHandler()`
  - `createHandler()`
  - `Handler()`
  - `just()`
  - `attach()`
  - *(... and 29 more)*

---

### ThreadPoolManager [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.ThreadPoolManager`
- **Package**: `com.thingclips.smart.asynclib`
- **Methods**: 19
- **Fields**: 18
- **Source**: `thingclips\smart\asynclib\ThreadPoolManager.java`

**Key Methods**:
  - `ThreadPoolManager()`
  - `getExtendParallelCPT()`
  - `getExtendParallelIO()`
  - `getParallelOverLimitSize()`
  - `getParallelOverThreshold()`
  - `extendCoreThreadLog()`
  - `getDefaultIoThread()`
  - `measureTask()`
  - `resetCoreThreadLog()`
  - `threadPoolBlockLog()`
  - *(... and 9 more)*

---

### Disposable [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.p002rx.Disposable`
- **Package**: `com.thingclips.smart.asynclib.p002rx`
- **Methods**: 2
- **Fields**: 0
- **Source**: `smart\asynclib\p002rx\Disposable.java`

**Key Methods**:
  - `dispose()`
  - `isDisposed()`

---

### AttachDisposable [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.p002rx.Attaches.AttachDisposable`
- **Package**: `com.thingclips.smart.asynclib.p002rx.Attaches`
- **Implements**: `OnAttach<T>, Disposable`
- **Methods**: 6
- **Fields**: 4
- **Source**: `asynclib\p002rx\Attaches\AttachDisposable.java`

**Key Methods**:
  - `AttachDisposable()`
  - `attach()`
  - `onPush()`
  - `dispose()`
  - `isDisposed()`
  - `onAttach()`

---

### LifecycleAttachDisposable [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.p002rx.Attaches.LifecycleAttachDisposable`
- **Package**: `com.thingclips.smart.asynclib.p002rx.Attaches`
- **Extends**: `AtomicBoolean`
- **Implements**: `OnAttach<T>, Disposable`
- **Methods**: 8
- **Fields**: 3
- **Source**: `asynclib\p002rx\Attaches\LifecycleAttachDisposable.java`

**Key Methods**:
  - `LifecycleAttachDisposable()`
  - `LifecycleEventObserver()`
  - `onStateChanged()`
  - `attach()`
  - `onPush()`
  - `dispose()`
  - `isDisposed()`
  - `get()`

---

### ObserverDisposable [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.p002rx.observers.ObserverDisposable`
- **Package**: `com.thingclips.smart.asynclib.p002rx.observers`
- **Implements**: `Observer<T>`
- **Methods**: 3
- **Fields**: 2
- **Source**: `asynclib\p002rx\observers\ObserverDisposable.java`

**Key Methods**:
  - `ObserverDisposable()`
  - `onPush()`
  - `push()`

---

### WrapThread [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.p002rx.observers.WrapThread`
- **Package**: `com.thingclips.smart.asynclib.p002rx.observers`
- **Implements**: `Observer<T>`
- **Methods**: 3
- **Fields**: 2
- **Source**: `asynclib\p002rx\observers\WrapThread.java`

**Key Methods**:
  - `WrapThread()`
  - `push()`
  - `run()`

---

### CustomThreadFactory [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.schedulers.CustomThreadFactory`
- **Package**: `com.thingclips.smart.asynclib.schedulers`
- **Extends**: `AtomicLong`
- **Implements**: `ThreadFactory`
- **Methods**: 4
- **Fields**: 4
- **Source**: `smart\asynclib\schedulers\CustomThreadFactory.java`

**Key Methods**:
  - `CustomThreadFactory()`
  - `newThread()`
  - `Thread()`
  - `CustomThreadFactory()`

---

### GlobalScheduler [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.schedulers.GlobalScheduler`
- **Package**: `com.thingclips.smart.asynclib.schedulers`
- **Implements**: `Scheduler`
- **Methods**: 2
- **Fields**: 1
- **Source**: `smart\asynclib\schedulers\GlobalScheduler.java`

**Key Methods**:
  - `execute()`
  - `executeDelay()`

---

### Scheduler [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.schedulers.Scheduler`
- **Package**: `com.thingclips.smart.asynclib.schedulers`
- **Methods**: 2
- **Fields**: 0
- **Source**: `smart\asynclib\schedulers\Scheduler.java`

**Key Methods**:
  - `execute()`
  - `executeDelay()`

---

### UIScheduler [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.schedulers.UIScheduler`
- **Package**: `com.thingclips.smart.asynclib.schedulers`
- **Implements**: `Scheduler`
- **Methods**: 3
- **Fields**: 1
- **Source**: `smart\asynclib\schedulers\UIScheduler.java`

**Key Methods**:
  - `Handler()`
  - `execute()`
  - `executeDelay()`

---

### IOWrapCallable [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.schedulers.io.IOWrapCallable`
- **Package**: `com.thingclips.smart.asynclib.schedulers.io`
- **Extends**: `TaskTracker`
- **Implements**: `Callable<V>`
- **Methods**: 5
- **Fields**: 3
- **Source**: `asynclib\schedulers\io\IOWrapCallable.java`

**Key Methods**:
  - `IOWrapCallable()`
  - `attachThreadWorker()`
  - `IllegalArgumentException()`
  - `call()`
  - `taskClassName()`

---

### IOWrapperTask [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.schedulers.io.IOWrapperTask`
- **Package**: `com.thingclips.smart.asynclib.schedulers.io`
- **Extends**: `TaskTracker`
- **Implements**: `Runnable`
- **Methods**: 5
- **Fields**: 3
- **Source**: `asynclib\schedulers\io\IOWrapperTask.java`

**Key Methods**:
  - `IOWrapperTask()`
  - `attachThreadWorker()`
  - `IllegalArgumentException()`
  - `run()`
  - `taskClassName()`

---

### ThreadWorker [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.schedulers.io.ThreadWorker`
- **Package**: `com.thingclips.smart.asynclib.schedulers.io`
- **Methods**: 10
- **Fields**: 7
- **Source**: `asynclib\schedulers\io\ThreadWorker.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `ScheduledThreadPoolExecutor()`
  - `destroy()`
  - `execute()`
  - `getExpirationTime()`
  - `setExpirationTime()`
  - `submit()`
  - `tryIdleStatus()`
  - `submit()`
  - `submit()`

---

### PriorityFutureTask [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.threadpool.PriorityFutureTask`
- **Package**: `com.thingclips.smart.asynclib.threadpool`
- **Extends**: `FutureTask<T>`
- **Implements**: `ITaskPriority, ITaskTracker`
- **Methods**: 9
- **Fields**: 2
- **Source**: `smart\asynclib\threadpool\PriorityFutureTask.java`

**Key Methods**:
  - `PriorityFutureTask()`
  - `TaskTracker()`
  - `costTime()`
  - `priority()`
  - `statePrint()`
  - `taskClassName()`
  - `waitTime()`
  - `PriorityFutureTask()`
  - `TaskTracker()`

---

### PriorityRunnable [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.threadpool.PriorityRunnable`
- **Package**: `com.thingclips.smart.asynclib.threadpool`
- **Extends**: `TaskTrackerRunnable`
- **Implements**: `ITaskPriority, ITaskTracker`
- **Methods**: 5
- **Fields**: 2
- **Source**: `smart\asynclib\threadpool\PriorityRunnable.java`

**Key Methods**:
  - `PriorityRunnable()`
  - `priority()`
  - `run()`
  - `taskClassName()`
  - `PriorityRunnable()`

---

### TaskTrackerRunnable [MEDIUM]


- **Full Name**: `com.thingclips.smart.asynclib.threadpool.TaskTrackerRunnable`
- **Package**: `com.thingclips.smart.asynclib.threadpool`
- **Extends**: `TaskTracker`
- **Implements**: `Runnable`
- **Methods**: 0
- **Fields**: 0
- **Source**: `smart\asynclib\threadpool\TaskTrackerRunnable.java`

---

### C0150R [MEDIUM]


- **Full Name**: `com.thingclips.smart.audioengine.C0150R`
- **Package**: `com.thingclips.smart.audioengine`
- **Methods**: 17
- **Fields**: 3367
- **Source**: `thingclips\smart\audioengine\C0150R.java`

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
  - *(... and 7 more)*

---

### pbbppqb [MEDIUM]


- **Full Name**: `com.thingclips.smart.audioengine.pbbppqb`
- **Package**: `com.thingclips.smart.audioengine`
- **Implements**: `ILog`
- **Methods**: 6
- **Fields**: 0
- **Source**: `thingclips\smart\audioengine\pbbppqb.java`

**Key Methods**:
  - `mo311d()`
  - `mo312e()`
  - `mo314i()`
  - `mo315v()`
  - `mo316w()`
  - `mo313e()`

---

### ThingAudioTrack [MEDIUM]


- **Full Name**: `com.thingclips.smart.audioengine.bean.ThingAudioTrack`
- **Package**: `com.thingclips.smart.audioengine.bean`
- **Extends**: `Thread`
- **Methods**: 10
- **Fields**: 25
- **Source**: `smart\audioengine\bean\ThingAudioTrack.java`

**Key Methods**:
  - `AudioTrackThread()`
  - `joinThread()`
  - `run()`
  - `ThingAudioTrack()`
  - `InitPlayout()`
  - `StartPlayout()`
  - `AudioTrackThread()`
  - `StopPlayout()`
  - `nativeCacheDirectBufferAddress()`
  - `nativeGetPlayoutData()`

---

### ILog [MEDIUM]


- **Full Name**: `com.thingclips.smart.audioengine.toolkit.api.ILog`
- **Package**: `com.thingclips.smart.audioengine.toolkit.api`
- **Methods**: 6
- **Fields**: 0
- **Source**: `audioengine\toolkit\api\ILog.java`

**Key Methods**:
  - `mo311d()`
  - `mo312e()`
  - `mo313e()`
  - `mo314i()`
  - `mo315v()`
  - `mo316w()`

---

### bdpdqbp [MEDIUM]


- **Full Name**: `com.thingclips.smart.avlogger.bdpdqbp`
- **Package**: `com.thingclips.smart.avlogger`
- **Implements**: `ThingAvLoggerInterface`
- **Methods**: 11
- **Fields**: 1
- **Source**: `thingclips\smart\avlogger\bdpdqbp.java`

**Key Methods**:
  - `deInitAvLogger()`
  - `enableDebug()`
  - `enableFileDump()`
  - `enableLocalLogFileRecord()`
  - `enableLogReport()`
  - `getDumpStatus()`
  - `getVersion()`
  - `initAvLogger()`
  - `setCacheFolder()`
  - `setFileDumpFolder()`
  - *(... and 1 more)*

---

### ThingAvLoggerInterface [MEDIUM]


- **Full Name**: `com.thingclips.smart.avlogger.api.ThingAvLoggerInterface`
- **Package**: `com.thingclips.smart.avlogger.api`
- **Methods**: 11
- **Fields**: 0
- **Source**: `smart\avlogger\api\ThingAvLoggerInterface.java`

**Key Methods**:
  - `deInitAvLogger()`
  - `enableDebug()`
  - `enableFileDump()`
  - `enableLocalLogFileRecord()`
  - `enableLogReport()`
  - `getDumpStatus()`
  - `getVersion()`
  - `initAvLogger()`
  - `setCacheFolder()`
  - `setFileDumpFolder()`
  - *(... and 1 more)*

---

### ThingAvLoggerJni [MEDIUM]


- **Full Name**: `com.thingclips.smart.avlogger.jni.ThingAvLoggerJni`
- **Package**: `com.thingclips.smart.avlogger.jni`
- **Methods**: 11
- **Fields**: 0
- **Source**: `smart\avlogger\jni\ThingAvLoggerJni.java`

**Key Methods**:
  - `GetVersion()`
  - `deInitAvLogger()`
  - `enableDebug()`
  - `enableFileDump()`
  - `enableLocalLogFileRecord()`
  - `enableLogReport()`
  - `getDumpStatus()`
  - `initAvLogger()`
  - `setCacheFolder()`
  - `setFileDumpFolder()`
  - *(... and 1 more)*

---

### ILog [MEDIUM]


- **Full Name**: `com.thingclips.smart.avlogger.toolkit.api.ILog`
- **Package**: `com.thingclips.smart.avlogger.toolkit.api`
- **Methods**: 6
- **Fields**: 0
- **Source**: `avlogger\toolkit\api\ILog.java`

**Key Methods**:
  - `mo318d()`
  - `mo319e()`
  - `mo320e()`
  - `mo321i()`
  - `mo322v()`
  - `mo323w()`

---

### LogImpl [MEDIUM]


- **Full Name**: `com.thingclips.smart.avlogger.toolkit.impl.LogImpl`
- **Package**: `com.thingclips.smart.avlogger.toolkit.impl`
- **Implements**: `ILog`
- **Methods**: 6
- **Fields**: 0
- **Source**: `avlogger\toolkit\impl\LogImpl.java`

**Key Methods**:
  - `mo318d()`
  - `mo319e()`
  - `mo321i()`
  - `mo322v()`
  - `mo323w()`
  - `mo320e()`

---

### BeaconFilterSetting [MEDIUM]


- **Full Name**: `com.thingclips.smart.bluet.api.BeaconFilterSetting`
- **Package**: `com.thingclips.smart.bluet.api`
- **Implements**: `Parcelable`
- **Methods**: 23
- **Fields**: 19
- **Source**: `smart\bluet\api\BeaconFilterSetting.java`

**Key Methods**:
  - `createFromParcel()`
  - `BeaconFilterSetting()`
  - `newArray()`
  - `build()`
  - `BeaconFilterSetting()`
  - `setDeviceAddress()`
  - `setDeviceName()`
  - `setIBeaconUuid()`
  - `setId()`
  - `setManufacturerData()`
  - *(... and 13 more)*

---

### IThingBleFittingsManager [MEDIUM]


- **Full Name**: `com.thingclips.smart.bluet.api.IThingBleFittingsManager`
- **Package**: `com.thingclips.smart.bluet.api`
- **Methods**: 4
- **Fields**: 0
- **Source**: `smart\bluet\api\IThingBleFittingsManager.java`

**Key Methods**:
  - `addFittingsChangeListener()`
  - `deleteFittings()`
  - `handleFittingsData()`
  - `removeFittingsChangeListener()`

---

### RunnableC0154a [MEDIUM]


- **Full Name**: `p004v.RunnableC0154a`
- **Package**: `p004v`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 4
- **Source**: `classes5\sources\p004v\RunnableC0154a.java`

**Key Methods**:
  - `run()`

---

### bpbbqdb [LOW]


- **Full Name**: `com.thingclips.sdk.matterlib.bpbbqdb`
- **Package**: `com.thingclips.sdk.matterlib`
- **Implements**: `IMatterConnectedCallback`
- **Methods**: 14
- **Fields**: 11
- **Source**: `thingclips\sdk\matterlib\bpbbqdb.java`

**Key Methods**:
  - `bpbbqdb()`
  - `CopyOnWriteArraySet()`
  - `bdpdqbp()`
  - `onConnectionFailure()`
  - `onDeviceConnected()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `if()`
  - `pdqppqb()`
  - `qddqppb()`
  - *(... and 4 more)*

---

## Package Structure

### Package Hierarchy

```
com/ (1113 classes)
      ├── matter/ (1 classes)
        ├── activator/ (5 classes)
        ├── api/ (10 classes)
        ├── bean/ (3 classes)
        ├── business/ (1 classes)
        ├── config/ (1 classes)
        ├── control/ (1 classes)
          ├── cache/ (1 classes)
        ├── discover/ (5 classes)
          ├── bean/ (2 classes)
  └── ... and 171 more packages

p004v/ (1 classes)
├── p004v/ (1 classes)

```

### Top 20 Packages by Class Count

| Package | Classes |
| --- | --- |
| com.thingclips.sdk.mdns.dnsjava | 125 |
| com.thingclips.sdk.mqtt | 58 |
| com.thingclips.smart.android.ble.api | 55 |
| com.thingclips.sdk.matterlib | 52 |
| com.thingclips.sdk.user | 32 |
| com.thingclips.smart.android.common.utils | 29 |
| com.thingclips.sdk.sigmesh.bean | 26 |
| com.thingclips.smart.android.blemesh.bean | 26 |
| com.thingclips.smart.android.camera.sdk.api | 25 |
| com.thingclips.smart.android.device.bean | 25 |
| com.thingclips.sdk.sigmesh.provisioner | 24 |
| com.thingclips.smart.android.blemesh.event | 21 |
| com.thingclips.smart.android.user.api | 21 |
| com.thingclips.smart.android.blemesh.api | 20 |
| com.thingclips.sdk.personallib | 15 |
| com.thingclips.sdk.mdns | 14 |
| com.thingclips.smart.android.ble.api.audio | 14 |
| com.thingclips.sdk.scenelib | 13 |
| com.thingclips.smart.android.network.util | 12 |
| com.thingclips.sdk.p000os | 11 |

## String Constants & UUIDs

### UUID Definitions Found

| UUID | Purpose | Occurrences | Files |
| --- | --- | --- | --- |
| 00000000-0000-1000-8000-00805f9b34fb | Unknown | 2 | ScanRecord.java |
| 00000103-0000-1001-8001-00805f9b07d0 | Unknown | 1 | BluetoothHelper.java |
| 00002902-0000-1000-8000-00805f9b34fb | Unknown | 1 | pdqppqb.java |
| 0000fd50-0000-1000-8000-00805f9b34fb | Unknown | 1 | BluetoothHelper.java |
| 0000fff6-0000-1000-8000-00805f9b34fb | Unknown | 8 | BluetoothHelper.java, MatterBleScanner.java, dqqbdqb.java |
| 64630238-8772-45f2-b87d-748a83218f04 | Unknown | 1 | BluetoothHelper.java |

## BLE Write Operations

Found 2 BLE write operations:

#### CovertCompatUtil.java

- **Line 601**: `setValue(stepDpPropertyBean)`

<details>
<summary>Show code snippet</summary>

```java
if (stepDpProperty == null) {
            return null;
        }
        FunctionDataPoint.StepDpPropertyBean stepDpPropertyBean = new FunctionDataPoint.StepDpPropertyBean();
        stepDpPropertyBean.setValue(stepDpProperty.getValue());
        return stepDpPropertyBean;
    }
}
```

</details>


#### qqpdpbp.java

- **Line 784**: `setValue(userExtraPropertyBean)`

<details>
<summary>Show code snippet</summary>

```java
private UserExtraPropertyBean bdpdqbp(AuthorizationType authorizationType, Boolean bool) {
        UserExtraPropertyBean userExtraPropertyBean = new UserExtraPropertyBean();
        userExtraPropertyBean.setCode(authorizationType.getValue());
        userExtraPropertyBean.setValue("1");
        userExtraPropertyBean.setStatus(bool.booleanValue() ? 1 : 0);
        return userExtraPropertyBean;
    }

    private MessageAttach bdpdqbp(String str) {
```

</details>


## Command Sequences

*No command sequences found in this DEX file.*

## Method Index

### Write/Send Methods

- `CopyOnWriteArraySet()` in `bdpdqbp`
- `sendThingDps()` in `bdpdqbp`
- `sendThingDps()` in `bdpdqbp`
- `sendThingRawDp()` in `bdpdqbp`
- `sendDps()` in `bdpdqbp`
- `sendIdentifyGroupCommand()` in `bdpdqbp`
- `sendIdentifyGroupCommand()` in `bdpdqbp`
- `sendIdentifyGroupCommand()` in `bdpdqbp`
- `writeActiveToken()` in `bdpdqbp`
- `CopyOnWriteArraySet()` in `bdpdqbp`
- `CopyOnWriteArraySet()` in `bdpdqbp`
- `CopyOnWriteArraySet()` in `bdpdqbp`
- `onCharacteristicWrite()` in `bppdpdq`
- `onDescriptorWrite()` in `bppdpdq`
- `onReliableWriteCompleted()` in `bppdpdq`
- *(... and 177 more)*

### Callback/Event Methods

- `onCancelAccountSuccess()` in `ThingMatterPlugin`
- `onDestroy()` in `ThingMatterPlugin`
- `setDeviceControllerInitCallback()` in `ThingMatterPlugin`
- `onError()` in `IMatterNsdDiscoverListener`
- `onConnectionFailure()` in `bdpdqbp`
- `onDeviceConnected()` in `bdpdqbp`
- `onFailure()` in `bdpdqbp`
- `onSuccess()` in `bdpdqbp`
- `onConnectionFailure()` in `bdpdqbp`
- `onDeviceConnected()` in `bdpdqbp`
- `onConnectionFailure()` in `bdpdqbp`
- `onDeviceConnected()` in `bdpdqbp`
- `onFailure()` in `bdpdqbp`
- `onSuccess()` in `bdpdqbp`
- `onDpReport()` in `bdpdqbp`
- *(... and 1145 more)*

## Full Class List

<details>
<summary>Click to expand full class list (1114 classes)</summary>

Total: 1114 classes

### com.thingclips.sdk.matter

- `com.thingclips.sdk.matter.ThingMatterPlugin`

### com.thingclips.sdk.matter.activator

- `com.thingclips.sdk.matter.activator.IDiscoveryListener`
- `com.thingclips.sdk.matter.activator.IDynamicDiscoveryListener`
- `com.thingclips.sdk.matter.activator.IMatterActivator`
- `com.thingclips.sdk.matter.activator.IMatterDiscoveryActivator`
- `com.thingclips.sdk.matter.activator.SetupPayload`

### com.thingclips.sdk.matter.api

- `com.thingclips.sdk.matter.api.ConnectedDeviceCallback`
- `com.thingclips.sdk.matter.api.ICompletionListener`
- `com.thingclips.sdk.matter.api.IDiscoverBonjourService`
- `com.thingclips.sdk.matter.api.IHostAddressListener`
- `com.thingclips.sdk.matter.api.IMatterActivatorListener`
- `com.thingclips.sdk.matter.api.IMatterModel`
- `com.thingclips.sdk.matter.api.IMatterNsdDiscoverListener`
- `com.thingclips.sdk.matter.api.MatterConnectCallback`
- `com.thingclips.sdk.matter.api.ThingMatterDpCallback`
- `com.thingclips.sdk.matter.api.ThingMatterReportCallback`

### com.thingclips.sdk.matter.bean

- `com.thingclips.sdk.matter.bean.FabricAllocBean`
- `com.thingclips.sdk.matter.bean.FabricInfo`
- `com.thingclips.sdk.matter.bean.MatterNocSignBean`

### com.thingclips.sdk.matter.business

- `com.thingclips.sdk.matter.business.bdpdqbp`

### com.thingclips.sdk.matter.config

- `com.thingclips.sdk.matter.config.MatterErrorCode`

### com.thingclips.sdk.matter.control

- `com.thingclips.sdk.matter.control.bdpdqbp`

### com.thingclips.sdk.matter.control.cache

- `com.thingclips.sdk.matter.control.cache.bdpdqbp`

### com.thingclips.sdk.matter.discover

- `com.thingclips.sdk.matter.discover.DiscoverServiceImp`
- `com.thingclips.sdk.matter.discover.bdpdqbp`
- `com.thingclips.sdk.matter.discover.bdpdqbp`
- `com.thingclips.sdk.matter.discover.bdpdqbp`
- `com.thingclips.sdk.matter.discover.bppdpdq`

### com.thingclips.sdk.matter.discover.bean

- `com.thingclips.sdk.matter.discover.bean.DiscoveryBean`
- `com.thingclips.sdk.matter.discover.bean.SharedDeviceLocation`

### com.thingclips.sdk.matter.discover.ble

- `com.thingclips.sdk.matter.discover.ble.bdpdqbp`

### com.thingclips.sdk.matter.discover.ble.bean

- `com.thingclips.sdk.matter.discover.ble.bean.IndicationReceived`
- `com.thingclips.sdk.matter.discover.ble.bean.ThingMatterLeBean`

### com.thingclips.sdk.matter.discover.nsd

- `com.thingclips.sdk.matter.discover.nsd.NsdResolveService`
- `com.thingclips.sdk.matter.discover.nsd.NsdResolver`

### com.thingclips.sdk.matter.model.bean

- `com.thingclips.sdk.matter.model.bean.MatterNodeId`

### com.thingclips.sdk.matter.nsd

- `com.thingclips.sdk.matter.nsd.Default`
- `com.thingclips.sdk.matter.nsd.Default`

### com.thingclips.sdk.matter.presenter

- `com.thingclips.sdk.matter.presenter.ThingMatterMultipleFabricDevice`
- `com.thingclips.sdk.matter.presenter.bdpdqbp`
- `com.thingclips.sdk.matter.presenter.bdpdqbp`
- `com.thingclips.sdk.matter.presenter.bdpdqbp`
- `com.thingclips.sdk.matter.presenter.bdpdqbp`
- `com.thingclips.sdk.matter.presenter.bppdpdq`
- `com.thingclips.sdk.matter.presenter.pdqppqb`

### com.thingclips.sdk.matter.presenter.connect

- `com.thingclips.sdk.matter.presenter.connect.bdpdqbp`

### com.thingclips.sdk.matter.presenter.connect.bean

- `com.thingclips.sdk.matter.presenter.connect.bean.ConnectedNode`
- `com.thingclips.sdk.matter.presenter.connect.bean.ResolvingTask`

### com.thingclips.sdk.matter.presenter.pipeline.bean

- `com.thingclips.sdk.matter.presenter.pipeline.bean.MatterFabricAttributeBean`
- `com.thingclips.sdk.matter.presenter.pipeline.bean.PipelineData`

### com.thingclips.sdk.matter.util

- `com.thingclips.sdk.matter.util.CertifiedUtil`
- `com.thingclips.sdk.matter.util.bdpdqbp`

### com.thingclips.sdk.matterlib

- `com.thingclips.sdk.matterlib.C0006R`
- `com.thingclips.sdk.matterlib.bdpdqbp`
- `com.thingclips.sdk.matterlib.bdqqbqd`
- `com.thingclips.sdk.matterlib.bpbbqdb`
- `com.thingclips.sdk.matterlib.bppdpdq`
- `com.thingclips.sdk.matterlib.bpqqdpq`
- `com.thingclips.sdk.matterlib.bqbdbqb`
- `com.thingclips.sdk.matterlib.bqbppdq`
- `com.thingclips.sdk.matterlib.bqqppqq`
- `com.thingclips.sdk.matterlib.dbbpbbb`
- `com.thingclips.sdk.matterlib.dbpdpbp`
- `com.thingclips.sdk.matterlib.dbppbbp`
- `com.thingclips.sdk.matterlib.ddbdqbd`
- `com.thingclips.sdk.matterlib.ddqdbbd`
- `com.thingclips.sdk.matterlib.dpdbqdp`
- `com.thingclips.sdk.matterlib.dpdqppp`
- `com.thingclips.sdk.matterlib.dqdbbqp`
- `com.thingclips.sdk.matterlib.dqdpbbd`
- `com.thingclips.sdk.matterlib.dqqbdqb`
- `com.thingclips.sdk.matterlib.pbbppqb`
- `com.thingclips.sdk.matterlib.pbddddb`
- `com.thingclips.sdk.matterlib.pbpdbqp`
- `com.thingclips.sdk.matterlib.pbpdpdp`
- `com.thingclips.sdk.matterlib.pbpqqdp`
- `com.thingclips.sdk.matterlib.pdbbqdp`
- `com.thingclips.sdk.matterlib.pdqppqb`
- `com.thingclips.sdk.matterlib.ppdpppq`
- `com.thingclips.sdk.matterlib.pppbppp`
- `com.thingclips.sdk.matterlib.pqdbppq`
- `com.thingclips.sdk.matterlib.pqdppqd`
- `com.thingclips.sdk.matterlib.pqdqqbd`
- `com.thingclips.sdk.matterlib.pqpbdqq`
- `com.thingclips.sdk.matterlib.pqpbpqd`
- `com.thingclips.sdk.matterlib.qbbdpbq`
- `com.thingclips.sdk.matterlib.qbpppdb`
- `com.thingclips.sdk.matterlib.qbqddpp`
- `com.thingclips.sdk.matterlib.qbqqdqq`
- `com.thingclips.sdk.matterlib.qdddbpp`
- `com.thingclips.sdk.matterlib.qddqppb`
- `com.thingclips.sdk.matterlib.qdpppbq`
- `com.thingclips.sdk.matterlib.qpbpqpq`
- `com.thingclips.sdk.matterlib.qppddqq`
- `com.thingclips.sdk.matterlib.qpppdqb`
- `com.thingclips.sdk.matterlib.qpqbppd`
- `com.thingclips.sdk.matterlib.qpqddqd`
- `com.thingclips.sdk.matterlib.qqdbbpp`
- `com.thingclips.sdk.matterlib.qqddbpb`
- `com.thingclips.sdk.matterlib.qqdqqpd`
- `com.thingclips.sdk.matterlib.qqpddqd`
- `com.thingclips.sdk.matterlib.qqpdpbp`
- `com.thingclips.sdk.matterlib.qqpppdp`
- `com.thingclips.sdk.matterlib.qqqpdpb`

### com.thingclips.sdk.matterlib.api

- `com.thingclips.sdk.matterlib.api.BuildConfig`
- `com.thingclips.sdk.matterlib.api.C0007R`

### com.thingclips.sdk.mdns

- `com.thingclips.sdk.mdns.Browse`
- `com.thingclips.sdk.mdns.BuildConfig`
- `com.thingclips.sdk.mdns.Constants`
- `com.thingclips.sdk.mdns.DNSSDListener`
- `com.thingclips.sdk.mdns.Lookup`
- `com.thingclips.sdk.mdns.MulticastDNSCache`
- `com.thingclips.sdk.mdns.MulticastDNSLookupBase`
- `com.thingclips.sdk.mdns.MulticastDNSMulticastOnlyQuerier`
- `com.thingclips.sdk.mdns.MulticastDNSQuerier`
- `com.thingclips.sdk.mdns.MulticastDNSService`
- `com.thingclips.sdk.mdns.Querier`
- `com.thingclips.sdk.mdns.ServiceInstance`
- `com.thingclips.sdk.mdns.ServiceName`
- `com.thingclips.sdk.mdns.ServiceRegistrationException`

### com.thingclips.sdk.mdns.dnsjava

- `com.thingclips.sdk.mdns.dnsjava.A6Record`
- `com.thingclips.sdk.mdns.dnsjava.AAAARecord`
- `com.thingclips.sdk.mdns.dnsjava.AFSDBRecord`
- `com.thingclips.sdk.mdns.dnsjava.APLRecord`
- `com.thingclips.sdk.mdns.dnsjava.ARecord`
- `com.thingclips.sdk.mdns.dnsjava.Address`
- `com.thingclips.sdk.mdns.dnsjava.CAARecord`
- `com.thingclips.sdk.mdns.dnsjava.CDNSKEYRecord`
- `com.thingclips.sdk.mdns.dnsjava.CDSRecord`
- `com.thingclips.sdk.mdns.dnsjava.CERTRecord`
- `com.thingclips.sdk.mdns.dnsjava.CNAMERecord`
- `com.thingclips.sdk.mdns.dnsjava.Cache`
- `com.thingclips.sdk.mdns.dnsjava.Client`
- `com.thingclips.sdk.mdns.dnsjava.ClientSubnetOption`
- `com.thingclips.sdk.mdns.dnsjava.Compression`
- `com.thingclips.sdk.mdns.dnsjava.Credibility`
- `com.thingclips.sdk.mdns.dnsjava.DClass`
- `com.thingclips.sdk.mdns.dnsjava.DHCIDRecord`
- `com.thingclips.sdk.mdns.dnsjava.DLVRecord`
- `com.thingclips.sdk.mdns.dnsjava.DNAMERecord`
- `com.thingclips.sdk.mdns.dnsjava.DNSInput`
- `com.thingclips.sdk.mdns.dnsjava.DNSKEYRecord`
- `com.thingclips.sdk.mdns.dnsjava.DNSOutput`
- `com.thingclips.sdk.mdns.dnsjava.DNSSEC`
- `com.thingclips.sdk.mdns.dnsjava.DSRecord`
- `com.thingclips.sdk.mdns.dnsjava.EDNSOption`
- `com.thingclips.sdk.mdns.dnsjava.EmptyRecord`
- `com.thingclips.sdk.mdns.dnsjava.ExtendedFlags`
- `com.thingclips.sdk.mdns.dnsjava.ExtendedResolver`
- `com.thingclips.sdk.mdns.dnsjava.Flags`
- `com.thingclips.sdk.mdns.dnsjava.FormattedTime`
- `com.thingclips.sdk.mdns.dnsjava.GPOSRecord`
- `com.thingclips.sdk.mdns.dnsjava.Generator`
- `com.thingclips.sdk.mdns.dnsjava.GenericEDNSOption`
- `com.thingclips.sdk.mdns.dnsjava.HINFORecord`
- `com.thingclips.sdk.mdns.dnsjava.Header`
- `com.thingclips.sdk.mdns.dnsjava.IPSECKEYRecord`
- `com.thingclips.sdk.mdns.dnsjava.ISDNRecord`
- `com.thingclips.sdk.mdns.dnsjava.InvalidDClassException`
- `com.thingclips.sdk.mdns.dnsjava.InvalidTTLException`
- `com.thingclips.sdk.mdns.dnsjava.InvalidTypeException`
- `com.thingclips.sdk.mdns.dnsjava.KEYBase`
- `com.thingclips.sdk.mdns.dnsjava.KEYRecord`
- `com.thingclips.sdk.mdns.dnsjava.KXRecord`
- `com.thingclips.sdk.mdns.dnsjava.LOCRecord`
- `com.thingclips.sdk.mdns.dnsjava.Lookup`
- `com.thingclips.sdk.mdns.dnsjava.MBRecord`
- `com.thingclips.sdk.mdns.dnsjava.MDRecord`
- `com.thingclips.sdk.mdns.dnsjava.MFRecord`
- `com.thingclips.sdk.mdns.dnsjava.MGRecord`
- `com.thingclips.sdk.mdns.dnsjava.MINFORecord`
- `com.thingclips.sdk.mdns.dnsjava.MRRecord`
- `com.thingclips.sdk.mdns.dnsjava.MXRecord`
- `com.thingclips.sdk.mdns.dnsjava.Master`
- `com.thingclips.sdk.mdns.dnsjava.Message`
- `com.thingclips.sdk.mdns.dnsjava.Mnemonic`
- `com.thingclips.sdk.mdns.dnsjava.MulticastDNSUtils`
- `com.thingclips.sdk.mdns.dnsjava.NAPTRRecord`
- `com.thingclips.sdk.mdns.dnsjava.NSAPRecord`
- `com.thingclips.sdk.mdns.dnsjava.NSAP_PTRRecord`
- `com.thingclips.sdk.mdns.dnsjava.NSEC3PARAMRecord`
- `com.thingclips.sdk.mdns.dnsjava.NSEC3Record`
- `com.thingclips.sdk.mdns.dnsjava.NSECRecord`
- `com.thingclips.sdk.mdns.dnsjava.NSIDOption`
- `com.thingclips.sdk.mdns.dnsjava.NSRecord`
- `com.thingclips.sdk.mdns.dnsjava.NULLRecord`
- `com.thingclips.sdk.mdns.dnsjava.NXTRecord`
- `com.thingclips.sdk.mdns.dnsjava.Name`
- `com.thingclips.sdk.mdns.dnsjava.NameTooLongException`
- `com.thingclips.sdk.mdns.dnsjava.OPENPGPKEYRecord`
- `com.thingclips.sdk.mdns.dnsjava.OPTRecord`
- `com.thingclips.sdk.mdns.dnsjava.Opcode`
- `com.thingclips.sdk.mdns.dnsjava.Options`
- `com.thingclips.sdk.mdns.dnsjava.PTRRecord`
- `com.thingclips.sdk.mdns.dnsjava.PXRecord`
- `com.thingclips.sdk.mdns.dnsjava.PacketLogger`
- `com.thingclips.sdk.mdns.dnsjava.RPRecord`
- `com.thingclips.sdk.mdns.dnsjava.RRSIGRecord`
- `com.thingclips.sdk.mdns.dnsjava.RRset`
- `com.thingclips.sdk.mdns.dnsjava.RTRecord`
- `com.thingclips.sdk.mdns.dnsjava.Rcode`
- `com.thingclips.sdk.mdns.dnsjava.Record`
- `com.thingclips.sdk.mdns.dnsjava.RelativeNameException`
- `com.thingclips.sdk.mdns.dnsjava.ResolveThread`
- `com.thingclips.sdk.mdns.dnsjava.Resolver`
- `com.thingclips.sdk.mdns.dnsjava.ResolverConfig`
- `com.thingclips.sdk.mdns.dnsjava.ResolverListener`
- `com.thingclips.sdk.mdns.dnsjava.ReverseMap`
- `com.thingclips.sdk.mdns.dnsjava.SIG0`
- `com.thingclips.sdk.mdns.dnsjava.SIGBase`
- `com.thingclips.sdk.mdns.dnsjava.SIGRecord`
- `com.thingclips.sdk.mdns.dnsjava.SMIMEARecord`
- `com.thingclips.sdk.mdns.dnsjava.SOARecord`
- `com.thingclips.sdk.mdns.dnsjava.SPFRecord`
- `com.thingclips.sdk.mdns.dnsjava.SRVRecord`
- `com.thingclips.sdk.mdns.dnsjava.SSHFPRecord`
- `com.thingclips.sdk.mdns.dnsjava.Section`
- `com.thingclips.sdk.mdns.dnsjava.Serial`
- `com.thingclips.sdk.mdns.dnsjava.SetResponse`
- `com.thingclips.sdk.mdns.dnsjava.SimpleResolver`
- `com.thingclips.sdk.mdns.dnsjava.SingleCompressedNameBase`
- `com.thingclips.sdk.mdns.dnsjava.SingleNameBase`
- `com.thingclips.sdk.mdns.dnsjava.TCPClient`
- `com.thingclips.sdk.mdns.dnsjava.TKEYRecord`
- `com.thingclips.sdk.mdns.dnsjava.TLSARecord`
- `com.thingclips.sdk.mdns.dnsjava.TSIG`
- `com.thingclips.sdk.mdns.dnsjava.TSIGRecord`
- `com.thingclips.sdk.mdns.dnsjava.TTL`
- `com.thingclips.sdk.mdns.dnsjava.TXTBase`
- `com.thingclips.sdk.mdns.dnsjava.TXTRecord`
- `com.thingclips.sdk.mdns.dnsjava.TextParseException`
- `com.thingclips.sdk.mdns.dnsjava.Tokenizer`
- `com.thingclips.sdk.mdns.dnsjava.Type`
- `com.thingclips.sdk.mdns.dnsjava.TypeBitmap`
- `com.thingclips.sdk.mdns.dnsjava.U16NameBase`
- `com.thingclips.sdk.mdns.dnsjava.UDPClient`
- `com.thingclips.sdk.mdns.dnsjava.UNKRecord`
- `com.thingclips.sdk.mdns.dnsjava.URIRecord`
- `com.thingclips.sdk.mdns.dnsjava.Update`
- `com.thingclips.sdk.mdns.dnsjava.WKSRecord`
- `com.thingclips.sdk.mdns.dnsjava.WireParseException`
- `com.thingclips.sdk.mdns.dnsjava.X25Record`
- `com.thingclips.sdk.mdns.dnsjava.Zone`
- `com.thingclips.sdk.mdns.dnsjava.ZoneTransferException`
- `com.thingclips.sdk.mdns.dnsjava.ZoneTransferIn`

### com.thingclips.sdk.mdns.dnsjava.utils

- `com.thingclips.sdk.mdns.dnsjava.utils.base16`
- `com.thingclips.sdk.mdns.dnsjava.utils.base32`
- `com.thingclips.sdk.mdns.dnsjava.utils.base64`
- `com.thingclips.sdk.mdns.dnsjava.utils.hexdump`

### com.thingclips.sdk.mdns.net

- `com.thingclips.sdk.mdns.net.DatagramProcessor`
- `com.thingclips.sdk.mdns.net.NetworkProcessor`
- `com.thingclips.sdk.mdns.net.Packet`
- `com.thingclips.sdk.mdns.net.PacketListener`
- `com.thingclips.sdk.mdns.net.UnicastProcessor`

### com.thingclips.sdk.mdns.utils

- `com.thingclips.sdk.mdns.utils.ExecutionTimer`
- `com.thingclips.sdk.mdns.utils.Executors`
- `com.thingclips.sdk.mdns.utils.ListenerProcessor`
- `com.thingclips.sdk.mdns.utils.Misc`
- `com.thingclips.sdk.mdns.utils.Wait`

### com.thingclips.sdk.model

- `com.thingclips.sdk.model.TimeManager`

### com.thingclips.sdk.mqtt

- `com.thingclips.sdk.mqtt.C0036R`
- `com.thingclips.sdk.mqtt.ThingMqttPlugin`
- `com.thingclips.sdk.mqtt.bddqqbb`
- `com.thingclips.sdk.mqtt.bdpdqbp`
- `com.thingclips.sdk.mqtt.bdqqbqd`
- `com.thingclips.sdk.mqtt.bpbbqdb`
- `com.thingclips.sdk.mqtt.bppdpdq`
- `com.thingclips.sdk.mqtt.bpqqdpq`
- `com.thingclips.sdk.mqtt.bqbdbqb`
- `com.thingclips.sdk.mqtt.bqbppdq`
- `com.thingclips.sdk.mqtt.bqqppqq`
- `com.thingclips.sdk.mqtt.dbbpbbb`
- `com.thingclips.sdk.mqtt.dbpdpbp`
- `com.thingclips.sdk.mqtt.dbppbbp`
- `com.thingclips.sdk.mqtt.dbqqppp`
- `com.thingclips.sdk.mqtt.ddbdqbd`
- `com.thingclips.sdk.mqtt.ddqdbbd`
- `com.thingclips.sdk.mqtt.dpdbqdp`
- `com.thingclips.sdk.mqtt.dpdqppp`
- `com.thingclips.sdk.mqtt.dppdpbd`
- `com.thingclips.sdk.mqtt.dqdbbqp`
- `com.thingclips.sdk.mqtt.dqddqdp`
- `com.thingclips.sdk.mqtt.dqdpbbd`
- `com.thingclips.sdk.mqtt.dqqbdqb`
- `com.thingclips.sdk.mqtt.pbbppqb`
- `com.thingclips.sdk.mqtt.pbddddb`
- `com.thingclips.sdk.mqtt.pbpdbqp`
- `com.thingclips.sdk.mqtt.pbpdpdp`
- `com.thingclips.sdk.mqtt.pbpqqdp`
- `com.thingclips.sdk.mqtt.pdbbqdp`
- `com.thingclips.sdk.mqtt.pdqdqbd`
- `com.thingclips.sdk.mqtt.pdqppqb`
- `com.thingclips.sdk.mqtt.ppdpppq`
- `com.thingclips.sdk.mqtt.pppbppp`
- `com.thingclips.sdk.mqtt.pqdbppq`
- `com.thingclips.sdk.mqtt.pqdppqd`
- `com.thingclips.sdk.mqtt.pqdqqbd`
- `com.thingclips.sdk.mqtt.pqpbdqq`
- `com.thingclips.sdk.mqtt.pqpbpqd`
- `com.thingclips.sdk.mqtt.qbbdpbq`
- `com.thingclips.sdk.mqtt.qbpppdb`
- `com.thingclips.sdk.mqtt.qbqddpp`
- `com.thingclips.sdk.mqtt.qbqqdqq`
- `com.thingclips.sdk.mqtt.qdddbpp`
- `com.thingclips.sdk.mqtt.qddqppb`
- `com.thingclips.sdk.mqtt.qdpppbq`
- `com.thingclips.sdk.mqtt.qpbpqpq`
- `com.thingclips.sdk.mqtt.qppddqq`
- `com.thingclips.sdk.mqtt.qpppdqb`
- `com.thingclips.sdk.mqtt.qpqbppd`
- `com.thingclips.sdk.mqtt.qpqddqd`
- `com.thingclips.sdk.mqtt.qqdbbpp`
- `com.thingclips.sdk.mqtt.qqddbpb`
- `com.thingclips.sdk.mqtt.qqdqqpd`
- `com.thingclips.sdk.mqtt.qqpddqd`
- `com.thingclips.sdk.mqtt.qqpdpbp`
- `com.thingclips.sdk.mqtt.qqpppdp`
- `com.thingclips.sdk.mqtt.qqqpdpb`

### com.thingclips.sdk.mqttmanager.bean

- `com.thingclips.sdk.mqttmanager.bean.MqttConfigBean`

### com.thingclips.sdk.mqttmanager.model

- `com.thingclips.sdk.mqttmanager.model.Connection`
- `com.thingclips.sdk.mqttmanager.model.bdpdqbp`

### com.thingclips.sdk.mqttprotocol.bean

- `com.thingclips.sdk.mqttprotocol.bean.PublishBean`
- `com.thingclips.sdk.mqttprotocol.bean.PublishBean2_1`
- `com.thingclips.sdk.mqttprotocol.bean.PublishBean2_2`
- `com.thingclips.sdk.mqttprotocol.bean.PublishBean2_3`
- `com.thingclips.sdk.mqttprotocol.bean.PublishQueryBean2_1`

### com.thingclips.sdk.network

- `com.thingclips.sdk.network.ThingApiSignManager`
- `com.thingclips.sdk.network.ThingNetworkSecurity`
- `com.thingclips.sdk.network.bdpdqbp`
- `com.thingclips.sdk.network.bppdpdq`
- `com.thingclips.sdk.network.pbbppqb`
- `com.thingclips.sdk.network.pdqppqb`
- `com.thingclips.sdk.network.pppbppp`
- `com.thingclips.sdk.network.qddqppb`
- `com.thingclips.sdk.network.qpppdqb`

### com.thingclips.sdk.ota

- `com.thingclips.sdk.ota.ThingOtaPlugin`

### com.thingclips.sdk.ota_service

- `com.thingclips.sdk.ota_service.ThingOtaServicePlugin`

### com.thingclips.sdk.p000os

- `com.thingclips.sdk.p000os.ThingOSActivator`
- `com.thingclips.sdk.p000os.ThingOSBLE`
- `com.thingclips.sdk.p000os.ThingOSDevice`
- `com.thingclips.sdk.p000os.ThingOSGroup`
- `com.thingclips.sdk.p000os.ThingOSMQTT`
- `com.thingclips.sdk.p000os.ThingOSMesh`
- `com.thingclips.sdk.p000os.ThingOSMultiControl`
- `com.thingclips.sdk.p000os.ThingOSScene`
- `com.thingclips.sdk.p000os.ThingOSTimer`
- `com.thingclips.sdk.p000os.ThingOSTyMesh`
- `com.thingclips.sdk.p000os.ThingOSUser`

### com.thingclips.sdk.p001yu.api

- `com.thingclips.sdk.p001yu.api.BuildConfig`
- `com.thingclips.sdk.p001yu.api.C0049R`
- `com.thingclips.sdk.p001yu.api.IYuChannel`
- `com.thingclips.sdk.p001yu.api.IYuPlugin`
- `com.thingclips.sdk.p001yu.api.IYuWorkStation`

### com.thingclips.sdk.p001yu.api.bean

- `com.thingclips.sdk.p001yu.api.bean.DeviceYuStatus`
- `com.thingclips.sdk.p001yu.api.bean.YuChannelDevStatusBean`

### com.thingclips.sdk.personal

- `com.thingclips.sdk.personal.C0037R`
- `com.thingclips.sdk.personal.ThingPersonalPlugin`

### com.thingclips.sdk.personal.bean

- `com.thingclips.sdk.personal.bean.UserExtraPropertyBean`

### com.thingclips.sdk.personallib

- `com.thingclips.sdk.personallib.bdpdqbp`
- `com.thingclips.sdk.personallib.bpbbqdb`
- `com.thingclips.sdk.personallib.bppdpdq`
- `com.thingclips.sdk.personallib.dpdbqdp`
- `com.thingclips.sdk.personallib.pbbppqb`
- `com.thingclips.sdk.personallib.pbddddb`
- `com.thingclips.sdk.personallib.pbpdbqp`
- `com.thingclips.sdk.personallib.pbpdpdp`
- `com.thingclips.sdk.personallib.pdqppqb`
- `com.thingclips.sdk.personallib.pppbppp`
- `com.thingclips.sdk.personallib.pqdbppq`
- `com.thingclips.sdk.personallib.qddqppb`
- `com.thingclips.sdk.personallib.qpppdqb`
- `com.thingclips.sdk.personallib.qqpddqd`
- `com.thingclips.sdk.personallib.qqpdpbp`

### com.thingclips.sdk.regions

- `com.thingclips.sdk.regions.IThingRegionsPlugin`
- `com.thingclips.sdk.regions.ThingRegionsPlugin`

### com.thingclips.sdk.scene

- `com.thingclips.sdk.scene.C0038R`
- `com.thingclips.sdk.scene.ThingScenePlugin`

### com.thingclips.sdk.scene.bean

- `com.thingclips.sdk.scene.bean.LocalSceneResBean`
- `com.thingclips.sdk.scene.bean.LocalSceneResultBean`

### com.thingclips.sdk.scene.utils

- `com.thingclips.sdk.scene.utils.CovertCompatUtil`

### com.thingclips.sdk.scenelib

- `com.thingclips.sdk.scenelib.bdpdqbp`
- `com.thingclips.sdk.scenelib.bppdpdq`
- `com.thingclips.sdk.scenelib.dpdbqdp`
- `com.thingclips.sdk.scenelib.pbbppqb`
- `com.thingclips.sdk.scenelib.pbddddb`
- `com.thingclips.sdk.scenelib.pbpdbqp`
- `com.thingclips.sdk.scenelib.pbpdpdp`
- `com.thingclips.sdk.scenelib.pdqppqb`
- `com.thingclips.sdk.scenelib.pppbppp`
- `com.thingclips.sdk.scenelib.pqdbppq`
- `com.thingclips.sdk.scenelib.qddqppb`
- `com.thingclips.sdk.scenelib.qpppdqb`
- `com.thingclips.sdk.scenelib.qqpddqd`

### com.thingclips.sdk.security

- `com.thingclips.sdk.security.EncryptionManager`
- `com.thingclips.sdk.security.SecuredPreferenceStore`
- `com.thingclips.sdk.security.SecuredStore`

### com.thingclips.sdk.sigmesh

- `com.thingclips.sdk.sigmesh.Features`

### com.thingclips.sdk.sigmesh.bean

- `com.thingclips.sdk.sigmesh.bean.AccessMessage`
- `com.thingclips.sdk.sigmesh.bean.CommandPackage`
- `com.thingclips.sdk.sigmesh.bean.ControlMessage`
- `com.thingclips.sdk.sigmesh.bean.DeviceInfoRep`
- `com.thingclips.sdk.sigmesh.bean.DpCommandBean`
- `com.thingclips.sdk.sigmesh.bean.MeshTransferBean`
- `com.thingclips.sdk.sigmesh.bean.Message`
- `com.thingclips.sdk.sigmesh.bean.ModelBindBean`
- `com.thingclips.sdk.sigmesh.bean.NetworkKey`
- `com.thingclips.sdk.sigmesh.bean.OTAFileRep`
- `com.thingclips.sdk.sigmesh.bean.OTAOffsetRep`
- `com.thingclips.sdk.sigmesh.bean.OTAResultRep`
- `com.thingclips.sdk.sigmesh.bean.OTASendRep`
- `com.thingclips.sdk.sigmesh.bean.OTAStartRep`
- `com.thingclips.sdk.sigmesh.bean.ProvisionedBaseMeshNode`
- `com.thingclips.sdk.sigmesh.bean.ProvisionedMeshNode`
- `com.thingclips.sdk.sigmesh.bean.ProvisioningCapabilities`
- `com.thingclips.sdk.sigmesh.bean.Reps`
- `com.thingclips.sdk.sigmesh.bean.Ret`
- `com.thingclips.sdk.sigmesh.bean.ScanRecord`
- `com.thingclips.sdk.sigmesh.bean.SecureNetworkBeacon`
- `com.thingclips.sdk.sigmesh.bean.SigConfigBean`
- `com.thingclips.sdk.sigmesh.bean.ThingSigMeshBean`
- `com.thingclips.sdk.sigmesh.bean.UnprovisionedBaseMeshNode`
- `com.thingclips.sdk.sigmesh.bean.UnprovisionedBeacon`
- `com.thingclips.sdk.sigmesh.bean.UnprovisionedMeshNode`

### com.thingclips.sdk.sigmesh.control

- `com.thingclips.sdk.sigmesh.control.TransportControlMessage`
- `com.thingclips.sdk.sigmesh.control.bdpdqbp`

### com.thingclips.sdk.sigmesh.manager

- `com.thingclips.sdk.sigmesh.manager.bdpdqbp`

### com.thingclips.sdk.sigmesh.model

- `com.thingclips.sdk.sigmesh.model.SigModel`
- `com.thingclips.sdk.sigmesh.model.VendorModel`

### com.thingclips.sdk.sigmesh.parse

- `com.thingclips.sdk.sigmesh.parse.ThingSigMeshParser`
- `com.thingclips.sdk.sigmesh.parse.bdpdqbp`

### com.thingclips.sdk.sigmesh.provisioner

- `com.thingclips.sdk.sigmesh.provisioner.ConfigAppKeyStatus`
- `com.thingclips.sdk.sigmesh.provisioner.ConfigCompositionDataStatus`
- `com.thingclips.sdk.sigmesh.provisioner.ConfigModelAppStatus`
- `com.thingclips.sdk.sigmesh.provisioner.ConfigModelPublicationStatus`
- `com.thingclips.sdk.sigmesh.provisioner.ConfigModelSubscriptionStatus`
- `com.thingclips.sdk.sigmesh.provisioner.ConfigNetworkTransmitStatus`
- `com.thingclips.sdk.sigmesh.provisioner.ConfigNodeResetStatus`
- `com.thingclips.sdk.sigmesh.provisioner.FittingsStatus`
- `com.thingclips.sdk.sigmesh.provisioner.GenericOnOffStatus`
- `com.thingclips.sdk.sigmesh.provisioner.GroupDeviceGetStatus`
- `com.thingclips.sdk.sigmesh.provisioner.HeartBeatStatus`
- `com.thingclips.sdk.sigmesh.provisioner.LightCtlStatus`
- `com.thingclips.sdk.sigmesh.provisioner.LightCtlTemperatureStatus`
- `com.thingclips.sdk.sigmesh.provisioner.LightHslStatus`
- `com.thingclips.sdk.sigmesh.provisioner.LightLightnessStatus`
- `com.thingclips.sdk.sigmesh.provisioner.LightModeStatus`
- `com.thingclips.sdk.sigmesh.provisioner.ThingVendorModelStatus`
- `com.thingclips.sdk.sigmesh.provisioner.ThingVendorTidModelStatus`
- `com.thingclips.sdk.sigmesh.provisioner.ThingVendorTidReportModelStatus`
- `com.thingclips.sdk.sigmesh.provisioner.VendorDSTRequestStatus`
- `com.thingclips.sdk.sigmesh.provisioner.VendorModelMessageStatus`
- `com.thingclips.sdk.sigmesh.provisioner.VendorModelStatus`
- `com.thingclips.sdk.sigmesh.provisioner.VendorSubscriptionListStatus`
- `com.thingclips.sdk.sigmesh.provisioner.VendorTimeRequestStatus`

### com.thingclips.sdk.sigmesh.provisioner.fast

- `com.thingclips.sdk.sigmesh.provisioner.fast.FastConfirmProvisionState`
- `com.thingclips.sdk.sigmesh.provisioner.fast.FastDefaultNodeIdModelState`
- `com.thingclips.sdk.sigmesh.provisioner.fast.FastGroupConfirmState`
- `com.thingclips.sdk.sigmesh.provisioner.fast.FastSetAddressModelState`

### com.thingclips.sdk.sigmesh.transport

- `com.thingclips.sdk.sigmesh.transport.ApplicationKey`
- `com.thingclips.sdk.sigmesh.transport.ConfigStatusMessage`
- `com.thingclips.sdk.sigmesh.transport.MeshModel`

### com.thingclips.sdk.sigmesh.util

- `com.thingclips.sdk.sigmesh.util.AddressArray`
- `com.thingclips.sdk.sigmesh.util.ExtendedInvalidCipherTextException`
- `com.thingclips.sdk.sigmesh.util.PublicationSettings`
- `com.thingclips.sdk.sigmesh.util.RelaySettings`
- `com.thingclips.sdk.sigmesh.util.SecureUtils`
- `com.thingclips.sdk.sigmesh.util.SparseIntArrayParcelable`

### com.thingclips.sdk.thingmesh.bean

- `com.thingclips.sdk.thingmesh.bean.CommandBean`

### com.thingclips.sdk.timer

- `com.thingclips.sdk.timer.ThingTimerPlugin`

### com.thingclips.sdk.timer.bean

- `com.thingclips.sdk.timer.bean.CategoryStatusBean`
- `com.thingclips.sdk.timer.bean.CommonTimerInnerBean`
- `com.thingclips.sdk.timer.bean.DpTimerBean`
- `com.thingclips.sdk.timer.bean.DpTimerListBean`
- `com.thingclips.sdk.timer.bean.DpTimerPointBean`
- `com.thingclips.sdk.timer.bean.GroupTimerBean`

### com.thingclips.sdk.user

- `com.thingclips.sdk.user.C0046R`
- `com.thingclips.sdk.user.ThingBaseUserPlugin`
- `com.thingclips.sdk.user.ThingUserAggregationManager`
- `com.thingclips.sdk.user.ThingUserDecoratorPlugin`
- `com.thingclips.sdk.user.ThingUserListenerPlugin`
- `com.thingclips.sdk.user.bdpdqbp`
- `com.thingclips.sdk.user.bpbbqdb`
- `com.thingclips.sdk.user.bppdpdq`
- `com.thingclips.sdk.user.bpqqdpq`
- `com.thingclips.sdk.user.bqqppqq`
- `com.thingclips.sdk.user.dbbpbbb`
- `com.thingclips.sdk.user.dpdbqdp`
- `com.thingclips.sdk.user.dpdqppp`
- `com.thingclips.sdk.user.dqdbbqp`
- `com.thingclips.sdk.user.dqdpbbd`
- `com.thingclips.sdk.user.pbbppqb`
- `com.thingclips.sdk.user.pbddddb`
- `com.thingclips.sdk.user.pbpdbqp`
- `com.thingclips.sdk.user.pbpdpdp`
- `com.thingclips.sdk.user.pbpqqdp`
- `com.thingclips.sdk.user.pdqppqb`
- `com.thingclips.sdk.user.pppbppp`
- `com.thingclips.sdk.user.pqdbppq`
- `com.thingclips.sdk.user.pqpbpqd`
- `com.thingclips.sdk.user.qbqqdqq`
- `com.thingclips.sdk.user.qdddbpp`
- `com.thingclips.sdk.user.qddqppb`
- `com.thingclips.sdk.user.qpbpqpq`
- `com.thingclips.sdk.user.qpppdqb`
- `com.thingclips.sdk.user.qqdbbpp`
- `com.thingclips.sdk.user.qqpddqd`
- `com.thingclips.sdk.user.qqpdpbp`

### com.thingclips.sdk.user.api

- `com.thingclips.sdk.user.api.IThingUserAggregationPlugin`

### com.thingclips.sdk.user.base

- `com.thingclips.sdk.user.base.C0047R`

### com.thingclips.sdk.user.bean

- `com.thingclips.sdk.user.bean.BizCodeDomainBean`
- `com.thingclips.sdk.user.bean.StorageSign`
- `com.thingclips.sdk.user.bean.TokenBean`

### com.thingclips.sdk.user.model

- `com.thingclips.sdk.user.model.IUser`

### com.thingclips.sdk.util

- `com.thingclips.sdk.util.OptimusUtil`

### com.thingclips.smart.android

- `com.thingclips.smart.android.SecurityFile`

### com.thingclips.smart.android.base

- `com.thingclips.smart.android.base.ApiParams`
- `com.thingclips.smart.android.base.BaseConfig`
- `com.thingclips.smart.android.base.BuildConfig`
- `com.thingclips.smart.android.base.C0050R`
- `com.thingclips.smart.android.base.EncryptApiParams`
- `com.thingclips.smart.android.base.ThingSmartSdk`

### com.thingclips.smart.android.base.bean

- `com.thingclips.smart.android.base.bean.CountryBean`
- `com.thingclips.smart.android.base.bean.CountryRespBean`

### com.thingclips.smart.android.base.broadcast

- `com.thingclips.smart.android.base.broadcast.NetworkBroadcastReceiver`

### com.thingclips.smart.android.base.database

- `com.thingclips.smart.android.base.database.StorageHelper`

### com.thingclips.smart.android.base.event

- `com.thingclips.smart.android.base.event.BaseEventSender`
- `com.thingclips.smart.android.base.event.NetWorkStatusEvent`
- `com.thingclips.smart.android.base.event.NetWorkStatusEventModel`
- `com.thingclips.smart.android.base.event.ThingEventBus`

### com.thingclips.smart.android.base.mmkv

- `com.thingclips.smart.android.base.mmkv.BuildConfig`

### com.thingclips.smart.android.base.mmkv.manager

- `com.thingclips.smart.android.base.mmkv.manager.MMKVManager`

### com.thingclips.smart.android.base.mmkv.util

- `com.thingclips.smart.android.base.mmkv.util.GlobalMMKVManager`

### com.thingclips.smart.android.base.provider

- `com.thingclips.smart.android.base.provider.ApiUrlProvider`
- `com.thingclips.smart.android.base.provider.DomainHelper`
- `com.thingclips.smart.android.base.provider.ServerDomainBean`

### com.thingclips.smart.android.base.utils

- `com.thingclips.smart.android.base.utils.PreferencesUtil`
- `com.thingclips.smart.android.base.utils.ProcessUtils`
- `com.thingclips.smart.android.base.utils.UserPreferenceUtil`

### com.thingclips.smart.android.ble

- `com.thingclips.smart.android.ble.IThingBeaconManager`
- `com.thingclips.smart.android.ble.IThingBleCommRodCtrl`
- `com.thingclips.smart.android.ble.IThingBleController`
- `com.thingclips.smart.android.ble.IThingBleManager`
- `com.thingclips.smart.android.ble.IThingBleOperator`
- `com.thingclips.smart.android.ble.IThingDeviceConnectManager`
- `com.thingclips.smart.android.ble.IThingFittings`
- `com.thingclips.smart.android.ble.IThingLEAudioManager`
- `com.thingclips.smart.android.ble.IThingThirdProtocolDelegate`
- `com.thingclips.smart.android.ble.IThingThirdProtocolSupport`

### com.thingclips.smart.android.ble.api

- `com.thingclips.smart.android.ble.api.ActivateBLEDeviceListener`
- `com.thingclips.smart.android.ble.api.AddGwSubDeviceListener`
- `com.thingclips.smart.android.ble.api.BeaconAuthBean`
- `com.thingclips.smart.android.ble.api.BleConnectStatusListener`
- `com.thingclips.smart.android.ble.api.BleControllerBean`
- `com.thingclips.smart.android.ble.api.BleControllerUpdateBean`
- `com.thingclips.smart.android.ble.api.BleLogCallback`
- `com.thingclips.smart.android.ble.api.BleRssiListener`
- `com.thingclips.smart.android.ble.api.BleScanResponse`
- `com.thingclips.smart.android.ble.api.BleWiFiDeviceBean`
- `com.thingclips.smart.android.ble.api.BluetoothBondStateBean`
- `com.thingclips.smart.android.ble.api.BluetoothStateChangedListener`
- `com.thingclips.smart.android.ble.api.ChannelDataConstants`
- `com.thingclips.smart.android.ble.api.CheckResultBean`
- `com.thingclips.smart.android.ble.api.CombosFlagCapability`
- `com.thingclips.smart.android.ble.api.ConfigErrorBean`
- `com.thingclips.smart.android.ble.api.DataChannelListener`
- `com.thingclips.smart.android.ble.api.DataCustom2ChannelListener`
- `com.thingclips.smart.android.ble.api.DataCustomChannelListener`
- `com.thingclips.smart.android.ble.api.DevIotDataBean`
- `com.thingclips.smart.android.ble.api.DeviceDataBean`
- `com.thingclips.smart.android.ble.api.ExtModuleStatusListener`
- `com.thingclips.smart.android.ble.api.IBleThroughDataListener`
- `com.thingclips.smart.android.ble.api.ICommRodSchemaListener`
- `com.thingclips.smart.android.ble.api.IGetCustomHomeWeather`
- `com.thingclips.smart.android.ble.api.IGetCustomLocationWeather`
- `com.thingclips.smart.android.ble.api.IGetHomeWeather`
- `com.thingclips.smart.android.ble.api.IGetLocationWeather`
- `com.thingclips.smart.android.ble.api.IGetWeather`
- `com.thingclips.smart.android.ble.api.IThingBleConfigListener`
- `com.thingclips.smart.android.ble.api.IThingBleGateway`
- `com.thingclips.smart.android.ble.api.IThingBluetoothFlow`
- `com.thingclips.smart.android.ble.api.LeConnectResponse`
- `com.thingclips.smart.android.ble.api.LeConnectStatusResponse`
- `com.thingclips.smart.android.ble.api.LeScanSetting`
- `com.thingclips.smart.android.ble.api.LocalDataModel`
- `com.thingclips.smart.android.ble.api.OnBleActivatorListener`
- `com.thingclips.smart.android.ble.api.OnBleConnectListener`
- `com.thingclips.smart.android.ble.api.OnBleDataTransferListener`
- `com.thingclips.smart.android.ble.api.OnBleIoTChannelListener`
- `com.thingclips.smart.android.ble.api.OnBleMultiModeDevStatusListener`
- `com.thingclips.smart.android.ble.api.OnBleRevChannelListener`
- `com.thingclips.smart.android.ble.api.OnBleSendChannelListener`
- `com.thingclips.smart.android.ble.api.OnBleToDeviceListener`
- `com.thingclips.smart.android.ble.api.OnBleUpgradeListener`
- `com.thingclips.smart.android.ble.api.OnDataLocalProcessingListener`
- `com.thingclips.smart.android.ble.api.OnDeviceAttributeListener`
- `com.thingclips.smart.android.ble.api.OnMultiModeActivatorStatusListener`
- `com.thingclips.smart.android.ble.api.OnThirdConnectListener`
- `com.thingclips.smart.android.ble.api.ResetErrorCode`
- `com.thingclips.smart.android.ble.api.ScanDeviceBean`
- `com.thingclips.smart.android.ble.api.ThingBleScanResponse`
- `com.thingclips.smart.android.ble.api.ThirdBleScanDeviceBuilder`
- `com.thingclips.smart.android.ble.api.WatchWeatherBean`
- `com.thingclips.smart.android.ble.api.WiFiInfo`

### com.thingclips.smart.android.ble.api.audio

- `com.thingclips.smart.android.ble.api.audio.AudioCommnonResponse`
- `com.thingclips.smart.android.ble.api.audio.AudioCommonCommand`
- `com.thingclips.smart.android.ble.api.audio.AudioNoramlResult`
- `com.thingclips.smart.android.ble.api.audio.AudioTokenBean`
- `com.thingclips.smart.android.ble.api.audio.CalendarResult`
- `com.thingclips.smart.android.ble.api.audio.LEAudioAlarmClockRequest`
- `com.thingclips.smart.android.ble.api.audio.LEAudioRequest`
- `com.thingclips.smart.android.ble.api.audio.LEAudioResult`
- `com.thingclips.smart.android.ble.api.audio.OnLEAudioStatusListener`
- `com.thingclips.smart.android.ble.api.audio.ThingLEAudioDataArgs`
- `com.thingclips.smart.android.ble.api.audio.ThingLEAudioEnum`
- `com.thingclips.smart.android.ble.api.audio.ThingLEAudioProvideArgs`
- `com.thingclips.smart.android.ble.api.audio.ThingLEAudioStartArgs`
- `com.thingclips.smart.android.ble.api.audio.WeatherResult`

### com.thingclips.smart.android.ble.bean

- `com.thingclips.smart.android.ble.bean.BatchBeaconActivatorBean`
- `com.thingclips.smart.android.ble.bean.BeaconBatchCheckBean`
- `com.thingclips.smart.android.ble.bean.BleOTABean`
- `com.thingclips.smart.android.ble.bean.CheckDeviceSetting`
- `com.thingclips.smart.android.ble.bean.QueryWifiSetting`
- `com.thingclips.smart.android.ble.bean.ResetBleSetting`
- `com.thingclips.smart.android.ble.bean.ScanReq`
- `com.thingclips.smart.android.ble.bean.ThirdConnectErrorBean`
- `com.thingclips.smart.android.ble.bean.ThirdConnectInfoBean`
- `com.thingclips.smart.android.ble.bean.ThirdConstant`
- `com.thingclips.smart.android.ble.bean.ThirdDpsUpdate`

### com.thingclips.smart.android.ble.builder

- `com.thingclips.smart.android.ble.builder.BleConnectBuilder`
- `com.thingclips.smart.android.ble.builder.BlueConnectParam`

### com.thingclips.smart.android.ble.connect

- `com.thingclips.smart.android.ble.connect.ConnectBuilder`
- `com.thingclips.smart.android.ble.connect.ConnectOptions`

### com.thingclips.smart.android.ble.connect.api

- `com.thingclips.smart.android.ble.connect.api.ConnectResponse`
- `com.thingclips.smart.android.ble.connect.api.INotifyDelegate`
- `com.thingclips.smart.android.ble.connect.api.IThingBleService`
- `com.thingclips.smart.android.ble.connect.api.OnBleConnectStatusChangeListener`
- `com.thingclips.smart.android.ble.connect.api.ReadRemoteRssiCallback`

### com.thingclips.smart.android.ble.connect.request

- `com.thingclips.smart.android.ble.connect.request.XRequest`
- `com.thingclips.smart.android.ble.connect.request.XResponse`

### com.thingclips.smart.android.ble.enums

- `com.thingclips.smart.android.ble.enums.BleConnectAbility`

### com.thingclips.smart.android.ble.scanner

- `com.thingclips.smart.android.ble.scanner.IThingInnerScanner`
- `com.thingclips.smart.android.ble.scanner.InnerScanResponse`

### com.thingclips.smart.android.blemesh

- `com.thingclips.smart.android.blemesh.IMeshCommonControl`
- `com.thingclips.smart.android.blemesh.IMeshDataAnalysis`
- `com.thingclips.smart.android.blemesh.IMeshLocalController`
- `com.thingclips.smart.android.blemesh.ISigMeshControl`
- `com.thingclips.smart.android.blemesh.ISigMeshRssi`
- `com.thingclips.smart.android.blemesh.IThingMeshControl`
- `com.thingclips.smart.android.blemesh.IThingMeshManager`
- `com.thingclips.smart.android.blemesh.IThingMeshService`

### com.thingclips.smart.android.blemesh.api

- `com.thingclips.smart.android.blemesh.api.BusinessResultListener`
- `com.thingclips.smart.android.blemesh.api.IMeshEventHandler`
- `com.thingclips.smart.android.blemesh.api.IMeshManager`
- `com.thingclips.smart.android.blemesh.api.IResultWithDataCallback`
- `com.thingclips.smart.android.blemesh.api.IThingBlueMeshActivatorListener`
- `com.thingclips.smart.android.blemesh.api.IThingBlueMeshBusiness`
- `com.thingclips.smart.android.blemesh.api.IThingBlueMeshClient`
- `com.thingclips.smart.android.blemesh.api.IThingBlueMeshConfig`
- `com.thingclips.smart.android.blemesh.api.IThingBlueMeshDevice`
- `com.thingclips.smart.android.blemesh.api.IThingBlueMeshGroup`
- `com.thingclips.smart.android.blemesh.api.IThingBlueMeshInit`
- `com.thingclips.smart.android.blemesh.api.IThingBlueMeshOta`
- `com.thingclips.smart.android.blemesh.api.IThingBlueMeshSearch`
- `com.thingclips.smart.android.blemesh.api.IThingBlueMeshSearchListener`
- `com.thingclips.smart.android.blemesh.api.IThingExtBlueMeshOta`
- `com.thingclips.smart.android.blemesh.api.IThingMeshCallback`
- `com.thingclips.smart.android.blemesh.api.IThingSigMeshClient`
- `com.thingclips.smart.android.blemesh.api.MeshConnectStatus`
- `com.thingclips.smart.android.blemesh.api.MeshConnectStatusListener`
- `com.thingclips.smart.android.blemesh.api.MeshUpgradeListener`

### com.thingclips.smart.android.blemesh.bean

- `com.thingclips.smart.android.blemesh.bean.BLEUpgradeBean`
- `com.thingclips.smart.android.blemesh.bean.BLEUpgradeInfoBean`
- `com.thingclips.smart.android.blemesh.bean.BlueMeshLinkageBean`
- `com.thingclips.smart.android.blemesh.bean.CommandType`
- `com.thingclips.smart.android.blemesh.bean.ConditionLinkageData`
- `com.thingclips.smart.android.blemesh.bean.DevSceneDataBean`
- `com.thingclips.smart.android.blemesh.bean.DeviceType`
- `com.thingclips.smart.android.blemesh.bean.DpsParseBean`
- `com.thingclips.smart.android.blemesh.bean.Element`
- `com.thingclips.smart.android.blemesh.bean.LinkageHash`
- `com.thingclips.smart.android.blemesh.bean.MeshActionLinkageData`
- `com.thingclips.smart.android.blemesh.bean.MeshBeacon`
- `com.thingclips.smart.android.blemesh.bean.MeshConditionLinkageData`
- `com.thingclips.smart.android.blemesh.bean.MeshDeviceOperationType`
- `com.thingclips.smart.android.blemesh.bean.MeshGroupOperationBean`
- `com.thingclips.smart.android.blemesh.bean.MeshLinkageHash`
- `com.thingclips.smart.android.blemesh.bean.MeshLogUploadDataBean`
- `com.thingclips.smart.android.blemesh.bean.MeshOperationBean`
- `com.thingclips.smart.android.blemesh.bean.SceneType`
- `com.thingclips.smart.android.blemesh.bean.SearchDeviceBean`
- `com.thingclips.smart.android.blemesh.bean.SendCommandParams`
- `com.thingclips.smart.android.blemesh.bean.SigMeshConfiguration`
- `com.thingclips.smart.android.blemesh.bean.SigMeshGlobalConfiguration`
- `com.thingclips.smart.android.blemesh.bean.SigMeshSearchDeviceBean`
- `com.thingclips.smart.android.blemesh.bean.TimeMillisConditionLinkageData`
- `com.thingclips.smart.android.blemesh.bean.TimerDayConditionLinkageData`

### com.thingclips.smart.android.blemesh.builder

- `com.thingclips.smart.android.blemesh.builder.MeshLocalGroupBuilder`
- `com.thingclips.smart.android.blemesh.builder.SearchBuilder`
- `com.thingclips.smart.android.blemesh.builder.ThingBlueMeshActivatorBuilder`
- `com.thingclips.smart.android.blemesh.builder.ThingBlueMeshOtaBuilder`
- `com.thingclips.smart.android.blemesh.builder.ThingSigMeshActivatorBuilder`

### com.thingclips.smart.android.blemesh.callback

- `com.thingclips.smart.android.blemesh.callback.ILocalQueryGroupDevCallback`

### com.thingclips.smart.android.blemesh.event

- `com.thingclips.smart.android.blemesh.event.BlueMeshGroupUpdateEvent`
- `com.thingclips.smart.android.blemesh.event.BlueMeshGroupUpdateEventModel`
- `com.thingclips.smart.android.blemesh.event.BlueMeshQueryGroupDevEvent`
- `com.thingclips.smart.android.blemesh.event.BlueMeshQueryGroupDevEventModel`
- `com.thingclips.smart.android.blemesh.event.MeshBatchReportEvent`
- `com.thingclips.smart.android.blemesh.event.MeshBatchReportEventModel`
- `com.thingclips.smart.android.blemesh.event.MeshDeviceRelationUpdateEvent`
- `com.thingclips.smart.android.blemesh.event.MeshDeviceRelationUpdateEventModel`
- `com.thingclips.smart.android.blemesh.event.MeshDpUpdateEvent`
- `com.thingclips.smart.android.blemesh.event.MeshDpUpdateEventModel`
- `com.thingclips.smart.android.blemesh.event.MeshLocalOnlineStatusUpdateEvent`
- `com.thingclips.smart.android.blemesh.event.MeshLocalOnlineStatusUpdateEventModel`
- `com.thingclips.smart.android.blemesh.event.MeshOnlineStatusUpdateEvent`
- `com.thingclips.smart.android.blemesh.event.MeshOnlineStatusUpdateEventModel`
- `com.thingclips.smart.android.blemesh.event.MeshPassThroughEventModel`
- `com.thingclips.smart.android.blemesh.event.MeshRawReportEvent`
- `com.thingclips.smart.android.blemesh.event.MeshRawReportEventModel`
- `com.thingclips.smart.android.blemesh.event.MeshUpdateEvent`
- `com.thingclips.smart.android.blemesh.event.MeshUpdateEventModel`
- `com.thingclips.smart.android.blemesh.event.MqttConnectStatusEvent`
- `com.thingclips.smart.android.blemesh.event.MqttConnectStatusEventModel`

### com.thingclips.smart.android.blemesh.linkage

- `com.thingclips.smart.android.blemesh.linkage.ILinkage`

### com.thingclips.smart.android.camera.api

- `com.thingclips.smart.android.camera.api.IThingHomeCamera`

### com.thingclips.smart.android.camera.api.bean

- `com.thingclips.smart.android.camera.api.bean.CameraPushDataBean`

### com.thingclips.smart.android.camera.sdk

- `com.thingclips.smart.android.camera.sdk.ThingIPCSdk`

### com.thingclips.smart.android.camera.sdk.annotation

- `com.thingclips.smart.android.camera.sdk.annotation.BuildForInside`
- `com.thingclips.smart.android.camera.sdk.annotation.BuildForOpen`
- `com.thingclips.smart.android.camera.sdk.annotation.OpenApi`

### com.thingclips.smart.android.camera.sdk.api

- `com.thingclips.smart.android.camera.sdk.api.ICameraBuilder`
- `com.thingclips.smart.android.camera.sdk.api.ICameraConfigInfo`
- `com.thingclips.smart.android.camera.sdk.api.ICameraFactory`
- `com.thingclips.smart.android.camera.sdk.api.ICameraSp`
- `com.thingclips.smart.android.camera.sdk.api.ICameraStatEvent`
- `com.thingclips.smart.android.camera.sdk.api.ICameraStatusUpdateCallback`
- `com.thingclips.smart.android.camera.sdk.api.ICameraWrapperFactory`
- `com.thingclips.smart.android.camera.sdk.api.ILog`
- `com.thingclips.smart.android.camera.sdk.api.IThingCameraMessage`
- `com.thingclips.smart.android.camera.sdk.api.IThingIPCCloud`
- `com.thingclips.smart.android.camera.sdk.api.IThingIPCCore`
- `com.thingclips.smart.android.camera.sdk.api.IThingIPCCount`
- `com.thingclips.smart.android.camera.sdk.api.IThingIPCDevice`
- `com.thingclips.smart.android.camera.sdk.api.IThingIPCDoorBellManager`
- `com.thingclips.smart.android.camera.sdk.api.IThingIPCDoorBellMsgIntercept`
- `com.thingclips.smart.android.camera.sdk.api.IThingIPCDoorbell`
- `com.thingclips.smart.android.camera.sdk.api.IThingIPCDpHelper`
- `com.thingclips.smart.android.camera.sdk.api.IThingIPCExtPlugin`
- `com.thingclips.smart.android.camera.sdk.api.IThingIPCHomeProxy`
- `com.thingclips.smart.android.camera.sdk.api.IThingIPCMsg`
- `com.thingclips.smart.android.camera.sdk.api.IThingIPCMsgPlugin`
- `com.thingclips.smart.android.camera.sdk.api.IThingIPCPTZ`
- `com.thingclips.smart.android.camera.sdk.api.IThingIPCPlugin`
- `com.thingclips.smart.android.camera.sdk.api.IThingIPCTool`
- `com.thingclips.smart.android.camera.sdk.api.IThingP2pPlugin`

### com.thingclips.smart.android.camera.sdk.bean

- `com.thingclips.smart.android.camera.sdk.bean.CameraMessageClassifyBean`
- `com.thingclips.smart.android.camera.sdk.bean.CameraStatus`
- `com.thingclips.smart.android.camera.sdk.bean.CloudStatusBean`
- `com.thingclips.smart.android.camera.sdk.bean.CollectionPointBean`
- `com.thingclips.smart.android.camera.sdk.bean.IPCRecordConfig`
- `com.thingclips.smart.android.camera.sdk.bean.IPCSnapshotConfig`
- `com.thingclips.smart.android.camera.sdk.bean.SupportResolution`
- `com.thingclips.smart.android.camera.sdk.bean.ThingDoorBellCallModel`

*(... and 82 more packages)*

</details>
