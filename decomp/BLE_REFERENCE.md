# BLE Protocol Reference - Consolidated Findings

This document consolidates all BLE-related discoveries across all 8 DEX files.

**Analysis Date**: 2026-01-10 00:28

---

## Table of Contents

1. [UUID Catalog](#uuid-catalog)
2. [Critical BLE Classes](#critical-ble-classes)
3. [Write Operations](#write-operations)
4. [Command Sequences](#command-sequences)
5. [Protocol Reconstruction](#protocol-reconstruction)

---

## UUID Catalog

### Known UUIDs (from HCI Analysis)

| UUID | Short | Purpose | Status |
| --- | --- | --- | --- |
| `00002adb-0000-1000-8000-00805f9b34fb` | 2adb | Mesh Provisioning In | ✅ Found |
| `00002add-0000-1000-8000-00805f9b34fb` | 2add | Mesh Proxy In | ✅ Found |
| `00002ade-0000-1000-8000-00805f9b34fb` | 2ade | Mesh Proxy Out | ✅ Found |
| `00010203-0405-0607-0809-0a0b0c0d1912` | 1912 | Telink Command | ✅ Found |

### All Discovered UUIDs

#### `00000000-0000-0000-0000-000000000000`

- **Occurrences**: 2
- **Found in**: classes2.md

- `zzli.java:670` - Variable: `N/A`
- `zzli.java:674` - Variable: `N/A`

#### `00000000-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 4
- **Found in**: classes4.md, classes5.md

- `qqpqqpd.java:33` - Variable: `qqpdpbp`
- `qqpqqpd.java:33` - Variable: `qqpdpbp`
- `ScanRecord.java:19` - Variable: `BASE_UUID`
- *(... and 1 more occurrences)*

#### `00000001-0000-1001-8001-00805f9b07d0`

- **Occurrences**: 4
- **Found in**: classes4.md

- `bppbqbb.java:24` - Variable: `dqdbbqp`
- `bppbqbb.java:24` - Variable: `dqdbbqp`
- `qpqqdbp.java:18` - Variable: `dpdbqdp`
- *(... and 1 more occurrences)*

#### `00000002-0000-1001-8001-00805f9b07d0`

- **Occurrences**: 4
- **Found in**: classes4.md

- `bppbqbb.java:25` - Variable: `dpdqppp`
- `bppbqbb.java:25` - Variable: `dpdqppp`
- `qpqqdbp.java:20` - Variable: `bpbbqdb`
- *(... and 1 more occurrences)*

#### `00000003-0000-1001-8001-00805f9b07d0`

- **Occurrences**: 2
- **Found in**: classes4.md

- `bppdpdq.java:53` - Variable: `pqdbppq`
- `bppdpdq.java:53` - Variable: `pqdbppq`

#### `00000103-0000-1001-8001-00805f9b07d0`

- **Occurrences**: 1
- **Found in**: classes5.md

- `BluetoothHelper.java:47` - Variable: `THING_C3_UUID`

#### `00001000-7475-7961-626c-636f6e666967`

- **Occurrences**: 2
- **Found in**: classes4.md

- `dpdpppb.java:30` - Variable: `SERVER_UUID`
- `dpdpppb.java:30` - Variable: `SERVER_UUID`

#### `00001001-7475-7961-626c-636f6e666967`

- **Occurrences**: 2
- **Found in**: classes4.md

- `dpdpppb.java:31` - Variable: `WRITE_UUID`
- `dpdpppb.java:31` - Variable: `WRITE_UUID`

#### `00001002-7475-7961-626c-636f6e666967`

- **Occurrences**: 2
- **Found in**: classes4.md

- `dpdpppb.java:32` - Variable: `NOTIFY_UUID`
- `dpdpppb.java:32` - Variable: `NOTIFY_UUID`

#### `00001801-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 2
- **Found in**: classes8.md

- `BleManager.java:37` - Variable: `f7814g`
- `BleManager.java:37` - Variable: `f7814g`

#### `0000180a-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 4
- **Found in**: classes2.md, classes4.md

- `Telink.java:35` - Variable: `f2055b`
- `Telink.java:35` - Variable: `f2055b`
- `bppbqbb.java:9` - Variable: `bppdpdq`
- *(... and 1 more occurrences)*

#### `0000180f-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 2
- **Found in**: classes8.md

- `BleManager.java:31` - Variable: `f7812e`
- `BleManager.java:31` - Variable: `f7812e`

#### `00001827-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 4
- **Found in**: classes4.md

- `bppbqbb.java:11` - Variable: `pppbppp`
- `bppbqbb.java:11` - Variable: `pppbppp`
- `bppqbqb.java:26` - Variable: `fromString`
- *(... and 1 more occurrences)*

#### `00001828-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 2
- **Found in**: classes4.md

- `bppbqbb.java:17` - Variable: `pqdbppq`
- `bppbqbb.java:17` - Variable: `pqdbppq`

#### `00001910-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 6
- **Found in**: classes4.md

- `bppbqbb.java:20` - Variable: `bpbbqdb`
- `bppbqbb.java:20` - Variable: `bpbbqdb`
- `qpqqdbp.java:7` - Variable: `bdpdqbp`
- *(... and 3 more occurrences)*

#### `00001912-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 2
- **Found in**: classes4.md

- `qpqqdbp.java:11` - Variable: `pppbppp`
- `qpqqdbp.java:11` - Variable: `pppbppp`

#### `00001920-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 4
- **Found in**: classes4.md

- `qpqqdbp.java:13` - Variable: `qpppdqb`
- `qpqqdbp.java:13` - Variable: `qpppdqb`
- `qpqqdbp.java:15` - Variable: `pbpdpdp`
- *(... and 1 more occurrences)*

#### `00002900-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 2
- **Found in**: classes8.md

- `BleServerManager.java:105` - Variable: `N/A`
- `BleServerManager.java:105` - Variable: `N/A`

#### `00002901-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 4
- **Found in**: classes4.md, classes8.md

- `Constants.java:92` - Variable: `CLIENT_2_CHARACTERISTIC_CONFIG`
- `Constants.java:92` - Variable: `CLIENT_2_CHARACTERISTIC_CONFIG`
- `BleServerManager.java:106` - Variable: `N/A`
- *(... and 1 more occurrences)*

#### `00002902-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 10
- **Found in**: classes1.md, classes4.md, classes5.md, classes8.md

- `AndroidBleManager.java:16` - Variable: `CLIENT_CHARACTERISTIC_CONFIG`
- `Constants.java:91` - Variable: `CLIENT_CHARACTERISTIC_CONFIG`
- `Constants.java:91` - Variable: `CLIENT_CHARACTERISTIC_CONFIG`
- *(... and 7 more occurrences)*

#### `00002a05-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 2
- **Found in**: classes8.md

- `BleManager.java:40` - Variable: `f7815h`
- `BleManager.java:40` - Variable: `f7815h`

#### `00002a19-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 2
- **Found in**: classes8.md

- `BleManager.java:34` - Variable: `f7813f`
- `BleManager.java:34` - Variable: `f7813f`

#### `00002a26-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 4
- **Found in**: classes2.md, classes4.md

- `Telink.java:41` - Variable: `f2057d`
- `Telink.java:41` - Variable: `f2057d`
- `bppbqbb.java:10` - Variable: `qddqppb`
- *(... and 1 more occurrences)*

#### `00002adb-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 2
- **Found in**: classes4.md

- `bppbqbb.java:12` - Variable: `pbbppqb`
- `bppbqbb.java:12` - Variable: `pbbppqb`

#### `00002adc-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 2
- **Found in**: classes4.md

- `bppbqbb.java:13` - Variable: `qpppdqb`
- `bppbqbb.java:13` - Variable: `qpppdqb`

#### `00002add-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 4
- **Found in**: classes4.md

- `bppbqbb.java:15` - Variable: `pbpdpdp`
- `bppbqbb.java:15` - Variable: `pbpdpdp`
- `bppbqbb.java:18` - Variable: `dpdbqdp`
- *(... and 1 more occurrences)*

#### `00002ade-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 4
- **Found in**: classes4.md

- `bppbqbb.java:16` - Variable: `pbpdbqp`
- `bppbqbb.java:16` - Variable: `pbpdbqp`
- `bppbqbb.java:19` - Variable: `qqpddqd`
- *(... and 1 more occurrences)*

#### `00002af0-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 2
- **Found in**: classes2.md

- `Telink.java:44` - Variable: `f2058e`
- `Telink.java:44` - Variable: `f2058e`

#### `00002b10-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 4
- **Found in**: classes4.md

- `bppbqbb.java:22` - Variable: `bqqppqq`
- `bppbqbb.java:22` - Variable: `bqqppqq`
- `qpqqdbp.java:10` - Variable: `qddqppb`
- *(... and 1 more occurrences)*

#### `00002b11-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 4
- **Found in**: classes4.md

- `bppbqbb.java:21` - Variable: `qqpdpbp`
- `bppbqbb.java:21` - Variable: `qqpdpbp`
- `qpqqdbp.java:8` - Variable: `pdqppqb`
- *(... and 1 more occurrences)*

#### `00002b12-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 2
- **Found in**: classes4.md

- `qpqqdbp.java:12` - Variable: `pbbppqb`
- `qpqqdbp.java:12` - Variable: `pbbppqb`

#### `00002b23-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 2
- **Found in**: classes4.md

- `qpqqdbp.java:14` - Variable: `pbddddb`
- `qpqqdbp.java:14` - Variable: `pbddddb`

#### `00002b24-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 2
- **Found in**: classes4.md

- `qpqqdbp.java:16` - Variable: `pbpdbqp`
- `qpqqdbp.java:16` - Variable: `pbpdbqp`

#### `00007fdd-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 2
- **Found in**: classes4.md

- `bppbqbb.java:14` - Variable: `pbddddb`
- `bppbqbb.java:14` - Variable: `pbddddb`

#### `0000fd50-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 9
- **Found in**: classes4.md, classes5.md

- `bppdpdq.java:52` - Variable: `pbpdbqp`
- `bppdpdq.java:52` - Variable: `pbpdbqp`
- `bppbqbb.java:23` - Variable: `pbpqqdp`
- *(... and 6 more occurrences)*

#### `0000fff6-0000-1000-8000-00805f9b34fb`

- **Occurrences**: 8
- **Found in**: classes5.md

- `BluetoothHelper.java:44` - Variable: `CHIP_UUID`
- `BluetoothHelper.java:475` - Variable: `serviceData`
- `BluetoothHelper.java:475` - Variable: `serviceData`
- *(... and 5 more occurrences)*

#### `00010203-0405-0607-0809-0a0b0c0d1910`

- **Occurrences**: 2
- **Found in**: classes2.md

- `Telink.java:47` - Variable: `f2059f`
- `Telink.java:47` - Variable: `f2059f`

#### `00010203-0405-0607-0809-0a0b0c0d1911`

- **Occurrences**: 2
- **Found in**: classes2.md

- `Telink.java:50` - Variable: `f2060g`
- `Telink.java:50` - Variable: `f2060g`

#### `00010203-0405-0607-0809-0a0b0c0d1912`

- **Occurrences**: 4
- **Found in**: classes2.md, classes4.md

- `Telink.java:53` - Variable: `f2061h`
- `Telink.java:53` - Variable: `f2061h`
- `bppbqbb.java:7` - Variable: `bdpdqbp`
- *(... and 1 more occurrences)*

#### `00010203-0405-0607-0809-0a0b0c0d1913`

- **Occurrences**: 2
- **Found in**: classes2.md

- `Telink.java:56` - Variable: `f2062i`
- `Telink.java:56` - Variable: `f2062i`

#### `00010203-0405-0607-0809-0a0b0c0d1914`

- **Occurrences**: 2
- **Found in**: classes2.md

- `Telink.java:59` - Variable: `f2063j`
- `Telink.java:59` - Variable: `f2063j`

#### `00010203-0405-0607-0809-0a0b0c0d2b12`

- **Occurrences**: 2
- **Found in**: classes4.md

- `bppbqbb.java:8` - Variable: `pdqppqb`
- `bppbqbb.java:8` - Variable: `pdqppqb`

#### `19200d0c-0b0a-0908-0706-050403020100`

- **Occurrences**: 2
- **Found in**: classes2.md

- `Telink.java:38` - Variable: `f2056c`
- `Telink.java:38` - Variable: `f2056c`

#### `258eafa5-e914-47da-95ca-c5ab0dc85b11`

- **Occurrences**: 1
- **Found in**: classes8.md

- `WebSocketProtocol.java:17` - Variable: `ACCEPT_MAGIC`

#### `64630238-8772-45f2-b87d-748a83218f04`

- **Occurrences**: 1
- **Found in**: classes5.md

- `BluetoothHelper.java:43` - Variable: `C3_UUID`

---

## Critical BLE Classes

### androidx.compose.p002ui.text.android.TextAndroidCanvas

- **Priority**: CRITICAL
- **Found in**: [classes1.md](classes1.md)
- **Extends**: `Canvas`

**Key Methods**:
- `clipOutPath()`
- `clipOutRect()`
- `clipPath()`
- `clipRect()`
- `concat()`
- *(... and 100 more)*

---

### androidx.media3.exoplayer.analytics.MediaMetricsListener

- **Priority**: CRITICAL
- **Found in**: [classes1.md](classes1.md)
- **Implements**: `AnalyticsListener, PlaybackSessionManager.Listener`

**Key Methods**:
- `ErrorInfo()`
- `PendingFormatUpdate()`
- `MediaMetricsListener()`
- `DefaultPlaybackSessionManager()`
- `mo7622H()`
- *(... and 69 more)*

---

### androidx.media3.exoplayer.audio.RunnableC1137c

- **Priority**: CRITICAL
- **Found in**: [classes1.md](classes1.md)
- **Implements**: `Runnable`

**Key Methods**:
- `run()`

---

### androidx.media3.exoplayer.drm.DefaultDrmSession

- **Priority**: CRITICAL
- **Found in**: [classes1.md](classes1.md)
- **Extends**: `Handler`
- **Implements**: `DrmSession`

**Key Methods**:
- `mo7877a()`
- `mo7878b()`
- `mo7879c()`
- `mo7880a()`
- `mo7881b()`
- *(... and 40 more)*

---

### androidx.media3.exoplayer.drm.DefaultDrmSessionManager

- **Priority**: CRITICAL
- **Found in**: [classes1.md](classes1.md)
- **Extends**: `Handler`
- **Implements**: `DrmSessionManager`

**Key Methods**:
- `DefaultLoadErrorHandlingPolicy()`
- `MediaDrmEventListener()`
- `mo7893a()`
- `MediaDrmHandler()`
- `handleMessage()`
- *(... and 38 more)*

---

### androidx.media3.exoplayer.drm.DrmUtil

- **Priority**: CRITICAL
- **Found in**: [classes1.md](classes1.md)

**Key Methods**:
- `m7905a()`
- `m7906b()`
- `m7907a()`
- `m7908b()`
- `m7909a()`

---

### androidx.media3.exoplayer.drm.DummyExoMediaDrm

- **Priority**: CRITICAL
- **Found in**: [classes1.md](classes1.md)
- **Implements**: `ExoMediaDrm`

**Key Methods**:
- `mo7910a()`
- `IllegalStateException()`
- `IllegalStateException()`
- `mo7912c()`
- `MediaDrmException()`
- *(... and 15 more)*

---

### androidx.media3.exoplayer.drm.AppManagedProvider

- **Priority**: CRITICAL
- **Found in**: [classes1.md](classes1.md)
- **Implements**: `Provider`

**Key Methods**:
- `mo1546a()`
- `KeyRequest()`
- `mo7893a()`
- `mo1546a()`
- `ProvisionRequest()`
- *(... and 14 more)*

---

### androidx.media3.exoplayer.drm.FrameworkMediaDrm

- **Priority**: CRITICAL
- **Found in**: [classes1.md](classes1.md)
- **Implements**: `ExoMediaDrm`

**Key Methods**:
- `Object()`
- `m7923a()`
- `m7924b()`
- `FrameworkMediaDrm()`
- `MediaDrm()`
- *(... and 19 more)*

---

### androidx.media3.exoplayer.drm.HttpMediaDrmCallback

- **Priority**: CRITICAL
- **Found in**: [classes1.md](classes1.md)
- **Implements**: `MediaDrmCallback`

**Key Methods**:
- `HttpMediaDrmCallback()`
- `HashMap()`
- `m7925c()`
- `StatsDataSource()`
- `DataSourceInputStream()`
- *(... and 10 more)*

---

## Write Operations

Total write operations found: 1024

### From classes.dex

- `AnimatedContentKt.java:511` - `setValue(mutableState)`
- `AnimatedContentKt.java:513` - `setValue(mutableState)`
- `AnimatedContentMeasurePolicy.java:180` - `setValue(f3078c)`
- `AnimatedEnterExitMeasurePolicy.java:168` - `setValue(f3189a)`
- `AnimatedVisibilityKt$AnimatedEnterExitImpl$1$1.java:76` - `setValue(mutableState)`
- *(... and 494 more)*

### From classes2.dex

- `C0119x5b19abbe.java:48` - `setValue(f950l1)`
- `CachingRepository.java:266` - `setValue(f1724c)`
- `CachingRepository.java:286` - `setValue(f1724c)`
- `CachingRepository.java:829` - `setValue(mutableStateFlow)`
- `CachingRepository.java:1077` - `setValue(mutableStateFlow)`
- *(... and 121 more)*

### From classes3.dex

- `CommissioningOutdoorCameraCheckConnectionFragment.java:173` - `setValue(f487j)`
- `CommissioningOutdoorCameraCheckConnectionFragment.java:179` - `setValue(f487j)`
- `C0219xfd2d9d7b.java:97` - `setValue(f2626p)`
- `C0219xfd2d9d7b.java:162` - `setValue(f2626p)`
- `ScanDevicesViewModel$startLoadingTimeout$1.java:86` - `setValue(mutableStateFlow)`
- *(... and 288 more)*

### From classes4.dex

- `YiDeviceManagerImpl.java:534` - `setValue(f49f)`
- `YiDeviceInfoManagerImpl.java:131` - `setValue(f201d)`
- `YiFirmwareManagerImpl.java:469` - `setValue(f243g)`
- `YiFirmwareManagerImpl.java:821` - `setValue(f244h)`
- `YiFirmwareManagerImpl.java:970` - `setValue(f243g)`
- *(... and 22 more)*

### From classes5.dex

- `qqpdpbp.java:784` - `setValue(userExtraPropertyBean)`
- `CovertCompatUtil.java:601` - `setValue(stepDpPropertyBean)`

### From classes8.dex

- `HttpClient.java:241` - `setValue(f441e)`
- `HttpClient.java:244` - `setValue(f442f)`
- `HttpClient.java:247` - `setValue(f443g)`
- `HttpClient.java:262` - `setValue(f416b)`
- `HttpTimeout$Feature$install$1.java:78` - `setValue(f739b)`
- *(... and 72 more)*

---

## Command Sequences

### Known Command Patterns (from HCI Analysis)

| Bytes | Purpose |
| --- | --- |
| `00 05 01` | Handshake Start |
| `00 00 01 ... 04 00 00` | Key Exchange |
| `04 00 00 [session]` | Session ID Response |
| `31 00` - `31 04` | Sync Sequence |
| `32 01 19 00 00 00` | Finalize |

### Discovered Command Sequences: 0

*No command sequences found in DEX files.*

Commands may be:
- Defined in native code (libBleLib.so)
- Generated dynamically
- Encrypted/encoded

---

## Protocol Reconstruction

Based on HCI analysis and code findings:

### Provisioning Sequence
```
1. Connect to device (telink_mesh1)
2. Write to 2adb (Mesh Prov In): 00 05 01 00 00 00 00 00 00 00 00 00
3. Write to 2adb: 00 00 01 00 00 00 00 00 00 00 04 00 00
4. Read from 2ade (Mesh Prov Out): 04 00 00 [session_id]
5. Write sync sequence to 2adb:
   - 31 00
   - 31 01
   - 31 02
   - 31 03
   - 31 04
6. Write to 2adb: 32 01 19 00 00 00
```

### Control Commands
```
Command Header: [transformed_id][C0][payload]
transformed_id = (((session_id & 0x0F) + 0x0A) << 4) & 0xFF
```
