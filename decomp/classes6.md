# DEX Analysis: classes6.dex


**File Size**: 2.0 MB
**Total Classes**: 813
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
| Total Classes | 813 |
| Total Methods | 10,078 |
| Total Fields | 61,961 |
| Total Packages | 124 |
| BLE-Related Classes | 329 |
| UUIDs Found | 0 |
| BLE Write Operations | 0 |
| Command Sequences | 0 |

## BLE-Related Classes

Found 329 BLE-related classes:

### pqpbpqd [CRITICAL]


- **Full Name**: `com.thingclips.smart.camera.middleware.pqpbpqd`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `ICameraConfigInfo`
- **Methods**: 16
- **Fields**: 27
- **Source**: `smart\camera\middleware\pqpbpqd.java`

**Key Methods**:
  - `pqpbpqd()`
  - `SDKSharePreferencesUtil()`
  - `getCameraVideoSegmentationModel()`
  - `getDefaultDefinition()`
  - `getDefaultTalkBackMode()`
  - `getMaxScaleFactor()`
  - `getRawDataJsonStr()`
  - `getSupportPlaySpeedList()`
  - `ArrayList()`
  - `getVideoNum()`
  - *(... and 6 more)*

---

### ThingHomeSdk [CRITICAL]


- **Full Name**: `com.thingclips.smart.home.sdk.ThingHomeSdk`
- **Package**: `com.thingclips.smart.home.sdk`
- **Methods**: 71
- **Fields**: 137
- **Source**: `smart\home\sdk\ThingHomeSdk.java`

**Key Methods**:
  - `closeService()`
  - `enableBackgroundConnect()`
  - `enableMqttBackgroundConnect()`
  - `getActivator()`
  - `getActivatorInstance()`
  - `getBeaconManager()`
  - `getBleManager()`
  - `getBleOperator()`
  - `getCameraInstance()`
  - `getDataInstance()`
  - *(... and 61 more)*

---

### IDevModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.home.sdk.api.IDevModel`
- **Package**: `com.thingclips.smart.home.sdk.api`
- **Methods**: 43
- **Fields**: 0
- **Source**: `home\sdk\api\IDevModel.java`

**Key Methods**:
  - `addZigBeeGroup()`
  - `addZigBeeScene()`
  - `autoConfigExecute()`
  - `broadcastSend()`
  - `gatewayRouterConfigExecute()`
  - `getDataPointStat()`
  - `getDeviceProperty()`
  - `getDp()`
  - `getDpList()`
  - `getInitiativeQueryDpsInfo()`
  - *(... and 33 more)*

---

### IHomeCacheManager [CRITICAL]


- **Full Name**: `com.thingclips.smart.home.sdk.api.IHomeCacheManager`
- **Package**: `com.thingclips.smart.home.sdk.api`
- **Methods**: 70
- **Fields**: 0
- **Source**: `home\sdk\api\IHomeCacheManager.java`

**Key Methods**:
  - `addDevGroupToRoom()`
  - `addDevListToGroup()`
  - `addDevListToHome()`
  - `addDevListToMesh()`
  - `addDevListToRoom()`
  - `addDevListToRoom()`
  - `addDevToGroup()`
  - `addDevToHome()`
  - `addDevToMesh()`
  - `addDevToRoom()`
  - *(... and 60 more)*

---

### IThingDeviceActivator [CRITICAL]


- **Full Name**: `com.thingclips.smart.home.sdk.api.IThingDeviceActivator`
- **Package**: `com.thingclips.smart.home.sdk.api`
- **Methods**: 31
- **Fields**: 0
- **Source**: `home\sdk\api\IThingDeviceActivator.java`

**Key Methods**:
  - `bindNbDeviceWithQRCode()`
  - `bindThingLinkDeviceWithQRCode()`
  - `deviceCloudActivate()`
  - `deviceCloudActivateWithPin()`
  - `deviceQrCodeParse()`
  - `getActivatorDeviceInfo()`
  - `getActivatorToken()`
  - `getActivatorToken()`
  - `getActivatorToken()`
  - `getActivatorToken()`
  - *(... and 21 more)*

---

### IThingHome [CRITICAL]


- **Full Name**: `com.thingclips.smart.home.sdk.api.IThingHome`
- **Package**: `com.thingclips.smart.home.sdk.api`
- **Methods**: 42
- **Fields**: 0
- **Source**: `home\sdk\api\IThingHome.java`

**Key Methods**:
  - `addRoom()`
  - `bindNewConfigDevs()`
  - `createBlueMesh()`
  - `createCommonGroup()`
  - `createGroup()`
  - `createSigMesh()`
  - `createThreadGroup()`
  - `createZigbeeGroup()`
  - `createZigbeeGroup()`
  - `dismissHome()`
  - *(... and 32 more)*

---

### IThingHomeDataManager [CRITICAL]


- **Full Name**: `com.thingclips.smart.home.sdk.api.IThingHomeDataManager`
- **Package**: `com.thingclips.smart.home.sdk.api`
- **Methods**: 53
- **Fields**: 0
- **Source**: `home\sdk\api\IThingHomeDataManager.java`

**Key Methods**:
  - `addDevRespList()`
  - `addProductList()`
  - `discoveredLanDevice()`
  - `getDevRespBean()`
  - `getDevRespBeanList()`
  - `getDeviceBean()`
  - `getDeviceRoomBean()`
  - `getDp()`
  - `getDps()`
  - `getGroupBean()`
  - *(... and 43 more)*

---

### IThingHomeDeviceShare [CRITICAL]


- **Full Name**: `com.thingclips.smart.home.sdk.api.IThingHomeDeviceShare`
- **Package**: `com.thingclips.smart.home.sdk.api`
- **Methods**: 22
- **Fields**: 0
- **Source**: `home\sdk\api\IThingHomeDeviceShare.java`

**Key Methods**:
  - `addShare()`
  - `addShareUserForGroup()`
  - `addShareWithHomeId()`
  - `addShareWithMemberId()`
  - `confirmShareInviteShare()`
  - `disableDevShare()`
  - `enableDevShare()`
  - `getReceivedShareInfo()`
  - `getUserShareInfo()`
  - `inviteShare()`
  - *(... and 12 more)*

---

### IThingHomeStatusListener [CRITICAL]


- **Full Name**: `com.thingclips.smart.home.sdk.api.IThingHomeStatusListener`
- **Package**: `com.thingclips.smart.home.sdk.api`
- **Methods**: 5
- **Fields**: 0
- **Source**: `home\sdk\api\IThingHomeStatusListener.java`

**Key Methods**:
  - `onDeviceAdded()`
  - `onDeviceRemoved()`
  - `onGroupAdded()`
  - `onGroupRemoved()`
  - `onMeshAdded()`

---

### HomeBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.HomeBean`
- **Package**: `com.thingclips.smart.home.sdk.bean`
- **Methods**: 43
- **Fields**: 33
- **Source**: `home\sdk\bean\HomeBean.java`

**Key Methods**:
  - `getBackground()`
  - `getCustomRole()`
  - `getDeviceList()`
  - `getGeoName()`
  - `getGroupList()`
  - `getHomeId()`
  - `getHomeStatus()`
  - `getInviteName()`
  - `getLat()`
  - `getLon()`
  - *(... and 33 more)*

**Notable Strings**:
  - `", meshList="`
  - `", sigMeshList="`

---

### IThingBlueMeshPlugin [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.api.IThingBlueMeshPlugin`
- **Package**: `com.thingclips.smart.interior.api`
- **Extends**: `IMeshCommonControl>`
- **Methods**: 18
- **Fields**: 0
- **Source**: `smart\interior\api\IThingBlueMeshPlugin.java`

**Key Methods**:
  - `getMeshControl()`
  - `getMeshEventHandler()`
  - `getMeshInstance()`
  - `getMeshManager()`
  - `getMeshStatusInstance()`
  - `getSigMeshInstance()`
  - `getThingBlueMeshClient()`
  - `getThingBlueMeshConfig()`
  - `getThingMeshService()`
  - `getThingSigMeshClient()`
  - *(... and 8 more)*

---

### IThingGroupPlugin [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.api.IThingGroupPlugin`
- **Package**: `com.thingclips.smart.interior.api`
- **Methods**: 4
- **Fields**: 0
- **Source**: `smart\interior\api\IThingGroupPlugin.java`

**Key Methods**:
  - `getGroupCacheInstance()`
  - `newGroupInstance()`
  - `newGroupModelInstance()`
  - `newMeshGroupInstance()`

---

### IThingDeviceOperate [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.device.IThingDeviceOperate`
- **Package**: `com.thingclips.smart.interior.device`
- **Methods**: 17
- **Fields**: 0
- **Source**: `smart\interior\device\IThingDeviceOperate.java`

**Key Methods**:
  - `getCategory()`
  - `getDeviceBizPropBean()`
  - `getDeviceRespBean()`
  - `getDps()`
  - `getHgwBean()`
  - `getIsLocalOnline()`
  - `getIsOnline()`
  - `getIsOnline()`
  - `getProductBean()`
  - `getProductRefBean()`
  - *(... and 7 more)*

---

### IThingMeshBatchDpUpdateListener [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.device.IThingMeshBatchDpUpdateListener`
- **Package**: `com.thingclips.smart.interior.device`
- **Methods**: 1
- **Fields**: 0
- **Source**: `smart\interior\device\IThingMeshBatchDpUpdateListener.java`

**Key Methods**:
  - `onMeshBatchDpUpdate()`

---

### IThingMeshRawReportListener [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.device.IThingMeshRawReportListener`
- **Package**: `com.thingclips.smart.interior.device`
- **Methods**: 1
- **Fields**: 0
- **Source**: `smart\interior\device\IThingMeshRawReportListener.java`

**Key Methods**:
  - `onMeshRawReport()`

---

### BlueMeshBatchReportBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.device.bean.BlueMeshBatchReportBean`
- **Package**: `com.thingclips.smart.interior.device.bean`
- **Methods**: 4
- **Fields**: 2
- **Source**: `interior\device\bean\BlueMeshBatchReportBean.java`

**Key Methods**:
  - `getCid()`
  - `getDps()`
  - `setCid()`
  - `setDps()`

---

### DeviceRespBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.device.bean.DeviceRespBean`
- **Package**: `com.thingclips.smart.interior.device.bean`
- **Implements**: `IStorageCache`
- **Methods**: 203
- **Fields**: 123
- **Source**: `interior\device\bean\DeviceRespBean.java`

**Key Methods**:
  - `isRemoteBindPubAddress()`
  - `setRemoteBindPubAddress()`
  - `getCommunicationModes()`
  - `getCommunicationNode()`
  - `getConnectionStatus()`
  - `getDataModel()`
  - `getLocalCommunicationNode()`
  - `getLocalDataModel()`
  - `getLocalNodeId()`
  - `getMqttTopicAttr()`
  - *(... and 193 more)*

---

### GroupRespBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.device.bean.GroupRespBean`
- **Package**: `com.thingclips.smart.interior.device.bean`
- **Methods**: 50
- **Fields**: 25
- **Source**: `interior\device\bean\GroupRespBean.java`

**Key Methods**:
  - `getCategory()`
  - `getDevId()`
  - `getDeviceNum()`
  - `getDisplayOrder()`
  - `getDpCodes()`
  - `getDpName()`
  - `getDps()`
  - `getGroupKey()`
  - `getGroupType()`
  - `getHomeDisplayOrder()`
  - *(... and 40 more)*

---

### GwDevResp [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.device.bean.GwDevResp`
- **Package**: `com.thingclips.smart.interior.device.bean`
- **Methods**: 48
- **Fields**: 24
- **Source**: `interior\device\bean\GwDevResp.java`

**Key Methods**:
  - `getAbility()`
  - `getActiveTime()`
  - `getBv()`
  - `getDevices()`
  - `getGwId()`
  - `getGwType()`
  - `getIcon()`
  - `getIconUrl()`
  - `getId()`
  - `getIsActive()`
  - *(... and 38 more)*

---

### MQ_1_ConnectStatusChangeBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.device.confusebean.MQ_1_ConnectStatusChangeBean`
- **Package**: `com.thingclips.smart.interior.device.confusebean`
- **Methods**: 8
- **Fields**: 4
- **Source**: `interior\device\confusebean\MQ_1_ConnectStatusChangeBean.java`

**Key Methods**:
  - `MQ_1_ConnectStatusChangeBean()`
  - `getConnectStatus()`
  - `getDevId()`
  - `getMeshId()`
  - `setConnectStatus()`
  - `setDevId()`
  - `toString()`
  - `StringBuilder()`

---

### MQ_25_MeshOnlineStatusUpdateBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.device.confusebean.MQ_25_MeshOnlineStatusUpdateBean`
- **Package**: `com.thingclips.smart.interior.device.confusebean`
- **Methods**: 6
- **Fields**: 4
- **Source**: `interior\device\confusebean\MQ_25_MeshOnlineStatusUpdateBean.java`

**Key Methods**:
  - `MQ_25_MeshOnlineStatusUpdateBean()`
  - `getDevId()`
  - `getMeshId()`
  - `getOffline()`
  - `getOnline()`
  - `toString()`

**Notable Strings**:
  - `"MQ_25_MeshOnlineStatusUpdateBean{meshId='"`

---

### MQ_29_MeshRawReportBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.device.confusebean.MQ_29_MeshRawReportBean`
- **Package**: `com.thingclips.smart.interior.device.confusebean`
- **Methods**: 3
- **Fields**: 2
- **Source**: `interior\device\confusebean\MQ_29_MeshRawReportBean.java`

**Key Methods**:
  - `MQ_29_MeshRawReportBean()`
  - `getMeshId()`
  - `getRaw()`

---

### MQ_30_MeshBatchReportBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.device.confusebean.MQ_30_MeshBatchReportBean`
- **Package**: `com.thingclips.smart.interior.device.confusebean`
- **Methods**: 4
- **Fields**: 2
- **Source**: `interior\device\confusebean\MQ_30_MeshBatchReportBean.java`

**Key Methods**:
  - `MQ_30_MeshBatchReportBean()`
  - `getBlueMeshBatchReportBeen()`
  - `getTopicId()`
  - `toString()`

**Notable Strings**:
  - `"MQ_30_MeshBatchReportBean{topicId='"`
  - `"', blueMeshBatchReportBeen="`

---

### MQ_35_MeshUpdateBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.device.confusebean.MQ_35_MeshUpdateBean`
- **Package**: `com.thingclips.smart.interior.device.confusebean`
- **Methods**: 4
- **Fields**: 3
- **Source**: `interior\device\confusebean\MQ_35_MeshUpdateBean.java`

**Key Methods**:
  - `MQ_35_MeshUpdateBean()`
  - `getHomeId()`
  - `getMeshId()`
  - `isMeshAdd()`

---

### MQ_4_MeshDpUpdateBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.device.confusebean.MQ_4_MeshDpUpdateBean`
- **Package**: `com.thingclips.smart.interior.device.confusebean`
- **Methods**: 8
- **Fields**: 6
- **Source**: `interior\device\confusebean\MQ_4_MeshDpUpdateBean.java`

**Key Methods**:
  - `MQ_4_MeshDpUpdateBean()`
  - `getCid()`
  - `getDevId()`
  - `getDps()`
  - `getMeshId()`
  - `getType()`
  - `toString()`
  - `StringBuilder()`

**Notable Strings**:
  - `"MQ_4_MeshDpUpdateBean{meshId='"`

---

### MQ_54_MeshRelationUpdateBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.device.confusebean.MQ_54_MeshRelationUpdateBean`
- **Package**: `com.thingclips.smart.interior.device.confusebean`
- **Methods**: 4
- **Fields**: 3
- **Source**: `interior\device\confusebean\MQ_54_MeshRelationUpdateBean.java`

**Key Methods**:
  - `MQ_54_MeshRelationUpdateBean()`
  - `getCids()`
  - `getMeshId()`
  - `getType()`

---

### BaseEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.event.BaseEventModel`
- **Package**: `com.thingclips.smart.interior.event`
- **Methods**: 2
- **Fields**: 9
- **Source**: `smart\interior\event\BaseEventModel.java`

**Key Methods**:
  - `getFrom()`
  - `setFrom()`

---

### DeviceDpsUpdateEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.event.DeviceDpsUpdateEventModel`
- **Package**: `com.thingclips.smart.interior.event`
- **Methods**: 8
- **Fields**: 11
- **Source**: `smart\interior\event\DeviceDpsUpdateEventModel.java`

**Key Methods**:
  - `getDevId()`
  - `getDps()`
  - `getDpsTime()`
  - `getFrom()`
  - `setDevId()`
  - `setDps()`
  - `setDpsTime()`
  - `setFrom()`

---

### DeviceUpdateEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.event.DeviceUpdateEventModel`
- **Package**: `com.thingclips.smart.interior.event`
- **Methods**: 6
- **Fields**: 7
- **Source**: `smart\interior\event\DeviceUpdateEventModel.java`

**Key Methods**:
  - `DeviceUpdateEventModel()`
  - `getDevId()`
  - `getHomeId()`
  - `getMeshId()`
  - `getMode()`
  - `DeviceUpdateEventModel()`

---

### GroupUpdateEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.event.GroupUpdateEventModel`
- **Package**: `com.thingclips.smart.interior.event`
- **Methods**: 3
- **Fields**: 8
- **Source**: `smart\interior\event\GroupUpdateEventModel.java`

**Key Methods**:
  - `GroupUpdateEventModel()`
  - `GroupUpdateEventModel()`
  - `GroupUpdateEventModel()`

---

### MeshRelationUpdateEvent [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.event.MeshRelationUpdateEvent`
- **Package**: `com.thingclips.smart.interior.event`
- **Methods**: 1
- **Fields**: 0
- **Source**: `smart\interior\event\MeshRelationUpdateEvent.java`

**Key Methods**:
  - `onEventMainThread()`

---

### MeshRelationUpdateEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.event.MeshRelationUpdateEventModel`
- **Package**: `com.thingclips.smart.interior.event`
- **Extends**: `BaseEventModel`
- **Methods**: 4
- **Fields**: 3
- **Source**: `smart\interior\event\MeshRelationUpdateEventModel.java`

**Key Methods**:
  - `MeshRelationUpdateEventModel()`
  - `getCids()`
  - `getMeshId()`
  - `getType()`

---

### SubDeviceRelationUpdateEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.event.SubDeviceRelationUpdateEventModel`
- **Package**: `com.thingclips.smart.interior.event`
- **Extends**: `BaseEventModel`
- **Methods**: 4
- **Fields**: 3
- **Source**: `smart\interior\event\SubDeviceRelationUpdateEventModel.java`

**Key Methods**:
  - `SubDeviceRelationUpdateEventModel()`
  - `getDevId()`
  - `getMeshId()`
  - `getType()`

---

### ZigbeeSubDevDpUpdateEventModel [CRITICAL]


- **Full Name**: `com.thingclips.smart.interior.event.ZigbeeSubDevDpUpdateEventModel`
- **Package**: `com.thingclips.smart.interior.event`
- **Methods**: 7
- **Fields**: 6
- **Source**: `smart\interior\event\ZigbeeSubDevDpUpdateEventModel.java`

**Key Methods**:
  - `ZigbeeSubDevDpUpdateEventModel()`
  - `getCid()`
  - `getDevId()`
  - `getDps()`
  - `getMeshId()`
  - `getType()`
  - `isFromCloud()`

---

### ThingVideoCaptureDevice [HIGH]


- **Full Name**: `com.thingclips.smart.camera.bean.ThingVideoCaptureDevice`
- **Package**: `com.thingclips.smart.camera.bean`
- **Extends**: `CameraDevice.StateCallback`
- **Implements**: `Comparator<Size>`
- **Methods**: 40
- **Fields**: 90
- **Source**: `smart\camera\bean\ThingVideoCaptureDevice.java`

**Key Methods**:
  - `bdpdqbp()`
  - `compare()`
  - `bppdpdq()`
  - `onImageAvailable()`
  - `if()`
  - `if()`
  - `if()`
  - `pdqppqb()`
  - `onDisconnected()`
  - `onError()`
  - *(... and 30 more)*

---

### ThingVideoEncoderImpl [HIGH]


- **Full Name**: `com.thingclips.smart.camera.bean.ThingVideoEncoderImpl`
- **Package**: `com.thingclips.smart.camera.bean`
- **Extends**: `Thread`
- **Methods**: 18
- **Fields**: 65
- **Source**: `smart\camera\bean\ThingVideoEncoderImpl.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `if()`
  - `if()`
  - `bdpdqbp()`
  - `ThingVideoEncoderImpl()`
  - `createEncodeThread()`
  - `bdpdqbp()`
  - `GetSupportedVideoEncoderName()`
  - `StringBuilder()`
  - *(... and 8 more)*

---

### C0003R [HIGH]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.C0003R`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk`
- **Methods**: 19
- **Fields**: 5129
- **Source**: `smart\camera\ipccamerasdk\C0003R.java`

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

### IPCThingP2PCamera [HIGH]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.IPCThingP2PCamera`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk`
- **Implements**: `ICameraP2P, ThingCameraListener, bqbdpqd`
- **Methods**: 235
- **Fields**: 320
- **Source**: `smart\camera\ipccamerasdk\IPCThingP2PCamera.java`

**Key Methods**:
  - `CopyOnWriteArrayList()`
  - `bdpdqbp()`
  - `onResponse()`
  - `bdqqbqd()`
  - `onFinished()`
  - `onResponse()`
  - `bpbbqdb()`
  - `onFinished()`
  - `onResponse()`
  - `bppdpdq()`
  - *(... and 225 more)*

---

### CloudBusiness [HIGH]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.cloud.CloudBusiness`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.cloud`
- **Extends**: `Business`
- **Implements**: `Business.ResultListener<JSONObject>`
- **Methods**: 34
- **Fields**: 33
- **Source**: `camera\ipccamerasdk\cloud\CloudBusiness.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `deleteCloudData()`
  - `ApiParams()`
  - `deleteCloudDataByDay()`
  - `ApiParams()`
  - `getAIDetectConfig()`
  - `getAuthorityGet()`
  - `ApiParams()`
  - *(... and 24 more)*

---

### IThingCloudCamera [HIGH]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.cloud.IThingCloudCamera`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.cloud`
- **Methods**: 42
- **Fields**: 0
- **Source**: `camera\ipccamerasdk\cloud\IThingCloudCamera.java`

**Key Methods**:
  - `configCloudDataTags()`
  - `configCloudDataTagsV1()`
  - `createCloudDevice()`
  - `deinitCloudCamera()`
  - `deleteCloudVideo()`
  - `deleteCloudVideo()`
  - `destroy()`
  - `destroyCloudBusiness()`
  - `enableAIDetect()`
  - `enableAIDetectEventType()`
  - *(... and 32 more)*

---

### ThingCloudCamera [HIGH]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.cloud.ThingCloudCamera`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.cloud`
- **Implements**: `ThingCameraListener, IThingCloudCamera`
- **Methods**: 165
- **Fields**: 133
- **Source**: `camera\ipccamerasdk\cloud\ThingCloudCamera.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bpbbqdb()`
  - `onFinished()`
  - `onProgress()`
  - `onResponse()`
  - *(... and 155 more)*

---

### ThingVirtualCamera [HIGH]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.virtual.ThingVirtualCamera`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.virtual`
- **Extends**: `IPCThingP2PCamera`
- **Implements**: `Runnable`
- **Methods**: 66
- **Fields**: 58
- **Source**: `camera\ipccamerasdk\virtual\ThingVirtualCamera.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `bdqqqpq()`
  - `bppdpdq()`
  - `run()`
  - `pbbppqb()`
  - `onFinished()`
  - `onProgress()`
  - `onResponse()`
  - `pdqppqb()`
  - *(... and 56 more)*

---

### bddbqbq [HIGH]


- **Full Name**: `com.thingclips.smart.camera.middleware.bddbqbq`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Extends**: `Lambda`
- **Implements**: `IThingIPCDoorBellManager`
- **Methods**: 34
- **Fields**: 90
- **Source**: `smart\camera\middleware\bddbqbq.java`

**Key Methods**:
  - `bddbqbq()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `invoke()`
  - `pdqppqb()`
  - `onError()`
  - `StringBuilder()`
  - `onSuccess()`
  - `IThingGetBeanCallback()`
  - `onResult()`
  - *(... and 24 more)*

---

### bdpdqbp [HIGH]


- **Full Name**: `com.thingclips.smart.camera.middleware.bdpdqbp`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Methods**: 5
- **Fields**: 8
- **Source**: `smart\camera\middleware\bdpdqbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bppdpdq()`
  - `pdqppqb()`
  - `qddqppb()`
  - `bdpdqbp()`

---

### ddbbppb [HIGH]


- **Full Name**: `com.thingclips.smart.camera.middleware.ddbbppb`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `IThingCameraMessage`
- **Methods**: 38
- **Fields**: 39
- **Source**: `smart\camera\middleware\ddbbppb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `dddpppb()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 28 more)*

---

### dddbppd [HIGH]


- **Full Name**: `com.thingclips.smart.camera.middleware.dddbppd`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `IThingIPCCore`
- **Methods**: 14
- **Fields**: 19
- **Source**: `smart\camera\middleware\dddbppd.java`

**Key Methods**:
  - `createCameraP2P()`
  - `ThingSmartNvrSubCameraP2P()`
  - `ThingSmartCameraP2P()`
  - `createNvrP2P()`
  - `deInit()`
  - `destroyNvrP2P()`
  - `getBuilderInstance()`
  - `qbpppdb()`
  - `getCameraConfig()`
  - `pqpbpqd()`
  - *(... and 4 more)*

---

### pdqdqbd [HIGH]


- **Full Name**: `com.thingclips.smart.camera.middleware.pdqdqbd`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Methods**: 1
- **Fields**: 10
- **Source**: `smart\camera\middleware\pdqdqbd.java`

**Key Methods**:
  - `bdpdqbp()`

---

### pqqpqpq [HIGH]


- **Full Name**: `com.thingclips.smart.camera.middleware.pqqpqpq`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `Handler.Callback`
- **Methods**: 8
- **Fields**: 32
- **Source**: `smart\camera\middleware\pqqpqpq.java`

**Key Methods**:
  - `Handler()`
  - `pqqpqpq()`
  - `bdpdqbp()`
  - `if()`
  - `if()`
  - `if()`
  - `if()`
  - `handleMessage()`

---

### qbqppdb [HIGH]


- **Full Name**: `com.thingclips.smart.camera.middleware.qbqppdb`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Extends**: `BaseBitmapDataSubscriber`
- **Implements**: `IThingIPCTool`
- **Methods**: 7
- **Fields**: 7
- **Source**: `smart\camera\middleware\qbqppdb.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onFailureImpl()`
  - `onNewResultImpl()`
  - `downloadEncryptedImg()`
  - `DecryptImageRequest()`
  - `bdpdqbp()`
  - `UiThreadImmediateExecutorService()`

---

### bppdpdq [HIGH]


- **Full Name**: `com.thingclips.smart.camera.middleware.p2p.bppdpdq`
- **Package**: `com.thingclips.smart.camera.middleware.p2p`
- **Implements**: `Runnable`
- **Methods**: 2
- **Fields**: 3
- **Source**: `camera\middleware\p2p\bppdpdq.java`

**Key Methods**:
  - `bppdpdq()`
  - `run()`

---

### pdqppqb [HIGH]


- **Full Name**: `com.thingclips.smart.camera.middleware.p2p.pdqppqb`
- **Package**: `com.thingclips.smart.camera.middleware.p2p`
- **Implements**: `Runnable`
- **Methods**: 2
- **Fields**: 2
- **Source**: `camera\middleware\p2p\pdqppqb.java`

**Key Methods**:
  - `pdqppqb()`
  - `run()`

---

### pppbppp [HIGH]


- **Full Name**: `com.thingclips.smart.camera.middleware.p2p.pppbppp`
- **Package**: `com.thingclips.smart.camera.middleware.p2p`
- **Implements**: `Runnable`
- **Methods**: 2
- **Fields**: 4
- **Source**: `camera\middleware\p2p\pppbppp.java`

**Key Methods**:
  - `pppbppp()`
  - `run()`

---

### qddqppb [HIGH]


- **Full Name**: `com.thingclips.smart.camera.middleware.p2p.qddqppb`
- **Package**: `com.thingclips.smart.camera.middleware.p2p`
- **Implements**: `Runnable`
- **Methods**: 2
- **Fields**: 3
- **Source**: `camera\middleware\p2p\qddqppb.java`

**Key Methods**:
  - `qddqppb()`
  - `run()`

---

### ThingSmartCameraP2PSync [HIGH]


- **Full Name**: `com.thingclips.smart.camera.middleware.p2p.ThingSmartCameraP2PSync`
- **Package**: `com.thingclips.smart.camera.middleware.p2p`
- **Extends**: `AbsConnectCallBack`
- **Implements**: `IThingSmartCameraP2P<Object>, bqbdpqd`
- **Methods**: 200
- **Fields**: 240
- **Source**: `camera\middleware\p2p\ThingSmartCameraP2PSync.java`

**Key Methods**:
  - `ArrayList()`
  - `bdpdqbp()`
  - `onError()`
  - `onSuccess()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `pbbppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 190 more)*

---

### ThingSmartNvrP2P [HIGH]


- **Full Name**: `com.thingclips.smart.camera.middleware.p2p.ThingSmartNvrP2P`
- **Package**: `com.thingclips.smart.camera.middleware.p2p`
- **Extends**: `AbsP2pCameraListener`
- **Implements**: `IThingSmartNvrP2P`
- **Methods**: 47
- **Fields**: 62
- **Source**: `camera\middleware\p2p\ThingSmartNvrP2P.java`

**Key Methods**:
  - `ArrayList()`
  - `CopyOnWriteArrayList()`
  - `ThingNvrSDKImpl()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bppdpdq()`
  - *(... and 37 more)*

---

### C0017R [HIGH]


- **Full Name**: `com.thingclips.smart.camera.sdk.C0017R`
- **Package**: `com.thingclips.smart.camera.sdk`
- **Methods**: 19
- **Fields**: 6572
- **Source**: `smart\camera\sdk\C0017R.java`

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

### ThingAPConfig [HIGH]


- **Full Name**: `com.thingclips.smart.config.ThingAPConfig`
- **Package**: `com.thingclips.smart.config`
- **Extends**: `Handler`
- **Implements**: `IThingAPConfig`
- **Methods**: 140
- **Fields**: 193
- **Source**: `thingclips\smart\config\ThingAPConfig.java`

**Key Methods**:
  - `AtomicInteger()`
  - `AtomicBoolean()`
  - `AtomicBoolean()`
  - `Handler()`
  - `HandlerC00211()`
  - `handleMessage()`
  - `HandlerC00211()`
  - `handleMessage()`
  - `C00222()`
  - `run()`
  - *(... and 130 more)*

**Notable Strings**:
  - `",uuid:"`

---

### ThingApDirectlyConfig [HIGH]


- **Full Name**: `com.thingclips.smart.config.ThingApDirectlyConfig`
- **Package**: `com.thingclips.smart.config`
- **Implements**: `IThingAPDirectlyConfig, qpbdppq, bbpqdqb`
- **Methods**: 27
- **Fields**: 40
- **Source**: `thingclips\smart\config\ThingApDirectlyConfig.java`

**Key Methods**:
  - `AtomicInteger()`
  - `buildConnectToActive()`
  - `StringBuilder()`
  - `StringBuilder()`
  - `StringBuilder()`
  - `buildTimeData()`
  - `JSONObject()`
  - `buildUdpReceive()`
  - `ApConfigUDPDataCallback()`
  - `OnApConfigDeviceInfoReportCallback()`
  - *(... and 17 more)*

---

### ThingBroadConfig [HIGH]


- **Full Name**: `com.thingclips.smart.config.ThingBroadConfig`
- **Package**: `com.thingclips.smart.config`
- **Implements**: `qpbdppq`
- **Methods**: 20
- **Fields**: 20
- **Source**: `thingclips\smart\config\ThingBroadConfig.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `AtomicInteger()`
  - `AtomicBoolean()`
  - `getInstance()`
  - `ThingBroadConfig()`
  - `normalControl()`
  - `IResultCallback()`
  - `onError()`
  - `StringBuilder()`
  - `onSuccess()`
  - *(... and 10 more)*

---

### ThingOptimizedConfig [HIGH]


- **Full Name**: `com.thingclips.smart.config.ThingOptimizedConfig`
- **Package**: `com.thingclips.smart.config`
- **Implements**: `IThingOptimizedApConfig`
- **Methods**: 25
- **Fields**: 22
- **Source**: `thingclips\smart\config\ThingOptimizedConfig.java`

**Key Methods**:
  - `ThingOptimizedConfig()`
  - `SingleHolder()`
  - `buildUDPReceiver()`
  - `ApConfigUDPDataCallback()`
  - `OnApConfigDeviceInfoReportCallback()`
  - `OnApConfigResultCallback()`
  - `StringBuilder()`
  - `getInstance()`
  - `hasAPSecurityActiveCap()`
  - `isNewEncrypt()`
  - *(... and 15 more)*

---

### ThingWiredConfig [HIGH]


- **Full Name**: `com.thingclips.smart.config.ThingWiredConfig`
- **Package**: `com.thingclips.smart.config`
- **Implements**: `IThingWiredConfig, qpbdppq, bbpqdqb`
- **Methods**: 23
- **Fields**: 21
- **Source**: `thingclips\smart\config\ThingWiredConfig.java`

**Key Methods**:
  - `ThingWiredConfig()`
  - `getInstance()`
  - `ThingWiredConfig()`
  - `isUnActive()`
  - `normalControl()`
  - `run()`
  - `if()`
  - `dddbppd()`
  - `onError()`
  - `onSuccess()`
  - *(... and 13 more)*

---

### C0048R [HIGH]


- **Full Name**: `com.thingclips.smart.device.core.sdk.C0048R`
- **Package**: `com.thingclips.smart.device.core.sdk`
- **Methods**: 19
- **Fields**: 6225
- **Source**: `device\core\sdk\C0048R.java`

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

### C0051R [HIGH]


- **Full Name**: `com.thingclips.smart.geofence.C0051R`
- **Package**: `com.thingclips.smart.geofence`
- **Methods**: 19
- **Fields**: 5129
- **Source**: `thingclips\smart\geofence\C0051R.java`

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

### C0052R [HIGH]


- **Full Name**: `com.thingclips.smart.home.sdk.C0052R`
- **Package**: `com.thingclips.smart.home.sdk`
- **Methods**: 19
- **Fields**: 6225
- **Source**: `smart\home\sdk\C0052R.java`

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

### SceneTask [HIGH]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.SceneTask`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene`
- **Implements**: `Serializable`
- **Methods**: 51
- **Fields**: 73
- **Source**: `sdk\bean\scene\SceneTask.java`

**Key Methods**:
  - `SceneTask()`
  - `createDelayTask()`
  - `SceneTask()`
  - `HashMap()`
  - `createDpGroupTask()`
  - `SceneTask()`
  - `createDpTask()`
  - `SceneTask()`
  - `createPhoneNotice()`
  - `SceneTask()`
  - *(... and 41 more)*

---

### C0056R [HIGH]


- **Full Name**: `com.thingclips.smart.imagepipeleine_okhttp3.C0056R`
- **Package**: `com.thingclips.smart.imagepipeleine_okhttp3`
- **Methods**: 18
- **Fields**: 2847
- **Source**: `thingclips\smart\imagepipeleine_okhttp3\C0056R.java`

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

### IThingHardware [HIGH]


- **Full Name**: `com.thingclips.smart.interior.hardware.IThingHardware`
- **Package**: `com.thingclips.smart.interior.hardware`
- **Methods**: 31
- **Fields**: 0
- **Source**: `smart\interior\hardware\IThingHardware.java`

**Key Methods**:
  - `addHgw()`
  - `addHgw()`
  - `addHgw()`
  - `addHgw()`
  - `addOnParsePkgFrameChangeListener()`
  - `control()`
  - `control()`
  - `deleteAllDev()`
  - `deleteDev()`
  - `getDevId()`
  - *(... and 21 more)*

---

### C0057R [HIGH]


- **Full Name**: `com.thingclips.smart.ipc.camera.base.C0057R`
- **Package**: `com.thingclips.smart.ipc.camera.base`
- **Methods**: 18
- **Fields**: 2847
- **Source**: `ipc\camera\base\C0057R.java`

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

### C0058R [HIGH]


- **Full Name**: `com.thingclips.smart.ipc.sdk.C0058R`
- **Package**: `com.thingclips.smart.ipc.sdk`
- **Methods**: 19
- **Fields**: 6572
- **Source**: `smart\ipc\sdk\C0058R.java`

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

### C0059R [HIGH]


- **Full Name**: `com.thingclips.smart.ipc.sdk.api.C0059R`
- **Package**: `com.thingclips.smart.ipc.sdk.api`
- **Methods**: 19
- **Fields**: 6548
- **Source**: `ipc\sdk\api\C0059R.java`

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

### ThingMonitorRenderer [HIGH]


- **Full Name**: `com.thingclips.smart.ipc.yuv.monitor.opengl.ThingMonitorRenderer`
- **Package**: `com.thingclips.smart.ipc.yuv.monitor.opengl`
- **Implements**: `GLSurfaceView.Renderer`
- **Methods**: 66
- **Fields**: 185
- **Source**: `yuv\monitor\opengl\ThingMonitorRenderer.java`

**Key Methods**:
  - `onMove()`
  - `onPositioningFrameUpdate()`
  - `onRender()`
  - `onZoomFree()`
  - `ThingMonitorRenderer()`
  - `calculatePointDistance()`
  - `calculatePositioningFrame()`
  - `checkFeatureTracking()`
  - `RectF()`
  - `cloneBuffer()`
  - *(... and 56 more)*

---

### GLESTextureView [HIGH]


- **Full Name**: `com.thingclips.smart.ipc.yuv.monitor.texture.GLESTextureView`
- **Package**: `com.thingclips.smart.ipc.yuv.monitor.texture`
- **Extends**: `TextureView`
- **Implements**: `TextureView.SurfaceTextureListener, IRenderer`
- **Methods**: 97
- **Fields**: 113
- **Source**: `yuv\monitor\texture\GLESTextureView.java`

**Key Methods**:
  - `BaseConfigChooser()`
  - `filterConfigSpec()`
  - `chooseConfig()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `chooseConfig()`
  - `ComponentSizeChooser()`
  - `findConfigAttrib()`
  - *(... and 87 more)*

---

### MMKVContentProvider [HIGH]


- **Full Name**: `com.thingclips.smart.mmkv.MMKVContentProvider`
- **Package**: `com.thingclips.smart.mmkv`
- **Extends**: `ContentProvider`
- **Methods**: 19
- **Fields**: 31
- **Source**: `thingclips\smart\mmkv\MMKVContentProvider.java`

**Key Methods**:
  - `contentUri()`
  - `getProcessNameByPID()`
  - `mmkvFromAshmemID()`
  - `ParcelableMMKV()`
  - `Bundle()`
  - `queryAuthority()`
  - `ComponentName()`
  - `call()`
  - `mmkvFromAshmemID()`
  - `delete()`
  - *(... and 9 more)*

---

### bdpdqbp [HIGH]


- **Full Name**: `com.thingclips.smart.mqtt.bdpdqbp`
- **Package**: `com.thingclips.smart.mqtt`
- **Extends**: `SQLiteOpenHelper`
- **Implements**: `com.thingclips.smart.mqtt.pdqppqb`
- **Methods**: 27
- **Fields**: 56
- **Source**: `thingclips\smart\mqtt\bdpdqbp.java`

**Key Methods**:
  - `C0094bdpdqbp()`
  - `qddqppb()`
  - `pdqppqb()`
  - `finalize()`
  - `hasNext()`
  - `remove()`
  - `UnsupportedOperationException()`
  - `bppdpdq()`
  - `onCreate()`
  - `MqttArrivedMessageTable()`
  - *(... and 17 more)*

---

### bppdpdq [HIGH]


- **Full Name**: `com.thingclips.smart.mqtt.bppdpdq`
- **Package**: `com.thingclips.smart.mqtt`
- **Extends**: `qddqppb`
- **Implements**: `MqttCallbackExtended, ConnectFinishCallback`
- **Methods**: 107
- **Fields**: 95
- **Source**: `thingclips\smart\mqtt\bppdpdq.java`

**Key Methods**:
  - `HashMap()`
  - `HashMap()`
  - `HashMap()`
  - `HashMap()`
  - `method()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `method()`
  - `C0095bppdpdq()`
  - *(... and 97 more)*

---

### MqttAndroidClient [HIGH]


- **Full Name**: `com.thingclips.smart.mqtt.MqttAndroidClient`
- **Package**: `com.thingclips.smart.mqtt`
- **Extends**: `BroadcastReceiver`
- **Implements**: `IMqttAsyncClient`
- **Methods**: 119
- **Fields**: 96
- **Source**: `thingclips\smart\mqtt\MqttAndroidClient.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `pdqppqb()`
  - `onServiceConnected()`
  - `onServiceDisconnected()`
  - `MqttAndroidClient()`
  - `connectAction()`
  - `connectExtendedAction()`
  - `connectFinishAction()`
  - `connectionLostAction()`
  - *(... and 109 more)*

---

### MqttService [HIGH]


- **Full Name**: `com.thingclips.smart.mqtt.MqttService`
- **Package**: `com.thingclips.smart.mqtt`
- **Extends**: `Service`
- **Implements**: `ddbdqbd`
- **Methods**: 63
- **Fields**: 28
- **Source**: `thingclips\smart\mqtt\MqttService.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `bdpdqbp()`
  - `run()`
  - `pdqppqb()`
  - `onReceive()`
  - `bppdpdq()`
  - `IllegalArgumentException()`
  - `onBind()`
  - `onCreate()`
  - `MqttServiceBinder()`
  - *(... and 53 more)*

---

### MqttAsyncClient [HIGH]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.MqttAsyncClient`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Extends**: `TimerTask`
- **Implements**: `IMqttAsyncClient`
- **Methods**: 131
- **Fields**: 66
- **Source**: `smart\mqttclient\mqttv3\MqttAsyncClient.java`

**Key Methods**:
  - `Object()`
  - `MqttReconnectActionListener()`
  - `rescheduleReconnectCycle()`
  - `onFailure()`
  - `onSuccess()`
  - `MqttReconnectCallback()`
  - `connectComplete()`
  - `connectionLost()`
  - `deliveryComplete()`
  - `messageArrived()`
  - *(... and 121 more)*

---

### MqttClient [HIGH]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.MqttClient`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Implements**: `IMqttClient`
- **Methods**: 63
- **Fields**: 21
- **Source**: `smart\mqttclient\mqttv3\MqttClient.java`

**Key Methods**:
  - `MqttClient()`
  - `MqttDefaultFilePersistence()`
  - `generateClientId()`
  - `close()`
  - `connect()`
  - `connectWithResult()`
  - `disconnect()`
  - `disconnectForcibly()`
  - `getClientId()`
  - `getConnectionFinishedInfo()`
  - *(... and 53 more)*

---

### MqttConnectOptions [HIGH]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.MqttConnectOptions`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Methods**: 54
- **Fields**: 31
- **Source**: `smart\mqttclient\mqttv3\MqttConnectOptions.java`

**Key Methods**:
  - `validateWill()`
  - `IllegalArgumentException()`
  - `getApplicationContext()`
  - `getConnectionTimeout()`
  - `getCustomWebSocketHeaders()`
  - `getDebug()`
  - `Properties()`
  - `getExecutorServiceTimeout()`
  - `getIpAddress()`
  - `getKeepAliveInterval()`
  - *(... and 44 more)*

---

### MqttException [HIGH]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.MqttException`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Extends**: `IOException`
- **Methods**: 8
- **Fields**: 36
- **Source**: `smart\mqttclient\mqttv3\MqttException.java`

**Key Methods**:
  - `MqttException()`
  - `getCause()`
  - `getMessage()`
  - `getReasonCode()`
  - `toString()`
  - `StringBuilder()`
  - `MqttException()`
  - `MqttException()`

---

### ScheduledExecutorPingSender [HIGH]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.ScheduledExecutorPingSender`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Implements**: `MqttPingSender`
- **Methods**: 9
- **Fields**: 9
- **Source**: `smart\mqttclient\mqttv3\ScheduledExecutorPingSender.java`

**Key Methods**:
  - `PingRunnable()`
  - `run()`
  - `ScheduledExecutorPingSender()`
  - `IllegalArgumentException()`
  - `init()`
  - `IllegalArgumentException()`
  - `schedule()`
  - `start()`
  - `stop()`

---

### ClientComms [HIGH]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.ClientComms`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Implements**: `Runnable`
- **Methods**: 91
- **Fields**: 119
- **Source**: `mqttclient\mqttv3\internal\ClientComms.java`

**Key Methods**:
  - `ConnectBG()`
  - `run()`
  - `ClientConnectMonitor()`
  - `MqttException()`
  - `CommsReceiver()`
  - `CommsSender()`
  - `start()`
  - `Thread()`
  - `DisconnectBG()`
  - `run()`
  - *(... and 81 more)*

---

### CommsCallback [HIGH]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.CommsCallback`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Implements**: `Runnable`
- **Methods**: 41
- **Fields**: 52
- **Source**: `mqttclient\mqttv3\internal\CommsCallback.java`

**Key Methods**:
  - `CommsCallback()`
  - `Object()`
  - `Object()`
  - `Object()`
  - `handleActionComplete()`
  - `handleMessage()`
  - `MqttToken()`
  - `if()`
  - `MqttPubComp()`
  - `MqttToken()`
  - *(... and 31 more)*

---

### CommsReceiver [HIGH]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.CommsReceiver`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Implements**: `Runnable`
- **Methods**: 16
- **Fields**: 35
- **Source**: `mqttclient\mqttv3\internal\CommsReceiver.java`

**Key Methods**:
  - `CommsReceiver()`
  - `Object()`
  - `MqttInputStream()`
  - `isReceiving()`
  - `isRunning()`
  - `run()`
  - `MqttException()`
  - `if()`
  - `if()`
  - `IOException()`
  - *(... and 6 more)*

---

### CommsSender [HIGH]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.CommsSender`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Implements**: `Runnable`
- **Methods**: 12
- **Fields**: 32
- **Source**: `mqttclient\mqttv3\internal\CommsSender.java`

**Key Methods**:
  - `CommsSender()`
  - `Object()`
  - `MqttOutputStream()`
  - `handleRunException()`
  - `MqttException()`
  - `isRunning()`
  - `run()`
  - `start()`
  - `Thread()`
  - `AtomicInteger()`
  - *(... and 2 more)*

---

### NetworkModuleService [HIGH]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.NetworkModuleService`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Methods**: 13
- **Fields**: 19
- **Source**: `mqttclient\mqttv3\internal\NetworkModuleService.java`

**Key Methods**:
  - `NetworkModuleService()`
  - `applyRFC3986AuthorityPatch()`
  - `createInstance()`
  - `URI()`
  - `IllegalArgumentException()`
  - `IllegalArgumentException()`
  - `hasQuic()`
  - `setURIField()`
  - `validateURI()`
  - `URI()`
  - *(... and 3 more)*

---

### C0079R [HIGH]


- **Full Name**: `com.thingclips.smart.optimus.sdk.C0079R`
- **Package**: `com.thingclips.smart.optimus.sdk`
- **Methods**: 19
- **Fields**: 5129
- **Source**: `smart\optimus\sdk\C0079R.java`

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

### C0084a [HIGH]


- **Full Name**: `com.thingclips.smart.optimus.sdk.C0084a`
- **Package**: `com.thingclips.smart.optimus.sdk`
- **Implements**: `ThreadFactory`
- **Methods**: 17
- **Fields**: 9
- **Source**: `smart\optimus\sdk\C0084a.java`

**Key Methods**:
  - `LinkedBlockingQueue()`
  - `AtomicInteger()`
  - `a()`
  - `newThread()`
  - `Thread()`
  - `b()`
  - `rejectedExecution()`
  - `if()`
  - `c()`
  - `run()`
  - *(... and 7 more)*

---

### C0085b [HIGH]


- **Full Name**: `com.thingclips.smart.optimus.sdk.C0085b`
- **Package**: `com.thingclips.smart.optimus.sdk`
- **Implements**: `Iterable<S>`
- **Methods**: 32
- **Fields**: 47
- **Source**: `smart\optimus\sdk\C0085b.java`

**Key Methods**:
  - `a()`
  - `hasNext()`
  - `next()`
  - `remove()`
  - `UnsupportedOperationException()`
  - `b()`
  - `m231a()`
  - `m232b()`
  - `NoSuchElementException()`
  - `ClassCastException()`
  - *(... and 22 more)*

---

### C0086c [HIGH]


- **Full Name**: `com.thingclips.smart.optimus.sdk.C0086c`
- **Package**: `com.thingclips.smart.optimus.sdk`
- **Extends**: `ZipEntry>`
- **Methods**: 9
- **Fields**: 25
- **Source**: `smart\optimus\sdk\C0086c.java`

**Key Methods**:
  - `StringBuilder()`
  - `m233a()`
  - `m235b()`
  - `m237c()`
  - `m234a()`
  - `m236b()`
  - `ArrayList()`
  - `File()`
  - `ZipFile()`

---

### OptimusLifecycle [HIGH]


- **Full Name**: `com.thingclips.smart.optimus.sdk.OptimusLifecycle`
- **Package**: `com.thingclips.smart.optimus.sdk`
- **Extends**: `Business`
- **Implements**: `Application.ActivityLifecycleCallbacks`
- **Methods**: 25
- **Fields**: 27
- **Source**: `smart\optimus\sdk\OptimusLifecycle.java`

**Key Methods**:
  - `AtomicInteger()`
  - `AtomicBoolean()`
  - `m212a()`
  - `EncryptApiParams()`
  - `syncRequest()`
  - `m208a()`
  - `HashMap()`
  - `initOptimus()`
  - `sendVersions()`
  - `JSONArray()`
  - *(... and 15 more)*

---

### ThingOptimusSdk [HIGH]


- **Full Name**: `com.thingclips.smart.optimus.sdk.ThingOptimusSdk`
- **Package**: `com.thingclips.smart.optimus.sdk`
- **Implements**: `Runnable`
- **Methods**: 21
- **Fields**: 28
- **Source**: `smart\optimus\sdk\ThingOptimusSdk.java`

**Key Methods**:
  - `HashMap()`
  - `HashMap()`
  - `Object()`
  - `RunnableC0080a()`
  - `run()`
  - `OptimusSdkInfo()`
  - `C0081b()`
  - `onResult()`
  - `C0082c()`
  - `mo213a()`
  - *(... and 11 more)*

---

### DeviceDpParserPlugin [HIGH]


- **Full Name**: `com.thingclips.smart.p002dp.parser.DeviceDpParserPlugin`
- **Package**: `com.thingclips.smart.p002dp.parser`
- **Extends**: `AbstractComponentService`
- **Implements**: `IAppDpParserPlugin`
- **Methods**: 7
- **Fields**: 0
- **Source**: `smart\p002dp\parser\DeviceDpParserPlugin.java`

**Key Methods**:
  - `dependencies()`
  - `getParser()`
  - `init()`
  - `remove()`
  - `removeAll()`
  - `update()`
  - `update()`

---

### ThingCameraSDKManager [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ThingCameraSDKManager`
- **Package**: `com.thingclips.smart.camera`
- **Methods**: 17
- **Fields**: 12
- **Source**: `thingclips\smart\camera\ThingCameraSDKManager.java`

**Key Methods**:
  - `build()`
  - `buildWithoutInit()`
  - `getILibLoader()`
  - `bppdpdq()`
  - `getILog()`
  - `qddqppb()`
  - `getIStatEvent()`
  - `pppbppp()`
  - `setILibLoader()`
  - `setILog()`
  - *(... and 7 more)*

---

### AudioEffect [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.annotation.AudioEffect`
- **Package**: `com.thingclips.smart.camera.annotation`
- **Methods**: 0
- **Fields**: 5
- **Source**: `smart\camera\annotation\AudioEffect.java`

---

### CloudPlaySpeed [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.annotation.CloudPlaySpeed`
- **Package**: `com.thingclips.smart.camera.annotation`
- **Methods**: 0
- **Fields**: 3
- **Source**: `smart\camera\annotation\CloudPlaySpeed.java`

---

### MuteStatus [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.annotation.MuteStatus`
- **Package**: `com.thingclips.smart.camera.annotation`
- **Methods**: 0
- **Fields**: 2
- **Source**: `smart\camera\annotation\MuteStatus.java`

---

### PlayBackSpeed [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.annotation.PlayBackSpeed`
- **Package**: `com.thingclips.smart.camera.annotation`
- **Methods**: 0
- **Fields**: 0
- **Source**: `smart\camera\annotation\PlayBackSpeed.java`

---

### SDCardState [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.annotation.SDCardState`
- **Package**: `com.thingclips.smart.camera.annotation`
- **Methods**: 0
- **Fields**: 5
- **Source**: `smart\camera\annotation\SDCardState.java`

---

### ThingCameraInterface [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.api.ThingCameraInterface`
- **Package**: `com.thingclips.smart.camera.api`
- **Methods**: 94
- **Fields**: 0
- **Source**: `smart\camera\api\ThingCameraInterface.java`

**Key Methods**:
  - `cancelCloudDataDownload()`
  - `cancelConvertIFrameToImageForVideoMessage()`
  - `cancelDownloadAlbumFile()`
  - `cancelVideoMessageDownload()`
  - `configCloudDataTags()`
  - `configCloudDataTagsV2()`
  - `connect()`
  - `connect()`
  - `connect()`
  - `deleteAlbumFile()`
  - *(... and 84 more)*

---

### ThingCameraListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.api.ThingCameraListener`
- **Package**: `com.thingclips.smart.camera.api`
- **Methods**: 6
- **Fields**: 3
- **Source**: `smart\camera\api\ThingCameraListener.java`

**Key Methods**:
  - `onAudioFrameRecved()`
  - `onAudioRecordReceived()`
  - `onEventInfoReceived()`
  - `onLocalVideoFrameRecved()`
  - `onSessionStatusChanged()`
  - `onVideoFrameRecved()`

---

### IBuilder [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.base.api.IBuilder`
- **Package**: `com.thingclips.smart.camera.base.api`
- **Methods**: 4
- **Fields**: 0
- **Source**: `camera\base\api\IBuilder.java`

**Key Methods**:
  - `getLog()`
  - `isLogEnable()`
  - `setLog()`
  - `setLogEnable()`

---

### ILog [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.base.api.ILog`
- **Package**: `com.thingclips.smart.camera.base.api`
- **Methods**: 7
- **Fields**: 0
- **Source**: `camera\base\api\ILog.java`

**Key Methods**:
  - `mo0d()`
  - `mo1e()`
  - `mo2e()`
  - `mo3i()`
  - `setLogEnabled()`
  - `mo4v()`
  - `mo5w()`

---

### CameraBaseBuilder [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.base.impl.CameraBaseBuilder`
- **Package**: `com.thingclips.smart.camera.base.impl`
- **Implements**: `IBuilder`
- **Methods**: 5
- **Fields**: 3
- **Source**: `camera\base\impl\CameraBaseBuilder.java`

**Key Methods**:
  - `getLog()`
  - `DefaultLog()`
  - `isLogEnable()`
  - `setLog()`
  - `setLogEnable()`

---

### DefaultLog [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.base.impl.DefaultLog`
- **Package**: `com.thingclips.smart.camera.base.impl`
- **Implements**: `ILog`
- **Methods**: 7
- **Fields**: 1
- **Source**: `camera\base\impl\DefaultLog.java`

**Key Methods**:
  - `mo0d()`
  - `mo1e()`
  - `mo3i()`
  - `setLogEnabled()`
  - `mo4v()`
  - `mo5w()`
  - `mo2e()`

---

### ThingCameraCode [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.base.log.ThingCameraCode`
- **Package**: `com.thingclips.smart.camera.base.log`
- **Methods**: 2
- **Fields**: 35
- **Source**: `camera\base\log\ThingCameraCode.java`

**Key Methods**:
  - `ThingCameraCode()`
  - `ThingCameraCode()`

---

### ThingCameraL [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.base.log.ThingCameraL`
- **Package**: `com.thingclips.smart.camera.base.log`
- **Methods**: 7
- **Fields**: 4
- **Source**: `camera\base\log\ThingCameraL.java`

**Key Methods**:
  - `m6d()`
  - `m7i()`
  - `log()`
  - `StringBuilder()`
  - `m8i()`
  - `log()`
  - `if()`

---

### ThingCameraAudioFrame [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.bean.ThingCameraAudioFrame`
- **Package**: `com.thingclips.smart.camera.bean`
- **Implements**: `Parcelable`
- **Methods**: 23
- **Fields**: 8
- **Source**: `smart\camera\bean\ThingCameraAudioFrame.java`

**Key Methods**:
  - `bdpdqbp()`
  - `createFromParcel()`
  - `ThingCameraAudioFrame()`
  - `newArray()`
  - `ThingCameraAudioFrame()`
  - `describeContents()`
  - `getBitWidth()`
  - `getChannelNum()`
  - `getDuration()`
  - `getProgress()`
  - *(... and 13 more)*

---

### ThingCameraVideoFrame [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.bean.ThingCameraVideoFrame`
- **Package**: `com.thingclips.smart.camera.bean`
- **Implements**: `Parcelable`
- **Methods**: 35
- **Fields**: 12
- **Source**: `smart\camera\bean\ThingCameraVideoFrame.java`

**Key Methods**:
  - `bdpdqbp()`
  - `createFromParcel()`
  - `ThingCameraVideoFrame()`
  - `newArray()`
  - `ThingCameraVideoFrame()`
  - `describeContents()`
  - `getCodecId()`
  - `getDuration()`
  - `getFrameRate()`
  - `getHeight()`
  - *(... and 25 more)*

---

### ThingFinishableCallback [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.callback.ThingFinishableCallback`
- **Package**: `com.thingclips.smart.camera.callback`
- **Extends**: `ThingBaseCallback`
- **Methods**: 1
- **Fields**: 0
- **Source**: `smart\camera\callback\ThingFinishableCallback.java`

**Key Methods**:
  - `onFinished()`

---

### ThingProgressiveCallback [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.callback.ThingProgressiveCallback`
- **Package**: `com.thingclips.smart.camera.callback`
- **Extends**: `ThingFinishableCallback`
- **Methods**: 1
- **Fields**: 0
- **Source**: `smart\camera\callback\ThingProgressiveCallback.java`

**Key Methods**:
  - `onProgress()`

---

### ThingAudioFrameInfo [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.camerasdk.bean.ThingAudioFrameInfo`
- **Package**: `com.thingclips.smart.camera.camerasdk.bean`
- **Implements**: `Parcelable`
- **Methods**: 20
- **Fields**: 7
- **Source**: `camera\camerasdk\bean\ThingAudioFrameInfo.java`

**Key Methods**:
  - `createFromParcel()`
  - `ThingAudioFrameInfo()`
  - `newArray()`
  - `ThingAudioFrameInfo()`
  - `describeContents()`
  - `getBitWidth()`
  - `getChannelNum()`
  - `getDuration()`
  - `getProgress()`
  - `getSampleRate()`
  - *(... and 10 more)*

---

### ThingVideoFrameInfo [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.camerasdk.bean.ThingVideoFrameInfo`
- **Package**: `com.thingclips.smart.camera.camerasdk.bean`
- **Implements**: `Parcelable`
- **Methods**: 40
- **Fields**: 17
- **Source**: `camera\camerasdk\bean\ThingVideoFrameInfo.java`

**Key Methods**:
  - `createFromParcel()`
  - `ThingVideoFrameInfo()`
  - `newArray()`
  - `ThingVideoFrameInfo()`
  - `describeContents()`
  - `getCodecId()`
  - `getDuration()`
  - `getFrameRate()`
  - `getHeight()`
  - `getIndex()`
  - *(... and 30 more)*

---

### Constants [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.chaos.middleware.Constants`
- **Package**: `com.thingclips.smart.camera.chaos.middleware`
- **Methods**: 1
- **Fields**: 21
- **Source**: `camera\chaos\middleware\Constants.java`

**Key Methods**:
  - `ThreadPoolExecutor()`

---

### StateServiceUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.chaos.middleware.StateServiceUtil`
- **Package**: `com.thingclips.smart.camera.chaos.middleware`
- **Methods**: 17
- **Fields**: 16
- **Source**: `camera\chaos\middleware\StateServiceUtil.java`

**Key Methods**:
  - `StateServiceUtil()`
  - `getClientTraceId()`
  - `getConnectTraceId()`
  - `getService()`
  - `sendAPMLog()`
  - `sendCameraLog()`
  - `sendConnectFullLinkLog()`
  - `sendFullLinkLog()`
  - `sendFullLinkStartLog()`
  - `sendIPCExtraDataLog()`
  - *(... and 7 more)*

---

### bppdpdq [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ffmpeg.bppdpdq`
- **Package**: `com.thingclips.smart.camera.ffmpeg`
- **Implements**: `ILog`
- **Methods**: 6
- **Fields**: 0
- **Source**: `smart\camera\ffmpeg\bppdpdq.java`

**Key Methods**:
  - `mo9d()`
  - `mo10e()`
  - `mo12i()`
  - `mo13v()`
  - `mo14w()`
  - `mo11e()`

---

### ILog [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ffmpeg.toolkit.api.ILog`
- **Package**: `com.thingclips.smart.camera.ffmpeg.toolkit.api`
- **Methods**: 6
- **Fields**: 0
- **Source**: `ffmpeg\toolkit\api\ILog.java`

**Key Methods**:
  - `mo9d()`
  - `mo10e()`
  - `mo11e()`
  - `mo12i()`
  - `mo13v()`
  - `mo14w()`

---

### CameraBusiness [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.business.CameraBusiness`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.business`
- **Extends**: `Business`
- **Implements**: `ICameraBusiness`
- **Methods**: 8
- **Fields**: 5
- **Source**: `camera\ipccamerasdk\business\CameraBusiness.java`

**Key Methods**:
  - `destroy()`
  - `requestCameraInfo()`
  - `ApiParams()`
  - `requestCameraSessionInit()`
  - `ApiParams()`
  - `runRequestTask()`
  - `requestCameraInfo()`
  - `ApiParams()`

---

### bdpdqbp [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.cloud.bdpdqbp`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.cloud`
- **Implements**: `OperationDelegateCallBack`
- **Methods**: 9
- **Fields**: 3
- **Source**: `camera\ipccamerasdk\cloud\bdpdqbp.java`

**Key Methods**:
  - `C0091bdpdqbp()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `C0091bdpdqbp()`

---

### bppdpdq [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.cloud.bppdpdq`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.cloud`
- **Implements**: `Runnable`
- **Methods**: 2
- **Fields**: 1
- **Source**: `camera\ipccamerasdk\cloud\bppdpdq.java`

**Key Methods**:
  - `bppdpdq()`
  - `run()`

---

### pdqppqb [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.cloud.pdqppqb`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.cloud`
- **Implements**: `Business.ResultListener<JSONObject>`
- **Methods**: 5
- **Fields**: 1
- **Source**: `camera\ipccamerasdk\cloud\pdqppqb.java`

**Key Methods**:
  - `pdqppqb()`
  - `bdpdqbp()`
  - `onFailure()`
  - `onSuccess()`
  - `bdpdqbp()`

---

### RunnableC0006a [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.cloud.RunnableC0006a`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.cloud`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 6
- **Source**: `camera\ipccamerasdk\cloud\RunnableC0006a.java`

**Key Methods**:
  - `run()`

---

### RunnableC0007b [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.cloud.RunnableC0007b`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.cloud`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 6
- **Source**: `camera\ipccamerasdk\cloud\RunnableC0007b.java`

**Key Methods**:
  - `run()`

---

### RunnableC0008c [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.cloud.RunnableC0008c`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.cloud`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 6
- **Source**: `camera\ipccamerasdk\cloud\RunnableC0008c.java`

**Key Methods**:
  - `run()`

---

### RunnableC0009d [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.cloud.RunnableC0009d`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.cloud`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 6
- **Source**: `camera\ipccamerasdk\cloud\RunnableC0009d.java`

**Key Methods**:
  - `run()`

---

### AbsMonitorViewProxy [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.monitor.AbsMonitorViewProxy`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.monitor`
- **Implements**: `IMonitorView`
- **Methods**: 33
- **Fields**: 4
- **Source**: `camera\ipccamerasdk\monitor\AbsMonitorViewProxy.java`

**Key Methods**:
  - `noImplWarning()`
  - `getMaxScaleFactor()`
  - `getMultiIndex()`
  - `getRockerAvailableDirection()`
  - `getScale()`
  - `getType()`
  - `getView()`
  - `isRockMode()`
  - `onPause()`
  - `onResume()`
  - *(... and 23 more)*

---

### IMonitorView [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.monitor.IMonitorView`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.monitor`
- **Methods**: 31
- **Fields**: 0
- **Source**: `camera\ipccamerasdk\monitor\IMonitorView.java`

**Key Methods**:
  - `getMaxScaleFactor()`
  - `getMultiIndex()`
  - `getRockerAvailableDirection()`
  - `getScale()`
  - `getType()`
  - `isRockMode()`
  - `onPause()`
  - `onResume()`
  - `setAutoRotation()`
  - `setEapilRenderType()`
  - *(... and 21 more)*

---

### Monitor [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.monitor.Monitor`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.monitor`
- **Extends**: `YUVMonitorSurfaceView`
- **Implements**: `GestureDetector.OnGestureListener, GestureDetector.OnDoubleTapListener, IRegistorIOTCListener`
- **Methods**: 51
- **Fields**: 53
- **Source**: `camera\ipccamerasdk\monitor\Monitor.java`

**Key Methods**:
  - `Monitor()`
  - `handleSeiInfo()`
  - `setTrackingHideForTemp()`
  - `getMultiIndex()`
  - `getRockerAvailableDirection()`
  - `getScale()`
  - `getType()`
  - `isRockMode()`
  - `onDetachedFromWindow()`
  - `onDoubleTap()`
  - *(... and 41 more)*

---

### bdpdqbp [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.p000dp.bdpdqbp`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.p000dp`
- **Implements**: `IDevListener`
- **Methods**: 6
- **Fields**: 28
- **Source**: `camera\ipccamerasdk\p000dp\bdpdqbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onDevInfoUpdate()`
  - `onDpUpdate()`
  - `onNetworkStatusChanged()`
  - `onRemoved()`
  - `onStatusChanged()`

---

### DpHelper [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.p000dp.DpHelper`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.p000dp`
- **Extends**: `Lambda`
- **Implements**: `IThingIPCDpHelper`
- **Methods**: 69
- **Fields**: 126
- **Source**: `camera\ipccamerasdk\p000dp\DpHelper.java`

**Key Methods**:
  - `bppdpdq()`
  - `invoke()`
  - `ppdpppq()`
  - `pbbppqb()`
  - `invoke()`
  - `pbddddb()`
  - `onError()`
  - `StringBuilder()`
  - `onSuccess()`
  - `method()`
  - *(... and 59 more)*

---

### DpStaticHelper [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.p000dp.DpStaticHelper`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.p000dp`
- **Methods**: 9
- **Fields**: 24
- **Source**: `camera\ipccamerasdk\p000dp\DpStaticHelper.java`

**Key Methods**:
  - `DpStaticHelper()`
  - `DpStaticHelper()`
  - `getCurrentValue()`
  - `getDeviceBean()`
  - `getSchemaBean()`
  - `getSchemaProperty()`
  - `isDPSupport()`
  - `parseObject()`
  - `String()`

---

### AbsTutkCameraP2P [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.p2p.AbsTutkCameraP2P`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.p2p`
- **Implements**: `ICameraP2P`
- **Methods**: 48
- **Fields**: 2
- **Source**: `camera\ipccamerasdk\p2p\AbsTutkCameraP2P.java`

**Key Methods**:
  - `cancelDownloadAlbumFile()`
  - `connect2()`
  - `deAllModules()`
  - `deleteAlbumFile()`
  - `deletePlaybackDataByDay()`
  - `deletePlaybackDataByFragments()`
  - `destroyCameraView()`
  - `disconnect()`
  - `downloadPlaybackEventImage()`
  - `enableAudioAEC()`
  - *(... and 38 more)*

---

### TagBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.p2p.TagBean`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.p2p`
- **Methods**: 92
- **Fields**: 17
- **Source**: `camera\ipccamerasdk\p2p\ICameraP2P.java`

**Key Methods**:
  - `TagBean()`
  - `getValue()`
  - `TagBean()`
  - `cancelDownloadAlbumFile()`
  - `connect()`
  - `connect()`
  - `connect2()`
  - `connectPlayback()`
  - `createDevice()`
  - `createDevice()`
  - *(... and 82 more)*

---

### CameraConstant [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.ipccamerasdk.utils.CameraConstant`
- **Package**: `com.thingclips.smart.camera.ipccamerasdk.utils`
- **Methods**: 11
- **Fields**: 45
- **Source**: `camera\ipccamerasdk\utils\CameraConstant.java`

**Key Methods**:
  - `CameraConstant()`
  - `getCameraRotateAngle()`
  - `getDeviceP2PType()`
  - `getSdkProvider()`
  - `StringBuilder()`
  - `getsdkProvider()`
  - `isNvrDVRSubDevice()`
  - `isSubDevice()`
  - `log()`
  - `m20m2()`
  - *(... and 1 more)*

---

### bdbbqbd [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.bdbbqbd`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `ThingProgressiveCallback`
- **Methods**: 4
- **Fields**: 1
- **Source**: `smart\camera\middleware\bdbbqbd.java`

**Key Methods**:
  - `bdbbqbd()`
  - `onFinished()`
  - `onProgress()`
  - `onResponse()`

---

### bdqbdpp [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.bdqbdpp`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Extends**: `Lambda`
- **Implements**: `IThingIPCPTZ, OnDeviceChangedListener`
- **Methods**: 51
- **Fields**: 48
- **Source**: `smart\camera\middleware\bdqbdpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `invoke()`
  - `DpHelper()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `ArrayList()`
  - `pdqppqb()`
  - `onFailure()`
  - `onSuccess()`
  - *(... and 41 more)*

---

### bdqqbqd [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.bdqqbqd`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `ILog`
- **Methods**: 7
- **Fields**: 1
- **Source**: `smart\camera\middleware\bdqqbqd.java`

**Key Methods**:
  - `m22d()`
  - `m23e()`
  - `m25i()`
  - `setLogEnabled()`
  - `m26v()`
  - `m27w()`
  - `m24e()`

---

### bdqqqbp [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.bdqqqbp`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `ThingCameraListener, IThingCloudVideo`
- **Methods**: 55
- **Fields**: 57
- **Source**: `smart\camera\middleware\bdqqqbp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `onResponse()`
  - `bppdpdq()`
  - `onFinished()`
  - `onResponse()`
  - `pbbppqb()`
  - `onResponse()`
  - `pdqppqb()`
  - `run()`
  - `pppbppp()`
  - *(... and 45 more)*

---

### bqbppdq [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.bqbppdq`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Methods**: 0
- **Fields**: 3
- **Source**: `smart\camera\middleware\bqbppdq.java`

---

### bqdbdbd [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.bqdbdbd`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `dqqbdqb`
- **Methods**: 3
- **Fields**: 11
- **Source**: `smart\camera\middleware\bqdbdbd.java`

**Key Methods**:
  - `bqdbdbd()`
  - `bdpdqbp()`
  - `bdpdqbp()`

---

### bqpqpqb [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.bqpqpqb`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Methods**: 11
- **Fields**: 13
- **Source**: `smart\camera\middleware\bqpqpqb.java`

**Key Methods**:
  - `HashMap()`
  - `bqpqpqb()`
  - `RelativeLayout()`
  - `bdpdqbp()`
  - `ImageView()`
  - `if()`
  - `ImageView()`
  - `if()`
  - `ImageView()`
  - `if()`
  - *(... and 1 more)*

---

### dbqqppp [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.dbqqppp`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Extends**: `AbsConnectCallBack`
- **Methods**: 4
- **Fields**: 9
- **Source**: `smart\camera\middleware\dbqqppp.java`

**Key Methods**:
  - `dbqqppp()`
  - `isIntercept()`
  - `onFailure()`
  - `onSuccess()`

---

### dddddqd [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.dddddqd`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `ThingProgressiveCallback`
- **Methods**: 4
- **Fields**: 2
- **Source**: `smart\camera\middleware\dddddqd.java`

**Key Methods**:
  - `dddddqd()`
  - `onFinished()`
  - `onProgress()`
  - `onResponse()`

---

### ddqdbbd [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.ddqdbbd`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `ICameraStatEvent`
- **Methods**: 16
- **Fields**: 9
- **Source**: `smart\camera\middleware\ddqdbbd.java`

**Key Methods**:
  - `bdpdqbp()`
  - `getClientTraceId()`
  - `getConnectTraceId()`
  - `sendAPMLog()`
  - `sendCameraLog()`
  - `sendConnectFullLinkLog()`
  - `sendFullLinkLog()`
  - `sendFullLinkStartLog()`
  - `sendIPCExtraDataLog()`
  - `StringBuilder()`
  - *(... and 6 more)*

---

### dqddqdp [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.dqddqdp`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Extends**: `FrameLayout`
- **Implements**: `bddqqbb`
- **Methods**: 22
- **Fields**: 54
- **Source**: `smart\camera\middleware\dqddqdp.java`

**Key Methods**:
  - `method()`
  - `dqddqdp()`
  - `YUVMonitorTextureView()`
  - `bbpqdqb()`
  - `bdpdqbp()`
  - `getMSafeDisX()`
  - `getMSafeDisY()`
  - `onAttachedToWindow()`
  - `onDetachedFromWindow()`
  - `onLayout()`
  - *(... and 12 more)*

---

### pbpdbqp [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.pbpdbqp`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `IThingResultCallback<JSONArray>`
- **Methods**: 4
- **Fields**: 6
- **Source**: `smart\camera\middleware\pbpdbqp.java`

**Key Methods**:
  - `pbpdbqp()`
  - `onError()`
  - `onSuccess()`
  - `pbpqqdp()`

---

### pbqpqdq [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.pbqpqdq`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `ThingFinishableCallback`
- **Methods**: 3
- **Fields**: 2
- **Source**: `smart\camera\middleware\pbqpqdq.java`

**Key Methods**:
  - `pbqpqdq()`
  - `onFinished()`
  - `onResponse()`

---

### ppbdppp [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.ppbdppp`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `ThingFileDownloadCallback`
- **Methods**: 6
- **Fields**: 1
- **Source**: `smart\camera\middleware\ppbdppp.java`

**Key Methods**:
  - `ppbdppp()`
  - `onDownloadFileFinished()`
  - `onDownloadFileProgress()`
  - `onFinished()`
  - `onProgress()`
  - `onResponse()`

---

### pqdqqbd [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.pqdqqbd`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Methods**: 2
- **Fields**: 6
- **Source**: `smart\camera\middleware\pqdqqbd.java`

**Key Methods**:
  - `pqdqqbd()`
  - `bqbdbqb()`

---

### pqpbdqq [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.pqpbdqq`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `Runnable`
- **Methods**: 2
- **Fields**: 2
- **Source**: `smart\camera\middleware\pqpbdqq.java`

**Key Methods**:
  - `pqpbdqq()`
  - `run()`

---

### pqqqddq [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.pqqqddq`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `ThingFinishableCallback`
- **Methods**: 3
- **Fields**: 1
- **Source**: `smart\camera\middleware\pqqqddq.java`

**Key Methods**:
  - `pqqqddq()`
  - `onFinished()`
  - `onResponse()`

---

### qbdqpqq [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.qbdqpqq`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `ThingFileDownloadCallback`
- **Methods**: 6
- **Fields**: 2
- **Source**: `smart\camera\middleware\qbdqpqq.java`

**Key Methods**:
  - `qbdqpqq()`
  - `onDownloadFileFinished()`
  - `onDownloadFileProgress()`
  - `onFinished()`
  - `onProgress()`
  - `onResponse()`

---

### qbqddpp [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.qbqddpp`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Extends**: `AbsMonitorViewProxy`
- **Methods**: 26
- **Fields**: 7
- **Source**: `smart\camera\middleware\qbqddpp.java`

**Key Methods**:
  - `qbqddpp()`
  - `Monitor()`
  - `getMaxScaleFactor()`
  - `getMultiIndex()`
  - `getRockerAvailableDirection()`
  - `getType()`
  - `getView()`
  - `isRockMode()`
  - `onPause()`
  - `onResume()`
  - *(... and 16 more)*

---

### qbqqdqq [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.qbqqdqq`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Methods**: 1
- **Fields**: 3
- **Source**: `smart\camera\middleware\qbqqdqq.java`

**Key Methods**:
  - `qbqqdqq()`

---

### qdbpqqq [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.qdbpqqq`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `IThingIPCHomeProxy`
- **Methods**: 7
- **Fields**: 12
- **Source**: `smart\camera\middleware\qdbpqqq.java`

**Key Methods**:
  - `getCameraInstance()`
  - `getDataInstance()`
  - `getMqttChannelInstance()`
  - `getUserInstance()`
  - `newDeviceInstance()`
  - `newGatewayInstance()`
  - `newOTAInstance()`

---

### qppddqq [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.qppddqq`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Methods**: 3
- **Fields**: 16
- **Source**: `smart\camera\middleware\qppddqq.java`

**Key Methods**:
  - `bdpdqbp()`
  - `Matrix()`
  - `FileOutputStream()`

---

### qpqbppd [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.qpqbppd`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Extends**: `ThingAvLoggerListener`
- **Methods**: 4
- **Fields**: 2
- **Source**: `smart\camera\middleware\qpqbppd.java`

**Key Methods**:
  - `onApmLogSender()`
  - `onFullLinkLogSender()`
  - `onNativeLogSender()`
  - `bdpdqbp()`

---

### qqdbbpp [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.qqdbbpp`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `Runnable`
- **Methods**: 10
- **Fields**: 18
- **Source**: `smart\camera\middleware\qqdbbpp.java`

**Key Methods**:
  - `bdpdqbp()`
  - `run()`
  - `qqdbbpp()`
  - `pdqppqb()`
  - `qqdbbpp()`
  - `bdpdqbp()`
  - `ScheduledThreadPoolExecutor()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bpqqdpq()`

---

### qqpbpdq [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.qqpbpdq`
- **Package**: `com.thingclips.smart.camera.middleware`
- **Implements**: `IThingIPCDevice`
- **Methods**: 5
- **Fields**: 13
- **Source**: `smart\camera\middleware\qqpbpdq.java`

**Key Methods**:
  - `qqpbpdq()`
  - `getDeviceBean()`
  - `getDp()`
  - `getSubDeviceBeanByNodeId()`
  - `queryDev()`

---

### CameraCloudSDK [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.cloud.CameraCloudSDK`
- **Package**: `com.thingclips.smart.camera.middleware.cloud`
- **Methods**: 10
- **Fields**: 4
- **Source**: `camera\middleware\cloud\CameraCloudSDK.java`

**Key Methods**:
  - `buyCloudStorage()`
  - `getCameraCloudInfo()`
  - `qqpdpbp()`
  - `getCloudMediaCount()`
  - `bqqppqq()`
  - `getMotionDetectionByTimeSlice()`
  - `pbbppqb()`
  - `getTimeLineInfoByTimeSlice()`
  - `pppbppp()`
  - `onDestroy()`

---

### CloudDayBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.cloud.bean.CloudDayBean`
- **Package**: `com.thingclips.smart.camera.middleware.cloud.bean`
- **Implements**: `Comparable<CloudDayBean>`
- **Methods**: 21
- **Fields**: 33
- **Source**: `middleware\cloud\bean\CloudDayBean.java`

**Key Methods**:
  - `getTimeZone()`
  - `getTodayEnd()`
  - `getTodayStart()`
  - `parse()`
  - `SimpleDateFormat()`
  - `getCurrentDayEndTime()`
  - `getCurrentStartDayTime()`
  - `getDay()`
  - `getMonth()`
  - `getMonthAndDay()`
  - *(... and 11 more)*

---

### TimePieceBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.cloud.bean.TimePieceBean`
- **Package**: `com.thingclips.smart.camera.middleware.cloud.bean`
- **Implements**: `Comparable<TimePieceBean>`
- **Methods**: 25
- **Fields**: 9
- **Source**: `middleware\cloud\bean\TimePieceBean.java`

**Key Methods**:
  - `TimePieceBean()`
  - `getAiDetectList()`
  - `getEndTime()`
  - `getEndTimeInMillisecond()`
  - `getIsAIStorage()`
  - `getPlayTime()`
  - `getPrefix()`
  - `getStartTime()`
  - `getStartTimeInMillisecond()`
  - `getType()`
  - *(... and 15 more)*

---

### bdpdqbp [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.p2p.bdpdqbp`
- **Package**: `com.thingclips.smart.camera.middleware.p2p`
- **Extends**: `ThingSmartCameraP2PSync`
- **Implements**: `dqqbdqb`
- **Methods**: 46
- **Fields**: 62
- **Source**: `camera\middleware\p2p\bdpdqbp.java`

**Key Methods**:
  - `C0093bdpdqbp()`
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `bppdpdq()`
  - `onFailure()`
  - `onSuccess()`
  - `method()`
  - `pbbppqb()`
  - `invoke()`
  - `pdqppqb()`
  - *(... and 36 more)*

---

### IThingSmartCameraP2P [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.p2p.IThingSmartCameraP2P`
- **Package**: `com.thingclips.smart.camera.middleware.p2p`
- **Methods**: 98
- **Fields**: 3
- **Source**: `camera\middleware\p2p\IThingSmartCameraP2P.java`

**Key Methods**:
  - `cancelBusiness()`
  - `cancelDownloadAlbumFile()`
  - `clearReferenceCount()`
  - `connect()`
  - `connect()`
  - `connect()`
  - `connect()`
  - `connectPlayback()`
  - `connectWithDevId()`
  - `deleteAlbumFile()`
  - *(... and 88 more)*

---

### ThingSmartCameraP2P [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.p2p.ThingSmartCameraP2P`
- **Package**: `com.thingclips.smart.camera.middleware.p2p`
- **Extends**: `bdpdqbp`
- **Methods**: 8
- **Fields**: 7
- **Source**: `camera\middleware\p2p\ThingSmartCameraP2P.java`

**Key Methods**:
  - `ThingSmartCameraP2P()`
  - `isNotInAsyncThread()`
  - `destroyP2P()`
  - `disconnect()`
  - `execute()`
  - `getExecutor()`
  - `innerConnect()`
  - `setSync()`

---

### ThingIPCCount [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.service.ThingIPCCount`
- **Package**: `com.thingclips.smart.camera.middleware.service`
- **Extends**: `AbstractOptimusManager`
- **Implements**: `IThingIPCCount`
- **Methods**: 3
- **Fields**: 1
- **Source**: `camera\middleware\service\ThingIPCCount.java`

**Key Methods**:
  - `identifier()`
  - `init()`
  - `version()`

---

### ThingIPCPlugin [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.service.ThingIPCPlugin`
- **Package**: `com.thingclips.smart.camera.middleware.service`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingIPCPlugin`
- **Methods**: 20
- **Fields**: 6
- **Source**: `camera\middleware\service\ThingIPCPlugin.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `createIPCDpHelper()`
  - `DpHelper()`
  - `dependencies()`
  - `getIPCCloudInstance()`
  - `ddqqbbq()`
  - `getIPCDoorbellInstance()`
  - `bbppbbd()`
  - `getIPCHomeProxy()`
  - `qdbpqqq()`
  - *(... and 10 more)*

---

### EncryptImageUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.utils.EncryptImageUtil`
- **Package**: `com.thingclips.smart.camera.middleware.utils`
- **Methods**: 5
- **Fields**: 13
- **Source**: `camera\middleware\utils\EncryptImageUtil.java`

**Key Methods**:
  - `showCoverImage()`
  - `if()`
  - `showLocalImg()`
  - `File()`
  - `showRemoteImg()`

---

### ImageEncryptionUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.utils.ImageEncryptionUtil`
- **Package**: `com.thingclips.smart.camera.middleware.utils`
- **Methods**: 28
- **Fields**: 61
- **Source**: `camera\middleware\utils\ImageEncryptionUtil.java`

**Key Methods**:
  - `bytesToInt()`
  - `decryptImage()`
  - `encryptImage()`
  - `getEncryptDestFile()`
  - `File()`
  - `getIv()`
  - `StringBuilder()`
  - `SecureRandom()`
  - `if()`
  - `getK()`
  - *(... and 18 more)*

---

### CameraPTZLocationView [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.widget.CameraPTZLocationView`
- **Package**: `com.thingclips.smart.camera.middleware.widget`
- **Extends**: `View`
- **Implements**: `Runnable`
- **Methods**: 22
- **Fields**: 41
- **Source**: `camera\middleware\widget\CameraPTZLocationView.java`

**Key Methods**:
  - `onHiden()`
  - `bdpdqbp()`
  - `run()`
  - `CameraPTZLocationView()`
  - `init()`
  - `Paint()`
  - `Handler()`
  - `moveStatusView()`
  - `postHideDelayed()`
  - `setDefaultCenter()`
  - *(... and 12 more)*

---

### PositioningDragView [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.widget.PositioningDragView`
- **Package**: `com.thingclips.smart.camera.middleware.widget`
- **Extends**: `FrameLayout`
- **Implements**: `GestureDetector.OnGestureListener, GestureDetector.OnDoubleTapListener`
- **Methods**: 34
- **Fields**: 48
- **Source**: `camera\middleware\widget\PositioningDragView.java`

**Key Methods**:
  - `method()`
  - `PositioningDragView()`
  - `GestureDetector()`
  - `handleMoveEvent()`
  - `StringBuilder()`
  - `handleUpEvent()`
  - `onParentLayoutChanged()`
  - `addDragFrame()`
  - `FrameLayout()`
  - `onTouch()`
  - *(... and 24 more)*

---

### ThingCameraView [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.widget.ThingCameraView`
- **Package**: `com.thingclips.smart.camera.middleware.widget`
- **Extends**: `RelativeLayout`
- **Implements**: `OnRenderDirectionCallback`
- **Methods**: 73
- **Fields**: 82
- **Source**: `camera\middleware\widget\ThingCameraView.java`

**Key Methods**:
  - `onActionUP()`
  - `onCreated()`
  - `startCameraMove()`
  - `videoViewClick()`
  - `bdpdqbp()`
  - `onCancel()`
  - `onDown()`
  - `onLeft()`
  - `onRight()`
  - `onUp()`
  - *(... and 63 more)*

---

### ThingMultiCameraView [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.middleware.widget.ThingMultiCameraView`
- **Package**: `com.thingclips.smart.camera.middleware.widget`
- **Extends**: `ThingCameraView`
- **Implements**: `Animator.AnimatorListener`
- **Methods**: 66
- **Fields**: 159
- **Source**: `camera\middleware\widget\ThingMultiCameraView.java`

**Key Methods**:
  - `onAnimationCancel()`
  - `onAnimationEnd()`
  - `onAnimationRepeat()`
  - `onAnimationStart()`
  - `ThingMultiCameraView()`
  - `addLocatorView()`
  - `ArrayList()`
  - `createMonitorViewHolder()`
  - `ArrayList()`
  - `ddbdpqb()`
  - *(... and 56 more)*

---

### ThingCameraNative [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.nativeapi.ThingCameraNative`
- **Package**: `com.thingclips.smart.camera.nativeapi`
- **Methods**: 93
- **Fields**: 0
- **Source**: `smart\camera\nativeapi\ThingCameraNative.java`

**Key Methods**:
  - `cancelCloudDataDownload()`
  - `cancelConvertIFrameToImageForVideoMessage()`
  - `cancelDownloadAlbumFile()`
  - `cancelVideoMessageDownload()`
  - `configCloudDataTags()`
  - `configCloudDataTagsV2()`
  - `connect()`
  - `connect4ppcs()`
  - `createSimpleCamera()`
  - `createStationCamera()`
  - *(... and 83 more)*

---

### bdpdqbp [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.p001v2.bdpdqbp`
- **Package**: `com.thingclips.smart.camera.p001v2`
- **Implements**: `ThingCameraEngineInterface`
- **Methods**: 14
- **Fields**: 9
- **Source**: `smart\camera\p001v2\bdpdqbp.java`

**Key Methods**:
  - `deInitP2PModule()`
  - `deInitialize()`
  - `genMp4Thumbnail()`
  - `File()`
  - `FileOutputStream()`
  - `getCurVideoSoftDecodeStatus()`
  - `getSoftDecodeStatus()`
  - `getVersion()`
  - `initP2PModule()`
  - `initialize()`
  - *(... and 4 more)*

---

### pdqppqb [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.p001v2.pdqppqb`
- **Package**: `com.thingclips.smart.camera.p001v2`
- **Implements**: `ThingCameraInterface`
- **Methods**: 97
- **Fields**: 53
- **Source**: `smart\camera\p001v2\pdqppqb.java`

**Key Methods**:
  - `pdqppqb()`
  - `bdpdqbp()`
  - `cancelCloudDataDownload()`
  - `cancelConvertIFrameToImageForVideoMessage()`
  - `cancelDownloadAlbumFile()`
  - `cancelVideoMessageDownload()`
  - `configCloudDataTags()`
  - `configCloudDataTagsV2()`
  - `connect()`
  - `deleteAlbumFile()`
  - *(... and 87 more)*

---

### qddqppb [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.p001v2.qddqppb`
- **Package**: `com.thingclips.smart.camera.p001v2`
- **Implements**: `ILog`
- **Methods**: 7
- **Fields**: 1
- **Source**: `smart\camera\p001v2\qddqppb.java`

**Key Methods**:
  - `mo45d()`
  - `mo46e()`
  - `mo48i()`
  - `setLogEnabled()`
  - `mo49v()`
  - `mo50w()`
  - `mo47e()`

---

### ThingAudioEncoder [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.record.ThingAudioEncoder`
- **Package**: `com.thingclips.smart.camera.record`
- **Extends**: `Thread`
- **Methods**: 21
- **Fields**: 42
- **Source**: `smart\camera\record\ThingAudioEncoder.java`

**Key Methods**:
  - `getNumber()`
  - `bdpdqbp()`
  - `run()`
  - `bppdpdq()`
  - `onAddAudioTrack()`
  - `onAudioSample()`
  - `ThingAudioEncoder()`
  - `createOutputThread()`
  - `bdpdqbp()`
  - `encodeByteBuffer()`
  - *(... and 11 more)*

---

### ThingMediaRecorder [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.record.ThingMediaRecorder`
- **Package**: `com.thingclips.smart.camera.record`
- **Implements**: `ThingVideoEncoder.pdqppqb, ThingAudioEncoder.pdqppqb`
- **Methods**: 22
- **Fields**: 42
- **Source**: `smart\camera\record\ThingMediaRecorder.java`

**Key Methods**:
  - `bdpdqbp()`
  - `bdpdqbp()`
  - `run()`
  - `if()`
  - `pdqppqb()`
  - `getColorFormat()`
  - `getMaxSupportHeight()`
  - `getMaxSupportWidth()`
  - `stopRecoredThread()`
  - `onAddAudioTrack()`
  - *(... and 12 more)*

---

### ThingRingBuffer [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.record.ThingRingBuffer`
- **Package**: `com.thingclips.smart.camera.record`
- **Methods**: 39
- **Fields**: 43
- **Source**: `smart\camera\record\ThingRingBuffer.java`

**Key Methods**:
  - `bdpdqbp()`
  - `pdqppqb()`
  - `ThingRingBuffer()`
  - `advance()`
  - `availableAfter()`
  - `nextOffset()`
  - `overflows()`
  - `nextOffset()`
  - `clear()`
  - `drop()`
  - *(... and 29 more)*

---

### ThingVideoEncoder [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.record.ThingVideoEncoder`
- **Package**: `com.thingclips.smart.camera.record`
- **Extends**: `Thread`
- **Methods**: 31
- **Fields**: 73
- **Source**: `smart\camera\record\ThingVideoEncoder.java`

**Key Methods**:
  - `getNumber()`
  - `bdpdqbp()`
  - `run()`
  - `onAddVideoTrack()`
  - `onVideoFrame()`
  - `pppbppp()`
  - `qddqppb()`
  - `ThingVideoEncoder()`
  - `ReentrantLock()`
  - `codecSupportsType()`
  - *(... and 21 more)*

---

### ILog [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.toolkit.api.ILog`
- **Package**: `com.thingclips.smart.camera.toolkit.api`
- **Methods**: 7
- **Fields**: 0
- **Source**: `camera\toolkit\api\ILog.java`

**Key Methods**:
  - `mo45d()`
  - `mo46e()`
  - `mo47e()`
  - `mo48i()`
  - `setLogEnabled()`
  - `mo49v()`
  - `mo50w()`

---

### MediaScannerUtils [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.utils.MediaScannerUtils`
- **Package**: `com.thingclips.smart.camera.utils`
- **Methods**: 31
- **Fields**: 55
- **Source**: `smart\camera\utils\MediaScannerUtils.java`

**Key Methods**:
  - `MediaScannerUtils()`
  - `copyFileWithStream()`
  - `getDataColumn()`
  - `getPathFromURI()`
  - `getDataColumn()`
  - `if()`
  - `if()`
  - `getDataColumn()`
  - `getDataColumn()`
  - `getRealPathFromURI()`
  - *(... and 21 more)*

---

### C0020L [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.utils.chaos.C0020L`
- **Package**: `com.thingclips.smart.camera.utils.chaos`
- **Methods**: 6
- **Fields**: 6
- **Source**: `camera\utils\chaos\C0020L.java`

**Key Methods**:
  - `m51d()`
  - `m52e()`
  - `m54i()`
  - `m55v()`
  - `m56w()`
  - `m53e()`

---

### CRC32 [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.utils.chaos.CRC32`
- **Package**: `com.thingclips.smart.camera.utils.chaos`
- **Methods**: 3
- **Fields**: 3
- **Source**: `camera\utils\chaos\CRC32.java`

**Key Methods**:
  - `CRC32()`
  - `get()`
  - `getChecksum()`

---

### DensityUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.utils.chaos.DensityUtil`
- **Package**: `com.thingclips.smart.camera.utils.chaos`
- **Methods**: 5
- **Fields**: 5
- **Source**: `camera\utils\chaos\DensityUtil.java`

**Key Methods**:
  - `DensityUtil()`
  - `dip2px()`
  - `getScreenResolution()`
  - `DisplayMetrics()`
  - `getStatusBarHeight()`

---

### MD5Utils [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.utils.chaos.MD5Utils`
- **Package**: `com.thingclips.smart.camera.utils.chaos`
- **Methods**: 19
- **Fields**: 11
- **Source**: `camera\utils\chaos\MD5Utils.java`

**Key Methods**:
  - `MD5Utils()`
  - `bytesToHexString()`
  - `StringBuilder()`
  - `computeMD5Hash()`
  - `computeMD5Hash()`
  - `md5AsBase64()`
  - `md5AsBase64For16()`
  - `md5AsBase64()`
  - `str2md5()`
  - `bytesToHexString()`
  - *(... and 9 more)*

---

### CameraExecutor [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.utils.chaos.thread.CameraExecutor`
- **Package**: `com.thingclips.smart.camera.utils.chaos.thread`
- **Implements**: `Executor`
- **Methods**: 5
- **Fields**: 8
- **Source**: `utils\chaos\thread\CameraExecutor.java`

**Key Methods**:
  - `CameraExecutor()`
  - `HandlerThread()`
  - `Handler()`
  - `execute()`
  - `quite()`

---

### IPCThreadFactory [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.utils.chaos.thread.IPCThreadFactory`
- **Package**: `com.thingclips.smart.camera.utils.chaos.thread`
- **Extends**: `AtomicLong`
- **Implements**: `ThreadFactory`
- **Methods**: 3
- **Fields**: 4
- **Source**: `utils\chaos\thread\IPCThreadFactory.java`

**Key Methods**:
  - `IPCThreadFactory()`
  - `newThread()`
  - `Thread()`

---

### UPThreadPoolManager [MEDIUM]


- **Full Name**: `com.thingclips.smart.camera.utils.chaos.thread.UPThreadPoolManager`
- **Package**: `com.thingclips.smart.camera.utils.chaos.thread`
- **Implements**: `Executor`
- **Methods**: 10
- **Fields**: 10
- **Source**: `utils\chaos\thread\UPThreadPoolManager.java`

**Key Methods**:
  - `UPThreadPoolManager()`
  - `UPThreadPoolManager()`
  - `HandlerThread()`
  - `Handler()`
  - `createIPCSDKExecutor()`
  - `CameraExecutor()`
  - `CameraExecutor()`
  - `getInstance()`
  - `UPThreadPoolManager()`
  - `execute()`

---

### ThingComponentsService [MEDIUM]


- **Full Name**: `com.thingclips.smart.components.annotation.ThingComponentsService`
- **Package**: `com.thingclips.smart.components.annotation`
- **Methods**: 0
- **Fields**: 0
- **Source**: `smart\components\annotation\ThingComponentsService.java`

---

### RunnableC0037a [MEDIUM]


- **Full Name**: `com.thingclips.smart.config.RunnableC0037a`
- **Package**: `com.thingclips.smart.config`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 6
- **Source**: `thingclips\smart\config\RunnableC0037a.java`

**Key Methods**:
  - `run()`

---

### RunnableC0038b [MEDIUM]


- **Full Name**: `com.thingclips.smart.config.RunnableC0038b`
- **Package**: `com.thingclips.smart.config`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 6
- **Source**: `thingclips\smart\config\RunnableC0038b.java`

**Key Methods**:
  - `run()`

---

### RunnableC0039c [MEDIUM]


- **Full Name**: `com.thingclips.smart.config.RunnableC0039c`
- **Package**: `com.thingclips.smart.config`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 6
- **Source**: `thingclips\smart\config\RunnableC0039c.java`

**Key Methods**:
  - `run()`

---

### RunnableC0040d [MEDIUM]


- **Full Name**: `com.thingclips.smart.config.RunnableC0040d`
- **Package**: `com.thingclips.smart.config`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 4
- **Source**: `thingclips\smart\config\RunnableC0040d.java`

**Key Methods**:
  - `run()`

---

### ThingApDirectlyReduceConfig [MEDIUM]


- **Full Name**: `com.thingclips.smart.config.ThingApDirectlyReduceConfig`
- **Package**: `com.thingclips.smart.config`
- **Implements**: `IThingAPDirectlyConfig, qpbdppq, bbpqdqb`
- **Methods**: 15
- **Fields**: 20
- **Source**: `thingclips\smart\config\ThingApDirectlyReduceConfig.java`

**Key Methods**:
  - `AtomicInteger()`
  - `connectToQueryDeviceInfo()`
  - `getInstance()`
  - `ThingApDirectlyReduceConfig()`
  - `onActivatorError()`
  - `onActivatorSuccess()`
  - `onDevResponse()`
  - `String()`
  - `onDevUpdate()`
  - `dddbppd()`
  - *(... and 5 more)*

---

### ThingApSLConfig [MEDIUM]


- **Full Name**: `com.thingclips.smart.config.ThingApSLConfig`
- **Package**: `com.thingclips.smart.config`
- **Implements**: `IDeviceHardwareFindListener, bbpqdqb, qpbdppq`
- **Methods**: 22
- **Fields**: 32
- **Source**: `thingclips\smart\config\ThingApSLConfig.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `ThingApSLConfig()`
  - `SingleHolder()`
  - `getBroadcastAddress()`
  - `getIPAddress()`
  - `getInstance()`
  - `getIntIpAddress()`
  - `onStopFind()`
  - `registerAndListenerDiscoverBroadcast()`
  - `JSONObject()`
  - *(... and 12 more)*

**Notable Strings**:
  - `"[onFind] uuid:"`
  - `",target uuid:"`

---

### ThingBroadConnectConfig [MEDIUM]


- **Full Name**: `com.thingclips.smart.config.ThingBroadConnectConfig`
- **Package**: `com.thingclips.smart.config`
- **Implements**: `qpbdppq`
- **Methods**: 16
- **Fields**: 16
- **Source**: `thingclips\smart\config\ThingBroadConnectConfig.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `AtomicInteger()`
  - `getInstance()`
  - `ThingBroadConnectConfig()`
  - `normalControl()`
  - `JSONObject()`
  - `IResultCallback()`
  - `onError()`
  - `StringBuilder()`
  - `onSuccess()`
  - *(... and 6 more)*

---

### ThingEZConfig [MEDIUM]


- **Full Name**: `com.thingclips.smart.config.ThingEZConfig`
- **Package**: `com.thingclips.smart.config`
- **Implements**: `IThingEZConfig`
- **Methods**: 7
- **Fields**: 3
- **Source**: `thingclips\smart\config\ThingEZConfig.java`

**Key Methods**:
  - `ThingEZConfig()`
  - `getInstance()`
  - `ThingEZConfig()`
  - `startConfig()`
  - `Thread()`
  - `run()`
  - `stopConfig()`

---

### RunnableC0044a [MEDIUM]


- **Full Name**: `com.thingclips.smart.config.optimized.RunnableC0044a`
- **Package**: `com.thingclips.smart.config.optimized`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 4
- **Source**: `smart\config\optimized\RunnableC0044a.java`

**Key Methods**:
  - `run()`

---

### RunnableC0045b [MEDIUM]


- **Full Name**: `com.thingclips.smart.config.optimized.RunnableC0045b`
- **Package**: `com.thingclips.smart.config.optimized`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 6
- **Source**: `smart\config\optimized\RunnableC0045b.java`

**Key Methods**:
  - `run()`

---

### RunnableC0046c [MEDIUM]


- **Full Name**: `com.thingclips.smart.config.optimized.RunnableC0046c`
- **Package**: `com.thingclips.smart.config.optimized`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 6
- **Source**: `smart\config\optimized\RunnableC0046c.java`

**Key Methods**:
  - `run()`

---

### RunnableC0047d [MEDIUM]


- **Full Name**: `com.thingclips.smart.config.optimized.RunnableC0047d`
- **Package**: `com.thingclips.smart.config.optimized`
- **Implements**: `Runnable`
- **Methods**: 1
- **Fields**: 6
- **Source**: `smart\config\optimized\RunnableC0047d.java`

**Key Methods**:
  - `run()`

---

### ThingApForTlsPresenter [MEDIUM]


- **Full Name**: `com.thingclips.smart.config.optimized.ThingApForTlsPresenter`
- **Package**: `com.thingclips.smart.config.optimized`
- **Extends**: `Handler`
- **Implements**: `Runnable`
- **Methods**: 68
- **Fields**: 103
- **Source**: `smart\config\optimized\ThingApForTlsPresenter.java`

**Key Methods**:
  - `AtomicBoolean()`
  - `Handler()`
  - `HandlerC00421()`
  - `handleMessage()`
  - `HandlerC00421()`
  - `handleMessage()`
  - `RunnableC00432()`
  - `addContent()`
  - `run()`
  - `ThingApForTlsPresenter()`
  - *(... and 58 more)*

**Notable Strings**:
  - `",uuid:"`

---

### OptimusManager [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.OptimusManager`
- **Package**: `com.thingclips.smart.home.sdk`
- **Extends**: `AbstractOptimusManager`
- **Implements**: `IOptimus`
- **Methods**: 3
- **Fields**: 0
- **Source**: `smart\home\sdk\OptimusManager.java`

**Key Methods**:
  - `identifier()`
  - `init()`
  - `version()`

---

### IActivator [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.api.IActivator`
- **Package**: `com.thingclips.smart.home.sdk.api`
- **Methods**: 3
- **Fields**: 0
- **Source**: `home\sdk\api\IActivator.java`

**Key Methods**:
  - `newBleActivator()`
  - `newMultiModeActivator()`
  - `newMultiModeParallelActivator()`

---

### IThingGroupModel [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.api.IThingGroupModel`
- **Package**: `com.thingclips.smart.home.sdk.api`
- **Methods**: 9
- **Fields**: 0
- **Source**: `home\sdk\api\IThingGroupModel.java`

**Key Methods**:
  - `createCommonGroup()`
  - `createNewGroup()`
  - `createThreadGroup()`
  - `createZigbeeEmptyGroup()`
  - `getGroupDeviceList()`
  - `getThreadGroupDeviceList()`
  - `getZigbeeGroupDeviceList()`
  - `onDestroy()`
  - `publishZigBeeGroupDps()`

---

### IThingHomeManager [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.api.IThingHomeManager`
- **Package**: `com.thingclips.smart.home.sdk.api`
- **Methods**: 7
- **Fields**: 0
- **Source**: `home\sdk\api\IThingHomeManager.java`

**Key Methods**:
  - `createHome()`
  - `joinHomeByInviteCode()`
  - `onDestroy()`
  - `queryHomeInfo()`
  - `queryHomeList()`
  - `registerThingHomeChangeListener()`
  - `unRegisterThingHomeChangeListener()`

---

### IThingHomeMember [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.api.IThingHomeMember`
- **Package**: `com.thingclips.smart.home.sdk.api`
- **Methods**: 27
- **Fields**: 0
- **Source**: `home\sdk\api\IThingHomeMember.java`

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

### IThingHomeScene [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.api.IThingHomeScene`
- **Package**: `com.thingclips.smart.home.sdk.api`
- **Methods**: 8
- **Fields**: 0
- **Source**: `home\sdk\api\IThingHomeScene.java`

**Key Methods**:
  - `deleteScene()`
  - `deleteSceneWithHomeId()`
  - `disableScene()`
  - `enableScene()`
  - `enableSceneWithTime()`
  - `executeScene()`
  - `modifyScene()`
  - `onDestroy()`

---

### IThingHomeSceneManager [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.api.IThingHomeSceneManager`
- **Package**: `com.thingclips.smart.home.sdk.api`
- **Methods**: 62
- **Fields**: 0
- **Source**: `home\sdk\api\IThingHomeSceneManager.java`

**Key Methods**:
  - `bindLocalScene()`
  - `createDelayTask()`
  - `createDevCondition()`
  - `createDpGroupTask()`
  - `createDpTask()`
  - `createGeoFenceCondition()`
  - `createPushMessage()`
  - `createScene()`
  - `createScene()`
  - `createScene()`
  - *(... and 52 more)*

---

### DeviceBizPropBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.DeviceBizPropBean`
- **Package**: `com.thingclips.smart.home.sdk.bean`
- **Methods**: 18
- **Fields**: 10
- **Source**: `home\sdk\bean\DeviceBizPropBean.java`

**Key Methods**:
  - `equals()`
  - `getBeaconCategory()`
  - `getBeaconKey()`
  - `getBluetoothCapability()`
  - `getDevId()`
  - `getDeviceUpgradeStatus()`
  - `getGwBTSubDevOtaCap()`
  - `getOtaUpgradeStatus()`
  - `hashCode()`
  - `isZigbeeInstallCode()`
  - *(... and 8 more)*

---

### MemberWrapperBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.MemberWrapperBean`
- **Package**: `com.thingclips.smart.home.sdk.bean`
- **Methods**: 27
- **Fields**: 36
- **Source**: `home\sdk\bean\MemberWrapperBean.java`

**Key Methods**:
  - `build()`
  - `MemberWrapperBean()`
  - `setAccount()`
  - `setAdmin()`
  - `setAutoAccept()`
  - `setCountryCode()`
  - `setCustomRoleId()`
  - `setHeadPic()`
  - `setHomeId()`
  - `setInvitationCode()`
  - *(... and 17 more)*

---

### PersonBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.PersonBean`
- **Package**: `com.thingclips.smart.home.sdk.bean`
- **Implements**: `Parcelable`
- **Methods**: 25
- **Fields**: 13
- **Source**: `home\sdk\bean\PersonBean.java`

**Key Methods**:
  - `createFromParcel()`
  - `PersonBean()`
  - `newArray()`
  - `describeContents()`
  - `getGid()`
  - `getHeadPic()`
  - `getId()`
  - `getMemberName()`
  - `getMname()`
  - `getMobile()`
  - *(... and 15 more)*

---

### ProductVerBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.ProductVerBean`
- **Package**: `com.thingclips.smart.home.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 8
- **Fields**: 5
- **Source**: `home\sdk\bean\ProductVerBean.java`

**Key Methods**:
  - `ProductVerBean()`
  - `equals()`
  - `getPid()`
  - `getVer()`
  - `hashCode()`
  - `setPid()`
  - `setVer()`
  - `ProductVerBean()`

---

### RoomAuthBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.RoomAuthBean`
- **Package**: `com.thingclips.smart.home.sdk.bean`
- **Implements**: `Parcelable`
- **Methods**: 17
- **Fields**: 6
- **Source**: `home\sdk\bean\RoomAuthBean.java`

**Key Methods**:
  - `createFromParcel()`
  - `RoomAuthBean()`
  - `newArray()`
  - `RoomAuthBean()`
  - `describeContents()`
  - `getName()`
  - `getRoomId()`
  - `getType()`
  - `isAuth()`
  - `setAuth()`
  - *(... and 7 more)*

---

### RoomBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.RoomBean`
- **Package**: `com.thingclips.smart.home.sdk.bean`
- **Methods**: 16
- **Fields**: 10
- **Source**: `home\sdk\bean\RoomBean.java`

**Key Methods**:
  - `getBackground()`
  - `getDeviceList()`
  - `getDisplayOrder()`
  - `getGroupList()`
  - `getIconUrl()`
  - `getName()`
  - `getRoomId()`
  - `isSel()`
  - `setBackground()`
  - `setDeviceList()`
  - *(... and 6 more)*

---

### ActionBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.ActionBean`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene`
- **Implements**: `Serializable`
- **Methods**: 27
- **Fields**: 15
- **Source**: `sdk\bean\scene\ActionBean.java`

**Key Methods**:
  - `ArrayList()`
  - `ArrayList()`
  - `ActionBean()`
  - `getActDetail()`
  - `getChooseKey()`
  - `getChooseRangeValue()`
  - `getDpId()`
  - `getId()`
  - `getName()`
  - `getOperators()`
  - *(... and 17 more)*

---

### ActRespBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.ActRespBean`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene`
- **Implements**: `Serializable`
- **Methods**: 16
- **Fields**: 8
- **Source**: `sdk\bean\scene\ActRespBean.java`

**Key Methods**:
  - `getActDetail()`
  - `getDpId()`
  - `getDpName()`
  - `getId()`
  - `getName()`
  - `getOperators()`
  - `getValueRangeDisplay()`
  - `getValueRangeJson()`
  - `setActDetail()`
  - `setDpId()`
  - *(... and 6 more)*

---

### ConditionAllBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.ConditionAllBean`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 2
- **Source**: `sdk\bean\scene\ConditionAllBean.java`

**Key Methods**:
  - `getDevConds()`
  - `getEnvConds()`
  - `setDevConds()`
  - `setEnvConds()`

---

### ConditionExtraInfoBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.ConditionExtraInfoBean`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene`
- **Implements**: `Serializable`
- **Methods**: 32
- **Fields**: 51
- **Source**: `sdk\bean\scene\ConditionExtraInfoBean.java`

**Key Methods**:
  - `equals()`
  - `getCalType()`
  - `getCenter()`
  - `getCityName()`
  - `getDelayTime()`
  - `getDpScale()`
  - `getGeotitle()`
  - `getMaxSeconds()`
  - `getMembers()`
  - `getOriginTempUnit()`
  - *(... and 22 more)*

---

### FunctionDataPoint [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.FunctionDataPoint`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene`
- **Implements**: `Serializable`
- **Methods**: 32
- **Fields**: 19
- **Source**: `sdk\bean\scene\FunctionDataPoint.java`

**Key Methods**:
  - `getValue()`
  - `setValue()`
  - `getColorType()`
  - `getDefaultValue()`
  - `getDpCode()`
  - `getDpId()`
  - `getDpName()`
  - `getDpProperty()`
  - `getMode()`
  - `getStepHighDpProperty()`
  - *(... and 22 more)*

---

### FunctionListBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.FunctionListBean`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene`
- **Implements**: `Serializable`
- **Methods**: 14
- **Fields**: 10
- **Source**: `sdk\bean\scene\FunctionListBean.java`

**Key Methods**:
  - `getDataPoints()`
  - `getFunctionCode()`
  - `getFunctionName()`
  - `getFunctionType()`
  - `getId()`
  - `getProductId()`
  - `getStatus()`
  - `setDataPoints()`
  - `setFunctionCode()`
  - `setFunctionName()`
  - *(... and 4 more)*

---

### MCGroup [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.MCGroup`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 2
- **Source**: `sdk\bean\scene\MCGroup.java`

**Key Methods**:
  - `getGroupName()`
  - `getId()`
  - `setGroupName()`
  - `setId()`

---

### PlaceFacadeBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.PlaceFacadeBean`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene`
- **Implements**: `Serializable`
- **Methods**: 12
- **Fields**: 7
- **Source**: `sdk\bean\scene\PlaceFacadeBean.java`

**Key Methods**:
  - `getArea()`
  - `getCity()`
  - `getCityId()`
  - `getPinyin()`
  - `getProvince()`
  - `isChoose()`
  - `setArea()`
  - `setChoose()`
  - `setCity()`
  - `setCityId()`
  - *(... and 2 more)*

---

### PreCondition [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.PreCondition`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene`
- **Implements**: `Serializable`
- **Methods**: 8
- **Fields**: 22
- **Source**: `sdk\bean\scene\PreCondition.java`

**Key Methods**:
  - `equals()`
  - `getCondType()`
  - `getExpr()`
  - `getId()`
  - `hashCode()`
  - `setCondType()`
  - `setExpr()`
  - `setId()`

---

### PreConditionExpr [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.PreConditionExpr`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene`
- **Implements**: `Serializable`
- **Methods**: 16
- **Fields**: 37
- **Source**: `sdk\bean\scene\PreConditionExpr.java`

**Key Methods**:
  - `equals()`
  - `getCityId()`
  - `getCityName()`
  - `getEnd()`
  - `getLoops()`
  - `getStart()`
  - `getTimeInterval()`
  - `getTimeZoneId()`
  - `hashCode()`
  - `setCityId()`
  - *(... and 6 more)*

---

### SceneAppearance [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.SceneAppearance`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene`
- **Implements**: `Serializable`
- **Methods**: 6
- **Fields**: 3
- **Source**: `sdk\bean\scene\SceneAppearance.java`

**Key Methods**:
  - `getCoverColors()`
  - `getCoverIconList()`
  - `getCoverPics()`
  - `setCoverColors()`
  - `setCoverIconList()`
  - `setCoverPics()`

---

### SceneBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.SceneBean`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene`
- **Implements**: `Serializable`
- **Methods**: 60
- **Fields**: 39
- **Source**: `sdk\bean\scene\SceneBean.java`

**Key Methods**:
  - `createSceneBean()`
  - `createSceneBean()`
  - `getActions()`
  - `getArrowIconUrl()`
  - `getBackground()`
  - `getCode()`
  - `getConditions()`
  - `getCoverIcon()`
  - `getDisableTime()`
  - `getDisplayColor()`
  - *(... and 50 more)*

---

### SceneCondition [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.SceneCondition`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene`
- **Implements**: `Serializable`
- **Methods**: 51
- **Fields**: 77
- **Source**: `sdk\bean\scene\SceneCondition.java`

**Key Methods**:
  - `createDevCondition()`
  - `SceneCondition()`
  - `ArrayList()`
  - `createGeoFenceCondition()`
  - `SceneCondition()`
  - `ConditionExtraInfoBean()`
  - `HashMap()`
  - `ArrayList()`
  - `ArrayList()`
  - `createSunRiseSetCondition()`
  - *(... and 41 more)*

---

### SceneLogResBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.SceneLogResBean`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene`
- **Implements**: `Serializable`
- **Methods**: 26
- **Fields**: 16
- **Source**: `sdk\bean\scene\SceneLogResBean.java`

**Key Methods**:
  - `getEventId()`
  - `getExecResult()`
  - `getExecResultMsg()`
  - `getExecTime()`
  - `getFailureCause()`
  - `getFailureCode()`
  - `getOwnerId()`
  - `getRuleId()`
  - `getRuleName()`
  - `getSceneType()`
  - *(... and 16 more)*

---

### SceneTaskGroupDevice [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.SceneTaskGroupDevice`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene`
- **Implements**: `Serializable`
- **Methods**: 6
- **Fields**: 3
- **Source**: `sdk\bean\scene\SceneTaskGroupDevice.java`

**Key Methods**:
  - `getDevices()`
  - `getExts()`
  - `getGoups()`
  - `setDevices()`
  - `setExts()`
  - `setGoups()`

---

### ConditionListBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.condition.ConditionListBean`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene.condition`
- **Implements**: `Serializable`
- **Methods**: 20
- **Fields**: 16
- **Source**: `bean\scene\condition\ConditionListBean.java`

**Key Methods**:
  - `ConditionListBean()`
  - `getEntityName()`
  - `getEntityType()`
  - `getId()`
  - `getName()`
  - `getNewIcon()`
  - `getOperators()`
  - `getProperty()`
  - `getType()`
  - `setEntityName()`
  - *(... and 10 more)*

---

### IProperty [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.condition.property.IProperty`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene.condition.property`
- **Extends**: `Serializable`
- **Methods**: 0
- **Fields**: 0
- **Source**: `scene\condition\property\IProperty.java`

---

### TaskListBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.home.sdk.bean.scene.dev.TaskListBean`
- **Package**: `com.thingclips.smart.home.sdk.bean.scene.dev`
- **Implements**: `Serializable`
- **Methods**: 22
- **Fields**: 13
- **Source**: `bean\scene\dev\TaskListBean.java`

**Key Methods**:
  - `TaskListBean()`
  - `getCondCalExtraInfo()`
  - `getDpId()`
  - `getEntityType()`
  - `getId()`
  - `getMcGroupNames()`
  - `getName()`
  - `getOperators()`
  - `getSchemaBean()`
  - `getTasks()`
  - *(... and 12 more)*

---

### IAppDpParserPlugin [MEDIUM]


- **Full Name**: `com.thingclips.smart.interior.api.IAppDpParserPlugin`
- **Package**: `com.thingclips.smart.interior.api`
- **Methods**: 5
- **Fields**: 0
- **Source**: `smart\interior\api\IAppDpParserPlugin.java`

**Key Methods**:
  - `getParser()`
  - `remove()`
  - `removeAll()`
  - `update()`
  - `update()`

---

### IClearable [MEDIUM]


- **Full Name**: `com.thingclips.smart.interior.api.IClearable`
- **Package**: `com.thingclips.smart.interior.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `smart\interior\api\IClearable.java`

**Key Methods**:
  - `onDestroy()`

---

### IThingBlePlugin [MEDIUM]


- **Full Name**: `com.thingclips.smart.interior.api.IThingBlePlugin`
- **Package**: `com.thingclips.smart.interior.api`
- **Methods**: 9
- **Fields**: 0
- **Source**: `smart\interior\api\IThingBlePlugin.java`

**Key Methods**:
  - `getThingBeaconManager()`
  - `getThingBleAbility()`
  - `getThingBleController()`
  - `getThingBleManager()`
  - `getThingBleOperator()`
  - `getThingInnerScanner()`
  - `getThingLEAudioManager()`
  - `isCloudOffline()`
  - `onDestroy()`

---

### IThingDevicePlugin [MEDIUM]


- **Full Name**: `com.thingclips.smart.interior.api.IThingDevicePlugin`
- **Package**: `com.thingclips.smart.interior.api`
- **Methods**: 37
- **Fields**: 0
- **Source**: `smart\interior\api\IThingDevicePlugin.java`

**Key Methods**:
  - `getBatchExecutionManager()`
  - `getDataInstance()`
  - `getDevListCacheManager()`
  - `getDevModel()`
  - `getDeviceOperate()`
  - `getDpsUpdateManager()`
  - `getEventCenter()`
  - `getLitePresenter()`
  - `getMqttChannelInstance()`
  - `getProductKey()`
  - *(... and 27 more)*

---

### IUserCommonPlugin [MEDIUM]


- **Full Name**: `com.thingclips.smart.interior.api.IUserCommonPlugin`
- **Package**: `com.thingclips.smart.interior.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `smart\interior\api\IUserCommonPlugin.java`

**Key Methods**:
  - `getCommonServices()`
  - `updateTimeZone()`

---

### IUserDomainPlugin [MEDIUM]


- **Full Name**: `com.thingclips.smart.interior.api.IUserDomainPlugin`
- **Package**: `com.thingclips.smart.interior.api`
- **Methods**: 4
- **Fields**: 0
- **Source**: `smart\interior\api\IUserDomainPlugin.java`

**Key Methods**:
  - `queryAllBizDomains()`
  - `queryAllBizDomainsFromCache()`
  - `queryDomainByBizCodeAndKey()`
  - `queryDomainByBizCodeAndKeyFromCache()`

---

### IThingDeviceDataCacheManager [MEDIUM]


- **Full Name**: `com.thingclips.smart.interior.device.IThingDeviceDataCacheManager`
- **Package**: `com.thingclips.smart.interior.device`
- **Methods**: 27
- **Fields**: 0
- **Source**: `smart\interior\device\IThingDeviceDataCacheManager.java`

**Key Methods**:
  - `getAuthPropertyByUUID()`
  - `getAuthPropertyByUUID()`
  - `getDev()`
  - `getDevList()`
  - `getDevice()`
  - `getDevice()`
  - `getDeviceBizPropBeanBatch()`
  - `getDp()`
  - `getDpCodeSchemaMap()`
  - `getDps()`
  - *(... and 17 more)*

---

### IThingDevListCacheManager [MEDIUM]


- **Full Name**: `com.thingclips.smart.interior.device.IThingDevListCacheManager`
- **Package**: `com.thingclips.smart.interior.device`
- **Methods**: 26
- **Fields**: 0
- **Source**: `smart\interior\device\IThingDevListCacheManager.java`

**Key Methods**:
  - `addDev()`
  - `addDevList()`
  - `checkGw()`
  - `devRespWrap()`
  - `getDev()`
  - `getDev()`
  - `getDev()`
  - `getDevByMac()`
  - `getDevByUuid()`
  - `getDevList()`
  - *(... and 16 more)*

---

### IThingGroupCache [MEDIUM]


- **Full Name**: `com.thingclips.smart.interior.device.IThingGroupCache`
- **Package**: `com.thingclips.smart.interior.device`
- **Methods**: 10
- **Fields**: 0
- **Source**: `smart\interior\device\IThingGroupCache.java`

**Key Methods**:
  - `addGroup()`
  - `addGroupList()`
  - `getDeviceBeanList()`
  - `getGroupBean()`
  - `getGroupList()`
  - `getGroupRespBean()`
  - `getGroupRespBeanList()`
  - `onDestroy()`
  - `removeGroup()`
  - `updateGroupCache()`

---

### DpsUpdateInfo [MEDIUM]


- **Full Name**: `com.thingclips.smart.interior.device.bean.DpsUpdateInfo`
- **Package**: `com.thingclips.smart.interior.device.bean`
- **Methods**: 19
- **Fields**: 10
- **Source**: `interior\device\bean\DpsUpdateInfo.java`

**Key Methods**:
  - `TimeSection()`
  - `getBeginTime()`
  - `getEndTime()`
  - `setBeginTime()`
  - `setEndTime()`
  - `TimeSection()`
  - `DpsUpdateInfo()`
  - `getDevId()`
  - `getDps()`
  - `getDpsTime()`
  - *(... and 9 more)*

---

### MQ_201_EnableWifiSuccessBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.interior.device.confusebean.MQ_201_EnableWifiSuccessBean`
- **Package**: `com.thingclips.smart.interior.device.confusebean`
- **Methods**: 2
- **Fields**: 1
- **Source**: `interior\device\confusebean\MQ_201_EnableWifiSuccessBean.java`

**Key Methods**:
  - `getErrorCode()`
  - `setErrorCode()`

---

### MQ_401_SmartEnableUpdate [MEDIUM]


- **Full Name**: `com.thingclips.smart.interior.device.confusebean.MQ_401_SmartEnableUpdate`
- **Package**: `com.thingclips.smart.interior.device.confusebean`
- **Methods**: 4
- **Fields**: 1
- **Source**: `interior\device\confusebean\MQ_401_SmartEnableUpdate.java`

**Key Methods**:
  - `MQ_401_SmartEnableUpdate()`
  - `MQ_401_SmartEnableUpdate()`
  - `getSmartData()`
  - `setSmartData()`

---

### IGwBleConnectStatusListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.interior.hardware.IGwBleConnectStatusListener`
- **Package**: `com.thingclips.smart.interior.hardware`
- **Methods**: 1
- **Fields**: 0
- **Source**: `smart\interior\hardware\IGwBleConnectStatusListener.java`

**Key Methods**:
  - `onConnectStatusChanged()`

---

### IThingLogPlugin [MEDIUM]


- **Full Name**: `com.thingclips.smart.interior.log.IThingLogPlugin`
- **Package**: `com.thingclips.smart.interior.log`
- **Methods**: 9
- **Fields**: 0
- **Source**: `smart\interior\log\IThingLogPlugin.java`

**Key Methods**:
  - `beginEvent()`
  - `endEvent()`
  - `event()`
  - `eventOnDebugTool()`
  - `flush()`
  - `logOnline()`
  - `pushTemporaryEvent()`
  - `temporaryEvent()`
  - `trackEvent()`

---

### CameraMessageBusiness [MEDIUM]


- **Full Name**: `com.thingclips.smart.ipc.messagecenter.business.CameraMessageBusiness`
- **Package**: `com.thingclips.smart.ipc.messagecenter.business`
- **Extends**: `Business`
- **Methods**: 4
- **Fields**: 0
- **Source**: `ipc\messagecenter\business\CameraMessageBusiness.java`

**Key Methods**:
  - `deleteAlarmDetectionMessageList()`
  - `getAlarmDetectionMessageList()`
  - `queryAlarmDetectionClassify()`
  - `queryAlarmDetectionDaysByMonth()`

---

### C0060R [MEDIUM]


- **Full Name**: `com.thingclips.smart.ipc.yuv.monitor.C0060R`
- **Package**: `com.thingclips.smart.ipc.yuv.monitor`
- **Methods**: 3
- **Fields**: 14
- **Source**: `ipc\yuv\monitor\C0060R.java`

**Key Methods**:
  - `attr()`
  - `styleable()`
  - `C0060R()`

---

### YUVMonitorSurfaceView [MEDIUM]


- **Full Name**: `com.thingclips.smart.ipc.yuv.monitor.YUVMonitorSurfaceView`
- **Package**: `com.thingclips.smart.ipc.yuv.monitor`
- **Extends**: `GLSurfaceView`
- **Implements**: `IYUVMonitor, ThingMonitorRenderer.OnRenderCallback`
- **Methods**: 22
- **Fields**: 6
- **Source**: `ipc\yuv\monitor\YUVMonitorSurfaceView.java`

**Key Methods**:
  - `YUVMonitorSurfaceView()`
  - `getConfig()`
  - `getMRotation()`
  - `getMScale()`
  - `initRender()`
  - `ThingMonitorRenderer()`
  - `onDetachedFromWindow()`
  - `onMove()`
  - `onPause()`
  - `onPositioningFrameUpdate()`
  - *(... and 12 more)*

---

### YUVMonitorTextureView [MEDIUM]


- **Full Name**: `com.thingclips.smart.ipc.yuv.monitor.YUVMonitorTextureView`
- **Package**: `com.thingclips.smart.ipc.yuv.monitor`
- **Extends**: `GLESTextureView`
- **Implements**: `IYUVMonitor, ThingMonitorRenderer.OnRenderCallback`
- **Methods**: 22
- **Fields**: 7
- **Source**: `ipc\yuv\monitor\YUVMonitorTextureView.java`

**Key Methods**:
  - `YUVMonitorTextureView()`
  - `getConfig()`
  - `getMRotation()`
  - `getMScale()`
  - `initRender()`
  - `ThingMonitorRenderer()`
  - `onMove()`
  - `onPause()`
  - `onPositioningFrameUpdate()`
  - `onRender()`
  - *(... and 12 more)*

---

### MonitorConfig [MEDIUM]


- **Full Name**: `com.thingclips.smart.ipc.yuv.monitor.api.MonitorConfig`
- **Package**: `com.thingclips.smart.ipc.yuv.monitor.api`
- **Methods**: 8
- **Fields**: 11
- **Source**: `yuv\monitor\api\MonitorConfig.java`

**Key Methods**:
  - `getMaxScaleFactor()`
  - `getMinScaleFactor()`
  - `isScalable()`
  - `isSupportDoubleClick()`
  - `setMaxScaleFactor()`
  - `setMinScaleFactor()`
  - `setScalable()`
  - `setSupportDoubleClick()`

---

### GLProgram [MEDIUM]


- **Full Name**: `com.thingclips.smart.ipc.yuv.monitor.opengl.GLProgram`
- **Package**: `com.thingclips.smart.ipc.yuv.monitor.opengl`
- **Methods**: 8
- **Fields**: 32
- **Source**: `yuv\monitor\opengl\GLProgram.java`

**Key Methods**:
  - `GLProgram()`
  - `buildProgram()`
  - `drawFrame()`
  - `getVerticesT()`
  - `loadProgram()`
  - `RuntimeException()`
  - `RuntimeException()`
  - `drawFrame()`

---

### GLProgram [MEDIUM]


- **Full Name**: `com.thingclips.smart.ipc.yuv.monitor.renderer.GLProgram`
- **Package**: `com.thingclips.smart.ipc.yuv.monitor.renderer`
- **Methods**: 16
- **Fields**: 39
- **Source**: `yuv\monitor\renderer\GLProgram.java`

**Key Methods**:
  - `GLProgram()`
  - `RuntimeException()`
  - `createBuffers()`
  - `setUp()`
  - `buildProgram()`
  - `RuntimeException()`
  - `RuntimeException()`
  - `RuntimeException()`
  - `RuntimeException()`
  - `RuntimeException()`
  - *(... and 6 more)*

---

### YUVAdapter [MEDIUM]


- **Full Name**: `com.thingclips.smart.ipc.yuv.monitor.test.YUVAdapter`
- **Package**: `com.thingclips.smart.ipc.yuv.monitor.test`
- **Methods**: 4
- **Fields**: 7
- **Source**: `yuv\monitor\test\YUVAdapter.java`

**Key Methods**:
  - `YUVAdapter()`
  - `YUVAdapter()`
  - `updateFrameYUVData()`
  - `YuvCroper()`

---

### DoubleClickCheck [MEDIUM]


- **Full Name**: `com.thingclips.smart.ipc.yuv.monitor.utils.DoubleClickCheck`
- **Package**: `com.thingclips.smart.ipc.yuv.monitor.utils`
- **Methods**: 2
- **Fields**: 5
- **Source**: `yuv\monitor\utils\DoubleClickCheck.java`

**Key Methods**:
  - `DoubleClickCheck()`
  - `isValid()`

---

### C0063L [MEDIUM]


- **Full Name**: `com.thingclips.smart.ipc.yuv.monitor.utils.log.C0063L`
- **Package**: `com.thingclips.smart.ipc.yuv.monitor.utils.log`
- **Methods**: 8
- **Fields**: 7
- **Source**: `monitor\utils\log\C0063L.java`

**Key Methods**:
  - `C0063L()`
  - `C0063L()`
  - `m188d()`
  - `m189e()`
  - `m190i()`
  - `setLogger()`
  - `m191v()`
  - `m192w()`

---

### LogLevel [MEDIUM]


- **Full Name**: `com.thingclips.smart.ipc.yuv.monitor.utils.log.LogLevel`
- **Package**: `com.thingclips.smart.ipc.yuv.monitor.utils.log`
- **Methods**: 0
- **Fields**: 0
- **Source**: `monitor\utils\log\LogLevel.java`

---

### ThingAudioFrameInfo [MEDIUM]


- **Full Name**: `com.thingclips.smart.mediaplayer.bean.ThingAudioFrameInfo`
- **Package**: `com.thingclips.smart.mediaplayer.bean`
- **Implements**: `Parcelable`
- **Methods**: 20
- **Fields**: 7
- **Source**: `smart\mediaplayer\bean\ThingAudioFrameInfo.java`

**Key Methods**:
  - `createFromParcel()`
  - `ThingAudioFrameInfo()`
  - `newArray()`
  - `ThingAudioFrameInfo()`
  - `describeContents()`
  - `getBitWidth()`
  - `getChannelNum()`
  - `getDuration()`
  - `getProgress()`
  - `getSampleRate()`
  - *(... and 10 more)*

---

### ThingAudioTrack [MEDIUM]


- **Full Name**: `com.thingclips.smart.mediaplayer.bean.ThingAudioTrack`
- **Package**: `com.thingclips.smart.mediaplayer.bean`
- **Extends**: `Thread`
- **Methods**: 11
- **Fields**: 24
- **Source**: `smart\mediaplayer\bean\ThingAudioTrack.java`

**Key Methods**:
  - `AudioTrackThread()`
  - `joinThread()`
  - `run()`
  - `ThingAudioTrack()`
  - `InitPlayout()`
  - `AudioTrack()`
  - `StartPlayout()`
  - `AudioTrackThread()`
  - `StopPlayout()`
  - `nativeCacheDirectBufferAddress()`
  - *(... and 1 more)*

---

### ThingVideoFrameInfo [MEDIUM]


- **Full Name**: `com.thingclips.smart.mediaplayer.bean.ThingVideoFrameInfo`
- **Package**: `com.thingclips.smart.mediaplayer.bean`
- **Implements**: `Parcelable`
- **Methods**: 29
- **Fields**: 12
- **Source**: `smart\mediaplayer\bean\ThingVideoFrameInfo.java`

**Key Methods**:
  - `createFromParcel()`
  - `ThingVideoFrameInfo()`
  - `newArray()`
  - `ThingVideoFrameInfo()`
  - `describeContents()`
  - `geAngle()`
  - `getDuration()`
  - `getFrameRate()`
  - `getHeight()`
  - `getIsKeyFrame()`
  - *(... and 19 more)*

---

### ThingAudioEncoder [MEDIUM]


- **Full Name**: `com.thingclips.smart.mediaplayer.record.ThingAudioEncoder`
- **Package**: `com.thingclips.smart.mediaplayer.record`
- **Methods**: 21
- **Fields**: 49
- **Source**: `smart\mediaplayer\record\ThingAudioEncoder.java`

**Key Methods**:
  - `getNumber()`
  - `onAddAudioTrack()`
  - `onAudioSample()`
  - `mimeType()`
  - `Settings()`
  - `ThingAudioEncoder()`
  - `createOutputThread()`
  - `Thread()`
  - `run()`
  - `encodeByteBuffer()`
  - *(... and 11 more)*

---

### ThingMediaRecorder [MEDIUM]


- **Full Name**: `com.thingclips.smart.mediaplayer.record.ThingMediaRecorder`
- **Package**: `com.thingclips.smart.mediaplayer.record`
- **Implements**: `ThingVideoEncoder.Callback, ThingAudioEncoder.Callback`
- **Methods**: 23
- **Fields**: 39
- **Source**: `smart\mediaplayer\record\ThingMediaRecorder.java`

**Key Methods**:
  - `Runnable()`
  - `run()`
  - `if()`
  - `MediaTrackData()`
  - `getByteBuf()`
  - `getTrackId()`
  - `getColorFormat()`
  - `getMaxSupportHeight()`
  - `getMaxSupportWidth()`
  - `stopRecoredThread()`
  - *(... and 13 more)*

---

### ThingRingBuffer [MEDIUM]


- **Full Name**: `com.thingclips.smart.mediaplayer.record.ThingRingBuffer`
- **Package**: `com.thingclips.smart.mediaplayer.record`
- **Methods**: 63
- **Fields**: 59
- **Source**: `smart\mediaplayer\record\ThingRingBuffer.java`

**Key Methods**:
  - `borrow()`
  - `ThingRingBuffer()`
  - `advance()`
  - `availableAfter()`
  - `nextOffset()`
  - `overflows()`
  - `nextOffset()`
  - `clear()`
  - `drop()`
  - `overrunPush()`
  - *(... and 53 more)*

---

### ThingVideoEncoder [MEDIUM]


- **Full Name**: `com.thingclips.smart.mediaplayer.record.ThingVideoEncoder`
- **Package**: `com.thingclips.smart.mediaplayer.record`
- **Methods**: 38
- **Fields**: 79
- **Source**: `smart\mediaplayer\record\ThingVideoEncoder.java`

**Key Methods**:
  - `onAddVideoTrack()`
  - `onVideoFrame()`
  - `mimeType()`
  - `Settings()`
  - `getNumber()`
  - `VideoFrame()`
  - `getData()`
  - `getFramerate()`
  - `getHeight()`
  - `getPixelFmt()`
  - *(... and 28 more)*

---

### ILog [MEDIUM]


- **Full Name**: `com.thingclips.smart.mediaplayer.toolkit.api.ILog`
- **Package**: `com.thingclips.smart.mediaplayer.toolkit.api`
- **Methods**: 6
- **Fields**: 0
- **Source**: `mediaplayer\toolkit\api\ILog.java`

**Key Methods**:
  - `mo194d()`
  - `mo195e()`
  - `mo196e()`
  - `mo197i()`
  - `mo198v()`
  - `mo199w()`

---

### LogImpl [MEDIUM]


- **Full Name**: `com.thingclips.smart.mediaplayer.toolkit.impl.LogImpl`
- **Package**: `com.thingclips.smart.mediaplayer.toolkit.impl`
- **Implements**: `ILog`
- **Methods**: 6
- **Fields**: 0
- **Source**: `mediaplayer\toolkit\impl\LogImpl.java`

**Key Methods**:
  - `mo194d()`
  - `mo195e()`
  - `mo197i()`
  - `mo198v()`
  - `mo199w()`
  - `mo196e()`

---

### MMKV [MEDIUM]


- **Full Name**: `com.thingclips.smart.mmkv.MMKV`
- **Package**: `com.thingclips.smart.mmkv`
- **Extends**: `Parcelable>`
- **Implements**: `SharedPreferences, SharedPreferences.Editor`
- **Methods**: 240
- **Fields**: 82
- **Source**: `thingclips\smart\mmkv\MMKV.java`

**Key Methods**:
  - `loadLibrary()`
  - `HashSet()`
  - `MMKV()`
  - `actualSize()`
  - `checkProcessMode()`
  - `MMKV()`
  - `IllegalArgumentException()`
  - `MMKV()`
  - `RuntimeException()`
  - `checkProcessMode()`
  - *(... and 230 more)*

---

### ParcelableMMKV [MEDIUM]


- **Full Name**: `com.thingclips.smart.mmkv.ParcelableMMKV`
- **Package**: `com.thingclips.smart.mmkv`
- **Implements**: `Parcelable`
- **Methods**: 8
- **Fields**: 17
- **Source**: `thingclips\smart\mmkv\ParcelableMMKV.java`

**Key Methods**:
  - `createFromParcel()`
  - `ParcelableMMKV()`
  - `newArray()`
  - `describeContents()`
  - `toMMKV()`
  - `writeToParcel()`
  - `ParcelableMMKV()`
  - `ParcelableMMKV()`

---

### MqttServiceBinder [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqtt.MqttServiceBinder`
- **Package**: `com.thingclips.smart.mqtt`
- **Extends**: `Binder`
- **Methods**: 4
- **Fields**: 2
- **Source**: `thingclips\smart\mqtt\MqttServiceBinder.java`

**Key Methods**:
  - `MqttServiceBinder()`
  - `getActivityToken()`
  - `getService()`
  - `setActivityToken()`

---

### ParcelableMqttMessage [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqtt.bean.ParcelableMqttMessage`
- **Package**: `com.thingclips.smart.mqtt.bean`
- **Extends**: `MqttMessage`
- **Implements**: `Parcelable`
- **Methods**: 9
- **Fields**: 3
- **Source**: `smart\mqtt\bean\ParcelableMqttMessage.java`

**Key Methods**:
  - `bdpdqbp()`
  - `createFromParcel()`
  - `ParcelableMqttMessage()`
  - `newArray()`
  - `ParcelableMqttMessage()`
  - `describeContents()`
  - `getMessageId()`
  - `writeToParcel()`
  - `ParcelableMqttMessage()`

---

### ConnectionFinishedInfo [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.ConnectionFinishedInfo`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Extends**: `Serializable`
- **Methods**: 13
- **Fields**: 2
- **Source**: `smart\mqttclient\mqttv3\ConnectionFinishedInfo.java`

**Key Methods**:
  - `getConnectEnd()`
  - `getConnectStart()`
  - `getMqttConnAckReceived()`
  - `getMqttConnPacketSent()`
  - `getSslEnd()`
  - `getSslStart()`
  - `getTotalTimeMs()`
  - `getConnectionMessage()`
  - `getConnectionSequenceNumber()`
  - `getException()`
  - *(... and 3 more)*

---

### DisconnectedBufferOptions [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.DisconnectedBufferOptions`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Methods**: 9
- **Fields**: 8
- **Source**: `smart\mqttclient\mqttv3\DisconnectedBufferOptions.java`

**Key Methods**:
  - `getBufferSize()`
  - `isBufferEnabled()`
  - `isDeleteOldestMessages()`
  - `isPersistBuffer()`
  - `setBufferEnabled()`
  - `setBufferSize()`
  - `IllegalArgumentException()`
  - `setDeleteOldestMessages()`
  - `setPersistBuffer()`

---

### IMqttActionListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.IMqttActionListener`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Methods**: 2
- **Fields**: 0
- **Source**: `smart\mqttclient\mqttv3\IMqttActionListener.java`

**Key Methods**:
  - `onFailure()`
  - `onSuccess()`

---

### IMqttAsyncClient [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.IMqttAsyncClient`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Extends**: `Closeable`
- **Methods**: 47
- **Fields**: 0
- **Source**: `smart\mqttclient\mqttv3\IMqttAsyncClient.java`

**Key Methods**:
  - `close()`
  - `connect()`
  - `connect()`
  - `connect()`
  - `connect()`
  - `deleteBufferedMessage()`
  - `disconnect()`
  - `disconnect()`
  - `disconnect()`
  - `disconnect()`
  - *(... and 37 more)*

---

### IMqttClient [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.IMqttClient`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Extends**: `Closeable`
- **Methods**: 40
- **Fields**: 0
- **Source**: `smart\mqttclient\mqttv3\IMqttClient.java`

**Key Methods**:
  - `close()`
  - `connect()`
  - `connect()`
  - `connectWithResult()`
  - `disconnect()`
  - `disconnect()`
  - `disconnectForcibly()`
  - `disconnectForcibly()`
  - `disconnectForcibly()`
  - `getClientId()`
  - *(... and 30 more)*

---

### MqttCallback [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.MqttCallback`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Methods**: 3
- **Fields**: 0
- **Source**: `smart\mqttclient\mqttv3\MqttCallback.java`

**Key Methods**:
  - `connectionLost()`
  - `deliveryComplete()`
  - `messageArrived()`

---

### MqttClientPersistence [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.MqttClientPersistence`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Extends**: `Closeable`
- **Methods**: 8
- **Fields**: 0
- **Source**: `smart\mqttclient\mqttv3\MqttClientPersistence.java`

**Key Methods**:
  - `clear()`
  - `close()`
  - `containsKey()`
  - `get()`
  - `keys()`
  - `open()`
  - `put()`
  - `remove()`

---

### MqttMessage [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.MqttMessage`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Methods**: 20
- **Fields**: 6
- **Source**: `smart\mqttclient\mqttv3\MqttMessage.java`

**Key Methods**:
  - `MqttMessage()`
  - `validateQos()`
  - `IllegalArgumentException()`
  - `checkMutable()`
  - `IllegalStateException()`
  - `clearPayload()`
  - `getId()`
  - `getPayload()`
  - `getQos()`
  - `isDuplicate()`
  - *(... and 10 more)*

---

### MqttPersistable [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.MqttPersistable`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Methods**: 6
- **Fields**: 0
- **Source**: `smart\mqttclient\mqttv3\MqttPersistable.java`

**Key Methods**:
  - `getHeaderBytes()`
  - `getHeaderLength()`
  - `getHeaderOffset()`
  - `getPayloadBytes()`
  - `getPayloadLength()`
  - `getPayloadOffset()`

---

### MqttPersistenceException [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.MqttPersistenceException`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Extends**: `MqttException`
- **Methods**: 4
- **Fields**: 2
- **Source**: `smart\mqttclient\mqttv3\MqttPersistenceException.java`

**Key Methods**:
  - `MqttPersistenceException()`
  - `MqttPersistenceException()`
  - `MqttPersistenceException()`
  - `MqttPersistenceException()`

---

### MqttSecurityException [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.MqttSecurityException`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Extends**: `MqttException`
- **Methods**: 3
- **Fields**: 1
- **Source**: `smart\mqttclient\mqttv3\MqttSecurityException.java`

**Key Methods**:
  - `MqttSecurityException()`
  - `MqttSecurityException()`
  - `MqttSecurityException()`

---

### TimerPingSender [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.TimerPingSender`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3`
- **Extends**: `TimerTask`
- **Implements**: `MqttPingSender`
- **Methods**: 8
- **Fields**: 9
- **Source**: `smart\mqttclient\mqttv3\TimerPingSender.java`

**Key Methods**:
  - `PingTask()`
  - `run()`
  - `init()`
  - `IllegalArgumentException()`
  - `schedule()`
  - `start()`
  - `Timer()`
  - `stop()`

---

### ClientState [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.ClientState`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Methods**: 83
- **Fields**: 139
- **Source**: `mqttclient\mqttv3\internal\ClientState.java`

**Key Methods**:
  - `ClientState()`
  - `Object()`
  - `Object()`
  - `Object()`
  - `Hashtable()`
  - `Vector()`
  - `Hashtable()`
  - `Hashtable()`
  - `Hashtable()`
  - `Hashtable()`
  - *(... and 73 more)*

---

### CommsTokenStore [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.CommsTokenStore`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Methods**: 21
- **Fields**: 35
- **Source**: `mqttclient\mqttv3\internal\CommsTokenStore.java`

**Key Methods**:
  - `CommsTokenStore()`
  - `Hashtable()`
  - `clear()`
  - `count()`
  - `getOutstandingDelTokens()`
  - `Vector()`
  - `getOutstandingTokens()`
  - `Vector()`
  - `getToken()`
  - `open()`
  - *(... and 11 more)*

---

### ConnectActionListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.ConnectActionListener`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Implements**: `IMqttActionListener`
- **Methods**: 8
- **Fields**: 15
- **Source**: `mqttclient\mqttv3\internal\ConnectActionListener.java`

**Key Methods**:
  - `ConnectActionListener()`
  - `getConnectionFinishedInfo()`
  - `connect()`
  - `MqttToken()`
  - `onFailure()`
  - `MqttException()`
  - `onSuccess()`
  - `setMqttCallbackExtended()`

---

### DisconnectedMessageBuffer [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.DisconnectedMessageBuffer`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Implements**: `Runnable`
- **Methods**: 12
- **Fields**: 14
- **Source**: `mqttclient\mqttv3\internal\DisconnectedMessageBuffer.java`

**Key Methods**:
  - `Object()`
  - `DisconnectedMessageBuffer()`
  - `deleteMessage()`
  - `getMessage()`
  - `getMessageCount()`
  - `isPersistBuffer()`
  - `putMessage()`
  - `BufferedMessage()`
  - `MqttException()`
  - `run()`
  - *(... and 2 more)*

---

### ExceptionHelper [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.ExceptionHelper`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Methods**: 8
- **Fields**: 2
- **Source**: `mqttclient\mqttv3\internal\ExceptionHelper.java`

**Key Methods**:
  - `ExceptionHelper()`
  - `createMqttException()`
  - `MqttException()`
  - `MqttSecurityException()`
  - `isClassAvailable()`
  - `createMqttException()`
  - `MqttSecurityException()`
  - `MqttException()`

---

### FileLock [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.FileLock`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Methods**: 5
- **Fields**: 8
- **Source**: `mqttclient\mqttv3\internal\FileLock.java`

**Key Methods**:
  - `FileLock()`
  - `File()`
  - `RandomAccessFile()`
  - `Exception()`
  - `release()`

---

### MessageCatalog [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.MessageCatalog`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Methods**: 3
- **Fields**: 1
- **Source**: `mqttclient\mqttv3\internal\MessageCatalog.java`

**Key Methods**:
  - `getMessage()`
  - `if()`
  - `getLocalizedMessage()`

---

### MqttPersistentData [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.MqttPersistentData`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Implements**: `MqttPersistable`
- **Methods**: 8
- **Fields**: 8
- **Source**: `mqttclient\mqttv3\internal\MqttPersistentData.java`

**Key Methods**:
  - `MqttPersistentData()`
  - `getHeaderBytes()`
  - `getHeaderLength()`
  - `getHeaderOffset()`
  - `getKey()`
  - `getPayloadBytes()`
  - `getPayloadLength()`
  - `getPayloadOffset()`

---

### SSLNetworkModule [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.SSLNetworkModule`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Extends**: `TCPNetworkModule`
- **Methods**: 14
- **Fields**: 15
- **Source**: `mqttclient\mqttv3\internal\SSLNetworkModule.java`

**Key Methods**:
  - `SSLNetworkModule()`
  - `getConnectionFinishedInfo()`
  - `getConnectionSequenceNumber()`
  - `getEnabledCiphers()`
  - `getSSLHostnameVerifier()`
  - `getServerURI()`
  - `isHttpsHostnameVerificationEnabled()`
  - `setEnabledCiphers()`
  - `setHttpsHostnameVerificationEnabled()`
  - `setSSLHostnameVerifier()`
  - *(... and 4 more)*

---

### SSLNetworkModuleFactory [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.SSLNetworkModuleFactory`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Implements**: `NetworkModuleFactory`
- **Methods**: 7
- **Fields**: 12
- **Source**: `mqttclient\mqttv3\internal\SSLNetworkModuleFactory.java`

**Key Methods**:
  - `createNetworkModule()`
  - `IllegalArgumentException()`
  - `SSLSocketFactoryFactory()`
  - `SSLNetworkModule()`
  - `getSupportedUriSchemes()`
  - `validateURI()`
  - `IllegalArgumentException()`

---

### TCPNetworkModuleFactory [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.TCPNetworkModuleFactory`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Implements**: `NetworkModuleFactory`
- **Methods**: 7
- **Fields**: 8
- **Source**: `mqttclient\mqttv3\internal\TCPNetworkModuleFactory.java`

**Key Methods**:
  - `createNetworkModule()`
  - `IllegalArgumentException()`
  - `if()`
  - `TCPNetworkModule()`
  - `getSupportedUriSchemes()`
  - `validateURI()`
  - `IllegalArgumentException()`

---

### Token [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.Token`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal`
- **Methods**: 46
- **Fields**: 37
- **Source**: `mqttclient\mqttv3\internal\Token.java`

**Key Methods**:
  - `Object()`
  - `Object()`
  - `Token()`
  - `checkResult()`
  - `getException()`
  - `getActionCallback()`
  - `getClient()`
  - `getException()`
  - `getGrantedQos()`
  - `getKey()`
  - *(... and 36 more)*

---

### SSLSocketFactoryFactory [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.security.SSLSocketFactoryFactory`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.security`
- **Methods**: 63
- **Fields**: 137
- **Source**: `mqttv3\internal\security\SSLSocketFactoryFactory.java`

**Key Methods**:
  - `SSLSocketFactoryFactory()`
  - `Hashtable()`
  - `checkPropertyKeys()`
  - `IllegalArgumentException()`
  - `convertPassword()`
  - `deObfuscate()`
  - `toChar()`
  - `getProperty()`
  - `getPropertyFromConfig()`
  - `getSSLContext()`
  - *(... and 53 more)*

---

### MqttConnack [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttConnack`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `MqttAck`
- **Methods**: 8
- **Fields**: 5
- **Source**: `mqttv3\internal\wire\MqttConnack.java`

**Key Methods**:
  - `MqttConnack()`
  - `DataInputStream()`
  - `getKey()`
  - `getReturnCode()`
  - `getSessionPresent()`
  - `getVariableHeader()`
  - `isMessageIdRequired()`
  - `toString()`

---

### MqttConnect [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttConnect`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `MqttWireMessage`
- **Methods**: 18
- **Fields**: 21
- **Source**: `mqttv3\internal\wire\MqttConnect.java`

**Key Methods**:
  - `MqttConnect()`
  - `DataInputStream()`
  - `getKey()`
  - `getMessageInfo()`
  - `getPayload()`
  - `ByteArrayOutputStream()`
  - `DataOutputStream()`
  - `String()`
  - `MqttException()`
  - `getVariableHeader()`
  - *(... and 8 more)*

---

### MqttDisconnect [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttDisconnect`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `MqttWireMessage`
- **Methods**: 6
- **Fields**: 3
- **Source**: `mqttv3\internal\wire\MqttDisconnect.java`

**Key Methods**:
  - `MqttDisconnect()`
  - `getKey()`
  - `getMessageInfo()`
  - `getVariableHeader()`
  - `isMessageIdRequired()`
  - `MqttDisconnect()`

---

### MqttInputStream [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttInputStream`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `InputStream`
- **Methods**: 10
- **Fields**: 22
- **Source**: `mqttv3\internal\wire\MqttInputStream.java`

**Key Methods**:
  - `ByteArrayOutputStream()`
  - `MqttInputStream()`
  - `DataInputStream()`
  - `readFully()`
  - `IndexOutOfBoundsException()`
  - `EOFException()`
  - `available()`
  - `close()`
  - `read()`
  - `readMqttWireMessage()`

---

### MqttOutputStream [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttOutputStream`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `OutputStream`
- **Methods**: 8
- **Fields**: 8
- **Source**: `mqttv3\internal\wire\MqttOutputStream.java`

**Key Methods**:
  - `MqttOutputStream()`
  - `BufferedOutputStream()`
  - `close()`
  - `flush()`
  - `write()`
  - `write()`
  - `write()`
  - `write()`

---

### MqttPersistableWireMessage [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttPersistableWireMessage`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `MqttWireMessage`
- **Implements**: `MqttPersistable`
- **Methods**: 12
- **Fields**: 3
- **Source**: `mqttv3\internal\wire\MqttPersistableWireMessage.java`

**Key Methods**:
  - `MqttPersistableWireMessage()`
  - `getHeaderBytes()`
  - `getHeader()`
  - `MqttPersistenceException()`
  - `getHeaderLength()`
  - `getHeaderBytes()`
  - `getHeaderOffset()`
  - `getPayloadBytes()`
  - `getPayload()`
  - `MqttPersistenceException()`
  - *(... and 2 more)*

---

### MqttPingReq [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttPingReq`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `MqttWireMessage`
- **Methods**: 6
- **Fields**: 2
- **Source**: `mqttv3\internal\wire\MqttPingReq.java`

**Key Methods**:
  - `MqttPingReq()`
  - `getKey()`
  - `getMessageInfo()`
  - `getVariableHeader()`
  - `isMessageIdRequired()`
  - `MqttPingReq()`

---

### MqttPingResp [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttPingResp`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `MqttAck`
- **Methods**: 4
- **Fields**: 2
- **Source**: `mqttv3\internal\wire\MqttPingResp.java`

**Key Methods**:
  - `MqttPingResp()`
  - `getKey()`
  - `getVariableHeader()`
  - `isMessageIdRequired()`

---

### MqttPubAck [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttPubAck`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `MqttAck`
- **Methods**: 6
- **Fields**: 1
- **Source**: `mqttv3\internal\wire\MqttPubAck.java`

**Key Methods**:
  - `MqttPubAck()`
  - `DataInputStream()`
  - `getVariableHeader()`
  - `encodeMessageId()`
  - `MqttPubAck()`
  - `MqttPubAck()`

---

### MqttPubComp [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttPubComp`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `MqttAck`
- **Methods**: 6
- **Fields**: 1
- **Source**: `mqttv3\internal\wire\MqttPubComp.java`

**Key Methods**:
  - `MqttPubComp()`
  - `DataInputStream()`
  - `getVariableHeader()`
  - `encodeMessageId()`
  - `MqttPubComp()`
  - `MqttPubComp()`

---

### MqttPublish [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttPublish`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `MqttPersistableWireMessage`
- **Methods**: 22
- **Fields**: 20
- **Source**: `mqttv3\internal\wire\MqttPublish.java`

**Key Methods**:
  - `MqttPublish()`
  - `encodePayload()`
  - `getMessage()`
  - `getMessageInfo()`
  - `getPayload()`
  - `getPayloadLength()`
  - `getPayload()`
  - `getTopicName()`
  - `getVariableHeader()`
  - `ByteArrayOutputStream()`
  - *(... and 12 more)*

---

### MqttPubRec [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttPubRec`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `MqttAck`
- **Methods**: 5
- **Fields**: 1
- **Source**: `mqttv3\internal\wire\MqttPubRec.java`

**Key Methods**:
  - `MqttPubRec()`
  - `DataInputStream()`
  - `getVariableHeader()`
  - `encodeMessageId()`
  - `MqttPubRec()`

---

### MqttPubRel [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttPubRel`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `MqttPersistableWireMessage`
- **Methods**: 7
- **Fields**: 1
- **Source**: `mqttv3\internal\wire\MqttPubRel.java`

**Key Methods**:
  - `MqttPubRel()`
  - `getMessageInfo()`
  - `getVariableHeader()`
  - `encodeMessageId()`
  - `toString()`
  - `MqttPubRel()`
  - `DataInputStream()`

---

### MqttSuback [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttSuback`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `MqttAck`
- **Methods**: 6
- **Fields**: 4
- **Source**: `mqttv3\internal\wire\MqttSuback.java`

**Key Methods**:
  - `MqttSuback()`
  - `DataInputStream()`
  - `getGrantedQos()`
  - `getVariableHeader()`
  - `toString()`
  - `StringBuffer()`

---

### MqttSubscribe [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttSubscribe`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `MqttWireMessage`
- **Methods**: 17
- **Fields**: 16
- **Source**: `mqttv3\internal\wire\MqttSubscribe.java`

**Key Methods**:
  - `MqttSubscribe()`
  - `DataInputStream()`
  - `getMessageInfo()`
  - `getPayload()`
  - `ByteArrayOutputStream()`
  - `DataOutputStream()`
  - `MqttException()`
  - `getVariableHeader()`
  - `ByteArrayOutputStream()`
  - `DataOutputStream()`
  - *(... and 7 more)*

---

### MqttUnsubAck [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttUnsubAck`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `MqttAck`
- **Methods**: 3
- **Fields**: 1
- **Source**: `mqttv3\internal\wire\MqttUnsubAck.java`

**Key Methods**:
  - `MqttUnsubAck()`
  - `DataInputStream()`
  - `getVariableHeader()`

---

### MqttUnsubscribe [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttUnsubscribe`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Extends**: `MqttWireMessage`
- **Methods**: 15
- **Fields**: 10
- **Source**: `mqttv3\internal\wire\MqttUnsubscribe.java`

**Key Methods**:
  - `MqttUnsubscribe()`
  - `getMessageInfo()`
  - `getPayload()`
  - `ByteArrayOutputStream()`
  - `DataOutputStream()`
  - `MqttException()`
  - `getVariableHeader()`
  - `ByteArrayOutputStream()`
  - `DataOutputStream()`
  - `MqttException()`
  - *(... and 5 more)*

---

### MqttWireMessage [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire.MqttWireMessage`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.internal.wire`
- **Methods**: 58
- **Fields**: 60
- **Source**: `mqttv3\internal\wire\MqttWireMessage.java`

**Key Methods**:
  - `MqttWireMessage()`
  - `createWireMessage()`
  - `createWireMessage()`
  - `decodeUTF8()`
  - `String()`
  - `MqttException()`
  - `encodeMBI()`
  - `ByteArrayOutputStream()`
  - `encodeUTF8()`
  - `MqttException()`
  - *(... and 48 more)*

---

### JSR47Logger [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.logging.JSR47Logger`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.logging`
- **Implements**: `Logger`
- **Methods**: 19
- **Fields**: 15
- **Source**: `mqttclient\mqttv3\logging\JSR47Logger.java`

**Key Methods**:
  - `JSR47Logger()`
  - `logToJsr47()`
  - `LogRecord()`
  - `SimpleLogFormatter()`
  - `if()`
  - `mapaulLevel()`
  - `fine()`
  - `finer()`
  - `info()`
  - `isLoggable()`
  - *(... and 9 more)*

---

### Logger [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.logging.Logger`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.logging`
- **Methods**: 10
- **Fields**: 1
- **Source**: `mqttclient\mqttv3\logging\Logger.java`

**Key Methods**:
  - `fine()`
  - `fine()`
  - `fine()`
  - `finer()`
  - `isLoggable()`
  - `log()`
  - `setResourceName()`
  - `severe()`
  - `trace()`
  - `warning()`

---

### PahoLogUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.logging.PahoLogUtil`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.logging`
- **Methods**: 11
- **Fields**: 3
- **Source**: `mqttclient\mqttv3\logging\PahoLogUtil.java`

**Key Methods**:
  - `m200d()`
  - `m202e()`
  - `getLogStatus()`
  - `m204i()`
  - `mqtt()`
  - `setLogSwitcher()`
  - `m205v()`
  - `m206w()`
  - `m201d()`
  - `m203e()`
  - *(... and 1 more)*

---

### SimpleLogFormatter [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.logging.SimpleLogFormatter`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.logging`
- **Extends**: `Formatter`
- **Methods**: 6
- **Fields**: 9
- **Source**: `mqttclient\mqttv3\logging\SimpleLogFormatter.java`

**Key Methods**:
  - `left()`
  - `StringBuffer()`
  - `format()`
  - `StringBuilder()`
  - `StringWriter()`
  - `PrintWriter()`

---

### MemoryPersistence [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.persist.MemoryPersistence`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.persist`
- **Implements**: `MqttClientPersistence`
- **Methods**: 10
- **Fields**: 2
- **Source**: `mqttclient\mqttv3\persist\MemoryPersistence.java`

**Key Methods**:
  - `checkIsOpen()`
  - `MqttPersistenceException()`
  - `clear()`
  - `close()`
  - `containsKey()`
  - `get()`
  - `keys()`
  - `open()`
  - `put()`
  - `remove()`

---

### MqttDefaultFilePersistence [MEDIUM]


- **Full Name**: `com.thingclips.smart.mqttclient.mqttv3.persist.MqttDefaultFilePersistence`
- **Package**: `com.thingclips.smart.mqttclient.mqttv3.persist`
- **Implements**: `MqttClientPersistence`
- **Methods**: 37
- **Fields**: 29
- **Source**: `mqttclient\mqttv3\persist\MqttDefaultFilePersistence.java`

**Key Methods**:
  - `MqttDefaultFilePersistence()`
  - `checkIsOpen()`
  - `MqttPersistenceException()`
  - `getFilenameFilter()`
  - `PersistanceFileNameFilter()`
  - `getFiles()`
  - `MqttPersistenceException()`
  - `isSafeChar()`
  - `restoreBackups()`
  - `MqttPersistenceException()`
  - *(... and 27 more)*

---

### ThingOptimusService [MEDIUM]


- **Full Name**: `com.thingclips.smart.optimus.annotation.ThingOptimusService`
- **Package**: `com.thingclips.smart.optimus.annotation`
- **Methods**: 0
- **Fields**: 0
- **Source**: `smart\optimus\annotation\ThingOptimusService.java`

---

### ThingOptimusProvider [MEDIUM]


- **Full Name**: `com.thingclips.smart.optimus.sdk.ThingOptimusProvider`
- **Package**: `com.thingclips.smart.optimus.sdk`
- **Extends**: `ContentProvider`
- **Methods**: 6
- **Fields**: 8
- **Source**: `smart\optimus\sdk\ThingOptimusProvider.java`

**Key Methods**:
  - `delete()`
  - `getType()`
  - `insert()`
  - `onCreate()`
  - `query()`
  - `update()`

---

### BuildConfig [MEDIUM]


- **Full Name**: `com.thingclips.smart.ota.service.api.BuildConfig`
- **Package**: `com.thingclips.smart.ota.service.api`
- **Methods**: 0
- **Fields**: 3
- **Source**: `ota\service\api\BuildConfig.java`

---

### IDeviceDpParser [MEDIUM]


- **Full Name**: `com.thingclips.smart.p002dp.parser.api.IDeviceDpParser`
- **Package**: `com.thingclips.smart.p002dp.parser.api`
- **Methods**: 4
- **Fields**: 0
- **Source**: `p002dp\parser\api\IDeviceDpParser.java`

**Key Methods**:
  - `getAllDp()`
  - `getDisplayDp()`
  - `getOperableDp()`
  - `getSwitchDp()`

---

### IDpParser [MEDIUM]


- **Full Name**: `com.thingclips.smart.p002dp.parser.api.IDpParser`
- **Package**: `com.thingclips.smart.p002dp.parser.api`
- **Methods**: 10
- **Fields**: 0
- **Source**: `p002dp\parser\api\IDpParser.java`

**Key Methods**:
  - `getCommands()`
  - `getDisplayStatus()`
  - `getDisplayStatusForQuickOp()`
  - `getDisplayTitle()`
  - `getDpId()`
  - `getDpShowType()`
  - `getIconFont()`
  - `getSchema()`
  - `getType()`
  - `getValue()`

---

### ThingCameraErrCode [LOW]


- **Full Name**: `com.thingclips.smart.camera.api.ThingCameraErrCode`
- **Package**: `com.thingclips.smart.camera.api`
- **Methods**: 0
- **Fields**: 37
- **Source**: `smart\camera\api\ThingCameraErrCode.java`

---

## Package Structure

### Package Hierarchy

```
com/ (812 classes)
      ├── camera/ (3 classes)
        ├── annotation/ (5 classes)
        ├── api/ (7 classes)
        ├── base/ (1 classes)
          ├── api/ (2 classes)
          ├── impl/ (2 classes)
          ├── log/ (4 classes)
        ├── bean/ (4 classes)
        ├── callback/ (4 classes)
          ├── bean/ (5 classes)
  └── ... and 113 more packages

p003x/ (1 classes)
├── p003x/ (1 classes)

```

### Top 20 Packages by Class Count

| Package | Classes |
| --- | --- |
| com.thingclips.smart.camera.middleware | 87 |
| com.thingclips.smart.interior.device.confusebean | 37 |
| com.thingclips.smart.home.sdk.bean | 36 |
| com.thingclips.smart.home.sdk.api | 32 |
| com.thingclips.smart.interior.hardware | 29 |
| com.thingclips.smart.mqttclient.mqttv3 | 27 |
| com.thingclips.smart.mqttclient.mqttv3.internal | 27 |
| com.thingclips.smart.interior.api | 25 |
| com.thingclips.smart.mqttclient.mqttv3.internal.wire | 23 |
| com.thingclips.smart.config | 22 |
| com.thingclips.smart.home.sdk.bean.scene | 22 |
| com.thingclips.smart.interior.event | 22 |
| com.thingclips.smart.interior.device | 17 |
| com.thingclips.smart.camera.middleware.p2p | 16 |
| com.thingclips.smart.camera.camerasdk.thingplayer.callback | 15 |
| com.thingclips.smart.home.sdk.builder | 14 |
| com.thingclips.smart.home.sdk.callback | 14 |
| com.thingclips.smart.camera.utils.chaos | 12 |
| com.thingclips.smart.camera.ipccamerasdk.cloud | 11 |
| com.thingclips.smart.interior.device.bean | 10 |

## String Constants & UUIDs

*No UUIDs found in this DEX file.*

## BLE Write Operations

*No BLE write operations found in this DEX file.*

## Command Sequences

*No command sequences found in this DEX file.*

## Method Index

### Write/Send Methods

- `sendAudioTalkData()` in `ThingCameraInterface`
- `startSendVideoTalkData()` in `ThingCameraInterface`
- `stopSendVideoTalkData()` in `ThingCameraInterface`
- `writeToParcel()` in `ThingCameraAudioFrame`
- `writeToParcel()` in `ThingCameraVideoFrame`
- `writeToParcel()` in `ThingAudioFrameInfo`
- `writeToParcel()` in `ThingVideoFrameInfo`
- `sendAPMLog()` in `StateServiceUtil`
- `sendCameraLog()` in `StateServiceUtil`
- `sendConnectFullLinkLog()` in `StateServiceUtil`
- `sendFullLinkLog()` in `StateServiceUtil`
- `sendFullLinkStartLog()` in `StateServiceUtil`
- `sendIPCExtraDataLog()` in `StateServiceUtil`
- `sendIPCSDKVisionLog()` in `StateServiceUtil`
- `sendLog()` in `StateServiceUtil`
- *(... and 82 more)*

### Callback/Event Methods

- `onAudioFrameRecved()` in `ThingCameraListener`
- `onAudioRecordReceived()` in `ThingCameraListener`
- `onEventInfoReceived()` in `ThingCameraListener`
- `onLocalVideoFrameRecved()` in `ThingCameraListener`
- `onSessionStatusChanged()` in `ThingCameraListener`
- `onVideoFrameRecved()` in `ThingCameraListener`
- `onImageAvailable()` in `ThingVideoCaptureDevice`
- `onDisconnected()` in `ThingVideoCaptureDevice`
- `onError()` in `ThingVideoCaptureDevice`
- `onOpened()` in `ThingVideoCaptureDevice`
- `onConfigureFailed()` in `ThingVideoCaptureDevice`
- `onConfigured()` in `ThingVideoCaptureDevice`
- `onVideoCaptureFrameRecv()` in `ThingVideoCaptureDevice`
- `onVideoEncodedStreamRecv()` in `ThingVideoEncoderImpl`
- `onFinished()` in `ThingFinishableCallback`
- *(... and 512 more)*

## Full Class List

<details>
<summary>Click to expand full class list (813 classes)</summary>

Total: 813 classes

### com.thingclips.smart.camera

- `com.thingclips.smart.camera.ThingCamera`
- `com.thingclips.smart.camera.ThingCameraEngine`
- `com.thingclips.smart.camera.ThingCameraSDKManager`

### com.thingclips.smart.camera.annotation

- `com.thingclips.smart.camera.annotation.AudioEffect`
- `com.thingclips.smart.camera.annotation.CloudPlaySpeed`
- `com.thingclips.smart.camera.annotation.MuteStatus`
- `com.thingclips.smart.camera.annotation.PlayBackSpeed`
- `com.thingclips.smart.camera.annotation.SDCardState`

### com.thingclips.smart.camera.api

- `com.thingclips.smart.camera.api.ThingCameraConstants`
- `com.thingclips.smart.camera.api.ThingCameraEngineInterface`
- `com.thingclips.smart.camera.api.ThingCameraErrCode`
- `com.thingclips.smart.camera.api.ThingCameraInterface`
- `com.thingclips.smart.camera.api.ThingCameraListener`
- `com.thingclips.smart.camera.api.ThingNvrListener`
- `com.thingclips.smart.camera.api.ThingNvrSDKJni`

### com.thingclips.smart.camera.base

- `com.thingclips.smart.camera.base.ThingIPCBase`

### com.thingclips.smart.camera.base.api

- `com.thingclips.smart.camera.base.api.IBuilder`
- `com.thingclips.smart.camera.base.api.ILog`

### com.thingclips.smart.camera.base.impl

- `com.thingclips.smart.camera.base.impl.CameraBaseBuilder`
- `com.thingclips.smart.camera.base.impl.DefaultLog`

### com.thingclips.smart.camera.base.log

- `com.thingclips.smart.camera.base.log.ThingCameraAction`
- `com.thingclips.smart.camera.base.log.ThingCameraCode`
- `com.thingclips.smart.camera.base.log.ThingCameraL`
- `com.thingclips.smart.camera.base.log.ThingCameraModule`

### com.thingclips.smart.camera.bean

- `com.thingclips.smart.camera.bean.ThingCameraAudioFrame`
- `com.thingclips.smart.camera.bean.ThingCameraVideoFrame`
- `com.thingclips.smart.camera.bean.ThingVideoCaptureDevice`
- `com.thingclips.smart.camera.bean.ThingVideoEncoderImpl`

### com.thingclips.smart.camera.callback

- `com.thingclips.smart.camera.callback.ThingBaseCallback`
- `com.thingclips.smart.camera.callback.ThingFileDownloadCallback`
- `com.thingclips.smart.camera.callback.ThingFinishableCallback`
- `com.thingclips.smart.camera.callback.ThingProgressiveCallback`

### com.thingclips.smart.camera.camerasdk.bean

- `com.thingclips.smart.camera.camerasdk.bean.ThingAudioFrameInfo`
- `com.thingclips.smart.camera.camerasdk.bean.ThingIOTCameraInfo`
- `com.thingclips.smart.camera.camerasdk.bean.ThingVideoFrameInfo`
- `com.thingclips.smart.camera.camerasdk.bean.ThingVideoSEIInfo`
- `com.thingclips.smart.camera.camerasdk.bean.ThingVideoSplitInfo`

### com.thingclips.smart.camera.camerasdk.thingplayer.callback

- `com.thingclips.smart.camera.camerasdk.thingplayer.callback.AbsConnectCallBack`
- `com.thingclips.smart.camera.camerasdk.thingplayer.callback.AbsP2pCameraListener`
- `com.thingclips.smart.camera.camerasdk.thingplayer.callback.FileDownLoadProgressCallBack`
- `com.thingclips.smart.camera.camerasdk.thingplayer.callback.FileDownloadFinishCallBack`
- `com.thingclips.smart.camera.camerasdk.thingplayer.callback.IRegistorIOTCListener`
- `com.thingclips.smart.camera.camerasdk.thingplayer.callback.IRegistorTalkListener`
- `com.thingclips.smart.camera.camerasdk.thingplayer.callback.ISpeakerEchoProcessor`
- `com.thingclips.smart.camera.camerasdk.thingplayer.callback.OnCameraGestureListener`
- `com.thingclips.smart.camera.camerasdk.thingplayer.callback.OnDragLocationCallback`
- `com.thingclips.smart.camera.camerasdk.thingplayer.callback.OnP2PCameraListener`
- `com.thingclips.smart.camera.camerasdk.thingplayer.callback.OnRenderDirectionCallback`
- `com.thingclips.smart.camera.camerasdk.thingplayer.callback.OnRenderZoomListener`
- `com.thingclips.smart.camera.camerasdk.thingplayer.callback.OperationCallBack`
- `com.thingclips.smart.camera.camerasdk.thingplayer.callback.OperationDelegateCallBack`
- `com.thingclips.smart.camera.camerasdk.thingplayer.callback.ProgressCallBack`

### com.thingclips.smart.camera.chaos.middleware

- `com.thingclips.smart.camera.chaos.middleware.Constants`
- `com.thingclips.smart.camera.chaos.middleware.StateServiceUtil`

### com.thingclips.smart.camera.ffmpeg

- `com.thingclips.smart.camera.ffmpeg.C0002R`
- `com.thingclips.smart.camera.ffmpeg.FFmpegManager`
- `com.thingclips.smart.camera.ffmpeg.bdpdqbp`
- `com.thingclips.smart.camera.ffmpeg.bppdpdq`
- `com.thingclips.smart.camera.ffmpeg.pdqppqb`

### com.thingclips.smart.camera.ffmpeg.toolkit.api

- `com.thingclips.smart.camera.ffmpeg.toolkit.api.ILibLoader`
- `com.thingclips.smart.camera.ffmpeg.toolkit.api.ILog`

### com.thingclips.smart.camera.ipccamerasdk

- `com.thingclips.smart.camera.ipccamerasdk.C0003R`
- `com.thingclips.smart.camera.ipccamerasdk.C0004a`
- `com.thingclips.smart.camera.ipccamerasdk.IPCThingP2PCamera`
- `com.thingclips.smart.camera.ipccamerasdk.IPCThingStationP2PCamera`

### com.thingclips.smart.camera.ipccamerasdk.bean

- `com.thingclips.smart.camera.ipccamerasdk.bean.AudioParams`
- `com.thingclips.smart.camera.ipccamerasdk.bean.CameraInfoBean`
- `com.thingclips.smart.camera.ipccamerasdk.bean.CloudFrameInfoBean`
- `com.thingclips.smart.camera.ipccamerasdk.bean.ConfigCameraBean`
- `com.thingclips.smart.camera.ipccamerasdk.bean.MonthDays`

### com.thingclips.smart.camera.ipccamerasdk.business

- `com.thingclips.smart.camera.ipccamerasdk.business.CameraBusiness`
- `com.thingclips.smart.camera.ipccamerasdk.business.ICameraBusiness`

### com.thingclips.smart.camera.ipccamerasdk.cloud

- `com.thingclips.smart.camera.ipccamerasdk.cloud.CloudBusiness`
- `com.thingclips.smart.camera.ipccamerasdk.cloud.IThingCloudCamera`
- `com.thingclips.smart.camera.ipccamerasdk.cloud.RunnableC0006a`
- `com.thingclips.smart.camera.ipccamerasdk.cloud.RunnableC0007b`
- `com.thingclips.smart.camera.ipccamerasdk.cloud.RunnableC0008c`
- `com.thingclips.smart.camera.ipccamerasdk.cloud.RunnableC0009d`
- `com.thingclips.smart.camera.ipccamerasdk.cloud.ThingCloudCamera`
- `com.thingclips.smart.camera.ipccamerasdk.cloud.bdpdqbp`
- `com.thingclips.smart.camera.ipccamerasdk.cloud.bppdpdq`
- `com.thingclips.smart.camera.ipccamerasdk.cloud.pdqppqb`
- `com.thingclips.smart.camera.ipccamerasdk.cloud.qddqppb`

### com.thingclips.smart.camera.ipccamerasdk.http

- `com.thingclips.smart.camera.ipccamerasdk.http.IHttpProxy`
- `com.thingclips.smart.camera.ipccamerasdk.http.IHttpProxyResultCallback`

### com.thingclips.smart.camera.ipccamerasdk.monitor

- `com.thingclips.smart.camera.ipccamerasdk.monitor.AbsMonitorViewProxy`
- `com.thingclips.smart.camera.ipccamerasdk.monitor.IMonitorView`
- `com.thingclips.smart.camera.ipccamerasdk.monitor.Monitor`
- `com.thingclips.smart.camera.ipccamerasdk.monitor.MonitorClickCallback`

### com.thingclips.smart.camera.ipccamerasdk.msgvideo

- `com.thingclips.smart.camera.ipccamerasdk.msgvideo.IThingCloudVideo`

### com.thingclips.smart.camera.ipccamerasdk.nvr

- `com.thingclips.smart.camera.ipccamerasdk.nvr.ThingNvrSDKImpl`

### com.thingclips.smart.camera.ipccamerasdk.p000dp

- `com.thingclips.smart.camera.ipccamerasdk.p000dp.DpHelper`
- `com.thingclips.smart.camera.ipccamerasdk.p000dp.DpStaticHelper`
- `com.thingclips.smart.camera.ipccamerasdk.p000dp.bdpdqbp`

### com.thingclips.smart.camera.ipccamerasdk.p2p

- `com.thingclips.smart.camera.ipccamerasdk.p2p.AbsTutkCameraP2P`
- `com.thingclips.smart.camera.ipccamerasdk.p2p.TagBean`

### com.thingclips.smart.camera.ipccamerasdk.utils

- `com.thingclips.smart.camera.ipccamerasdk.utils.CameraConstant`
- `com.thingclips.smart.camera.ipccamerasdk.utils.P2PConstant`

### com.thingclips.smart.camera.ipccamerasdk.virtual

- `com.thingclips.smart.camera.ipccamerasdk.virtual.ThingVirtualCamera`

### com.thingclips.smart.camera.middleware

- `com.thingclips.smart.camera.middleware.bbbdppp`
- `com.thingclips.smart.camera.middleware.bbppbbd`
- `com.thingclips.smart.camera.middleware.bbpqdqb`
- `com.thingclips.smart.camera.middleware.bdbbqbd`
- `com.thingclips.smart.camera.middleware.bdbdqdp`
- `com.thingclips.smart.camera.middleware.bddbqbq`
- `com.thingclips.smart.camera.middleware.bddqqbb`
- `com.thingclips.smart.camera.middleware.bdpdqbp`
- `com.thingclips.smart.camera.middleware.bdqbdpp`
- `com.thingclips.smart.camera.middleware.bdqqbqd`
- `com.thingclips.smart.camera.middleware.bdqqqbp`
- `com.thingclips.smart.camera.middleware.bdqqqpq`
- `com.thingclips.smart.camera.middleware.bpbbqdb`
- `com.thingclips.smart.camera.middleware.bpbqpqd`
- `com.thingclips.smart.camera.middleware.bppdpdq`
- `com.thingclips.smart.camera.middleware.bpqqdpq`
- `com.thingclips.smart.camera.middleware.bqbdbqb`
- `com.thingclips.smart.camera.middleware.bqbdpqd`
- `com.thingclips.smart.camera.middleware.bqbppdq`
- `com.thingclips.smart.camera.middleware.bqdbdbd`
- `com.thingclips.smart.camera.middleware.bqpqpqb`
- `com.thingclips.smart.camera.middleware.bqqppqq`
- `com.thingclips.smart.camera.middleware.dbbpbbb`
- `com.thingclips.smart.camera.middleware.dbpdpbp`
- `com.thingclips.smart.camera.middleware.dbppbbp`
- `com.thingclips.smart.camera.middleware.dbqqppp`
- `com.thingclips.smart.camera.middleware.ddbbppb`
- `com.thingclips.smart.camera.middleware.ddbdpqb`
- `com.thingclips.smart.camera.middleware.ddbdqbd`
- `com.thingclips.smart.camera.middleware.dddbppd`
- `com.thingclips.smart.camera.middleware.dddddqd`
- `com.thingclips.smart.camera.middleware.dddpppb`
- `com.thingclips.smart.camera.middleware.ddqdbbd`
- `com.thingclips.smart.camera.middleware.ddqqbbq`
- `com.thingclips.smart.camera.middleware.dpdbqdp`
- `com.thingclips.smart.camera.middleware.dpdqppp`
- `com.thingclips.smart.camera.middleware.dppdpbd`
- `com.thingclips.smart.camera.middleware.dqbpdbq`
- `com.thingclips.smart.camera.middleware.dqdbbqp`
- `com.thingclips.smart.camera.middleware.dqddqdp`
- `com.thingclips.smart.camera.middleware.dqdpbbd`
- `com.thingclips.smart.camera.middleware.dqqbdqb`
- `com.thingclips.smart.camera.middleware.pbbppqb`
- `com.thingclips.smart.camera.middleware.pbddddb`
- `com.thingclips.smart.camera.middleware.pbpdbqp`
- `com.thingclips.smart.camera.middleware.pbpdpdp`
- `com.thingclips.smart.camera.middleware.pbpqqdp`
- `com.thingclips.smart.camera.middleware.pbqpqdq`
- `com.thingclips.smart.camera.middleware.pdbbqdp`
- `com.thingclips.smart.camera.middleware.pdqdqbd`
- `com.thingclips.smart.camera.middleware.pdqppqb`
- `com.thingclips.smart.camera.middleware.ppbdppp`
- `com.thingclips.smart.camera.middleware.ppdpppq`
- `com.thingclips.smart.camera.middleware.pppbppp`
- `com.thingclips.smart.camera.middleware.pqdbppq`
- `com.thingclips.smart.camera.middleware.pqdppqd`
- `com.thingclips.smart.camera.middleware.pqdqqbd`
- `com.thingclips.smart.camera.middleware.pqpbdqq`
- `com.thingclips.smart.camera.middleware.pqpbpqd`
- `com.thingclips.smart.camera.middleware.pqqpqpq`
- `com.thingclips.smart.camera.middleware.pqqqddq`
- `com.thingclips.smart.camera.middleware.qbbdpbq`
- `com.thingclips.smart.camera.middleware.qbdqpqq`
- `com.thingclips.smart.camera.middleware.qbpppdb`
- `com.thingclips.smart.camera.middleware.qbqddpp`
- `com.thingclips.smart.camera.middleware.qbqppdb`
- `com.thingclips.smart.camera.middleware.qbqqdqq`
- `com.thingclips.smart.camera.middleware.qdbpqqq`
- `com.thingclips.smart.camera.middleware.qdddbpp`
- `com.thingclips.smart.camera.middleware.qddqppb`
- `com.thingclips.smart.camera.middleware.qdpppbq`
- `com.thingclips.smart.camera.middleware.qpbdppq`
- `com.thingclips.smart.camera.middleware.qpbpqpq`
- `com.thingclips.smart.camera.middleware.qppddqq`
- `com.thingclips.smart.camera.middleware.qpppdqb`
- `com.thingclips.smart.camera.middleware.qpqbbpp`
- `com.thingclips.smart.camera.middleware.qpqbppd`
- `com.thingclips.smart.camera.middleware.qpqddqd`
- `com.thingclips.smart.camera.middleware.qqbbddb`
- `com.thingclips.smart.camera.middleware.qqdbbpp`
- `com.thingclips.smart.camera.middleware.qqddbpb`
- `com.thingclips.smart.camera.middleware.qqdqqpd`
- `com.thingclips.smart.camera.middleware.qqpbpdq`
- `com.thingclips.smart.camera.middleware.qqpddqd`
- `com.thingclips.smart.camera.middleware.qqpdpbp`
- `com.thingclips.smart.camera.middleware.qqpppdp`
- `com.thingclips.smart.camera.middleware.qqqpdpb`

### com.thingclips.smart.camera.middleware.cloud

- `com.thingclips.smart.camera.middleware.cloud.CameraCloudSDK`
- `com.thingclips.smart.camera.middleware.cloud.ICloudCacheManagerCallback`

### com.thingclips.smart.camera.middleware.cloud.bean

- `com.thingclips.smart.camera.middleware.cloud.bean.AIDetectConfigBean`
- `com.thingclips.smart.camera.middleware.cloud.bean.AIDetectEventBean`
- `com.thingclips.smart.camera.middleware.cloud.bean.AIEventBean`
- `com.thingclips.smart.camera.middleware.cloud.bean.AITimePieceBean`
- `com.thingclips.smart.camera.middleware.cloud.bean.CloudDayBean`
- `com.thingclips.smart.camera.middleware.cloud.bean.CloudUrlBean`
- `com.thingclips.smart.camera.middleware.cloud.bean.CloudUrlsBean`
- `com.thingclips.smart.camera.middleware.cloud.bean.TimePieceBean`
- `com.thingclips.smart.camera.middleware.cloud.bean.TimeRangeBean`

### com.thingclips.smart.camera.middleware.nvr

- `com.thingclips.smart.camera.middleware.nvr.NvrDeviceIndex`
- `com.thingclips.smart.camera.middleware.nvr.NvrP2PManager`

### com.thingclips.smart.camera.middleware.p2p

- `com.thingclips.smart.camera.middleware.p2p.CameraStrategy`
- `com.thingclips.smart.camera.middleware.p2p.ICameraConfig`
- `com.thingclips.smart.camera.middleware.p2p.IThingSmartCameraP2P`
- `com.thingclips.smart.camera.middleware.p2p.IThingSmartNvrP2P`
- `com.thingclips.smart.camera.middleware.p2p.ThingSmartCameraP2P`
- `com.thingclips.smart.camera.middleware.p2p.ThingSmartCameraP2PFactory`
- `com.thingclips.smart.camera.middleware.p2p.ThingSmartCameraP2PSync`
- `com.thingclips.smart.camera.middleware.p2p.ThingSmartNvrP2P`
- `com.thingclips.smart.camera.middleware.p2p.ThingSmartNvrSubCameraP2P`
- `com.thingclips.smart.camera.middleware.p2p.bdpdqbp`
- `com.thingclips.smart.camera.middleware.p2p.bppdpdq`
- `com.thingclips.smart.camera.middleware.p2p.pbbppqb`
- `com.thingclips.smart.camera.middleware.p2p.pdqppqb`
- `com.thingclips.smart.camera.middleware.p2p.pppbppp`
- `com.thingclips.smart.camera.middleware.p2p.qddqppb`
- `com.thingclips.smart.camera.middleware.p2p.qpppdqb`

### com.thingclips.smart.camera.middleware.service

- `com.thingclips.smart.camera.middleware.service.ThingIPCCount`
- `com.thingclips.smart.camera.middleware.service.ThingIPCPlugin`

### com.thingclips.smart.camera.middleware.utils

- `com.thingclips.smart.camera.middleware.utils.EncryptImageUtil`
- `com.thingclips.smart.camera.middleware.utils.ImageEncryptionUtil`

### com.thingclips.smart.camera.middleware.widget

- `com.thingclips.smart.camera.middleware.widget.AbsVideoViewCallback`
- `com.thingclips.smart.camera.middleware.widget.C0013b`
- `com.thingclips.smart.camera.middleware.widget.CameraPTZLocationView`
- `com.thingclips.smart.camera.middleware.widget.PositioningDragView`
- `com.thingclips.smart.camera.middleware.widget.ThingCameraView`
- `com.thingclips.smart.camera.middleware.widget.ThingMultiCameraView`

### com.thingclips.smart.camera.nativeapi

- `com.thingclips.smart.camera.nativeapi.ThingCameraEngineNative`
- `com.thingclips.smart.camera.nativeapi.ThingCameraNative`

### com.thingclips.smart.camera.nvrsdk

- `com.thingclips.smart.camera.nvrsdk.INvrP2P`

### com.thingclips.smart.camera.p001v2

- `com.thingclips.smart.camera.p001v2.bdpdqbp`
- `com.thingclips.smart.camera.p001v2.bppdpdq`
- `com.thingclips.smart.camera.p001v2.pdqppqb`
- `com.thingclips.smart.camera.p001v2.pppbppp`
- `com.thingclips.smart.camera.p001v2.qddqppb`

### com.thingclips.smart.camera.record

- `com.thingclips.smart.camera.record.ThingAudioEncoder`
- `com.thingclips.smart.camera.record.ThingMediaRecorder`
- `com.thingclips.smart.camera.record.ThingRingBuffer`
- `com.thingclips.smart.camera.record.ThingVideoEncoder`

### com.thingclips.smart.camera.sdk

- `com.thingclips.smart.camera.sdk.C0017R`

### com.thingclips.smart.camera.toolkit.api

- `com.thingclips.smart.camera.toolkit.api.ILibLoader`
- `com.thingclips.smart.camera.toolkit.api.ILog`
- `com.thingclips.smart.camera.toolkit.api.IStatEvent`

### com.thingclips.smart.camera.utils

- `com.thingclips.smart.camera.utils.MediaScannerUtils`

### com.thingclips.smart.camera.utils.chaos

- `com.thingclips.smart.camera.utils.chaos.BitmapUtils`
- `com.thingclips.smart.camera.utils.chaos.C0020L`
- `com.thingclips.smart.camera.utils.chaos.CRC32`
- `com.thingclips.smart.camera.utils.chaos.DensityUtil`
- `com.thingclips.smart.camera.utils.chaos.HexUtil`
- `com.thingclips.smart.camera.utils.chaos.IntToButeArray`
- `com.thingclips.smart.camera.utils.chaos.JsonUtil`
- `com.thingclips.smart.camera.utils.chaos.MD5Utils`
- `com.thingclips.smart.camera.utils.chaos.SDKSharePreferencesUtil`
- `com.thingclips.smart.camera.utils.chaos.SHA256Utils`
- `com.thingclips.smart.camera.utils.chaos.SdkAppUtils`
- `com.thingclips.smart.camera.utils.chaos.TimeZoneUtils`

### com.thingclips.smart.camera.utils.chaos.thread

- `com.thingclips.smart.camera.utils.chaos.thread.CameraExecutor`
- `com.thingclips.smart.camera.utils.chaos.thread.IPCThreadFactory`
- `com.thingclips.smart.camera.utils.chaos.thread.UPThreadPoolManager`

### com.thingclips.smart.common

- `com.thingclips.smart.common.BuildConfig`

### com.thingclips.smart.components.annotation

- `com.thingclips.smart.components.annotation.ThingComponentsService`

### com.thingclips.smart.config

- `com.thingclips.smart.config.BuildConfig`
- `com.thingclips.smart.config.C0041e`
- `com.thingclips.smart.config.HardwareConfig`
- `com.thingclips.smart.config.IThingAPConfig`
- `com.thingclips.smart.config.IThingAPDirectlyConfig`
- `com.thingclips.smart.config.IThingEZConfig`
- `com.thingclips.smart.config.IThingOptimizedApConfig`
- `com.thingclips.smart.config.IThingWiredConfig`
- `com.thingclips.smart.config.RunnableC0037a`
- `com.thingclips.smart.config.RunnableC0038b`
- `com.thingclips.smart.config.RunnableC0039c`
- `com.thingclips.smart.config.RunnableC0040d`
- `com.thingclips.smart.config.ThingAPConfig`
- `com.thingclips.smart.config.ThingApDirectlyConfig`
- `com.thingclips.smart.config.ThingApDirectlyReduceConfig`
- `com.thingclips.smart.config.ThingApSLConfig`
- `com.thingclips.smart.config.ThingBroadConfig`
- `com.thingclips.smart.config.ThingBroadConnectConfig`
- `com.thingclips.smart.config.ThingConfig`
- `com.thingclips.smart.config.ThingEZConfig`
- `com.thingclips.smart.config.ThingOptimizedConfig`
- `com.thingclips.smart.config.ThingWiredConfig`

### com.thingclips.smart.config.bean

- `com.thingclips.smart.config.bean.APConfigBeanUDP`
- `com.thingclips.smart.config.bean.APConfigBeanUDP4G`
- `com.thingclips.smart.config.bean.ApCode`
- `com.thingclips.smart.config.bean.ApQueryWifiBean`
- `com.thingclips.smart.config.bean.ApResultStateBean`
- `com.thingclips.smart.config.bean.ApResultWifiBean`
- `com.thingclips.smart.config.bean.ApTcpBean`
- `com.thingclips.smart.config.bean.Hgw2Bean`
- `com.thingclips.smart.config.bean.ParamsBean`

### com.thingclips.smart.config.constant

- `com.thingclips.smart.config.constant.ApCapabilityConstant`
- `com.thingclips.smart.config.constant.ApOptimizationCapability`

### com.thingclips.smart.config.helper

- `com.thingclips.smart.config.helper.TlsConnectHelper`

### com.thingclips.smart.config.optimized

- `com.thingclips.smart.config.optimized.RunnableC0044a`
- `com.thingclips.smart.config.optimized.RunnableC0045b`
- `com.thingclips.smart.config.optimized.RunnableC0046c`
- `com.thingclips.smart.config.optimized.RunnableC0047d`
- `com.thingclips.smart.config.optimized.ThingApForTlsPresenter`

### com.thingclips.smart.device.bean

- `com.thingclips.smart.device.bean.DeviceUpgradeBean`
- `com.thingclips.smart.device.bean.FirmwareUpgradeInfoBean`
- `com.thingclips.smart.device.bean.ThingDevUpgradeStatusBean`

### com.thingclips.smart.device.core.sdk

- `com.thingclips.smart.device.core.sdk.BuildConfig`
- `com.thingclips.smart.device.core.sdk.C0048R`

### com.thingclips.smart.geofence

- `com.thingclips.smart.geofence.C0051R`

### com.thingclips.smart.home.sdk

- `com.thingclips.smart.home.sdk.BuildConfig`
- `com.thingclips.smart.home.sdk.C0052R`
- `com.thingclips.smart.home.sdk.IOptimus`
- `com.thingclips.smart.home.sdk.OptimusManager`
- `com.thingclips.smart.home.sdk.ThingHomeSdk`

### com.thingclips.smart.home.sdk.anntation

- `com.thingclips.smart.home.sdk.anntation.HomeStatus`
- `com.thingclips.smart.home.sdk.anntation.MemberRole`
- `com.thingclips.smart.home.sdk.anntation.MemberStatus`
- `com.thingclips.smart.home.sdk.anntation.PanelType`
- `com.thingclips.smart.home.sdk.anntation.RoleResourceType`

### com.thingclips.smart.home.sdk.api

- `com.thingclips.smart.home.sdk.api.IActivator`
- `com.thingclips.smart.home.sdk.api.IDevModel`
- `com.thingclips.smart.home.sdk.api.IGwSearchListener`
- `com.thingclips.smart.home.sdk.api.IHomeCacheManager`
- `com.thingclips.smart.home.sdk.api.IHomePatchCacheManager`
- `com.thingclips.smart.home.sdk.api.IThingDeviceActivator`
- `com.thingclips.smart.home.sdk.api.IThingGroupModel`
- `com.thingclips.smart.home.sdk.api.IThingGwActivator`
- `com.thingclips.smart.home.sdk.api.IThingGwSearcher`
- `com.thingclips.smart.home.sdk.api.IThingHome`
- `com.thingclips.smart.home.sdk.api.IThingHomeChangeListener`
- `com.thingclips.smart.home.sdk.api.IThingHomeDataManager`
- `com.thingclips.smart.home.sdk.api.IThingHomeDeviceShare`
- `com.thingclips.smart.home.sdk.api.IThingHomeDeviceStatusListener`
- `com.thingclips.smart.home.sdk.api.IThingHomeManager`
- `com.thingclips.smart.home.sdk.api.IThingHomeMember`
- `com.thingclips.smart.home.sdk.api.IThingHomePatch`
- `com.thingclips.smart.home.sdk.api.IThingHomeRelationUpdateListener`
- `com.thingclips.smart.home.sdk.api.IThingHomeRoomInfoChangeExListener`
- `com.thingclips.smart.home.sdk.api.IThingHomeRoomInfoChangeListener`
- `com.thingclips.smart.home.sdk.api.IThingHomeScene`
- `com.thingclips.smart.home.sdk.api.IThingHomeSceneManager`
- `com.thingclips.smart.home.sdk.api.IThingHomeSpeech`
- `com.thingclips.smart.home.sdk.api.IThingHomeStatusListener`
- `com.thingclips.smart.home.sdk.api.IThingLightningActivator`
- `com.thingclips.smart.home.sdk.api.IThingLightningSearchListener`
- `com.thingclips.smart.home.sdk.api.IThingLightningSearcher`
- `com.thingclips.smart.home.sdk.api.IThingRoom`
- `com.thingclips.smart.home.sdk.api.IThingServer`
- `com.thingclips.smart.home.sdk.api.IThingZigBeeConfigLocalSceneCallback`
- `com.thingclips.smart.home.sdk.api.IThingZigBeeLocalScene`
- `com.thingclips.smart.home.sdk.api.IWarningMsgListener`

### com.thingclips.smart.home.sdk.api.config

- `com.thingclips.smart.home.sdk.api.config.IApConnectListener`
- `com.thingclips.smart.home.sdk.api.config.IBaseConnectListener`
- `com.thingclips.smart.home.sdk.api.config.IConfig`
- `com.thingclips.smart.home.sdk.api.config.IConnectListener`
- `com.thingclips.smart.home.sdk.api.config.IGwConfigListener`
- `com.thingclips.smart.home.sdk.api.config.IOptimizedApConnectListener`
- `com.thingclips.smart.home.sdk.api.config.IOptimizedConfig`

### com.thingclips.smart.home.sdk.bean

- `com.thingclips.smart.home.sdk.bean.ActiveDmDeviceBean`
- `com.thingclips.smart.home.sdk.bean.ApHandlerBean`
- `com.thingclips.smart.home.sdk.bean.ConfigProductInfoBean`
- `com.thingclips.smart.home.sdk.bean.CustomRoleBean`
- `com.thingclips.smart.home.sdk.bean.DashBoardBean`
- `com.thingclips.smart.home.sdk.bean.DeviceAndGroupInHomeBean`
- `com.thingclips.smart.home.sdk.bean.DeviceAndGroupInRoomBean`
- `com.thingclips.smart.home.sdk.bean.DeviceBizPropBean`
- `com.thingclips.smart.home.sdk.bean.DeviceLogBean`
- `com.thingclips.smart.home.sdk.bean.DeviceShareBean`
- `com.thingclips.smart.home.sdk.bean.EnvBean`
- `com.thingclips.smart.home.sdk.bean.ExtendedConfig`
- `com.thingclips.smart.home.sdk.bean.HomeBean`
- `com.thingclips.smart.home.sdk.bean.LightningSearchBean`
- `com.thingclips.smart.home.sdk.bean.MemberBean`
- `com.thingclips.smart.home.sdk.bean.MemberWrapperBean`
- `com.thingclips.smart.home.sdk.bean.MessageHasNew`
- `com.thingclips.smart.home.sdk.bean.ParamsHandlerBean`
- `com.thingclips.smart.home.sdk.bean.PersonBean`
- `com.thingclips.smart.home.sdk.bean.ProductRefBean`
- `com.thingclips.smart.home.sdk.bean.ProductVerBean`
- `com.thingclips.smart.home.sdk.bean.RoomAuthBean`
- `com.thingclips.smart.home.sdk.bean.RoomBean`
- `com.thingclips.smart.home.sdk.bean.ShareInfoFromDevBean`
- `com.thingclips.smart.home.sdk.bean.ShareReceivedUserDetailBean`
- `com.thingclips.smart.home.sdk.bean.ShareSentUserDetailBean`
- `com.thingclips.smart.home.sdk.bean.SharedUserInfoBean`
- `com.thingclips.smart.home.sdk.bean.SharerInfoBean`
- `com.thingclips.smart.home.sdk.bean.SpeechGuideBean`
- `com.thingclips.smart.home.sdk.bean.SpeechPhraseBean`
- `com.thingclips.smart.home.sdk.bean.TransferDataBean`
- `com.thingclips.smart.home.sdk.bean.UniversalBean`
- `com.thingclips.smart.home.sdk.bean.VoiceCommandBean`
- `com.thingclips.smart.home.sdk.bean.WarnMessageBean`
- `com.thingclips.smart.home.sdk.bean.WeatherBean`
- `com.thingclips.smart.home.sdk.bean.WiFiInfoBean`

### com.thingclips.smart.home.sdk.bean.scene

- `com.thingclips.smart.home.sdk.bean.scene.ActRespBean`
- `com.thingclips.smart.home.sdk.bean.scene.ActionBean`
- `com.thingclips.smart.home.sdk.bean.scene.ConditionActionBean`
- `com.thingclips.smart.home.sdk.bean.scene.ConditionAllBean`
- `com.thingclips.smart.home.sdk.bean.scene.ConditionExtraInfoBean`
- `com.thingclips.smart.home.sdk.bean.scene.ConditionRespBean`
- `com.thingclips.smart.home.sdk.bean.scene.FunctionDataPoint`
- `com.thingclips.smart.home.sdk.bean.scene.FunctionListBean`
- `com.thingclips.smart.home.sdk.bean.scene.LocalSceneBean`
- `com.thingclips.smart.home.sdk.bean.scene.MCGroup`
- `com.thingclips.smart.home.sdk.bean.scene.PlaceFacadeBean`
- `com.thingclips.smart.home.sdk.bean.scene.PreCondition`
- `com.thingclips.smart.home.sdk.bean.scene.PreConditionExpr`
- `com.thingclips.smart.home.sdk.bean.scene.SceneAppearance`
- `com.thingclips.smart.home.sdk.bean.scene.SceneAuthBean`
- `com.thingclips.smart.home.sdk.bean.scene.SceneBean`
- `com.thingclips.smart.home.sdk.bean.scene.SceneCondition`
- `com.thingclips.smart.home.sdk.bean.scene.SceneIdBean`
- `com.thingclips.smart.home.sdk.bean.scene.SceneLogDetailBean`
- `com.thingclips.smart.home.sdk.bean.scene.SceneLogResBean`
- `com.thingclips.smart.home.sdk.bean.scene.SceneTask`
- `com.thingclips.smart.home.sdk.bean.scene.SceneTaskGroupDevice`

### com.thingclips.smart.home.sdk.bean.scene.condition

- `com.thingclips.smart.home.sdk.bean.scene.condition.ConditionListBean`

### com.thingclips.smart.home.sdk.bean.scene.condition.property

- `com.thingclips.smart.home.sdk.bean.scene.condition.property.BoolProperty`
- `com.thingclips.smart.home.sdk.bean.scene.condition.property.EnumProperty`
- `com.thingclips.smart.home.sdk.bean.scene.condition.property.IProperty`
- `com.thingclips.smart.home.sdk.bean.scene.condition.property.TimerProperty`
- `com.thingclips.smart.home.sdk.bean.scene.condition.property.ValueProperty`

### com.thingclips.smart.home.sdk.bean.scene.condition.rule

- `com.thingclips.smart.home.sdk.bean.scene.condition.rule.BoolRule`
- `com.thingclips.smart.home.sdk.bean.scene.condition.rule.EnumRule`
- `com.thingclips.smart.home.sdk.bean.scene.condition.rule.Rule`
- `com.thingclips.smart.home.sdk.bean.scene.condition.rule.SunSetRiseRule`
- `com.thingclips.smart.home.sdk.bean.scene.condition.rule.TimerRule`
- `com.thingclips.smart.home.sdk.bean.scene.condition.rule.ValueRule`

### com.thingclips.smart.home.sdk.bean.scene.dev

- `com.thingclips.smart.home.sdk.bean.scene.dev.TaskListBean`

### com.thingclips.smart.home.sdk.builder

- `com.thingclips.smart.home.sdk.builder.APSLActivatorBuilder`
- `com.thingclips.smart.home.sdk.builder.ActivatorBuilder`
- `com.thingclips.smart.home.sdk.builder.GroupCreateBuilder`
- `com.thingclips.smart.home.sdk.builder.ThingApActivatorBuilder`
- `com.thingclips.smart.home.sdk.builder.ThingAutoConfigActivatorBuilder`
- `com.thingclips.smart.home.sdk.builder.ThingBroadbandActivatorBuilder`
- `com.thingclips.smart.home.sdk.builder.ThingBroadbandConfigBuilder`
- `com.thingclips.smart.home.sdk.builder.ThingCameraActivatorBuilder`
- `com.thingclips.smart.home.sdk.builder.ThingDirectlyConnectedActivatorBuilder`
- `com.thingclips.smart.home.sdk.builder.ThingDirectlyDeviceActivatorBuilder`
- `com.thingclips.smart.home.sdk.builder.ThingGwActivatorBuilder`
- `com.thingclips.smart.home.sdk.builder.ThingGwSubDevActivatorBuilder`
- `com.thingclips.smart.home.sdk.builder.ThingLightningDevActivatorBuilder`
- `com.thingclips.smart.home.sdk.builder.ThingQRCodeActivatorBuilder`

### com.thingclips.smart.home.sdk.callback

- `com.thingclips.smart.home.sdk.callback.IGetHomeWetherCallBack`
- `com.thingclips.smart.home.sdk.callback.IIGetHomeWetherSketchCallBack`
- `com.thingclips.smart.home.sdk.callback.IThingDeviceUpgradeStatusCallback`
- `com.thingclips.smart.home.sdk.callback.IThingDeviceUpgradeStatusExtCallback`
- `com.thingclips.smart.home.sdk.callback.IThingGetHomeListCallback`
- `com.thingclips.smart.home.sdk.callback.IThingGetMemberListCallback`
- `com.thingclips.smart.home.sdk.callback.IThingGetRoomListCallback`
- `com.thingclips.smart.home.sdk.callback.IThingHomeResultCallback`
- `com.thingclips.smart.home.sdk.callback.IThingMemberResultCallback`
- `com.thingclips.smart.home.sdk.callback.IThingResultCallback`
- `com.thingclips.smart.home.sdk.callback.IThingRoomResultCallback`
- `com.thingclips.smart.home.sdk.callback.IThingSingleTransfer`
- `com.thingclips.smart.home.sdk.callback.IThingTransferCallback`
- `com.thingclips.smart.home.sdk.callback.IThingVoiceTransfer`

### com.thingclips.smart.home.sdk.utils

- `com.thingclips.smart.home.sdk.utils.SchemaMapper`

### com.thingclips.smart.imagepipeleine_okhttp3

- `com.thingclips.smart.imagepipeleine_okhttp3.BuildConfig`
- `com.thingclips.smart.imagepipeleine_okhttp3.C0056R`

### com.thingclips.smart.interior.api

- `com.thingclips.smart.interior.api.IAppDpParserPlugin`
- `com.thingclips.smart.interior.api.IClearable`
- `com.thingclips.smart.interior.api.IThingBlePlugin`
- `com.thingclips.smart.interior.api.IThingBlueMeshPlugin`
- `com.thingclips.smart.interior.api.IThingCameraPlugin`
- `com.thingclips.smart.interior.api.IThingDeviceActivatorPlugin`
- `com.thingclips.smart.interior.api.IThingDevicePlugin`
- `com.thingclips.smart.interior.api.IThingDeviceSharePlugin`
- `com.thingclips.smart.interior.api.IThingGeoFenceOperatePlugin`
- `com.thingclips.smart.interior.api.IThingGeoFencePlugin`
- `com.thingclips.smart.interior.api.IThingGroupPlugin`
- `com.thingclips.smart.interior.api.IThingHardwarePlugin`
- `com.thingclips.smart.interior.api.IThingHomePlugin`
- `com.thingclips.smart.interior.api.IThingMqttPlugin`
- `com.thingclips.smart.interior.api.IThingPersonalCenterPlugin`
- `com.thingclips.smart.interior.api.IThingScenePlugin`
- `com.thingclips.smart.interior.api.IThingSweeperPlugin`
- `com.thingclips.smart.interior.api.IThingTimerPlugin`
- `com.thingclips.smart.interior.api.IThingUserListenerPlugin`
- `com.thingclips.smart.interior.api.IThingUserPlugin`
- `com.thingclips.smart.interior.api.IUserCommonPlugin`
- `com.thingclips.smart.interior.api.IUserDomainPlugin`
- `com.thingclips.smart.interior.api.IUserGeneralBusiness`
- `com.thingclips.smart.interior.api.IUserHighwayPlugin`
- `com.thingclips.smart.interior.api.IUserRegionPlugin`

### com.thingclips.smart.interior.bean

- `com.thingclips.smart.interior.bean.DomainExBean`
- `com.thingclips.smart.interior.bean.UserExBean`
- `com.thingclips.smart.interior.bean.UserRespBean`

### com.thingclips.smart.interior.callback

- `com.thingclips.smart.interior.callback.ICancelAccountListener`
- `com.thingclips.smart.interior.callback.ILoginSuccessListener`
- `com.thingclips.smart.interior.callback.ILogoutSuccessListener`

### com.thingclips.smart.interior.config

- `com.thingclips.smart.interior.config.ICheckDevAcitveStatusByToken`
- `com.thingclips.smart.interior.config.ICheckDevActiveStatusByTokenListener`
- `com.thingclips.smart.interior.config.IPollDevByToken`

### com.thingclips.smart.interior.config.bean

- `com.thingclips.smart.interior.config.bean.ActiveQRTokenBean`
- `com.thingclips.smart.interior.config.bean.ActiveTokenBean`
- `com.thingclips.smart.interior.config.bean.ConfigDevResp`

### com.thingclips.smart.interior.device

- `com.thingclips.smart.interior.device.IDevCloudControl`
- `com.thingclips.smart.interior.device.IDeviceHardwareResponseListener`
- `com.thingclips.smart.interior.device.IDeviceMqttProtocolListener`
- `com.thingclips.smart.interior.device.IThingDevListCacheManager`
- `com.thingclips.smart.interior.device.IThingDeviceCommunicationListener`
- `com.thingclips.smart.interior.device.IThingDeviceDataCacheManager`
- `com.thingclips.smart.interior.device.IThingDeviceDpChangeListener`
- `com.thingclips.smart.interior.device.IThingDeviceInfoChangeListener`
- `com.thingclips.smart.interior.device.IThingDeviceMessageManager`
- `com.thingclips.smart.interior.device.IThingDeviceOnlineStatusListener`
- `com.thingclips.smart.interior.device.IThingDeviceOperate`
- `com.thingclips.smart.interior.device.IThingDpsUpdateManager`
- `com.thingclips.smart.interior.device.IThingGroupCache`
- `com.thingclips.smart.interior.device.IThingHardwareOnlineStatusListener`
- `com.thingclips.smart.interior.device.IThingMeshBatchDpUpdateListener`
- `com.thingclips.smart.interior.device.IThingMeshRawReportListener`
- `com.thingclips.smart.interior.device.IThingSubDeviceOnlineStatusListener`

### com.thingclips.smart.interior.device.bean

- `com.thingclips.smart.interior.device.bean.BlueMeshBatchReportBean`
- `com.thingclips.smart.interior.device.bean.CloudControlRawBean`
- `com.thingclips.smart.interior.device.bean.DevResp`
- `com.thingclips.smart.interior.device.bean.DeviceRespBean`
- `com.thingclips.smart.interior.device.bean.DpResp`
- `com.thingclips.smart.interior.device.bean.DpsUpdateInfo`
- `com.thingclips.smart.interior.device.bean.GroupRespBean`
- `com.thingclips.smart.interior.device.bean.GwDevResp`
- `com.thingclips.smart.interior.device.bean.OtaAutoUpgradeRespBean`
- `com.thingclips.smart.interior.device.bean.SubDeviceCorrectModel`

### com.thingclips.smart.interior.device.config

- `com.thingclips.smart.interior.device.config.DevErrorCode`
- `com.thingclips.smart.interior.device.config.GWConfig`

### com.thingclips.smart.interior.device.confusebean

- `com.thingclips.smart.interior.device.confusebean.DpPublish`
- `com.thingclips.smart.interior.device.confusebean.MQ_0_DeviceShareChangedBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_1_ConnectStatusChangeBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_201_EnableWifiSuccessBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_203_AddZigbeeGroupBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_203_DataReceivedBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_205_AddZigbeeSceneBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_25_MeshOnlineStatusUpdateBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_29_MeshRawReportBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_302_DataBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_308_DataBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_30_MeshBatchReportBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_33_SubDevAdd`
- `com.thingclips.smart.interior.device.confusebean.MQ_35_MeshUpdateBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_37_GroupChangedBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_39_40_HomeChanged`
- `com.thingclips.smart.interior.device.confusebean.MQ_401_SmartEnableUpdate`
- `com.thingclips.smart.interior.device.confusebean.MQ_43_DataPushBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_47_GroupDpsUpdateBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_4_MeshDpUpdateBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_501_TTSMsgBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_52_DataPushBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_54_MeshRelationUpdateBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_56_WarnMessageBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_63_ScanBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_68_GatewaySubDeviceTransfer`
- `com.thingclips.smart.interior.device.confusebean.MQ_802_PushAlarmBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_803_ThingPushBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_9_16_DeviceUpgradeBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_9_DeviceUpgradeStatusBean`
- `com.thingclips.smart.interior.device.confusebean.MQ_Link_DeviceMessageBean`
- `com.thingclips.smart.interior.device.confusebean.Protocol_16_Bean`
- `com.thingclips.smart.interior.device.confusebean.Protocol_32_Bean`
- `com.thingclips.smart.interior.device.confusebean.Protocol_33_Bean`
- `com.thingclips.smart.interior.device.confusebean.Protocol_34_Bean`
- `com.thingclips.smart.interior.device.confusebean.Protocol_4_Bean`
- `com.thingclips.smart.interior.device.confusebean.SandO`

### com.thingclips.smart.interior.enums

- `com.thingclips.smart.interior.enums.ApTypeEnum`

### com.thingclips.smart.interior.event

- `com.thingclips.smart.interior.event.BaseEventModel`
- `com.thingclips.smart.interior.event.DevUpdateEvent`
- `com.thingclips.smart.interior.event.DevUpdateEventModel`
- `com.thingclips.smart.interior.event.DeviceDpsUpdateEvent`
- `com.thingclips.smart.interior.event.DeviceDpsUpdateEventModel`
- `com.thingclips.smart.interior.event.DeviceOnlineStatusEvent`
- `com.thingclips.smart.interior.event.DeviceOnlineStatusEventModel`
- `com.thingclips.smart.interior.event.DeviceUpdateEvent`
- `com.thingclips.smart.interior.event.DeviceUpdateEventModel`
- `com.thingclips.smart.interior.event.DpUpdateEvent`
- `com.thingclips.smart.interior.event.DpUpdateEventModel`
- `com.thingclips.smart.interior.event.GroupDpsUpdateEvent`
- `com.thingclips.smart.interior.event.GroupDpsUpdateEventModel`
- `com.thingclips.smart.interior.event.GroupUpdateEvent`
- `com.thingclips.smart.interior.event.GroupUpdateEventModel`
- `com.thingclips.smart.interior.event.MeshRelationUpdateEvent`
- `com.thingclips.smart.interior.event.MeshRelationUpdateEventModel`
- `com.thingclips.smart.interior.event.SubDevCorrectEventModel`
- `com.thingclips.smart.interior.event.SubDeviceRelationUpdateEvent`
- `com.thingclips.smart.interior.event.SubDeviceRelationUpdateEventModel`
- `com.thingclips.smart.interior.event.ZigbeeSubDevDpUpdateEvent`
- `com.thingclips.smart.interior.event.ZigbeeSubDevDpUpdateEventModel`

### com.thingclips.smart.interior.hardware

- `com.thingclips.smart.interior.hardware.HardwareConfig`
- `com.thingclips.smart.interior.hardware.IApActivatorConfigListener`
- `com.thingclips.smart.interior.hardware.IDevResponseWithoutDpDataListener`
- `com.thingclips.smart.interior.hardware.IDeviceActivatorConfigListener`
- `com.thingclips.smart.interior.hardware.IDeviceHardwareConfigListener`
- `com.thingclips.smart.interior.hardware.IDeviceHardwareFindListener`
- `com.thingclips.smart.interior.hardware.IDeviceHardwareResultListener`
- `com.thingclips.smart.interior.hardware.IGwBleConnectStatusListener`
- `com.thingclips.smart.interior.hardware.IHardwareLogEventListener`
- `com.thingclips.smart.interior.hardware.ILocalDpMessageRespListener`
- `com.thingclips.smart.interior.hardware.ILocalOnlineStatusListener`
- `com.thingclips.smart.interior.hardware.ILogEventListener`
- `com.thingclips.smart.interior.hardware.IParsePkgFrameListener`
- `com.thingclips.smart.interior.hardware.IThingAPConfig`
- `com.thingclips.smart.interior.hardware.IThingAPSLConfigListener`
- `com.thingclips.smart.interior.hardware.IThingApDirectlyConfig`
- `com.thingclips.smart.interior.hardware.IThingApFindListener`
- `com.thingclips.smart.interior.hardware.IThingEZConfig`
- `com.thingclips.smart.interior.hardware.IThingHardware`
- `com.thingclips.smart.interior.hardware.IThingHardwareBusiness`
- `com.thingclips.smart.interior.hardware.IThingHardwareQuery`
- `com.thingclips.smart.interior.hardware.IThingHardwareQueryManager`
- `com.thingclips.smart.interior.hardware.IThingHardwareResultCallback`
- `com.thingclips.smart.interior.hardware.IThingOptimizedApConfig`
- `com.thingclips.smart.interior.hardware.IThingRouterConfigListener`
- `com.thingclips.smart.interior.hardware.IThingWifiGetLogConfig`
- `com.thingclips.smart.interior.hardware.IThingWiredConfig`
- `com.thingclips.smart.interior.hardware.ThingLocalControlBean`
- `com.thingclips.smart.interior.hardware.ThingLocalNormalControlBean`

### com.thingclips.smart.interior.hardware.builder

- `com.thingclips.smart.interior.hardware.builder.IThingWifiFindConfigListener`
- `com.thingclips.smart.interior.hardware.builder.ThingQueryInfoBuilder`

### com.thingclips.smart.interior.home

- `com.thingclips.smart.interior.home.IThingHomeDataLocalCache`

### com.thingclips.smart.interior.log

- `com.thingclips.smart.interior.log.IThingLogPlugin`

### com.thingclips.smart.interior.mqtt

- `com.thingclips.smart.interior.mqtt.IMqttServer`
- `com.thingclips.smart.interior.mqtt.IMqttServerStatusCallback`
- `com.thingclips.smart.interior.mqtt.MqttConfigUtil`
- `com.thingclips.smart.interior.mqtt.MqttControlBuilder`
- `com.thingclips.smart.interior.mqtt.MqttErrorCode`
- `com.thingclips.smart.interior.mqtt.MqttFlowRespParseListener`
- `com.thingclips.smart.interior.mqtt.MqttMessageRespParseListener`
- `com.thingclips.smart.interior.mqtt.PublishAndDeliveryCallback`

### com.thingclips.smart.ipc.camera.base

- `com.thingclips.smart.ipc.camera.base.BuildConfig`
- `com.thingclips.smart.ipc.camera.base.C0057R`

### com.thingclips.smart.ipc.messagecenter

- `com.thingclips.smart.ipc.messagecenter.MessageConstant`

### com.thingclips.smart.ipc.messagecenter.bean

- `com.thingclips.smart.ipc.messagecenter.bean.AITagBean`
- `com.thingclips.smart.ipc.messagecenter.bean.CameraMessageBean`
- `com.thingclips.smart.ipc.messagecenter.bean.CameraMessageClassifyBean`

### com.thingclips.smart.ipc.messagecenter.business

- `com.thingclips.smart.ipc.messagecenter.business.CameraMessageBusiness`

### com.thingclips.smart.ipc.sdk

- `com.thingclips.smart.ipc.sdk.BuildConfig`
- `com.thingclips.smart.ipc.sdk.C0058R`

### com.thingclips.smart.ipc.sdk.api

- `com.thingclips.smart.ipc.sdk.api.BuildConfig`
- `com.thingclips.smart.ipc.sdk.api.C0059R`

### com.thingclips.smart.ipc.yuv.monitor

- `com.thingclips.smart.ipc.yuv.monitor.BuildConfig`
- `com.thingclips.smart.ipc.yuv.monitor.C0060R`
- `com.thingclips.smart.ipc.yuv.monitor.FPSCheckHelp`
- `com.thingclips.smart.ipc.yuv.monitor.MgGLTextureView`
- `com.thingclips.smart.ipc.yuv.monitor.YUVMonitorSurfaceView`
- `com.thingclips.smart.ipc.yuv.monitor.YUVMonitorTextureView`

### com.thingclips.smart.ipc.yuv.monitor.api

- `com.thingclips.smart.ipc.yuv.monitor.api.IYUVMonitor`
- `com.thingclips.smart.ipc.yuv.monitor.api.MonitorConfig`

### com.thingclips.smart.ipc.yuv.monitor.opengl

- `com.thingclips.smart.ipc.yuv.monitor.opengl.GLHelper`
- `com.thingclips.smart.ipc.yuv.monitor.opengl.GLProgram`
- `com.thingclips.smart.ipc.yuv.monitor.opengl.ThingMonitorRenderer`

### com.thingclips.smart.ipc.yuv.monitor.renderer

- `com.thingclips.smart.ipc.yuv.monitor.renderer.GLHelper`
- `com.thingclips.smart.ipc.yuv.monitor.renderer.GLProgram`
- `com.thingclips.smart.ipc.yuv.monitor.renderer.IRenderer`
- `com.thingclips.smart.ipc.yuv.monitor.renderer.YUVRender`

### com.thingclips.smart.ipc.yuv.monitor.test

- `com.thingclips.smart.ipc.yuv.monitor.test.DebugUtils`
- `com.thingclips.smart.ipc.yuv.monitor.test.YUVAdapter`
- `com.thingclips.smart.ipc.yuv.monitor.test.YuvCroper`

### com.thingclips.smart.ipc.yuv.monitor.texture

- `com.thingclips.smart.ipc.yuv.monitor.texture.GLESTextureView`
- `com.thingclips.smart.ipc.yuv.monitor.texture.IGLESRenderer`

### com.thingclips.smart.ipc.yuv.monitor.utils

- `com.thingclips.smart.ipc.yuv.monitor.utils.DoubleClickCheck`
- `com.thingclips.smart.ipc.yuv.monitor.utils.VaryTools`

### com.thingclips.smart.ipc.yuv.monitor.utils.log

- `com.thingclips.smart.ipc.yuv.monitor.utils.log.C0063L`
- `com.thingclips.smart.ipc.yuv.monitor.utils.log.ILog`
- `com.thingclips.smart.ipc.yuv.monitor.utils.log.LogLevel`

### com.thingclips.smart.mediaplayer

- `com.thingclips.smart.mediaplayer.ThingMediaPlayer`
- `com.thingclips.smart.mediaplayer.ThingMediaPlayerLog`
- `com.thingclips.smart.mediaplayer.ThingMediaPlayerManager`
- `com.thingclips.smart.mediaplayer.ThingMediaPlayerSDK`

### com.thingclips.smart.mediaplayer.bean

- `com.thingclips.smart.mediaplayer.bean.ThingAudioFrameInfo`
- `com.thingclips.smart.mediaplayer.bean.ThingAudioTrack`
- `com.thingclips.smart.mediaplayer.bean.ThingRunningInfo`
- `com.thingclips.smart.mediaplayer.bean.ThingVideoFrameInfo`

### com.thingclips.smart.mediaplayer.callback

- `com.thingclips.smart.mediaplayer.callback.MediaPlayerListener`
- `com.thingclips.smart.mediaplayer.callback.MediaPlayerLogListener`

*(... and 24 more packages)*

</details>
