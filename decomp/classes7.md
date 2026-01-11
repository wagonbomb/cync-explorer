# DEX Analysis: classes7.dex


**File Size**: 1.7 MB
**Total Classes**: 497
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
| Total Classes | 497 |
| Total Methods | 5,615 |
| Total Fields | 66,624 |
| Total Packages | 63 |
| BLE-Related Classes | 296 |
| UUIDs Found | 0 |
| BLE Write Operations | 0 |
| Command Sequences | 0 |

## BLE-Related Classes

Found 296 BLE-related classes:

### IDeviceService [CRITICAL]


- **Full Name**: `com.thingclips.smart.scene.api.service.IDeviceService`
- **Package**: `com.thingclips.smart.scene.api.service`
- **Methods**: 18
- **Fields**: 0
- **Source**: `scene\api\service\IDeviceService.java`

**Key Methods**:
  - `getActionDeviceAll()`
  - `getActionDeviceDpAll()`
  - `getActionDeviceIdAll()`
  - `getActionGroupDeviceDpAll()`
  - `getCategoryDeviceGroups()`
  - `getConditionDeviceAll()`
  - `getConditionDeviceDpAll()`
  - `getConditionDeviceIdAll()`
  - `getFaceDeviceAll()`
  - `getFaceDeviceIdAll()`
  - *(... and 8 more)*

---

### DefaultImpls [CRITICAL]


- **Full Name**: `com.thingclips.smart.scene.api.service.DefaultImpls`
- **Package**: `com.thingclips.smart.scene.api.service`
- **Extends**: `BatchExecutionDps>`
- **Methods**: 35
- **Fields**: 0
- **Source**: `scene\api\service\IExecuteService.java`

**Key Methods**:
  - `UnsupportedOperationException()`
  - `UnsupportedOperationException()`
  - `UnsupportedOperationException()`
  - `UnsupportedOperationException()`
  - `UnsupportedOperationException()`
  - `UnsupportedOperationException()`
  - `UnsupportedOperationException()`
  - `UnsupportedOperationException()`
  - `UnsupportedOperationException()`
  - `UnsupportedOperationException()`
  - *(... and 25 more)*

**Notable Strings**:
  - `"meshIds"`
  - `"meshDevicePublishDps"`
  - `"meshId"`
  - `"meshGroupPublishDps"`
  - `"registerMeshDeviceListener"`
  - *(... and 9 more)*

---

### ExecuteSceneExtensionsKt [CRITICAL]


- **Full Name**: `com.thingclips.smart.scene.execute.ExecuteSceneExtensionsKt`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `BatchExecutionDps>`
- **Methods**: 96
- **Fields**: 324
- **Source**: `smart\scene\execute\ExecuteSceneExtensionsKt.java`

**Key Methods**:
  - `batchExecuteDeviceOnLocal()`
  - `execute()`
  - `StringBuilder()`
  - `if()`
  - `if()`
  - `if()`
  - `IllegalStateException()`
  - `executeCommonDevice()`
  - `IResultCallback()`
  - `onError()`
  - *(... and 86 more)*

**Notable Strings**:
  - `" + groupBean.getId());
        DeviceUtil.INSTANCE.getSceneService().executeService().groupPublishDps(groupBean.getId(), str2, new IResultCallback() { // from class: com.thingclips.smart.scene.execute.ExecuteSceneExtensionsKt$executeCommonGroupDevice$1$1
            @Override // com.thingclips.smart.sdk.api.IResultCallback
            public void onError(@Nullable String code, @Nullable String error) {
                ExecuteAnalysisUtil executeAnalysisUtil = ExecuteAnalysisUtil.INSTANCE;
                String value = TargetType.TARGET_GROUP.getValue();
                String value2 = ProtocolType.PROTOCOL_ZIGBEE.getValue();
                executeAnalysisUtil.setExecuteActionInfo(str, value, SDKStatus.STATUS_FAILURE.getValue(), value2);
            }

            @Override // com.thingclips.smart.sdk.api.IResultCallback
            public void onSuccess() {
                ExecuteAnalysisUtil executeAnalysisUtil = ExecuteAnalysisUtil.INSTANCE;
                String value = TargetType.TARGET_GROUP.getValue();
                String value2 = ProtocolType.PROTOCOL_ZIGBEE.getValue();
                executeAnalysisUtil.setExecuteActionInfo(str, value, SDKStatus.STATUS_SUCCESS.getValue(), value2);
            }
        });
        return Unit.INSTANCE;
    }

    private static final void executeDeviceGroupOnLocal(SceneAction sceneAction) {
        GroupBean groupDevice = DeviceUtil.INSTANCE.getGroupDevice(NumberUtils.toLong(sceneAction.getEntityId()));
        Map<String, Object> executorProperty = sceneAction.getExecutorProperty();
        String jSONObject = executorProperty != null ? new JSONObject(executorProperty).toString() : null;
        if (groupDevice != null) {
            String meshId = groupDevice.getMeshId();
            if (meshId == null || StringsKt.isBlank(meshId)) {
                String id = sceneAction.getId();
                Intrinsics.checkNotNullExpressionValue(id, "`
  - `");
                executeMeshGroupDevice(id2, groupDevice, jSONObject);
            } else if (groupType != 3) {
                String id3 = sceneAction.getId();
                Intrinsics.checkNotNullExpressionValue(id3, "`
  - `");
                executeSigMeshGroupDevice(id4, groupDevice, jSONObject);
            }
        }
    }

    private static final void executeDeviceOnLocal(SceneAction sceneAction) {
        L.i("`
  - `", imports = {}))
    private static final Unit executeMeshDevice(final String str, DeviceBean deviceBean, String str2) {
        String str3;
        if (str2 == null) {
            return null;
        }
        IExecuteService executeService = DeviceUtil.INSTANCE.getSceneService().executeService();
        String meshId = deviceBean.getMeshId();
        if (meshId == null) {
            meshId = "`
  - `";
        } else {
            Intrinsics.checkNotNullExpressionValue(meshId, "`
  - *(... and 11 more)*

---

### MonitorResultExtensionsKt [CRITICAL]


- **Full Name**: `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `Object>`
- **Methods**: 39
- **Fields**: 145
- **Source**: `smart\scene\execute\MonitorResultExtensionsKt.java`

**Key Methods**:
  - `ReentrantLock()`
  - `batchMonitorDeviceChangeFlow()`
  - `delayFlow()`
  - `dpCmdExecuteSucSet()`
  - `LinkedHashSet()`
  - `getInitialStateFlow()`
  - `getLock()`
  - `getMqttChannelInstance()`
  - `monitorGroupChangeFlow()`
  - `monitorMqtt802Flow()`
  - *(... and 29 more)*

**Notable Strings**:
  - `");
                linkedHashMap.put(id5, actionExecuteResult);
                sparseArray4.put(i2, linkedHashMap);
            }
            i = i3;
        }
        return z;
    }

    private static final void releaseDeviceMonitor(String str) {
        DeviceUtil.INSTANCE.getSceneService().executeService().unRegisterDevListener(str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void releaseGroupMonitor(long j) {
        DeviceUtil.INSTANCE.getSceneService().executeService().unRegisterGroupListener(j);
    }

    private static final void releaseMeshMonitor(String str) {
        DeviceUtil.INSTANCE.getSceneService().executeService().unRegisterMeshDevListener(str);
    }

    public static final void releaseMonitor(@NotNull SceneAction sceneAction) {
        Intrinsics.checkNotNullParameter(sceneAction, "`
  - `");
        String actionExecutor = sceneAction.getActionExecutor();
        if (!ArraysKt.contains(ActionConstantKt.getDeviceTypeActionArray(), actionExecutor)) {
            if (Intrinsics.areEqual(actionExecutor, ActionConstantKt.ACTION_TYPE_DEVICE_GROUP)) {
                releaseGroupMonitor(NumberUtils.toLong(sceneAction.getEntityId()));
                return;
            }
            return;
        }
        String entityId = sceneAction.getEntityId();
        DeviceBean device = entityId != null ? DeviceUtil.INSTANCE.getDevice(entityId) : null;
        if (device != null) {
            if (device.isBlueMesh()) {
                String meshId = device.getMeshId();
                Intrinsics.checkNotNullExpressionValue(meshId, "`
  - `");
                releaseMeshMonitor(meshId);
            } else if (device.isSigMesh()) {
                String meshId2 = device.getMeshId();
                Intrinsics.checkNotNullExpressionValue(meshId2, "`
  - `");
                releaseSigMeshMonitor(meshId2);
            } else {
                String str = device.devId;
                Intrinsics.checkNotNullExpressionValue(str, "`
  - `");
                releaseDeviceMonitor(str);
            }
        }
    }

    private static final void releaseSigMeshMonitor(String str) {
        DeviceUtil.INSTANCE.getSceneService().executeService().unRegisterSigMeshDevListener(str);
    }

    @NotNull
    public static final ActionExecuteResult synchronizedGet(@NotNull List<ActionExecuteResult> list, int i) {
        Intrinsics.checkNotNullParameter(list, "`

---

### SceneBusiness [CRITICAL]


- **Full Name**: `com.thingclips.smart.scene.lib.service.SceneBusiness`
- **Package**: `com.thingclips.smart.scene.lib.service`
- **Extends**: `Business`
- **Methods**: 138
- **Fields**: 152
- **Source**: `scene\lib\service\SceneBusiness.java`

**Key Methods**:
  - `LinkedHashMap()`
  - `getSceneDeviceList()`
  - `ApiParams()`
  - `onFailure()`
  - `onSuccess()`
  - `LinkedHashSet()`
  - `LinkedHashSet()`
  - `preciseDecimalPoints()`
  - `batchModifySceneRooms()`
  - `ApiParams()`
  - *(... and 128 more)*

**Notable Strings**:
  - `", geoFilterProperty);
        apiParams.setSessionRequire(true);
        apiParams.setGid(relationId);
        asyncArrayList(apiParams, NormalScene.class, listener);
    }

    public final void getStandardInfo(@NotNull List<String> meshIds, @NotNull Business.ResultListener<ArrayList<StandardSceneInfo>> listener) {
        Intrinsics.checkNotNullParameter(meshIds, "`
  - `", meshIds);
        asyncArrayList(apiParams, StandardSceneInfo.class, listener);
    }

    public final void getStatusConditionDeviceDpAll(@NotNull String relationId, @NotNull String deviceId, @NotNull Business.ResultListener<ArrayList<ConditionItemDetail>> listener) {
        Intrinsics.checkNotNullParameter(relationId, "`

---

### DeviceService [CRITICAL]


- **Full Name**: `com.thingclips.smart.scene.lib.service.device.DeviceService`
- **Package**: `com.thingclips.smart.scene.lib.service.device`
- **Implements**: `IDeviceService`
- **Methods**: 59
- **Fields**: 50
- **Source**: `lib\service\device\DeviceService.java`

**Key Methods**:
  - `DeviceService()`
  - `SceneBusiness()`
  - `DeviceService()`
  - `getActionDeviceAll()`
  - `onFailure()`
  - `onSuccess()`
  - `ArrayList()`
  - `ArrayList()`
  - `getActionDeviceDpAll()`
  - `onFailure()`
  - *(... and 49 more)*

**Notable Strings**:
  - `");
        deviceBusiness.getConditionDeviceDpAll(deviceId, new Business.ResultListener<ArrayList<ConditionItemDetail>>() { // from class: com.thingclips.smart.scene.lib.service.device.DeviceService$getConditionDeviceDpAll$1
            public void onFailure(@Nullable BusinessResponse p0, @Nullable ArrayList<ConditionItemDetail> p1, @Nullable String p2) {
                IResultCallback<List<ConditionItemDetail>> iResultCallback = callback;
                if (iResultCallback != null) {
                    iResultCallback.onError(p0 != null ? p0.errorCode : null, p0 != null ? p0.errorMsg : null);
                }
            }

            public void onSuccess(@Nullable BusinessResponse p0, @Nullable ArrayList<ConditionItemDetail> p1, @Nullable String p2) {
                IResultCallback<List<ConditionItemDetail>> iResultCallback = callback;
                if (iResultCallback != null) {
                    iResultCallback.onSuccess(p1);
                }
            }
        });
    }

    @Override // com.thingclips.smart.scene.api.service.IDeviceService
    public void getConditionDeviceIdAll(long relationId, @Nullable final IResultCallback<List<String>> callback) {
        SceneBusiness.getConditionDeviceAll$default(deviceBusiness, relationId, null, new Business.ResultListener<ArrayList<String>>() { // from class: com.thingclips.smart.scene.lib.service.device.DeviceService$getConditionDeviceIdAll$1
            public void onFailure(@Nullable BusinessResponse p0, @Nullable ArrayList<String> p1, @Nullable String p2) {
                IResultCallback<List<String>> iResultCallback = callback;
                if (iResultCallback != null) {
                    iResultCallback.onError(p0 != null ? p0.errorCode : null, p0 != null ? p0.errorMsg : null);
                }
            }

            public void onSuccess(@Nullable BusinessResponse p0, @Nullable ArrayList<String> p1, @Nullable String p2) {
                IResultCallback<List<String>> iResultCallback = callback;
                if (iResultCallback != null) {
                    iResultCallback.onSuccess(p1);
                }
            }
        }, 2, null);
    }

    @Override // com.thingclips.smart.scene.api.service.IDeviceService
    public void getFaceDeviceAll(long relationId, @Nullable final IResultCallback<List<DeviceBean>> callback) {
        deviceBusiness.getLockOrFaceDeviceAll(relationId, 9, new Business.ResultListener<ArrayList<String>>() { // from class: com.thingclips.smart.scene.lib.service.device.DeviceService$getFaceDeviceAll$1
            public void onFailure(@Nullable BusinessResponse p0, @Nullable ArrayList<String> p1, @Nullable String p2) {
                IResultCallback<List<DeviceBean>> iResultCallback = callback;
                if (iResultCallback != null) {
                    iResultCallback.onError(p0 != null ? p0.errorCode : null, p0 != null ? p0.errorMsg : null);
                }
            }

            public void onSuccess(@Nullable BusinessResponse p0, @Nullable ArrayList<String> p1, @Nullable String p2) {
                ArrayList arrayList;
                IResultCallback<List<DeviceBean>> iResultCallback = callback;
                if (iResultCallback != null) {
                    if (p1 != null) {
                        arrayList = new ArrayList(CollectionsKt.g(p1));
                        Iterator<T> it = p1.iterator();
                        while (it.hasNext()) {
                            arrayList.add(DeviceUtil.INSTANCE.getDevice((String) it.next()));
                        }
                    } else {
                        arrayList = null;
                    }
                    iResultCallback.onSuccess(arrayList);
                }
            }
        });
    }

    @Override // com.thingclips.smart.scene.api.service.IDeviceService
    public void getFaceDeviceIdAll(long relationId, @Nullable final IResultCallback<List<String>> callback) {
        deviceBusiness.getLockOrFaceDeviceAll(relationId, 9, new Business.ResultListener<ArrayList<String>>() { // from class: com.thingclips.smart.scene.lib.service.device.DeviceService$getFaceDeviceIdAll$1
            public void onFailure(@Nullable BusinessResponse p0, @Nullable ArrayList<String> p1, @Nullable String p2) {
                IResultCallback<List<String>> iResultCallback = callback;
                if (iResultCallback != null) {
                    iResultCallback.onError(p0 != null ? p0.errorCode : null, p0 != null ? p0.errorMsg : null);
                }
            }

            public void onSuccess(@Nullable BusinessResponse p0, @Nullable ArrayList<String> p1, @Nullable String p2) {
                IResultCallback<List<String>> iResultCallback = callback;
                if (iResultCallback != null) {
                    iResultCallback.onSuccess(p1);
                }
            }
        });
    }

    @Override // com.thingclips.smart.scene.api.service.IDeviceService
    public void getFaceMemberAll(long relationId, @Nullable final IResultCallback<List<FaceDeviceMember>> callback) {
        deviceBusiness.getFaceMemberAll(relationId, new Business.ResultListener<ArrayList<FaceDeviceMember>>() { // from class: com.thingclips.smart.scene.lib.service.device.DeviceService$getFaceMemberAll$1
            public void onFailure(@Nullable BusinessResponse p0, @Nullable ArrayList<FaceDeviceMember> p1, @Nullable String p2) {
                IResultCallback<List<FaceDeviceMember>> iResultCallback = callback;
                if (iResultCallback != null) {
                    iResultCallback.onError(p0 != null ? p0.errorCode : null, p0 != null ? p0.errorMsg : null);
                }
            }

            public void onSuccess(@Nullable BusinessResponse p0, @Nullable ArrayList<FaceDeviceMember> p1, @Nullable String p2) {
                IResultCallback<List<FaceDeviceMember>> iResultCallback = callback;
                if (iResultCallback != null) {
                    iResultCallback.onSuccess(p1);
                }
            }
        });
    }

    @Override // com.thingclips.smart.scene.api.service.IDeviceService
    public void getLockDeviceAll(long relationId, @Nullable final IResultCallback<List<DeviceBean>> callback) {
        deviceBusiness.getLockOrFaceDeviceAll(relationId, 11, new Business.ResultListener<ArrayList<String>>() { // from class: com.thingclips.smart.scene.lib.service.device.DeviceService$getLockDeviceAll$1
            public void onFailure(@Nullable BusinessResponse p0, @Nullable ArrayList<String> p1, @Nullable String p2) {
                IResultCallback<List<DeviceBean>> iResultCallback = callback;
                if (iResultCallback != null) {
                    iResultCallback.onError(p0 != null ? p0.errorCode : null, p0 != null ? p0.errorMsg : null);
                }
            }

            public void onSuccess(@Nullable BusinessResponse p0, @Nullable ArrayList<String> p1, @Nullable String p2) {
                ArrayList arrayList;
                IResultCallback<List<DeviceBean>> iResultCallback = callback;
                if (iResultCallback != null) {
                    if (p1 != null) {
                        arrayList = new ArrayList(CollectionsKt.g(p1));
                        Iterator<T> it = p1.iterator();
                        while (it.hasNext()) {
                            arrayList.add(DeviceUtil.INSTANCE.getDevice((String) it.next()));
                        }
                    } else {
                        arrayList = null;
                    }
                    iResultCallback.onSuccess(arrayList);
                }
            }
        });
    }

    @Override // com.thingclips.smart.scene.api.service.IDeviceService
    public void getLockDeviceIdAll(long relationId, @Nullable final IResultCallback<List<String>> callback) {
        deviceBusiness.getLockOrFaceDeviceAll(relationId, 11, new Business.ResultListener<ArrayList<String>>() { // from class: com.thingclips.smart.scene.lib.service.device.DeviceService$getLockDeviceIdAll$1
            public void onFailure(@Nullable BusinessResponse p0, @Nullable ArrayList<String> p1, @Nullable String p2) {
                IResultCallback<List<String>> iResultCallback = callback;
                if (iResultCallback != null) {
                    iResultCallback.onError(p0 != null ? p0.errorCode : null, p0 != null ? p0.errorMsg : null);
                }
            }

            public void onSuccess(@Nullable BusinessResponse p0, @Nullable ArrayList<String> p1, @Nullable String p2) {
                IResultCallback<List<String>> iResultCallback = callback;
                if (iResultCallback != null) {
                    iResultCallback.onSuccess(p1);
                }
            }
        });
    }

    @Override // com.thingclips.smart.scene.api.service.IDeviceService
    public void getStandardInfo(@NotNull List<String> meshIds, @Nullable final IResultCallback<List<StandardSceneInfo>> callback) {
        Intrinsics.checkNotNullParameter(meshIds, "`
  - `");
        deviceBusiness.getStandardInfo(meshIds, new Business.ResultListener<ArrayList<StandardSceneInfo>>() { // from class: com.thingclips.smart.scene.lib.service.device.DeviceService$getStandardInfo$1
            public void onFailure(@Nullable BusinessResponse bizResponse, @Nullable ArrayList<StandardSceneInfo> bizResult, @Nullable String apiName) {
                IResultCallback<List<StandardSceneInfo>> iResultCallback = callback;
                if (iResultCallback != null) {
                    iResultCallback.onError(bizResponse != null ? bizResponse.errorCode : null, bizResponse != null ? bizResponse.errorMsg : null);
                }
            }

            public void onSuccess(@Nullable BusinessResponse bizResponse, @Nullable ArrayList<StandardSceneInfo> bizResult, @Nullable String apiName) {
                IResultCallback<List<StandardSceneInfo>> iResultCallback = callback;
                if (iResultCallback != null) {
                    iResultCallback.onSuccess(bizResult);
                }
            }
        });
    }

    @Override // com.thingclips.smart.scene.api.service.IDeviceService
    public void getStatusConditionDeviceAll(long relationId, @Nullable final IResultCallback<List<DeviceBean>> callback) {
        deviceBusiness.getConditionDeviceAll(relationId, "`

---

### ExecuteService [CRITICAL]


- **Full Name**: `com.thingclips.smart.scene.lib.service.execute.ExecuteService`
- **Package**: `com.thingclips.smart.scene.lib.service.execute`
- **Extends**: `BatchExecutionDps>`
- **Implements**: `IExecuteService`
- **Methods**: 34
- **Fields**: 24
- **Source**: `lib\service\execute\ExecuteService.java`

**Key Methods**:
  - `ExecuteService()`
  - `SceneBusiness()`
  - `ExecuteService()`
  - `batchExecuteDeviceDps()`
  - `executeLocalScene()`
  - `executeLocalSceneNew()`
  - `executeScene()`
  - `executeSceneMqtt()`
  - `executeSceneOnCloud()`
  - `onFailure()`
  - *(... and 24 more)*

**Notable Strings**:
  - `"meshIds"`
  - `"meshDevicePublishDps"`
  - `"meshId"`
  - `"meshGroupPublishDps"`
  - `"registerMeshDeviceListener"`
  - *(... and 14 more)*

---

### DeviceUtil [CRITICAL]


- **Full Name**: `com.thingclips.smart.scene.lib.util.DeviceUtil`
- **Package**: `com.thingclips.smart.scene.lib.util`
- **Extends**: `BatchExecutionDps>`
- **Methods**: 137
- **Fields**: 124
- **Source**: `scene\lib\util\DeviceUtil.java`

**Key Methods**:
  - `DeviceUtil()`
  - `m78invoke()`
  - `m79invoke()`
  - `m80invoke()`
  - `LinkedHashMap()`
  - `LinkedHashMap()`
  - `LinkedHashMap()`
  - `LinkedHashMap()`
  - `DeviceUtil()`
  - `equalsIgnoreCaseWhenStr()`
  - *(... and 127 more)*

**Notable Strings**:
  - `";

    @Nullable
    private static IDeviceMqttProtocolListener<MQ_205_AddZigbeeSceneBean> gwMqttCallBack;

    @NotNull
    public static final DeviceUtil INSTANCE = new DeviceUtil();

    /* renamed from: devicePlugin$delegate, reason: from kotlin metadata */
    @NotNull
    private static final Lazy devicePlugin = LazyKt.lazy(new Function0<IThingDevicePlugin>() { // from class: com.thingclips.smart.scene.lib.util.DeviceUtil$devicePlugin$2
        /* renamed from: invoke, reason: merged with bridge method [inline-methods] */
        public final IThingDevicePlugin m78invoke() {
            return (IThingDevicePlugin) PluginManager.service(IThingDevicePlugin.class);
        }
    });

    /* renamed from: groupDevicePlugin$delegate, reason: from kotlin metadata */
    @NotNull
    private static final Lazy groupDevicePlugin = LazyKt.lazy(new Function0<IThingGroupPlugin>() { // from class: com.thingclips.smart.scene.lib.util.DeviceUtil$groupDevicePlugin$2
        /* renamed from: invoke, reason: merged with bridge method [inline-methods] */
        public final IThingGroupPlugin m79invoke() {
            return (IThingGroupPlugin) PluginManager.service(IThingGroupPlugin.class);
        }
    });

    /* renamed from: meshPlugin$delegate, reason: from kotlin metadata */
    @NotNull
    private static final Lazy meshPlugin = LazyKt.lazy(new Function0<IThingBlueMeshPlugin>() { // from class: com.thingclips.smart.scene.lib.util.DeviceUtil$meshPlugin$2
        /* renamed from: invoke, reason: merged with bridge method [inline-methods] */
        public final IThingBlueMeshPlugin m80invoke() {
            return (IThingBlueMeshPlugin) PluginManager.service(IThingBlueMeshPlugin.class);
        }
    });

    @NotNull
    private static final Map<String, IThingBlueMeshDevice> meshDevListenerInstanceMap = new LinkedHashMap();

    @NotNull
    private static final Map<String, IThingBlueMeshDevice> sigMeshDevListenerInstanceMap = new LinkedHashMap();

    @NotNull
    private static final Map<String, IThingDevice> devListenerInstanceMap = new LinkedHashMap();

    @NotNull
    private static final Map<Long, IThingGroup> groupListenerInstanceMap = new LinkedHashMap();

    @Metadata(d1 = {"`
  - `" : device.getNodeId();
            devId = communicationId;
        } else {
            str = devId;
        }
        return new Pair<>(devId, str);
    }

    private final IThingDevicePlugin getDevicePlugin() {
        return (IThingDevicePlugin) devicePlugin.getValue();
    }

    private final IThingGroupPlugin getGroupDevicePlugin() {
        return (IThingGroupPlugin) groupDevicePlugin.getValue();
    }

    private final IThingBlueMeshPlugin getMeshPlugin() {
        return (IThingBlueMeshPlugin) meshPlugin.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void registerGwMqttListener$lambda$26(Function4 function4, MQ_205_AddZigbeeSceneBean mQ_205_AddZigbeeSceneBean) {
        Intrinsics.checkNotNullParameter(function4, "`
  - `");
        Iterator<T> it = schemaMap.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry entry = (Map.Entry) it.next();
            if (executorProperty.containsKey(entry.getKey()) && TextUtils.equals(((SchemaBean) entry.getValue()).mode, ModeEnum.WR.getType())) {
                return true;
            }
        }
        return false;
    }

    public final void meshDevicePublishDps(@NotNull String meshId, @NotNull String nodeId, @NotNull String pcc, @NotNull String dps, @Nullable final IResultCallback callback) {
        Intrinsics.checkNotNullParameter(meshId, "`
  - `");
        getMeshPlugin().newBlueMeshDeviceInstance(meshId).publishDps(nodeId, pcc, dps, new IResultCallback() { // from class: com.thingclips.smart.scene.lib.util.DeviceUtil$meshDevicePublishDps$1
            @Override // com.thingclips.smart.sdk.api.IResultCallback
            public void onError(@Nullable String code, @Nullable String error) {
                e.z("`
  - `");
                IResultCallback iResultCallback = IResultCallback.this;
                if (iResultCallback != null) {
                    iResultCallback.onSuccess();
                }
            }
        });
    }

    public final void meshGroupPublishDps(@NotNull String meshId, @NotNull String localId, @NotNull String category, @NotNull String dps, @Nullable final IResultCallback callback) {
        Intrinsics.checkNotNullParameter(meshId, "`
  - *(... and 17 more)*

---

### IMeshRegister [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.IMeshRegister`
- **Package**: `com.thingclips.smart.sdk.api`
- **Methods**: 4
- **Fields**: 0
- **Source**: `smart\sdk\api\IMeshRegister.java`

**Key Methods**:
  - `registerMeshDevListener()`
  - `registerOriginalMeshDevListener()`
  - `unRegisterMeshDevListener()`
  - `unRegisterOriginalMeshDevListener()`

---

### IThingDevEventListener [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.IThingDevEventListener`
- **Package**: `com.thingclips.smart.sdk.api`
- **Methods**: 7
- **Fields**: 0
- **Source**: `smart\sdk\api\IThingDevEventListener.java`

**Key Methods**:
  - `onDevInfoUpdate()`
  - `onDpUpdate()`
  - `onMeshRelationChanged()`
  - `onMqttEvent()`
  - `onNetworkStatusChanged()`
  - `onStatusChanged()`
  - `onSubDevRelationChanged()`

---

### IAddGroupCallback [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IAddGroupCallback`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IAddGroupCallback.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### IAddRemoteBindSubDevCallback [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IAddRemoteBindSubDevCallback`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Extends**: `IAddSubDevCallback`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IAddRemoteBindSubDevCallback.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### IAddRoomCallback [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IAddRoomCallback`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IAddRoomCallback.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### IAddSubDevCallback [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IAddSubDevCallback`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IAddSubDevCallback.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### IBlueMeshActivatorListener [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IBlueMeshActivatorListener`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 3
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IBlueMeshActivatorListener.java`

**Key Methods**:
  - `onFailure()`
  - `onStep()`
  - `onSuccess()`

---

### IBlueMeshCreateCallback [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IBlueMeshCreateCallback`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IBlueMeshCreateCallback.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### IBlueMeshManager [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IBlueMeshManager`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 9
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IBlueMeshManager.java`

**Key Methods**:
  - `createBlueMesh()`
  - `getBlueMeshBean()`
  - `getBlueMeshList()`
  - `getThingMeshParseBean()`
  - `onDestroy()`
  - `parseVenderIdFromDp()`
  - `requestMeshList()`
  - `requestUpgradeInfo()`
  - `updateBuleMesh()`

---

### IGetGroupAndDevListCallback [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IGetGroupAndDevListCallback`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IGetGroupAndDevListCallback.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### IGetMeshRoomAndGroupListCallback [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IGetMeshRoomAndGroupListCallback`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IGetMeshRoomAndGroupListCallback.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### IGroupDevCallback [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IGroupDevCallback`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IGroupDevCallback.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### IMeshActionTransmitter [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IMeshActionTransmitter`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 1
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IMeshActionTransmitter.java`

**Key Methods**:
  - `sendMessage()`

---

### IMeshDeviceListener [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IMeshDeviceListener`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 6
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IMeshDeviceListener.java`

**Key Methods**:
  - `onDevInfoUpdate()`
  - `onDpUpdate()`
  - `onNetworkStatusChanged()`
  - `onRawDataUpdate()`
  - `onRemoved()`
  - `onStatusChanged()`

---

### IMeshDeviceRssiCallback [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IMeshDeviceRssiCallback`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 1
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IMeshDeviceRssiCallback.java`

**Key Methods**:
  - `onMeshDeviceRssi()`

---

### IMeshDevListener [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IMeshDevListener`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 6
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IMeshDevListener.java`

**Key Methods**:
  - `onDevInfoUpdate()`
  - `onDpUpdate()`
  - `onNetworkStatusChanged()`
  - `onRawDataUpdate()`
  - `onRemoved()`
  - `onStatusChanged()`

---

### IMeshDevListenerV2 [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IMeshDevListenerV2`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Implements**: `IMeshDevListener`
- **Methods**: 1
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IMeshDevListenerV2.java`

**Key Methods**:
  - `onPassThroughDataReceive()`

---

### IMeshDevListenerV3 [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IMeshDevListenerV3`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Extends**: `IMeshDevListener`
- **Methods**: 1
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IMeshDevListenerV3.java`

**Key Methods**:
  - `onDpUpdate()`

---

### IMeshStatusListener [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IMeshStatusListener`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 3
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IMeshStatusListener.java`

**Key Methods**:
  - `getMeshDeviceCacheDps()`
  - `getMeshDeviceCloudStatus()`
  - `getMeshDeviceLocalStatus()`

---

### IRequestMeshListCallback [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IRequestMeshListCallback`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IRequestMeshListCallback.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### IRequestSigMeshListCallback [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IRequestSigMeshListCallback`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IRequestSigMeshListCallback.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### IRequestUpgradeInfoCallback [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IRequestUpgradeInfoCallback`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IRequestUpgradeInfoCallback.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### ISigMeshConnect [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.ISigMeshConnect`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 4
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\ISigMeshConnect.java`

**Key Methods**:
  - `disConnect()`
  - `inConfig()`
  - `isConnect()`
  - `startConnect()`

---

### ISigMeshCreateCallback [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.ISigMeshCreateCallback`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\ISigMeshCreateCallback.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### ISigMeshManager [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.ISigMeshManager`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 6
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\ISigMeshManager.java`

**Key Methods**:
  - `createSigMesh()`
  - `getSigMeshBean()`
  - `getSigMeshList()`
  - `onDestroy()`
  - `requestSigMeshList()`
  - `updateSigMesh()`

---

### IThingBlueMesh [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IThingBlueMesh`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 21
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IThingBlueMesh.java`

**Key Methods**:
  - `addGroup()`
  - `addSubDev()`
  - `addSubDev()`
  - `broadcastDps()`
  - `getDataByDpIds()`
  - `getMeshSubDevBean()`
  - `getMeshSubDevBeanByMac()`
  - `getMeshSubDevBeanByNodeId()`
  - `getMeshSubDevList()`
  - `groupDpReport()`
  - *(... and 11 more)*

---

### IThingBlueMeshActivator [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IThingBlueMeshActivator`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IThingBlueMeshActivator.java`

**Key Methods**:
  - `startActivator()`
  - `stopActivator()`

---

### IThingMeshGroup [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IThingMeshGroup`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 1
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IThingMeshGroup.java`

**Key Methods**:
  - `publishDps()`

---

### IThingRoomManager [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.IThingRoomManager`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\api\bluemesh\IThingRoomManager.java`

**Key Methods**:
  - `createRoom()`
  - `getRoomList()`

---

### IMeshAdvPreControl [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.advertise.IMeshAdvPreControl`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh.advertise`
- **Methods**: 8
- **Fields**: 0
- **Source**: `api\bluemesh\advertise\IMeshAdvPreControl.java`

**Key Methods**:
  - `flash()`
  - `flash()`
  - `off()`
  - `off()`
  - `m9on()`
  - `m10on()`
  - `reverse()`
  - `reverse()`

---

### IMeshAdvTransmitter [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.advertise.IMeshAdvTransmitter`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh.advertise`
- **Methods**: 1
- **Fields**: 0
- **Source**: `api\bluemesh\advertise\IMeshAdvTransmitter.java`

**Key Methods**:
  - `advertise()`

---

### GenericAction [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.message.GenericAction`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh.message`
- **Extends**: `MeshAction`
- **Methods**: 1
- **Fields**: 0
- **Source**: `api\bluemesh\message\GenericAction.java`

**Key Methods**:
  - `GenericAction()`

---

### GenericOnOffAction [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.message.GenericOnOffAction`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh.message`
- **Extends**: `GenericAction`
- **Methods**: 3
- **Fields**: 1
- **Source**: `api\bluemesh\message\GenericOnOffAction.java`

**Key Methods**:
  - `GenericOnOffAction()`
  - `isOpen()`
  - `GenericOnOffAction()`

---

### MeshAction [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.message.MeshAction`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh.message`
- **Methods**: 4
- **Fields**: 3
- **Source**: `api\bluemesh\message\MeshAction.java`

**Key Methods**:
  - `MeshAction()`
  - `getNodeId()`
  - `isAck()`
  - `isFastConfig()`

---

### SearchForGenericAction [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.message.SearchForGenericAction`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh.message`
- **Extends**: `GenericAction`
- **Methods**: 2
- **Fields**: 0
- **Source**: `api\bluemesh\message\SearchForGenericAction.java`

**Key Methods**:
  - `SearchForGenericAction()`
  - `SearchForGenericAction()`

---

### VendorAction [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.message.VendorAction`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh.message`
- **Extends**: `MeshAction`
- **Methods**: 17
- **Fields**: 21
- **Source**: `api\bluemesh\message\VendorAction.java`

**Key Methods**:
  - `build()`
  - `VendorAction()`
  - `setAck()`
  - `setBackOpCode()`
  - `setCompanyIdentifier()`
  - `setFastConfig()`
  - `setModelIdentifier()`
  - `setNodeId()`
  - `setOpCode()`
  - `setParameters()`
  - *(... and 7 more)*

---

### VendorDpAction [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.message.VendorDpAction`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh.message`
- **Extends**: `VendorAction`
- **Methods**: 10
- **Fields**: 12
- **Source**: `api\bluemesh\message\VendorDpAction.java`

**Key Methods**:
  - `build()`
  - `VendorDpAction()`
  - `setAck()`
  - `setDps()`
  - `setFastConfig()`
  - `setNodeId()`
  - `setSchemaBeanMap()`
  - `VendorDpAction()`
  - `getDps()`
  - `getSchemaBeanMap()`

---

### ISigMeshPreCtrl [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.precontrol.ISigMeshPreCtrl`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh.precontrol`
- **Extends**: `ISigMeshConnect`
- **Methods**: 2
- **Fields**: 0
- **Source**: `api\bluemesh\precontrol\ISigMeshPreCtrl.java`

**Key Methods**:
  - `searchForNodes()`
  - `switchOnOff()`

---

### PreCtrlProvision [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.bluemesh.precontrol.PreCtrlProvision`
- **Package**: `com.thingclips.smart.sdk.api.bluemesh.precontrol`
- **Methods**: 4
- **Fields**: 2
- **Source**: `api\bluemesh\precontrol\PreCtrlProvision.java`

**Key Methods**:
  - `getDefaultNodeId()`
  - `getSearchDeviceBean()`
  - `setDefaultNodeId()`
  - `setSearchDeviceBean()`

---

### ISmartCacheManager [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.api.cache.ISmartCacheManager`
- **Package**: `com.thingclips.smart.sdk.api.cache`
- **Methods**: 50
- **Fields**: 0
- **Source**: `sdk\api\cache\ISmartCacheManager.java`

**Key Methods**:
  - `clear()`
  - `get()`
  - `getKeys()`
  - `onDestroy()`
  - `put()`
  - `put()`
  - `remove()`
  - `clear()`
  - `clear()`
  - `get()`
  - *(... and 40 more)*

---

### BeaconMeshBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.BeaconMeshBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 6
- **Fields**: 3
- **Source**: `smart\sdk\bean\BeaconMeshBean.java`

**Key Methods**:
  - `getAppKey()`
  - `getId()`
  - `getMeshId()`
  - `setAppKey()`
  - `setId()`
  - `setMeshId()`

---

### BlueMeshBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.BlueMeshBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `IStorageCache`
- **Methods**: 23
- **Fields**: 11
- **Source**: `smart\sdk\bean\BlueMeshBean.java`

**Key Methods**:
  - `getCode()`
  - `getEndTime()`
  - `getKey()`
  - `getLocalKey()`
  - `getMeshId()`
  - `getName()`
  - `getPassword()`
  - `getPv()`
  - `getResptime()`
  - `getStartTime()`
  - *(... and 13 more)*

---

### BlueMeshGroupBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.BlueMeshGroupBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 10
- **Fields**: 5
- **Source**: `smart\sdk\bean\BlueMeshGroupBean.java`

**Key Methods**:
  - `getCategory()`
  - `getId()`
  - `getLocalId()`
  - `getName()`
  - `getTime()`
  - `setCategory()`
  - `setId()`
  - `setLocalId()`
  - `setName()`
  - `setTime()`

---

### BlueMeshModuleMapBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.BlueMeshModuleMapBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 4
- **Fields**: 2
- **Source**: `smart\sdk\bean\BlueMeshModuleMapBean.java`

**Key Methods**:
  - `getBluetooth()`
  - `getWifi()`
  - `setBluetooth()`
  - `setWifi()`

---

### BlueMeshRelationDevBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.BlueMeshRelationDevBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 6
- **Fields**: 3
- **Source**: `smart\sdk\bean\BlueMeshRelationDevBean.java`

**Key Methods**:
  - `getId()`
  - `getName()`
  - `getNodeId()`
  - `setId()`
  - `setName()`
  - `setNodeId()`

---

### BlueMeshRoomBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.BlueMeshRoomBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 6
- **Fields**: 3
- **Source**: `smart\sdk\bean\BlueMeshRoomBean.java`

**Key Methods**:
  - `getBackground()`
  - `getId()`
  - `getName()`
  - `setBackground()`
  - `setId()`
  - `setName()`

---

### BlueMeshShareBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.BlueMeshShareBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 12
- **Fields**: 6
- **Source**: `smart\sdk\bean\BlueMeshShareBean.java`

**Key Methods**:
  - `getEndTime()`
  - `getId()`
  - `getName()`
  - `getStartTime()`
  - `isShare()`
  - `isTempShare()`
  - `setEndTime()`
  - `setId()`
  - `setName()`
  - `setShare()`
  - *(... and 2 more)*

---

### BlueMeshSubDevBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.BlueMeshSubDevBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 62
- **Fields**: 31
- **Source**: `smart\sdk\bean\BlueMeshSubDevBean.java`

**Key Methods**:
  - `getActiveTime()`
  - `getAttribute()`
  - `getCategory()`
  - `getDevId()`
  - `getDisplayDps()`
  - `getDisplayMsgs()`
  - `getDps()`
  - `getFaultDps()`
  - `getI18nTime()`
  - `getIcon()`
  - *(... and 52 more)*

---

### BlueMeshWifiStatusBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.BlueMeshWifiStatusBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 8
- **Fields**: 4
- **Source**: `smart\sdk\bean\BlueMeshWifiStatusBean.java`

**Key Methods**:
  - `getBv()`
  - `getIsOnline()`
  - `getPv()`
  - `getVerSw()`
  - `setBv()`
  - `setIsOnline()`
  - `setPv()`
  - `setVerSw()`

---

### DeviceBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.DeviceBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 225
- **Fields**: 256
- **Source**: `smart\sdk\bean\DeviceBean.java`

**Key Methods**:
  - `getModule()`
  - `getUpgradeStatus()`
  - `setModule()`
  - `setUpgradeStatus()`
  - `DeviceBean()`
  - `getDeviceDespBean()`
  - `hasWifi()`
  - `getAbility()`
  - `getAccessType()`
  - `getAppRnVersion()`
  - *(... and 215 more)*

---

### GroupBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.GroupBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 54
- **Fields**: 38
- **Source**: `smart\sdk\bean\GroupBean.java`

**Key Methods**:
  - `getCategory()`
  - `getDevId()`
  - `getDevIds()`
  - `getDeviceBeans()`
  - `ArrayList()`
  - `getDeviceNum()`
  - `getDisplayOrder()`
  - `getDpCodes()`
  - `getDpName()`
  - `getDps()`
  - *(... and 44 more)*

---

### ProductBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.ProductBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `IStorageCache`
- **Methods**: 67
- **Fields**: 52
- **Source**: `smart\sdk\bean\ProductBean.java`

**Key Methods**:
  - `ConcurrentHashMap()`
  - `ConcurrentHashMap()`
  - `buildCodeSchema()`
  - `buildSchema()`
  - `getDpCodeSchemaMap()`
  - `HashMap()`
  - `getSchema()`
  - `getSchemaExt()`
  - `getSchemaMap()`
  - `setSchema()`
  - *(... and 57 more)*

---

### ShareIdBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.ShareIdBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 4
- **Fields**: 2
- **Source**: `smart\sdk\bean\ShareIdBean.java`

**Key Methods**:
  - `getDevIds()`
  - `getMeshIds()`
  - `setDevIds()`
  - `setMeshIds()`

---

### SigMeshBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.SigMeshBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Extends**: `BlueMeshBean`
- **Methods**: 12
- **Fields**: 2
- **Source**: `smart\sdk\bean\SigMeshBean.java`

**Key Methods**:
  - `getAppkey()`
  - `getMeshkey()`
  - `getIvIndex()`
  - `getMeshKey()`
  - `getMeshkey()`
  - `getNetWorkkey()`
  - `getName()`
  - `setAppkey()`
  - `setIvIndex()`
  - `setMeshKey()`
  - *(... and 2 more)*

---

### SubDeviceDpEvent [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.SubDeviceDpEvent`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 12
- **Fields**: 6
- **Source**: `smart\sdk\bean\SubDeviceDpEvent.java`

**Key Methods**:
  - `getDevId()`
  - `getDps()`
  - `getFromCloud()`
  - `getMeshId()`
  - `getNodeId()`
  - `getType()`
  - `setDevId()`
  - `setDps()`
  - `setFromCloud()`
  - `setMeshId()`
  - *(... and 2 more)*

---

### ThreadNetworkInfoBean [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.ThreadNetworkInfoBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 24
- **Fields**: 11
- **Source**: `smart\sdk\bean\ThreadNetworkInfoBean.java`

**Key Methods**:
  - `ThreadNetworkInfoBean()`
  - `getChannel()`
  - `getDataSet()`
  - `getDevId()`
  - `getExtendedPanId()`
  - `getLqi()`
  - `getMasterKey()`
  - `getMeshLocalPrefix()`
  - `getNetworkName()`
  - `getPanId()`
  - *(... and 14 more)*

**Notable Strings**:
  - `"MeshLocalPrefix"`
  - `", meshLocalPrefix='"`

---

### IBlueMeshProperty [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.cache.IBlueMeshProperty`
- **Package**: `com.thingclips.smart.sdk.bean.cache`
- **Methods**: 13
- **Fields**: 0
- **Source**: `sdk\bean\cache\IBlueMeshProperty.java`

**Key Methods**:
  - `getBlueMeshBean()`
  - `getCode()`
  - `getEndTime()`
  - `getKey()`
  - `getLocalKey()`
  - `getMeshId()`
  - `getName()`
  - `getPassword()`
  - `getPv()`
  - `getResptime()`
  - *(... and 3 more)*

---

### DevUpgradeStatus [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.cache.DevUpgradeStatus`
- **Package**: `com.thingclips.smart.sdk.bean.cache`
- **Methods**: 99
- **Fields**: 4
- **Source**: `sdk\bean\cache\IDeviceProperty.java`

**Key Methods**:
  - `getAbility()`
  - `getAppRnVersion()`
  - `getAttribute()`
  - `getBaseAttribute()`
  - `getBv()`
  - `getCadv()`
  - `getCategory()`
  - `getCategoryCode()`
  - `getCommunicationId()`
  - `getCommunicationOnline()`
  - *(... and 89 more)*

---

### IGroupProperty [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.cache.IGroupProperty`
- **Package**: `com.thingclips.smart.sdk.bean.cache`
- **Methods**: 23
- **Fields**: 0
- **Source**: `sdk\bean\cache\IGroupProperty.java`

**Key Methods**:
  - `getCategory()`
  - `getDevIds()`
  - `getDeviceBeans()`
  - `getDeviceNum()`
  - `getDisplayOrder()`
  - `getDpCodes()`
  - `getDpName()`
  - `getDps()`
  - `getGroupRespBean()`
  - `getHomeDisplayOrder()`
  - *(... and 13 more)*

---

### ISigMeshProperty [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.bean.cache.ISigMeshProperty`
- **Package**: `com.thingclips.smart.sdk.bean.cache`
- **Extends**: `IBlueMeshProperty`
- **Methods**: 2
- **Fields**: 0
- **Source**: `sdk\bean\cache\ISigMeshProperty.java`

**Key Methods**:
  - `getMeshKey()`
  - `getSigMeshBean()`

---

### ConnectStrategy [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.builder.ConnectStrategy`
- **Package**: `com.thingclips.smart.sdk.builder`
- **Methods**: 0
- **Fields**: 3
- **Source**: `smart\sdk\builder\ConnectStrategy.java`

---

### MeshConnectBuilder [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.builder.MeshConnectBuilder`
- **Package**: `com.thingclips.smart.sdk.builder`
- **Extends**: `SearchDeviceBean>`
- **Methods**: 20
- **Fields**: 24
- **Source**: `smart\sdk\builder\MeshConnectBuilder.java`

**Key Methods**:
  - `build()`
  - `MeshConnectBuilder()`
  - `setConnectStatusListener()`
  - `setConnectStrategy()`
  - `setDeviceList()`
  - `setNodeIds()`
  - `setScanTimeout()`
  - `setSearchDeviceBean()`
  - `setSigMeshBean()`
  - `setTTL()`
  - *(... and 10 more)*

---

### ActivatorMeshStepCode [CRITICAL]


- **Full Name**: `com.thingclips.smart.sdk.enums.ActivatorMeshStepCode`
- **Package**: `com.thingclips.smart.sdk.enums`
- **Methods**: 0
- **Fields**: 2
- **Source**: `smart\sdk\enums\ActivatorMeshStepCode.java`

---

### C0000R [HIGH]


- **Full Name**: `com.thingclips.smart.scene.api.C0000R`
- **Package**: `com.thingclips.smart.scene.api`
- **Methods**: 19
- **Fields**: 6213
- **Source**: `smart\scene\api\C0000R.java`

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

### IActionService [HIGH]


- **Full Name**: `com.thingclips.smart.scene.api.service.IActionService`
- **Package**: `com.thingclips.smart.scene.api.service`
- **Methods**: 8
- **Fields**: 0
- **Source**: `scene\api\service\IActionService.java`

**Key Methods**:
  - `getAddServiceAll()`
  - `getLinkShowLightScene()`
  - `getMobileInfo()`
  - `getMobileLeftTimes()`
  - `getSMSInfo()`
  - `getSMSLeftTimes()`
  - `getSupportSecurity()`
  - `onDestroy()`

---

### DefaultImpls [HIGH]


- **Full Name**: `com.thingclips.smart.scene.api.service.DefaultImpls`
- **Package**: `com.thingclips.smart.scene.api.service`
- **Methods**: 122
- **Fields**: 0
- **Source**: `scene\api\service\IAtopUrlConfig.java`

**Key Methods**:
  - `getBatchModifySceneRooms()`
  - `getDeleteBatchSceneData()`
  - `getDeleteScene()`
  - `getDeleteSceneWithHomeId()`
  - `getDisableAutomation()`
  - `getDislikeRecomScene()`
  - `getEnableAutomation()`
  - `getEnableAutomationWithTime()`
  - `getExecuteScene()`
  - `getGetActionDeviceAll()`
  - *(... and 112 more)*

---

### DefaultImpls [HIGH]


- **Full Name**: `com.thingclips.smart.scene.api.service.DefaultImpls`
- **Package**: `com.thingclips.smart.scene.api.service`
- **Methods**: 19
- **Fields**: 1
- **Source**: `scene\api\service\IBaseService.java`

**Key Methods**:
  - `UnsupportedOperationException()`
  - `deleteBatchSceneData()`
  - `deleteScene()`
  - `deleteSceneWithHomeId()`
  - `disableAutomation()`
  - `enableAutomation()`
  - `enableAutomationWithTime()`
  - `getCountLimit()`
  - `getHomeSimpleScenesByType()`
  - `getSceneALlMemberCache()`
  - *(... and 9 more)*

---

### DefaultImpls [HIGH]


- **Full Name**: `com.thingclips.smart.scene.api.service.DefaultImpls`
- **Package**: `com.thingclips.smart.scene.api.service`
- **Methods**: 7
- **Fields**: 0
- **Source**: `scene\api\service\IConditionService.java`

**Key Methods**:
  - `UnsupportedOperationException()`
  - `getConditionAll()`
  - `getLocalByCityId()`
  - `getLocalByCoordinate()`
  - `getLocalCityAll()`
  - `onDestroy()`
  - `reportPermissionAndLatlon()`

---

### DefaultImpls [HIGH]


- **Full Name**: `com.thingclips.smart.scene.api.service.DefaultImpls`
- **Package**: `com.thingclips.smart.scene.api.service`
- **Extends**: `Object>`
- **Methods**: 26
- **Fields**: 0
- **Source**: `scene\api\service\IExtService.java`

**Key Methods**:
  - `UnsupportedOperationException()`
  - `UnsupportedOperationException()`
  - `addGeofence()`
  - `addGidSid()`
  - `clearGidSid()`
  - `executeDeviceDp()`
  - `getDevice()`
  - `getDeviceCommunication()`
  - `getDeviceNodeId()`
  - `getGroupDevice()`
  - *(... and 16 more)*

---

### ILogService [HIGH]


- **Full Name**: `com.thingclips.smart.scene.api.service.ILogService`
- **Package**: `com.thingclips.smart.scene.api.service`
- **Methods**: 5
- **Fields**: 0
- **Source**: `scene\api\service\ILogService.java`

**Key Methods**:
  - `getDeviceLogAll()`
  - `getExecuteLogAll()`
  - `getExecuteLogDetail()`
  - `getSceneLogInfoAll()`
  - `onDestroy()`

---

### DefaultImpls [HIGH]


- **Full Name**: `com.thingclips.smart.scene.api.service.DefaultImpls`
- **Package**: `com.thingclips.smart.scene.api.service`
- **Methods**: 21
- **Fields**: 0
- **Source**: `scene\api\service\IRecommendService.java`

**Key Methods**:
  - `UnsupportedOperationException()`
  - `UnsupportedOperationException()`
  - `UnsupportedOperationException()`
  - `UnsupportedOperationException()`
  - `dislikeRecommend()`
  - `getCollectAll()`
  - `getHomeRecommend()`
  - `getOemProductUrl()`
  - `getProductUrl()`
  - `getRecommendAll()`
  - *(... and 11 more)*

---

### SceneChangeCallback [HIGH]


- **Full Name**: `com.thingclips.smart.scene.api.service.SceneChangeCallback`
- **Package**: `com.thingclips.smart.scene.api.service`
- **Methods**: 5
- **Fields**: 0
- **Source**: `scene\api\service\SceneChangeCallback.java`

**Key Methods**:
  - `onAddScene()`
  - `onDeleteScene()`
  - `onDisableScene()`
  - `onEnableScene()`
  - `onUpdateScene()`

---

### C0009R [HIGH]


- **Full Name**: `com.thingclips.smart.scene.execute.C0009R`
- **Package**: `com.thingclips.smart.scene.execute`
- **Methods**: 19
- **Fields**: 6213
- **Source**: `smart\scene\execute\C0009R.java`

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

### DeviceUtil [HIGH]


- **Full Name**: `com.thingclips.smart.scene.execute.DeviceUtil`
- **Package**: `com.thingclips.smart.scene.execute`
- **Methods**: 12
- **Fields**: 13
- **Source**: `smart\scene\execute\DeviceUtil.java`

**Key Methods**:
  - `DeviceUtil()`
  - `m73invoke()`
  - `DeviceUtil()`
  - `getDevice()`
  - `getSceneService()`
  - `getGroupDevice()`
  - `getSceneService()`
  - `getGroupDevices()`
  - `getSceneService()`
  - `getSceneService()`
  - *(... and 2 more)*

---

### ExecuteAnalysisUtil [HIGH]


- **Full Name**: `com.thingclips.smart.scene.execute.ExecuteAnalysisUtil`
- **Package**: `com.thingclips.smart.scene.execute`
- **Methods**: 21
- **Fields**: 38
- **Source**: `smart\scene\execute\ExecuteAnalysisUtil.java`

**Key Methods**:
  - `ExecuteAnalysisUtil()`
  - `m74invoke()`
  - `CopyOnWriteArrayList()`
  - `ExecuteAnalysisUtil()`
  - `getAnalysisService()`
  - `analysisActionExecuteResult()`
  - `LinkedHashMap()`
  - `if()`
  - `if()`
  - `if()`
  - *(... and 11 more)*

**Notable Strings**:
  - `", Integer.valueOf(BluetoothAdapter.getDefaultAdapter().isEnabled() ? 1 : 0));
            String target = executeActionInfoBean.getTarget();
            if (target != null) {
                linkedHashMap.put("`
  - `", Integer.valueOf(BluetoothAdapter.getDefaultAdapter().isEnabled() ? 1 : 0));
            StatService analysisService2 = INSTANCE.getAnalysisService();
            if (analysisService2 != null) {
                analysisService2.eventObjectMap(ANALYSIS_EXECUTE_RESULT, linkedHashMap);
            }
        }
    }

    public final void analysisExecuteStatus(@NotNull String sceneId, @NotNull ExecuteStatus executeStatus) {
        Intrinsics.checkNotNullParameter(sceneId, StateKey.SCENE_ID);
        Intrinsics.checkNotNullParameter(executeStatus, "`

---

### MonitorResultExtensionsKt [HIGH]


- **Full Name**: `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<ProducerScope<`
- **Methods**: 35
- **Fields**: 201
- **Source**: `smart\scene\execute\MonitorResultExtensionsKt$batchMonitorDeviceChangeFlow$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invokeSuspend()`
  - `LinkedHashMap()`
  - `LinkedHashMap()`
  - `ArrayList()`
  - `ArrayList()`
  - `ArrayList()`
  - `LinkedHashSet()`
  - `LinkedHashMap()`
  - *(... and 25 more)*

---

### MonitorResultExtensionsKt [HIGH]


- **Full Name**: `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<ProducerScope<`
- **Methods**: 21
- **Fields**: 78
- **Source**: `smart\scene\execute\MonitorResultExtensionsKt$monitorGroupChangeFlow$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invokeSuspend()`
  - `ArrayList()`
  - `ArrayList()`
  - `Timer()`
  - `run()`
  - `ArrayList()`
  - `LinkedHashSet()`
  - `method()`
  - *(... and 11 more)*

---

### SceneExecuteUseCase [HIGH]


- **Full Name**: `com.thingclips.smart.scene.execute.SceneExecuteUseCase`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `SceneAction>`
- **Methods**: 8
- **Fields**: 7
- **Source**: `smart\scene\execute\SceneExecuteUseCase.java`

**Key Methods**:
  - `SceneExecuteUseCase()`
  - `CancellableContinuationImpl()`
  - `IResultCallback()`
  - `onError()`
  - `onSuccess()`
  - `execute()`
  - `executeSceneOnCloud()`
  - `executeSceneOnCloudWithResult()`

---

### C0011R [HIGH]


- **Full Name**: `com.thingclips.smart.scene.lib.C0011R`
- **Package**: `com.thingclips.smart.scene.lib`
- **Methods**: 19
- **Fields**: 6213
- **Source**: `smart\scene\lib\C0011R.java`

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

### ThingNewScenePlugin [HIGH]


- **Full Name**: `com.thingclips.smart.scene.lib.ThingNewScenePlugin`
- **Package**: `com.thingclips.smart.scene.lib`
- **Extends**: `AbstractComponentService`
- **Implements**: `IThingNewScenePlugin`
- **Methods**: 3
- **Fields**: 0
- **Source**: `smart\scene\lib\ThingNewScenePlugin.java`

**Key Methods**:
  - `dependencies()`
  - `init()`
  - `sceneServiceInstance()`

---

### ApiConstantKt [HIGH]


- **Full Name**: `com.thingclips.smart.scene.lib.constant.ApiConstantKt`
- **Package**: `com.thingclips.smart.scene.lib.constant`
- **Methods**: 0
- **Fields**: 59
- **Source**: `scene\lib\constant\ApiConstantKt.java`

---

### SceneAtopUrlConfig [HIGH]


- **Full Name**: `com.thingclips.smart.scene.lib.service.SceneAtopUrlConfig`
- **Package**: `com.thingclips.smart.scene.lib.service`
- **Implements**: `IAtopUrlConfig`
- **Methods**: 124
- **Fields**: 123
- **Source**: `scene\lib\service\SceneAtopUrlConfig.java`

**Key Methods**:
  - `SceneAtopUrlConfig()`
  - `SceneAtopUrlConfig()`
  - `getBatchModifySceneRooms()`
  - `getDeleteBatchSceneData()`
  - `getDeleteScene()`
  - `getDeleteSceneWithHomeId()`
  - `getDisableAutomation()`
  - `getDislikeRecomScene()`
  - `getEnableAutomation()`
  - `getEnableAutomationWithTime()`
  - *(... and 114 more)*

---

### SceneFusionBusiness [HIGH]


- **Full Name**: `com.thingclips.smart.scene.lib.service.SceneFusionBusiness`
- **Package**: `com.thingclips.smart.scene.lib.service`
- **Extends**: `FusionBusiness`
- **Methods**: 6
- **Fields**: 6
- **Source**: `scene\lib\service\SceneFusionBusiness.java`

**Key Methods**:
  - `getHomeSceneListByType()`
  - `StringBuilder()`
  - `FusionApiParams()`
  - `LinkedHashMap()`
  - `JSONObject()`
  - `JSONObject()`

---

### ActionService [HIGH]


- **Full Name**: `com.thingclips.smart.scene.lib.service.action.ActionService`
- **Package**: `com.thingclips.smart.scene.lib.service.action`
- **Implements**: `IActionService`
- **Methods**: 25
- **Fields**: 16
- **Source**: `lib\service\action\ActionService.java`

**Key Methods**:
  - `ActionService()`
  - `SceneBusiness()`
  - `ActionService()`
  - `getAddServiceAll()`
  - `onFailure()`
  - `onSuccess()`
  - `getLinkShowLightScene()`
  - `onFailure()`
  - `onSuccess()`
  - `getMobileInfo()`
  - *(... and 15 more)*

---

### BaseService [HIGH]


- **Full Name**: `com.thingclips.smart.scene.lib.service.base.BaseService`
- **Package**: `com.thingclips.smart.scene.lib.service.base`
- **Implements**: `IBaseService`
- **Methods**: 62
- **Fields**: 57
- **Source**: `lib\service\base\BaseService.java`

**Key Methods**:
  - `BaseService()`
  - `SceneBusiness()`
  - `BaseService()`
  - `clientCorrectionSceneStatus()`
  - `deleteBatchSceneData()`
  - `onFailure()`
  - `onSuccess()`
  - `deleteScene()`
  - `onSuccess()`
  - `onFailure()`
  - *(... and 52 more)*

---

### ConditionService [HIGH]


- **Full Name**: `com.thingclips.smart.scene.lib.service.condition.ConditionService`
- **Package**: `com.thingclips.smart.scene.lib.service.condition`
- **Implements**: `IConditionService`
- **Methods**: 17
- **Fields**: 10
- **Source**: `lib\service\condition\ConditionService.java`

**Key Methods**:
  - `ConditionService()`
  - `SceneBusiness()`
  - `ConditionService()`
  - `getConditionAll()`
  - `onFailure()`
  - `onSuccess()`
  - `getLocalByCityId()`
  - `onFailure()`
  - `onSuccess()`
  - `getLocalByCoordinate()`
  - *(... and 7 more)*

---

### ExtService [HIGH]


- **Full Name**: `com.thingclips.smart.scene.lib.service.ext.ExtService`
- **Package**: `com.thingclips.smart.scene.lib.service.ext`
- **Extends**: `Object>`
- **Implements**: `IExtService`
- **Methods**: 35
- **Fields**: 10
- **Source**: `lib\service\ext\ExtService.java`

**Key Methods**:
  - `ExtService()`
  - `SceneBusiness()`
  - `ExtService()`
  - `addGeofence()`
  - `addGidSid()`
  - `clearGidSid()`
  - `executeDeviceDp()`
  - `getDevice()`
  - `getDeviceCommunication()`
  - `getDeviceNodeId()`
  - *(... and 25 more)*

---

### LogService [HIGH]


- **Full Name**: `com.thingclips.smart.scene.lib.service.log.LogService`
- **Package**: `com.thingclips.smart.scene.lib.service.log`
- **Implements**: `ILogService`
- **Methods**: 16
- **Fields**: 10
- **Source**: `lib\service\log\LogService.java`

**Key Methods**:
  - `LogService()`
  - `SceneBusiness()`
  - `LogService()`
  - `getDeviceLogAll()`
  - `onFailure()`
  - `onSuccess()`
  - `getExecuteLogAll()`
  - `onFailure()`
  - `onSuccess()`
  - `getExecuteLogDetail()`
  - *(... and 6 more)*

---

### RecommendService [HIGH]


- **Full Name**: `com.thingclips.smart.scene.lib.service.recommend.RecommendService`
- **Package**: `com.thingclips.smart.scene.lib.service.recommend`
- **Extends**: `DeviceRecommendScene.RecommendSceneData>>>`
- **Implements**: `IRecommendService`
- **Methods**: 56
- **Fields**: 34
- **Source**: `lib\service\recommend\RecommendService.java`

**Key Methods**:
  - `RecommendService()`
  - `SceneBusiness()`
  - `RecommendService()`
  - `dislikeRecommend()`
  - `onFailure()`
  - `onSuccess()`
  - `getCollectAll()`
  - `onFailure()`
  - `onSuccess()`
  - `getHomeRecommend()`
  - *(... and 46 more)*

---

### GeofenceUtil [HIGH]


- **Full Name**: `com.thingclips.smart.scene.lib.util.GeofenceUtil`
- **Package**: `com.thingclips.smart.scene.lib.util`
- **Methods**: 19
- **Fields**: 33
- **Source**: `scene\lib\util\GeofenceUtil.java`

**Key Methods**:
  - `GeofenceUtil()`
  - `m81invoke()`
  - `m82invoke()`
  - `GeofenceUtil()`
  - `getGeoFenceOperateService()`
  - `getGeoFenceService()`
  - `addGeofence()`
  - `LocationInfo()`
  - `OnThingGeoFenceStatusListener()`
  - `onFail()`
  - *(... and 9 more)*

---

### MqttSubscribeUtil [HIGH]


- **Full Name**: `com.thingclips.smart.scene.lib.util.MqttSubscribeUtil`
- **Package**: `com.thingclips.smart.scene.lib.util`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<ProducerScope<`
- **Methods**: 13
- **Fields**: 22
- **Source**: `scene\lib\util\MqttSubscribeUtil$loadSceneChange$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invokeSuspend()`
  - `onAddScene()`
  - `onDeleteScene()`
  - `onDisableScene()`
  - `onEnableScene()`
  - `onUpdateScene()`
  - `invoke()`
  - `m84invoke()`
  - *(... and 3 more)*

---

### C0021R [HIGH]


- **Full Name**: `com.thingclips.smart.scene.model.C0021R`
- **Package**: `com.thingclips.smart.scene.model`
- **Methods**: 18
- **Fields**: 5989
- **Source**: `smart\scene\model\C0021R.java`

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

### ServiceInfo [HIGH]


- **Full Name**: `com.thingclips.smart.scene.model.action.ServiceInfo`
- **Package**: `com.thingclips.smart.scene.model.action`
- **Implements**: `Serializable`
- **Methods**: 16
- **Fields**: 8
- **Source**: `scene\model\action\ServiceInfo.java`

**Key Methods**:
  - `getAttributeKey()`
  - `getAttributeSign()`
  - `getIconMini()`
  - `getIconV2()`
  - `getId()`
  - `getNameKey()`
  - `getRemark()`
  - `getUrl()`
  - `setAttributeKey()`
  - `setAttributeSign()`
  - *(... and 6 more)*

---

### ServiceLeftTime [HIGH]


- **Full Name**: `com.thingclips.smart.scene.model.action.ServiceLeftTime`
- **Package**: `com.thingclips.smart.scene.model.action`
- **Implements**: `Serializable`
- **Methods**: 8
- **Fields**: 4
- **Source**: `scene\model\action\ServiceLeftTime.java`

**Key Methods**:
  - `getExpireDate()`
  - `getPackageDesc()`
  - `getPackageStatus()`
  - `getRemainingTimes()`
  - `setExpireDate()`
  - `setPackageDesc()`
  - `setPackageStatus()`
  - `setRemainingTimes()`

---

### ServiceMember [HIGH]


- **Full Name**: `com.thingclips.smart.scene.model.action.ServiceMember`
- **Package**: `com.thingclips.smart.scene.model.action`
- **Implements**: `Serializable`
- **Methods**: 2
- **Fields**: 1
- **Source**: `scene\model\action\ServiceMember.java`

**Key Methods**:
  - `getUsername()`
  - `setUsername()`

---

### SMSServiceInfo [HIGH]


- **Full Name**: `com.thingclips.smart.scene.model.action.SMSServiceInfo`
- **Package**: `com.thingclips.smart.scene.model.action`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 2
- **Source**: `scene\model\action\SMSServiceInfo.java`

**Key Methods**:
  - `getPackageUser()`
  - `getUserList()`
  - `setPackageUser()`
  - `setUserList()`

---

### VoiceServiceInfo [HIGH]


- **Full Name**: `com.thingclips.smart.scene.model.action.VoiceServiceInfo`
- **Package**: `com.thingclips.smart.scene.model.action`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 2
- **Source**: `scene\model\action\VoiceServiceInfo.java`

**Key Methods**:
  - `getUserList()`
  - `getVoicePackageUser()`
  - `setUserList()`
  - `setVoicePackageUser()`

---

### Companion [HIGH]


- **Full Name**: `com.thingclips.smart.scene.model.constant.Companion`
- **Package**: `com.thingclips.smart.scene.model.constant`
- **Methods**: 5
- **Fields**: 4
- **Source**: `scene\model\constant\PushType.java`

**Key Methods**:
  - `Companion()`
  - `Companion()`
  - `getByValue()`
  - `getByValue()`
  - `getType()`

---

### C0025R [HIGH]


- **Full Name**: `com.thingclips.smart.scene.model.core.C0025R`
- **Package**: `com.thingclips.smart.scene.model.core`
- **Methods**: 18
- **Fields**: 5989
- **Source**: `scene\model\core\C0025R.java`

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

### BluetoothPermissionUtil [HIGH]


- **Full Name**: `com.thingclips.smart.sdk.BluetoothPermissionUtil`
- **Package**: `com.thingclips.smart.sdk`
- **Methods**: 3
- **Fields**: 15
- **Source**: `thingclips\smart\sdk\BluetoothPermissionUtil.java`

**Key Methods**:
  - `checkSelfPermission()`
  - `isBluetoothOpened()`
  - `putBluetoothPermissionLogStat()`

**Notable Strings**:
  - `"android.permission.BLUETOOTH"`
  - `"android.permission.BLUETOOTH_ADMIN"`
  - `"android.permission.BLUETOOTH_ADVERTISE"`
  - `"android.permission.BLUETOOTH_CONNECT"`
  - `"android.permission.BLUETOOTH_SCAN"`
  - *(... and 6 more)*

---

### ThingSdk [HIGH]


- **Full Name**: `com.thingclips.smart.sdk.ThingSdk`
- **Package**: `com.thingclips.smart.sdk`
- **Methods**: 42
- **Fields**: 33
- **Source**: `thingclips\smart\sdk\ThingSdk.java`

**Key Methods**:
  - `clearBaseConfig()`
  - `getApplication()`
  - `getDeviceCoreVersion()`
  - `getEventBus()`
  - `getFunCommonConfig()`
  - `getLatitude()`
  - `getLongitude()`
  - `getNeedLoginListener()`
  - `getNeedLoginWithDataListener()`
  - `getNeedLoginWithTypeListener()`
  - *(... and 32 more)*

---

### IDiscoveryServiceListener [HIGH]


- **Full Name**: `com.thingclips.smart.sdk.api.IDiscoveryServiceListener`
- **Package**: `com.thingclips.smart.sdk.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `smart\sdk\api\IDiscoveryServiceListener.java`

**Key Methods**:
  - `onError()`
  - `onServiceConnected()`

---

### IThingDeviceListManager [HIGH]


- **Full Name**: `com.thingclips.smart.sdk.api.IThingDeviceListManager`
- **Package**: `com.thingclips.smart.sdk.api`
- **Methods**: 68
- **Fields**: 0
- **Source**: `smart\sdk\api\IThingDeviceListManager.java`

**Key Methods**:
  - `addDev()`
  - `addDevList()`
  - `addProductList()`
  - `clearAllDeviceProductPanelInfo()`
  - `discoveredLanDevice()`
  - `getAllProductRefListFromLocal()`
  - `getAllStandardProductConfigsFromLocal()`
  - `getAuthPropertyByUUID()`
  - `getAuthPropertyByUUID()`
  - `getDev()`
  - *(... and 58 more)*

---

### C0036R [HIGH]


- **Full Name**: `com.thingclips.smart.sdk.bluetooth.api.C0036R`
- **Package**: `com.thingclips.smart.sdk.bluetooth.api`
- **Methods**: 15
- **Fields**: 1720
- **Source**: `sdk\bluetooth\api\C0036R.java`

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
  - *(... and 5 more)*

---

### C0037R [HIGH]


- **Full Name**: `com.thingclips.smart.sdk.bluetooth.business.api.C0037R`
- **Package**: `com.thingclips.smart.sdk.bluetooth.business.api`
- **Methods**: 18
- **Fields**: 5989
- **Source**: `bluetooth\business\api\C0037R.java`

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

### C0038R [HIGH]


- **Full Name**: `com.thingclips.smart.sdk.camera.api.C0038R`
- **Package**: `com.thingclips.smart.sdk.camera.api`
- **Methods**: 15
- **Fields**: 1751
- **Source**: `sdk\camera\api\C0038R.java`

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

### C0039R [HIGH]


- **Full Name**: `com.thingclips.smart.sdk.device.api.C0039R`
- **Package**: `com.thingclips.smart.sdk.device.api`
- **Methods**: 15
- **Fields**: 1751
- **Source**: `sdk\device\api\C0039R.java`

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

### C0042R [HIGH]


- **Full Name**: `com.thingclips.smart.sdk.hardware.business.api.C0042R`
- **Package**: `com.thingclips.smart.sdk.hardware.business.api`
- **Methods**: 18
- **Fields**: 5989
- **Source**: `hardware\business\api\C0042R.java`

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

### C0043R [HIGH]


- **Full Name**: `com.thingclips.smart.sdk.homelib.api.C0043R`
- **Package**: `com.thingclips.smart.sdk.homelib.api`
- **Methods**: 19
- **Fields**: 6213
- **Source**: `sdk\homelib\api\C0043R.java`

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

### IResultCallback [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.api.IResultCallback`
- **Package**: `com.thingclips.smart.scene.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `smart\scene\api\IResultCallback.java`

**Key Methods**:
  - `onError()`
  - `onSuccess()`

---

### ISceneService [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.api.ISceneService`
- **Package**: `com.thingclips.smart.scene.api`
- **Methods**: 13
- **Fields**: 0
- **Source**: `smart\scene\api\ISceneService.java`

**Key Methods**:
  - `actionService()`
  - `atopUrlConfig()`
  - `baseService()`
  - `conditionService()`
  - `deviceService()`
  - `executeService()`
  - `extService()`
  - `loadRecommendSceneUpdateFlow()`
  - `loadSceneChangeFlow()`
  - `loadSceneUpdateFlow()`
  - *(... and 3 more)*

---

### IThingNewScenePlugin [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.api.IThingNewScenePlugin`
- **Package**: `com.thingclips.smart.scene.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `smart\scene\api\IThingNewScenePlugin.java`

**Key Methods**:
  - `sceneServiceInstance()`

---

### IRestfulUrlConfig [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.api.service.IRestfulUrlConfig`
- **Package**: `com.thingclips.smart.scene.api.service`
- **Methods**: 2
- **Fields**: 0
- **Source**: `scene\api\service\IRestfulUrlConfig.java`

**Key Methods**:
  - `getGetHomeSceneAllByType()`
  - `setGetHomeSceneAllByType()`

---

### ExecuteNetUtils [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.ExecuteNetUtils`
- **Package**: `com.thingclips.smart.scene.execute`
- **Methods**: 4
- **Fields**: 15
- **Source**: `smart\scene\execute\ExecuteNetUtils.java`

**Key Methods**:
  - `ExecuteNetUtils()`
  - `ExecuteNetUtils()`
  - `isConnectedButNoInternet()`
  - `isConnectedViaWifi()`

---

### ExecuteSceneExtensionsKt [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.ExecuteSceneExtensionsKt`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `ContinuationImpl`
- **Methods**: 1
- **Fields**: 2
- **Source**: `smart\scene\execute\ExecuteSceneExtensionsKt$execute$1.java`

**Key Methods**:
  - `invokeSuspend()`

---

### ExecuteSceneExtensionsKt [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.ExecuteSceneExtensionsKt`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `ContinuationImpl`
- **Methods**: 1
- **Fields**: 4
- **Source**: `smart\scene\execute\ExecuteSceneExtensionsKt$executeOnlineScene$1.java`

**Key Methods**:
  - `invokeSuspend()`

---

### ExecuteSceneExtensionsKt [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.ExecuteSceneExtensionsKt`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `ContinuationImpl`
- **Methods**: 1
- **Fields**: 4
- **Source**: `smart\scene\execute\ExecuteSceneExtensionsKt$executeSceneOnCloudWithSupplement$1.java`

**Key Methods**:
  - `invokeSuspend()`

---

### ExecuteSceneExtensionsKt [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.ExecuteSceneExtensionsKt`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `ContinuationImpl`
- **Methods**: 1
- **Fields**: 4
- **Source**: `smart\scene\execute\ExecuteSceneExtensionsKt$executeSceneOnLocal$1.java`

**Key Methods**:
  - `invokeSuspend()`

---

### ExecuteSceneExtensionsKt [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.ExecuteSceneExtensionsKt`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `ContinuationImpl`
- **Methods**: 1
- **Fields**: 4
- **Source**: `smart\scene\execute\ExecuteSceneExtensionsKt$executeZigbeeSceneOnLocal$1.java`

**Key Methods**:
  - `invokeSuspend()`

---

### ExecuteUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.ExecuteUtil`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 7
- **Fields**: 8
- **Source**: `smart\scene\execute\ExecuteUtil$executeManual$1$executeResult$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invokeSuspend()`
  - `SceneExecuteUseCase()`
  - `IllegalStateException()`
  - `invoke()`
  - `create()`

---

### ExecuteUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.ExecuteUtil`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 6
- **Fields**: 5
- **Source**: `smart\scene\execute\ExecuteUtil$executeManual$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `invoke()`
  - `create()`

---

### ExecuteUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.ExecuteUtil`
- **Package**: `com.thingclips.smart.scene.execute`
- **Methods**: 4
- **Fields**: 4
- **Source**: `smart\scene\execute\ExecuteUtil.java`

**Key Methods**:
  - `ExecuteUtil()`
  - `ExecuteUtil()`
  - `executeManual()`
  - `executeManual()`

---

### MonitorResultExtensionsKt [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `SuspendLambda`
- **Implements**: `Function3<FlowCollector<`
- **Methods**: 4
- **Fields**: 1
- **Source**: `smart\scene\execute\MonitorResultExtensionsKt$batchMonitorDeviceChangeFlow$2.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `invoke()`

---

### MonitorResultExtensionsKt [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<FlowCollector<`
- **Methods**: 8
- **Fields**: 25
- **Source**: `smart\scene\execute\MonitorResultExtensionsKt$delayFlow$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invokeSuspend()`
  - `ActionExecuteResult()`
  - `ArrayList()`
  - `IllegalStateException()`
  - `invoke()`
  - `create()`

---

### MonitorResultExtensionsKt [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<FlowCollector<`
- **Methods**: 7
- **Fields**: 8
- **Source**: `smart\scene\execute\MonitorResultExtensionsKt$getInitialStateFlow$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invokeSuspend()`
  - `ArrayList()`
  - `IllegalStateException()`
  - `invoke()`
  - `create()`

---

### MonitorResultExtensionsKt [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `SuspendLambda`
- **Implements**: `Function3<FlowCollector<`
- **Methods**: 4
- **Fields**: 1
- **Source**: `smart\scene\execute\MonitorResultExtensionsKt$monitorGroupChangeFlow$2.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `invoke()`

---

### MonitorResultExtensionsKt [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<ProducerScope<`
- **Methods**: 16
- **Fields**: 62
- **Source**: `smart\scene\execute\MonitorResultExtensionsKt$monitorMqtt802Flow$1.java`

**Key Methods**:
  - `method()`
  - `StringBuilder()`
  - `ArrayList()`
  - `create()`
  - `invokeSuspend()`
  - `Timer()`
  - `run()`
  - `ArrayList()`
  - `IThingMqttRetainChannelListener()`
  - `onMessageReceived()`
  - *(... and 6 more)*

---

### MonitorResultExtensionsKt [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `SuspendLambda`
- **Implements**: `Function3<FlowCollector<`
- **Methods**: 4
- **Fields**: 1
- **Source**: `smart\scene\execute\MonitorResultExtensionsKt$monitorMqtt802Flow$2.java`

**Key Methods**:
  - `method()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `invoke()`

---

### MonitorResultExtensionsKt [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<FlowCollector<`
- **Methods**: 7
- **Fields**: 14
- **Source**: `smart\scene\execute\MonitorResultExtensionsKt$otherFlow$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invokeSuspend()`
  - `ArrayList()`
  - `IllegalStateException()`
  - `invoke()`
  - `create()`

---

### SceneExecuteUseCase [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.SceneExecuteUseCase`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `FunctionReferenceImpl`
- **Implements**: `Function3<String, List<`
- **Methods**: 1
- **Fields**: 0
- **Source**: `smart\scene\execute\SceneExecuteUseCase$execute$2.java`

**Key Methods**:
  - `invoke()`

---

### SceneExecuteUseCase [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.SceneExecuteUseCase`
- **Package**: `com.thingclips.smart.scene.execute`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<CoroutineScope, Continuation<`
- **Methods**: 6
- **Fields**: 7
- **Source**: `smart\scene\execute\SceneExecuteUseCase$executeSceneOnCloud$1.java`

**Key Methods**:
  - `method()`
  - `create()`
  - `invokeSuspend()`
  - `IllegalStateException()`
  - `invoke()`
  - `create()`

---

### ActionExecuteResult [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.model.ActionExecuteResult`
- **Package**: `com.thingclips.smart.scene.execute.model`
- **Methods**: 12
- **Fields**: 7
- **Source**: `scene\execute\model\ActionExecuteResult.java`

**Key Methods**:
  - `ActionExecuteResult()`
  - `getUnderDelay()`
  - `getAction()`
  - `getExecuteStatus()`
  - `copy()`
  - `ActionExecuteResult()`
  - `equals()`
  - `getAction()`
  - `getExecuteStatus()`
  - `getUnderDelay()`
  - *(... and 2 more)*

---

### ExecuteActionInfoBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.model.ExecuteActionInfoBean`
- **Package**: `com.thingclips.smart.scene.execute.model`
- **Methods**: 17
- **Fields**: 12
- **Source**: `scene\execute\model\ExecuteActionInfoBean.java`

**Key Methods**:
  - `ExecuteActionInfoBean()`
  - `getTarget()`
  - `getStatus()`
  - `getProtocol()`
  - `copy()`
  - `ExecuteActionInfoBean()`
  - `equals()`
  - `getProtocol()`
  - `getStatus()`
  - `getTarget()`
  - *(... and 7 more)*

---

### ExecuteScene [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.execute.model.ExecuteScene`
- **Package**: `com.thingclips.smart.scene.execute.model`
- **Extends**: `SceneAction>`
- **Methods**: 20
- **Fields**: 10
- **Source**: `scene\execute\model\ExecuteScene.java`

**Key Methods**:
  - `ExecuteScene()`
  - `getSceneId()`
  - `component2()`
  - `getNewLocalScene()`
  - `copy()`
  - `ExecuteScene()`
  - `equals()`
  - `getActions()`
  - `getDeviceValidation()`
  - `getGwId()`
  - *(... and 10 more)*

---

### SceneService [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.lib.SceneService`
- **Package**: `com.thingclips.smart.scene.lib`
- **Implements**: `ISceneService`
- **Methods**: 15
- **Fields**: 1
- **Source**: `smart\scene\lib\SceneService.java`

**Key Methods**:
  - `SceneService()`
  - `SceneService()`
  - `actionService()`
  - `atopUrlConfig()`
  - `baseService()`
  - `conditionService()`
  - `deviceService()`
  - `executeService()`
  - `extService()`
  - `loadRecommendSceneUpdateFlow()`
  - *(... and 5 more)*

---

### SceneRestfulUrlConfig [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.lib.service.SceneRestfulUrlConfig`
- **Package**: `com.thingclips.smart.scene.lib.service`
- **Implements**: `IRestfulUrlConfig`
- **Methods**: 4
- **Fields**: 3
- **Source**: `scene\lib\service\SceneRestfulUrlConfig.java`

**Key Methods**:
  - `SceneRestfulUrlConfig()`
  - `SceneRestfulUrlConfig()`
  - `getGetHomeSceneAllByType()`
  - `setGetHomeSceneAllByType()`

---

### MqttSubscribeUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.lib.util.MqttSubscribeUtil`
- **Package**: `com.thingclips.smart.scene.lib.util`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<ProducerScope<`
- **Methods**: 14
- **Fields**: 28
- **Source**: `scene\lib\util\MqttSubscribeUtil$loadRecommendSceneUpdate$1.java`

**Key Methods**:
  - `method()`
  - `C00141()`
  - `invoke()`
  - `m83invoke()`
  - `create()`
  - `invokeSuspend()`
  - `C0018b()`
  - `method()`
  - `C00141()`
  - `invoke()`
  - *(... and 4 more)*

---

### MqttSubscribeUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.lib.util.MqttSubscribeUtil`
- **Package**: `com.thingclips.smart.scene.lib.util`
- **Extends**: `SuspendLambda`
- **Implements**: `Function2<ProducerScope<`
- **Methods**: 14
- **Fields**: 33
- **Source**: `scene\lib\util\MqttSubscribeUtil$loadSceneUpdate$1.java`

**Key Methods**:
  - `method()`
  - `C00161()`
  - `invoke()`
  - `m85invoke()`
  - `create()`
  - `invokeSuspend()`
  - `C0018b()`
  - `method()`
  - `C00161()`
  - `invoke()`
  - *(... and 4 more)*

---

### MqttSubscribeUtil [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.lib.util.MqttSubscribeUtil`
- **Package**: `com.thingclips.smart.scene.lib.util`
- **Methods**: 6
- **Fields**: 6
- **Source**: `scene\lib\util\MqttSubscribeUtil.java`

**Key Methods**:
  - `MqttSubscribeUtil()`
  - `MqttSubscribeUtil()`
  - `getMqttChannelInstance()`
  - `loadRecommendSceneUpdate()`
  - `loadSceneChange()`
  - `loadSceneUpdate()`

---

### FusionPageNormalScenes [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.FusionPageNormalScenes`
- **Package**: `com.thingclips.smart.scene.model`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 2
- **Source**: `smart\scene\model\FusionPageNormalScenes.java`

**Key Methods**:
  - `getDatas()`
  - `getTotalCount()`
  - `setDatas()`
  - `setTotalCount()`

---

### NormalScene [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.NormalScene`
- **Package**: `com.thingclips.smart.scene.model`
- **Extends**: `ScopesLinkageRule<NormalSceneExtBean>`
- **Implements**: `Serializable`
- **Methods**: 93
- **Fields**: 23
- **Source**: `smart\scene\model\NormalScene.java`

**Key Methods**:
  - `NormalScene()`
  - `NormalSceneExtBean()`
  - `getActions()`
  - `ArrayList()`
  - `getArrowIconUrl()`
  - `getBackground()`
  - `getCategorys()`
  - `getConditions()`
  - `ArrayList()`
  - `getCoverIcon()`
  - *(... and 83 more)*

---

### NormalSceneExtBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.NormalSceneExtBean`
- **Package**: `com.thingclips.smart.scene.model`
- **Implements**: `Serializable`
- **Methods**: 40
- **Fields**: 20
- **Source**: `smart\scene\model\NormalSceneExtBean.java`

**Key Methods**:
  - `getArrowIconUrl()`
  - `getBackground()`
  - `getCategorys()`
  - `getCoverIcon()`
  - `getDisableTime()`
  - `getDisplayColor()`
  - `getGwId()`
  - `getLinkageType()`
  - `getOutOfWork()`
  - `getPanelType()`
  - *(... and 30 more)*

---

### PageNormalSceneReqParams [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.PageNormalSceneReqParams`
- **Package**: `com.thingclips.smart.scene.model`
- **Implements**: `Serializable`
- **Methods**: 10
- **Fields**: 4
- **Source**: `smart\scene\model\PageNormalSceneReqParams.java`

**Key Methods**:
  - `PageNormalSceneReqParams()`
  - `getPage()`
  - `getPageSize()`
  - `getRelationId()`
  - `getSceneType()`
  - `setPage()`
  - `setPageSize()`
  - `setRelationId()`
  - `setSceneType()`
  - `PageNormalSceneReqParams()`

---

### RecommendScene [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.RecommendScene`
- **Package**: `com.thingclips.smart.scene.model`
- **Implements**: `Serializable`
- **Methods**: 44
- **Fields**: 22
- **Source**: `smart\scene\model\RecommendScene.java`

**Key Methods**:
  - `getActions()`
  - `getAttribute()`
  - `getBackground()`
  - `getColor()`
  - `getConditions()`
  - `getCoverColor()`
  - `getCoverIcon()`
  - `getDisplayColor()`
  - `getEnabled()`
  - `getHotCount()`
  - *(... and 34 more)*

---

### ActionItem [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.action.ActionItem`
- **Package**: `com.thingclips.smart.scene.model.action`
- **Methods**: 19
- **Fields**: 12
- **Source**: `scene\model\action\ActionItem.java`

**Key Methods**:
  - `ActionItem()`
  - `getActionIcon()`
  - `getActionName()`
  - `getActionType()`
  - `getIsManual()`
  - `copy()`
  - `ActionItem()`
  - `equals()`
  - `getActionIcon()`
  - `getActionName()`
  - *(... and 9 more)*

---

### PushItemData [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.action.PushItemData`
- **Package**: `com.thingclips.smart.scene.model.action`
- **Methods**: 19
- **Fields**: 23
- **Source**: `scene\model\action\PushItemData.java`

**Key Methods**:
  - `PushItemData()`
  - `getPushType()`
  - `getChecked()`
  - `getShopUrl()`
  - `getLastTimes()`
  - `getUnableTip()`
  - `getContacts()`
  - `copy()`
  - `PushItemData()`
  - `equals()`
  - *(... and 9 more)*

---

### RelationGroup [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.action.RelationGroup`
- **Package**: `com.thingclips.smart.scene.model.action`
- **Implements**: `Serializable`
- **Methods**: 2
- **Fields**: 1
- **Source**: `scene\model\action\RelationGroup.java`

**Key Methods**:
  - `getGroups()`
  - `setGroups()`

---

### SceneAction [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.action.SceneAction`
- **Package**: `com.thingclips.smart.scene.model.action`
- **Extends**: `ScopesAction<SceneActionExtBean>`
- **Implements**: `Serializable`
- **Methods**: 62
- **Fields**: 16
- **Source**: `scene\model\action\SceneAction.java`

**Key Methods**:
  - `SceneAction()`
  - `SceneActionExtBean()`
  - `containStandardSceneInfo()`
  - `getActionDisplay()`
  - `getActionDisplayNew()`
  - `getActionExecutor()`
  - `getAction()`
  - `getAndroidUiInfo()`
  - `getConvertTemp()`
  - `getDefaultIconUrl()`
  - *(... and 52 more)*

---

### SceneActionExtBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.action.SceneActionExtBean`
- **Package**: `com.thingclips.smart.scene.model.action`
- **Implements**: `Serializable`
- **Methods**: 32
- **Fields**: 16
- **Source**: `scene\model\action\SceneActionExtBean.java`

**Key Methods**:
  - `getActionDisplay()`
  - `getActionDisplayNew()`
  - `getAndroidUiInfo()`
  - `getDefaultIconUrl()`
  - `getDeleteDevIcon()`
  - `getDevIcon()`
  - `getEntityName()`
  - `getI18nTime()`
  - `getPid()`
  - `getProductId()`
  - *(... and 22 more)*

---

### ConditionExtraInfo [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.condition.ConditionExtraInfo`
- **Package**: `com.thingclips.smart.scene.model.condition`
- **Implements**: `Serializable`
- **Methods**: 36
- **Fields**: 38
- **Source**: `scene\model\condition\ConditionExtraInfo.java`

**Key Methods**:
  - `createFromMap()`
  - `ConditionExtraInfo()`
  - `transferToMap()`
  - `HashMap()`
  - `getCalType()`
  - `getCenter()`
  - `getCityName()`
  - `getConvertTemp()`
  - `getDelayTime()`
  - `getDpScale()`
  - *(... and 26 more)*

---

### ConditionInnerProperty [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.condition.ConditionInnerProperty`
- **Package**: `com.thingclips.smart.scene.model.condition`
- **Implements**: `Serializable`
- **Methods**: 22
- **Fields**: 11
- **Source**: `scene\model\condition\ConditionInnerProperty.java`

**Key Methods**:
  - `getData()`
  - `getLoops()`
  - `getMax()`
  - `getMin()`
  - `getRange()`
  - `getScale()`
  - `getStep()`
  - `getTime()`
  - `getTimezoneId()`
  - `getType()`
  - *(... and 12 more)*

---

### ConditionItem [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.condition.ConditionItem`
- **Package**: `com.thingclips.smart.scene.model.condition`
- **Methods**: 20
- **Fields**: 16
- **Source**: `scene\model\condition\ConditionItem.java`

**Key Methods**:
  - `ConditionItem()`
  - `getConditionIcon()`
  - `getConditionName()`
  - `getConditionHint()`
  - `getType()`
  - `getDisable()`
  - `copy()`
  - `ConditionItem()`
  - `equals()`
  - `getConditionHint()`
  - *(... and 10 more)*

---

### ConditionItemDetail [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.condition.ConditionItemDetail`
- **Package**: `com.thingclips.smart.scene.model.condition`
- **Implements**: `Serializable`
- **Methods**: 26
- **Fields**: 13
- **Source**: `scene\model\condition\ConditionItemDetail.java`

**Key Methods**:
  - `getCondCalExtraInfo()`
  - `getEntityId()`
  - `getEntityName()`
  - `getEntitySubId()`
  - `getEntityType()`
  - `getId()`
  - `getMcGroups()`
  - `getName()`
  - `getNewIcon()`
  - `getOperators()`
  - *(... and 16 more)*

---

### ConditionItemList [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.condition.ConditionItemList`
- **Package**: `com.thingclips.smart.scene.model.condition`
- **Implements**: `Serializable`
- **Methods**: 6
- **Fields**: 3
- **Source**: `scene\model\condition\ConditionItemList.java`

**Key Methods**:
  - `getDevConds()`
  - `getEnvConds()`
  - `getSecurityConds()`
  - `setDevConds()`
  - `setEnvConds()`
  - `setSecurityConds()`

---

### ConditionOuterProperty [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.condition.ConditionOuterProperty`
- **Package**: `com.thingclips.smart.scene.model.condition`
- **Implements**: `Serializable`
- **Methods**: 20
- **Fields**: 10
- **Source**: `scene\model\condition\ConditionOuterProperty.java`

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

### DeviceData [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.condition.DeviceData`
- **Package**: `com.thingclips.smart.scene.model.condition`
- **Methods**: 13
- **Fields**: 7
- **Source**: `scene\model\condition\DeviceData.java`

**Key Methods**:
  - `DeviceData()`
  - `getEntityType()`
  - `getEntitySubId()`
  - `getEntityName()`
  - `copy()`
  - `DeviceData()`
  - `equals()`
  - `getEntityName()`
  - `getEntitySubId()`
  - `getEntityType()`
  - *(... and 3 more)*

---

### GeoPermissionProperty [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.condition.GeoPermissionProperty`
- **Package**: `com.thingclips.smart.scene.model.condition`
- **Implements**: `Serializable`
- **Methods**: 6
- **Fields**: 3
- **Source**: `scene\model\condition\GeoPermissionProperty.java`

**Key Methods**:
  - `getHasPositionPermission()`
  - `getLat()`
  - `getLon()`
  - `setHasPositionPermission()`
  - `setLat()`
  - `setLon()`

---

### LocationCity [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.condition.LocationCity`
- **Package**: `com.thingclips.smart.scene.model.condition`
- **Implements**: `Serializable`
- **Methods**: 12
- **Fields**: 5
- **Source**: `scene\model\condition\LocationCity.java`

**Key Methods**:
  - `LocationCity()`
  - `getArea()`
  - `getCity()`
  - `getCityId()`
  - `getPinyin()`
  - `getProvince()`
  - `setArea()`
  - `setCity()`
  - `setCityId()`
  - `setPinyin()`
  - *(... and 2 more)*

---

### LockDeviceMember [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.condition.LockDeviceMember`
- **Package**: `com.thingclips.smart.scene.model.condition`
- **Methods**: 15
- **Fields**: 16
- **Source**: `scene\model\condition\LockDeviceMember.java`

**Key Methods**:
  - `LockDeviceMember()`
  - `getMemberAvatar()`
  - `getMemberName()`
  - `getMemberId()`
  - `getChecked()`
  - `copy()`
  - `LockDeviceMember()`
  - `equals()`
  - `getChecked()`
  - `getMemberAvatar()`
  - *(... and 5 more)*

---

### NewMCGroup [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.condition.NewMCGroup`
- **Package**: `com.thingclips.smart.scene.model.condition`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 2
- **Source**: `scene\model\condition\NewMCGroup.java`

**Key Methods**:
  - `getGroupName()`
  - `getId()`
  - `setGroupName()`
  - `setId()`

---

### SceneCondition [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.condition.SceneCondition`
- **Package**: `com.thingclips.smart.scene.model.condition`
- **Extends**: `ScopesCondition<SceneConditionExtBean>`
- **Implements**: `Serializable`
- **Methods**: 41
- **Fields**: 1
- **Source**: `scene\model\condition\SceneCondition.java`

**Key Methods**:
  - `SceneCondition()`
  - `SceneConditionExtBean()`
  - `getCondType()`
  - `getCondition()`
  - `getDefaultIconUrl()`
  - `getDeleteDevIcon()`
  - `getEntityId()`
  - `getCondition()`
  - `getEntityName()`
  - `getEntitySubIds()`
  - *(... and 31 more)*

---

### SceneConditionExtBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.condition.SceneConditionExtBean`
- **Package**: `com.thingclips.smart.scene.model.condition`
- **Implements**: `Serializable`
- **Methods**: 16
- **Fields**: 8
- **Source**: `scene\model\condition\SceneConditionExtBean.java`

**Key Methods**:
  - `getDefaultIconUrl()`
  - `getDeleteDevIcon()`
  - `getEntityName()`
  - `getExprDisplay()`
  - `getIconUrl()`
  - `getProductId()`
  - `getProductPic()`
  - `isDevDelMark()`
  - `setDefaultIconUrl()`
  - `setDeleteDevIcon()`
  - *(... and 6 more)*

---

### WeatherData [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.condition.WeatherData`
- **Package**: `com.thingclips.smart.scene.model.condition`
- **Methods**: 22
- **Fields**: 15
- **Source**: `scene\model\condition\WeatherData.java`

**Key Methods**:
  - `WeatherData()`
  - `getEntityType()`
  - `getEntitySubId()`
  - `getIcon()`
  - `getDatapointType()`
  - `getEntityName()`
  - `getValueData()`
  - `component7()`
  - `getSceneCondition()`
  - `copy()`
  - *(... and 12 more)*

---

### WeatherEnumData [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.condition.WeatherEnumData`
- **Package**: `com.thingclips.smart.scene.model.condition`
- **Methods**: 15
- **Fields**: 13
- **Source**: `scene\model\condition\WeatherEnumData.java`

**Key Methods**:
  - `WeatherEnumData()`
  - `getWeatherSubType()`
  - `getWeatherName()`
  - `getSunTimer()`
  - `getChecked()`
  - `copy()`
  - `WeatherEnumData()`
  - `equals()`
  - `getChecked()`
  - `getSunTimer()`
  - *(... and 5 more)*

---

### WeatherValueData [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.condition.WeatherValueData`
- **Package**: `com.thingclips.smart.scene.model.condition`
- **Methods**: 20
- **Fields**: 14
- **Source**: `scene\model\condition\WeatherValueData.java`

**Key Methods**:
  - `WeatherValueData()`
  - `getValue()`
  - `component2()`
  - `getUnit()`
  - `getMin()`
  - `getMax()`
  - `getStep()`
  - `copy()`
  - `WeatherValueData()`
  - `equals()`
  - *(... and 10 more)*

---

### ActionConstantKt [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.constant.ActionConstantKt`
- **Package**: `com.thingclips.smart.scene.model.constant`
- **Methods**: 7
- **Fields**: 30
- **Source**: `scene\model\constant\ActionConstantKt.java`

**Key Methods**:
  - `getAutomationTypeArray()`
  - `getDeviceTypeActionArray()`
  - `getLocalExecuteArray()`
  - `getNewLocalExecuteArray()`
  - `getNotExecuteArray()`
  - `getPushTypeArray()`
  - `getSceneTypeArray()`

---

### Companion [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.constant.Companion`
- **Package**: `com.thingclips.smart.scene.model.constant`
- **Methods**: 5
- **Fields**: 5
- **Source**: `scene\model\constant\ConditionMatch.java`

**Key Methods**:
  - `Companion()`
  - `Companion()`
  - `getByValue()`
  - `getByValue()`
  - `getType()`

---

### Companion [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.constant.Companion`
- **Package**: `com.thingclips.smart.scene.model.constant`
- **Methods**: 5
- **Fields**: 4
- **Source**: `scene\model\constant\DatapointType.java`

**Key Methods**:
  - `Companion()`
  - `Companion()`
  - `getByValue()`
  - `getByValue()`
  - `getType()`

---

### Companion [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.constant.Companion`
- **Package**: `com.thingclips.smart.scene.model.constant`
- **Methods**: 5
- **Fields**: 5
- **Source**: `scene\model\constant\ExecuteDetailStatus.java`

**Key Methods**:
  - `Companion()`
  - `Companion()`
  - `getByValue()`
  - `getByValue()`
  - `getValue()`

---

### Companion [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.constant.Companion`
- **Package**: `com.thingclips.smart.scene.model.constant`
- **Methods**: 5
- **Fields**: 5
- **Source**: `scene\model\constant\ExecuteResult.java`

**Key Methods**:
  - `Companion()`
  - `Companion()`
  - `getByValue()`
  - `getByValue()`
  - `getValue()`

---

### Companion [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.constant.Companion`
- **Package**: `com.thingclips.smart.scene.model.constant`
- **Methods**: 4
- **Fields**: 4
- **Source**: `scene\model\constant\PanelType.java`

**Key Methods**:
  - `Companion()`
  - `Companion()`
  - `getByValue()`
  - `getByValue()`

---

### Companion [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.constant.Companion`
- **Package**: `com.thingclips.smart.scene.model.constant`
- **Methods**: 5
- **Fields**: 4
- **Source**: `scene\model\constant\RunMode.java`

**Key Methods**:
  - `Companion()`
  - `Companion()`
  - `getByValue()`
  - `getByValue()`
  - `getMode()`

---

### Companion [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.constant.Companion`
- **Package**: `com.thingclips.smart.scene.model.constant`
- **Methods**: 5
- **Fields**: 5
- **Source**: `scene\model\constant\SceneStatusType.java`

**Key Methods**:
  - `Companion()`
  - `Companion()`
  - `getByValue()`
  - `getByValue()`
  - `getType()`

---

### Companion [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.constant.Companion`
- **Package**: `com.thingclips.smart.scene.model.constant`
- **Methods**: 5
- **Fields**: 5
- **Source**: `scene\model\constant\SceneType.java`

**Key Methods**:
  - `Companion()`
  - `Companion()`
  - `getByValue()`
  - `getByValue()`
  - `getType()`

---

### removed [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.constant.removed`
- **Package**: `com.thingclips.smart.scene.model.constant`
- **Methods**: 10
- **Fields**: 5
- **Source**: `scene\model\constant\WeatherType.java`

**Key Methods**:
  - `WeatherType()`
  - `Companion()`
  - `Companion()`
  - `getByType()`
  - `getValueTypeArray()`
  - `WeatherType()`
  - `getByType()`
  - `valueOf()`
  - `values()`
  - `getType()`

---

### ValidateSceneResultBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.constant.createSceneType.ValidateSceneResultBean`
- **Package**: `com.thingclips.smart.scene.model.constant.createSceneType`
- **Implements**: `Serializable`
- **Methods**: 15
- **Fields**: 9
- **Source**: `model\constant\createSceneType\ValidateSceneResultBean.java`

**Key Methods**:
  - `ValidateSceneResultBean()`
  - `component1()`
  - `component2()`
  - `getActionType()`
  - `copy()`
  - `ValidateSceneResultBean()`
  - `equals()`
  - `getActionType()`
  - `getFailTasks()`
  - `getSuccessTasks()`
  - *(... and 5 more)*

---

### ValidateSceneResultItemBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.constant.createSceneType.ValidateSceneResultItemBean`
- **Package**: `com.thingclips.smart.scene.model.constant.createSceneType`
- **Methods**: 12
- **Fields**: 11
- **Source**: `model\constant\createSceneType\ValidateSceneResultItemBean.java`

**Key Methods**:
  - `ValidateSceneResultItemBean()`
  - `getSceneAction()`
  - `getSuccess()`
  - `getErrMsgRes()`
  - `copy()`
  - `ValidateSceneResultItemBean()`
  - `equals()`
  - `getErrMsgRes()`
  - `getSceneAction()`
  - `getSuccess()`
  - *(... and 2 more)*

---

### ActionDeviceDataPointDetail [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.ActionDeviceDataPointDetail`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Implements**: `Serializable`
- **Methods**: 30
- **Fields**: 15
- **Source**: `scene\model\device\ActionDeviceDataPointDetail.java`

**Key Methods**:
  - `getColorType()`
  - `getDefaultValue()`
  - `getDpCode()`
  - `getDpId()`
  - `getDpName()`
  - `getDpProperty()`
  - `getId()`
  - `getMode()`
  - `getStepHighDpProperty()`
  - `getStepLowDpProperty()`
  - *(... and 20 more)*

---

### ActionDeviceDataPointList [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.ActionDeviceDataPointList`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Implements**: `Serializable`
- **Methods**: 14
- **Fields**: 7
- **Source**: `scene\model\device\ActionDeviceDataPointList.java`

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

### ActionDeviceGroup [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.ActionDeviceGroup`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Implements**: `Serializable`
- **Methods**: 7
- **Fields**: 3
- **Source**: `scene\model\device\ActionDeviceGroup.java`

**Key Methods**:
  - `ActionDeviceGroup()`
  - `getDevices()`
  - `getExts()`
  - `getGroups()`
  - `setDevices()`
  - `setExts()`
  - `setGroups()`

---

### ActionDeviceGroupId [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.ActionDeviceGroupId`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Implements**: `Serializable`
- **Methods**: 6
- **Fields**: 3
- **Source**: `scene\model\device\ActionDeviceGroupId.java`

**Key Methods**:
  - `getDeviceIds()`
  - `getExts()`
  - `getGroupIds()`
  - `setDeviceIds()`
  - `setExts()`
  - `setGroupIds()`

---

### BleIotData [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.BleIotData`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Methods**: 15
- **Fields**: 8
- **Source**: `scene\model\device\BleIotData.java`

**Key Methods**:
  - `BleIotData()`
  - `getActionType()`
  - `component2()`
  - `getSubCmd()`
  - `getPacketMaxSize()`
  - `copy()`
  - `BleIotData()`
  - `equals()`
  - `getActionType()`
  - `getData()`
  - *(... and 5 more)*

---

### CategoryChooseItem [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.CategoryChooseItem`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Methods**: 13
- **Fields**: 10
- **Source**: `scene\model\device\CategoryChooseItem.java`

**Key Methods**:
  - `CategoryChooseItem()`
  - `getCategoryName()`
  - `getCategoryId()`
  - `getChoose()`
  - `copy()`
  - `CategoryChooseItem()`
  - `equals()`
  - `getCategoryId()`
  - `getCategoryName()`
  - `getChoose()`
  - *(... and 3 more)*

---

### DeviceActionData [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.DeviceActionData`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Implements**: `Serializable`
- **Methods**: 27
- **Fields**: 13
- **Source**: `scene\model\device\DeviceActionData.java`

**Key Methods**:
  - `DeviceActionData()`
  - `getDatapointType()`
  - `getDpEnumTypeData()`
  - `getDpId()`
  - `getDpName()`
  - `getDpValueType()`
  - `getDpValueTypeData()`
  - `getEditable()`
  - `getId()`
  - `getLightType()`
  - *(... and 17 more)*

---

### DeviceActionDetailBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.DeviceActionDetailBean`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Methods**: 34
- **Fields**: 17
- **Source**: `scene\model\device\DeviceActionDetailBean.java`

**Key Methods**:
  - `DeviceActionDetailBean()`
  - `getAdvancedFunctions()`
  - `getAppletCode()`
  - `getCurrentValue()`
  - `getDeviceActionDataList()`
  - `getDeviceId()`
  - `getDeviceType()`
  - `getEntityId()`
  - `getFunctionId()`
  - `getFunctionName()`
  - *(... and 24 more)*

---

### DeviceChooseItem [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.DeviceChooseItem`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Methods**: 16
- **Fields**: 11
- **Source**: `scene\model\device\DeviceChooseItem.java`

**Key Methods**:
  - `DeviceChooseItem()`
  - `getType()`
  - `getDeviceName()`
  - `getDeviceId()`
  - `getDeviceIcon()`
  - `getDeviceType()`
  - `copy()`
  - `DeviceChooseItem()`
  - `equals()`
  - `getDeviceIcon()`
  - *(... and 6 more)*

---

### DeviceChooseParams [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.DeviceChooseParams`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Methods**: 21
- **Fields**: 24
- **Source**: `scene\model\device\DeviceChooseParams.java`

**Key Methods**:
  - `DeviceChooseParams()`
  - `getConditionType()`
  - `getConditionGenre()`
  - `getZigbeeDevId()`
  - `getOperateSchema()`
  - `getIsFromRn()`
  - `getBizType()`
  - `getRoomId()`
  - `copy()`
  - `DeviceChooseParams()`
  - *(... and 11 more)*

---

### DeviceConditionData [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.DeviceConditionData`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Extends**: `NewMCGroup>`
- **Methods**: 31
- **Fields**: 23
- **Source**: `scene\model\device\DeviceConditionData.java`

**Key Methods**:
  - `DeviceConditionData()`
  - `getDeviceId()`
  - `component10()`
  - `getDatapointType()`
  - `getDatapointId()`
  - `getDatapointName()`
  - `getDeviceIcon()`
  - `getValueTypeData()`
  - `component7()`
  - `getEntityType()`
  - *(... and 21 more)*

---

### DpEnumTypeData [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.DpEnumTypeData`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Implements**: `Serializable`
- **Methods**: 6
- **Fields**: 3
- **Source**: `scene\model\device\DpEnumTypeData.java`

**Key Methods**:
  - `getCurrentIndex()`
  - `getValue()`
  - `getValueKey()`
  - `setCurrentIndex()`
  - `setValue()`
  - `setValueKey()`

---

### DpValueTypeData [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.DpValueTypeData`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Implements**: `Serializable`
- **Methods**: 12
- **Fields**: 6
- **Source**: `scene\model\device\DpValueTypeData.java`

**Key Methods**:
  - `getCurrentValueKey()`
  - `getMax()`
  - `getMin()`
  - `getScale()`
  - `getStep()`
  - `getUnit()`
  - `setCurrentValueKey()`
  - `setMax()`
  - `setMin()`
  - `setScale()`
  - *(... and 2 more)*

---

### FaceDeviceMember [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.FaceDeviceMember`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Implements**: `Serializable`
- **Methods**: 8
- **Fields**: 4
- **Source**: `scene\model\device\FaceDeviceMember.java`

**Key Methods**:
  - `getId()`
  - `getName()`
  - `getPath()`
  - `getType()`
  - `setId()`
  - `setName()`
  - `setPath()`
  - `setType()`

---

### InfraredUiData [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.InfraredUiData`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 2
- **Source**: `scene\model\device\InfraredUiData.java`

**Key Methods**:
  - `getAndroid_online()`
  - `getId()`
  - `setAndroid_online()`
  - `setId()`

---

### IrPanelExtBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.IrPanelExtBean`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Implements**: `Serializable`
- **Methods**: 10
- **Fields**: 5
- **Source**: `scene\model\device\IrPanelExtBean.java`

**Key Methods**:
  - `getAndroidUiInfo()`
  - `getI18nTime()`
  - `getPid()`
  - `getUiInfo()`
  - `getUiid()`
  - `setAndroidUiInfo()`
  - `setI18nTime()`
  - `setPid()`
  - `setUiInfo()`
  - `setUiid()`

---

### OtherTypeData [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.OtherTypeData`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Methods**: 17
- **Fields**: 19
- **Source**: `scene\model\device\OtherTypeData.java`

**Key Methods**:
  - `OtherTypeData()`
  - `getDatapointKey()`
  - `getDatapointOption()`
  - `getChecked()`
  - `getVirtualItem()`
  - `getDurationTime()`
  - `copy()`
  - `OtherTypeData()`
  - `equals()`
  - `getChecked()`
  - *(... and 7 more)*

---

### SceneValidateResultBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.SceneValidateResultBean`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Implements**: `Serializable`
- **Methods**: 9
- **Fields**: 3
- **Source**: `scene\model\device\SceneValidateResultBean.java`

**Key Methods**:
  - `SceneValidateResultBean()`
  - `getFailTasks()`
  - `getSuccessTasks()`
  - `getType()`
  - `setFailTasks()`
  - `setSuccessTasks()`
  - `setType()`
  - `SceneValidateResultBean()`
  - `SceneValidateResultBean()`

---

### SceneZigbeeValidateDialogBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.SceneZigbeeValidateDialogBean`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Methods**: 11
- **Fields**: 6
- **Source**: `scene\model\device\SceneZigbeeValidateDialogBean.java`

**Key Methods**:
  - `SceneZigbeeValidateDialogBean()`
  - `getSceneAction()`
  - `getErrCode()`
  - `copy()`
  - `SceneZigbeeValidateDialogBean()`
  - `equals()`
  - `getErrCode()`
  - `getSceneAction()`
  - `hashCode()`
  - `toString()`
  - *(... and 1 more)*

---

### SchemaExt [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.SchemaExt`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Implements**: `Serializable`
- **Methods**: 6
- **Fields**: 3
- **Source**: `scene\model\device\SchemaExt.java`

**Key Methods**:
  - `getId()`
  - `getInputStyle()`
  - `getInputType()`
  - `setId()`
  - `setInputStyle()`
  - `setInputType()`

---

### StandardSceneInfo [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.StandardSceneInfo`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Implements**: `Serializable`
- **Methods**: 9
- **Fields**: 3
- **Source**: `scene\model\device\StandardSceneInfo.java`

**Key Methods**:
  - `StandardSceneInfo()`
  - `getGid()`
  - `getGwId()`
  - `getSid()`
  - `setGid()`
  - `setGwId()`
  - `setSid()`
  - `StandardSceneInfo()`
  - `StandardSceneInfo()`

---

### StepDpProperty [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.StepDpProperty`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Implements**: `Serializable`
- **Methods**: 2
- **Fields**: 1
- **Source**: `scene\model\device\StepDpProperty.java`

**Key Methods**:
  - `getValue()`
  - `setValue()`

---

### ValueTypeData [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.ValueTypeData`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Methods**: 22
- **Fields**: 16
- **Source**: `scene\model\device\ValueTypeData.java`

**Key Methods**:
  - `ValueTypeData()`
  - `getValue()`
  - `component2()`
  - `getUnit()`
  - `getMin()`
  - `getScale()`
  - `getMax()`
  - `getStep()`
  - `copy()`
  - `ValueTypeData()`
  - *(... and 12 more)*

---

### WholeHouseDeviceGroupIds [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.device.WholeHouseDeviceGroupIds`
- **Package**: `com.thingclips.smart.scene.model.device`
- **Implements**: `Serializable`
- **Methods**: 6
- **Fields**: 3
- **Source**: `scene\model\device\WholeHouseDeviceGroupIds.java`

**Key Methods**:
  - `getDeviceIds()`
  - `getExts()`
  - `getGroupIds()`
  - `setDeviceIds()`
  - `setExts()`
  - `setGroupIds()`

---

### PreCondition [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.edit.PreCondition`
- **Package**: `com.thingclips.smart.scene.model.edit`
- **Extends**: `ScopesPreCondition<PreConditionExtBean>`
- **Implements**: `Serializable`
- **Methods**: 11
- **Fields**: 2
- **Source**: `scene\model\edit\PreCondition.java`

**Key Methods**:
  - `PreCondition()`
  - `PreConditionExtBean()`
  - `getCondType()`
  - `getPreC()`
  - `getExpr()`
  - `getId()`
  - `getPreC()`
  - `setCondType()`
  - `setExpr()`
  - `setId()`
  - *(... and 1 more)*

---

### PreConditionExpr [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.edit.PreConditionExpr`
- **Package**: `com.thingclips.smart.scene.model.edit`
- **Implements**: `Serializable`
- **Methods**: 18
- **Fields**: 12
- **Source**: `scene\model\edit\PreConditionExpr.java`

**Key Methods**:
  - `createFromMap()`
  - `PreConditionExpr()`
  - `transferToMap()`
  - `HashMap()`
  - `getCityId()`
  - `getCityName()`
  - `getEnd()`
  - `getLoops()`
  - `getStart()`
  - `getTimeInterval()`
  - *(... and 8 more)*

---

### PreConditionExtBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.edit.PreConditionExtBean`
- **Package**: `com.thingclips.smart.scene.model.edit`
- **Implements**: `Serializable`
- **Methods**: 0
- **Fields**: 0
- **Source**: `scene\model\edit\PreConditionExtBean.java`

---

### SceneStyle [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.edit.SceneStyle`
- **Package**: `com.thingclips.smart.scene.model.edit`
- **Implements**: `Serializable`
- **Methods**: 6
- **Fields**: 3
- **Source**: `scene\model\edit\SceneStyle.java`

**Key Methods**:
  - `getCoverColors()`
  - `getCoverIconList()`
  - `getCoverPics()`
  - `setCoverColors()`
  - `setCoverIconList()`
  - `setCoverPics()`

---

### BannerList [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.ext.BannerList`
- **Package**: `com.thingclips.smart.scene.model.ext`
- **Implements**: `Serializable`
- **Methods**: 2
- **Fields**: 1
- **Source**: `scene\model\ext\BannerList.java`

**Key Methods**:
  - `getBannerLeadList()`
  - `setBannerLeadList()`

---

### CountLimit [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.ext.CountLimit`
- **Package**: `com.thingclips.smart.scene.model.ext`
- **Implements**: `Serializable`
- **Methods**: 8
- **Fields**: 4
- **Source**: `scene\model\ext\CountLimit.java`

**Key Methods**:
  - `getAutomationCount()`
  - `getAutomationLimit()`
  - `getSceneCount()`
  - `getSceneLimit()`
  - `setAutomationCount()`
  - `setAutomationLimit()`
  - `setSceneCount()`
  - `setSceneLimit()`

---

### GuideBanner [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.ext.GuideBanner`
- **Package**: `com.thingclips.smart.scene.model.ext`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 2
- **Source**: `scene\model\ext\GuideBanner.java`

**Key Methods**:
  - `getContext()`
  - `getIconUrl()`
  - `setContext()`
  - `setIconUrl()`

---

### ProductUrl [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.ext.ProductUrl`
- **Package**: `com.thingclips.smart.scene.model.ext`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 2
- **Source**: `scene\model\ext\ProductUrl.java`

**Key Methods**:
  - `getCommodityStatus()`
  - `getPath()`
  - `setCommodityStatus()`
  - `setPath()`

---

### PublicProductUrl [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.ext.PublicProductUrl`
- **Package**: `com.thingclips.smart.scene.model.ext`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 2
- **Source**: `scene\model\ext\PublicProductUrl.java`

**Key Methods**:
  - `getJumpUrl()`
  - `isAccess()`
  - `setAccess()`
  - `setJumpUrl()`

---

### GeoFilterProperty [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.home.GeoFilterProperty`
- **Package**: `com.thingclips.smart.scene.model.home`
- **Implements**: `Serializable`
- **Methods**: 2
- **Fields**: 1
- **Source**: `scene\model\home\GeoFilterProperty.java`

**Key Methods**:
  - `isFilterNewGeofence()`
  - `setFilterNewGeofence()`

---

### RecommendSceneUpdateModel [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.home.RecommendSceneUpdateModel`
- **Package**: `com.thingclips.smart.scene.model.home`
- **Methods**: 15
- **Fields**: 8
- **Source**: `scene\model\home\RecommendSceneUpdateModel.java`

**Key Methods**:
  - `RecommendSceneUpdateModel()`
  - `getOwnerId()`
  - `getOperateType()`
  - `getRecommendId()`
  - `getMessageType()`
  - `copy()`
  - `RecommendSceneUpdateModel()`
  - `equals()`
  - `getMessageType()`
  - `getOperateType()`
  - *(... and 5 more)*

---

### SceneChangeV1 [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.home.SceneChangeV1`
- **Package**: `com.thingclips.smart.scene.model.home`
- **Methods**: 10
- **Fields**: 5
- **Source**: `scene\model\home\SceneChangeV1.java`

**Key Methods**:
  - `SceneChangeV1()`
  - `getSceneId()`
  - `getSceneChangeType()`
  - `copy()`
  - `SceneChangeV1()`
  - `equals()`
  - `getSceneChangeType()`
  - `getSceneId()`
  - `hashCode()`
  - `toString()`

---

### SceneUpdateModel [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.home.SceneUpdateModel`
- **Package**: `com.thingclips.smart.scene.model.home`
- **Methods**: 17
- **Fields**: 12
- **Source**: `scene\model\home\SceneUpdateModel.java`

**Key Methods**:
  - `SceneUpdateModel()`
  - `getRelationId()`
  - `getGwId()`
  - `getLinkageType()`
  - `getRuleId()`
  - `getMessageType()`
  - `copy()`
  - `SceneUpdateModel()`
  - `equals()`
  - `getGwId()`
  - *(... and 7 more)*

---

### SelectionsParams [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.home.SelectionsParams`
- **Package**: `com.thingclips.smart.scene.model.home`
- **Methods**: 15
- **Fields**: 20
- **Source**: `scene\model\home\SelectionsParams.java`

**Key Methods**:
  - `SelectionsParams()`
  - `getRelationId()`
  - `component2()`
  - `component3()`
  - `getNeedUnboundRoom()`
  - `copy()`
  - `SelectionsParams()`
  - `equals()`
  - `getCategories()`
  - `getNeedUnboundRoom()`
  - *(... and 5 more)*

---

### ExecuteLogDetail [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.log.ExecuteLogDetail`
- **Package**: `com.thingclips.smart.scene.model.log`
- **Implements**: `Serializable`
- **Methods**: 22
- **Fields**: 10
- **Source**: `scene\model\log\ExecuteLogDetail.java`

**Key Methods**:
  - `ExecuteLogDetail()`
  - `getActionEntityId()`
  - `getActionEntityName()`
  - `getActionEntityUrl()`
  - `getActionExecutor()`
  - `getActionId()`
  - `getDetail()`
  - `getErrorCode()`
  - `getErrorMsg()`
  - `getExecStatus()`
  - *(... and 12 more)*

---

### ExecuteLogItem [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.log.ExecuteLogItem`
- **Package**: `com.thingclips.smart.scene.model.log`
- **Implements**: `Serializable`
- **Methods**: 26
- **Fields**: 13
- **Source**: `scene\model\log\ExecuteLogItem.java`

**Key Methods**:
  - `getEventId()`
  - `getExecMessage()`
  - `getExecResult()`
  - `getExecResultMsg()`
  - `getExecTime()`
  - `getFailureCause()`
  - `getFailureCode()`
  - `getOwnerId()`
  - `getRuleId()`
  - `getRuleName()`
  - *(... and 16 more)*

---

### ExecuteLogList [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.log.ExecuteLogList`
- **Package**: `com.thingclips.smart.scene.model.log`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 2
- **Source**: `scene\model\log\ExecuteLogList.java`

**Key Methods**:
  - `getDatas()`
  - `getTotalCount()`
  - `setDatas()`
  - `setTotalCount()`

---

### LogDetail [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.log.LogDetail`
- **Package**: `com.thingclips.smart.scene.model.log`
- **Implements**: `Serializable`
- **Methods**: 12
- **Fields**: 6
- **Source**: `scene\model\log\LogDetail.java`

**Key Methods**:
  - `getCode()`
  - `getDetailId()`
  - `getDetailName()`
  - `getIcon()`
  - `getMsg()`
  - `getStatus()`
  - `setCode()`
  - `setDetailId()`
  - `setDetailName()`
  - `setIcon()`
  - *(... and 2 more)*

---

### NormalSceneChooseItem [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.manage.NormalSceneChooseItem`
- **Package**: `com.thingclips.smart.scene.model.manage`
- **Extends**: `SceneCondition>`
- **Methods**: 27
- **Fields**: 33
- **Source**: `scene\model\manage\NormalSceneChooseItem.java`

**Key Methods**:
  - `NormalSceneChooseItem()`
  - `getSceneType()`
  - `getChecked()`
  - `getId()`
  - `getName()`
  - `getIsEnabled()`
  - `component5()`
  - `component6()`
  - `getSceneStatus()`
  - `getDisplayColor()`
  - *(... and 17 more)*

---

### LocalSceneParamBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.p000rn.LocalSceneParamBean`
- **Package**: `com.thingclips.smart.scene.model.p000rn`
- **Implements**: `Serializable`
- **Methods**: 10
- **Fields**: 5
- **Source**: `scene\model\p000rn\LocalSceneParamBean.java`

**Key Methods**:
  - `LocalSceneParamBean()`
  - `getDevId()`
  - `getPanelType()`
  - `copy()`
  - `LocalSceneParamBean()`
  - `equals()`
  - `getDevId()`
  - `getPanelType()`
  - `hashCode()`
  - `toString()`

---

### PassThroughByLocalParamBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.p000rn.PassThroughByLocalParamBean`
- **Package**: `com.thingclips.smart.scene.model.p000rn`
- **Methods**: 16
- **Fields**: 20
- **Source**: `scene\model\p000rn\PassThroughByLocalParamBean.java`

**Key Methods**:
  - `PassThroughByLocalParamBean()`
  - `getLocalId()`
  - `getId()`
  - `getBtnId()`
  - `getDevId()`
  - `getAction()`
  - `copy()`
  - `PassThroughByLocalParamBean()`
  - `equals()`
  - `getAction()`
  - *(... and 6 more)*

---

### WithoutGatewayCallbackFailBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.p000rn.WithoutGatewayCallbackFailBean`
- **Package**: `com.thingclips.smart.scene.model.p000rn`
- **Methods**: 12
- **Fields**: 7
- **Source**: `scene\model\p000rn\WithoutGatewayCallbackFailBean.java`

**Key Methods**:
  - `WithoutGatewayCallbackFailBean()`
  - `getCode()`
  - `getMessage()`
  - `copy()`
  - `WithoutGatewayCallbackFailBean()`
  - `equals()`
  - `getCode()`
  - `getMessage()`
  - `hashCode()`
  - `toString()`
  - *(... and 2 more)*

---

### WithoutGatewayCallbackSuccessBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.p000rn.WithoutGatewayCallbackSuccessBean`
- **Package**: `com.thingclips.smart.scene.model.p000rn`
- **Methods**: 15
- **Fields**: 14
- **Source**: `scene\model\p000rn\WithoutGatewayCallbackSuccessBean.java`

**Key Methods**:
  - `WithoutGatewayCallbackSuccessBean()`
  - `getActionType()`
  - `getLocalId()`
  - `getId()`
  - `getSceneId()`
  - `copy()`
  - `WithoutGatewayCallbackSuccessBean()`
  - `equals()`
  - `getActionType()`
  - `getId()`
  - *(... and 5 more)*

---

### WithoutGatewayParamBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.p000rn.WithoutGatewayParamBean`
- **Package**: `com.thingclips.smart.scene.model.p000rn`
- **Implements**: `Serializable`
- **Methods**: 19
- **Fields**: 25
- **Source**: `scene\model\p000rn\WithoutGatewayParamBean.java`

**Key Methods**:
  - `WithoutGatewayParamBean()`
  - `getLocalId()`
  - `getId()`
  - `getCategoryCode()`
  - `component4()`
  - `getDevId()`
  - `getSceneId()`
  - `copy()`
  - `WithoutGatewayParamBean()`
  - `equals()`
  - *(... and 9 more)*

---

### DeviceRecommendScene [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.recommend.DeviceRecommendScene`
- **Package**: `com.thingclips.smart.scene.model.recommend`
- **Extends**: `LinkedHashMap<String`
- **Implements**: `Serializable`
- **Methods**: 19
- **Fields**: 9
- **Source**: `scene\model\recommend\DeviceRecommendScene.java`

**Key Methods**:
  - `getBackground()`
  - `getDisplayColor()`
  - `getJumpType()`
  - `getJumpUrl()`
  - `getLibraryId()`
  - `getName()`
  - `getRecommendId()`
  - `getRecommendSource()`
  - `setBackground()`
  - `setDisplayColor()`
  - *(... and 9 more)*

---

### RecommendPlainScene [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.recommend.RecommendPlainScene`
- **Package**: `com.thingclips.smart.scene.model.recommend`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 2
- **Source**: `scene\model\recommend\RecommendPlainScene.java`

**Key Methods**:
  - `getDevId()`
  - `getRuleList()`
  - `setDevId()`
  - `setRuleList()`

---

### RecommendRuleData [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.recommend.RecommendRuleData`
- **Package**: `com.thingclips.smart.scene.model.recommend`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 2
- **Source**: `scene\model\recommend\RecommendRuleData.java`

**Key Methods**:
  - `getId()`
  - `getName()`
  - `setId()`
  - `setName()`

---

### Event [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.result.Event`
- **Package**: `com.thingclips.smart.scene.model.result`
- **Methods**: 4
- **Fields**: 3
- **Source**: `scene\model\result\Event.java`

**Key Methods**:
  - `Event()`
  - `getContentIfNotHandled()`
  - `getHasBeenHandled()`
  - `peekContent()`

---

### Result [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.result.Result`
- **Package**: `com.thingclips.smart.scene.model.result`
- **Extends**: `Result`
- **Methods**: 21
- **Fields**: 7
- **Source**: `scene\model\result\Result.java`

**Key Methods**:
  - `method()`
  - `Error()`
  - `getException()`
  - `copy()`
  - `Error()`
  - `equals()`
  - `getException()`
  - `hashCode()`
  - `toString()`
  - `Loading()`
  - *(... and 11 more)*

---

### ResultKt [MEDIUM]


- **Full Name**: `com.thingclips.smart.scene.model.result.ResultKt`
- **Package**: `com.thingclips.smart.scene.model.result`
- **Extends**: `T>`
- **Methods**: 3
- **Fields**: 2
- **Source**: `scene\model\result\ResultKt.java`

**Key Methods**:
  - `getData()`
  - `getSucceeded()`
  - `successOr()`

---

### ThingBaseSdk [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.ThingBaseSdk`
- **Package**: `com.thingclips.smart.sdk`
- **Methods**: 17
- **Fields**: 19
- **Source**: `thingclips\smart\sdk\ThingBaseSdk.java`

**Key Methods**:
  - `FunCommonConfig()`
  - `getApplication()`
  - `getEventBus()`
  - `getFunCommonConfig()`
  - `getLatitude()`
  - `getLocationSwitch()`
  - `getLongitude()`
  - `getSaasSdkType()`
  - `getSdkRunType()`
  - `getSystemApp()`
  - *(... and 7 more)*

---

### ActivatorErrorCode [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.api.ActivatorErrorCode`
- **Package**: `com.thingclips.smart.sdk.api`
- **Methods**: 3
- **Fields**: 33
- **Source**: `smart\sdk\api\ActivatorErrorCode.java`

**Key Methods**:
  - `MSG()`
  - `getOptimizationApCode()`
  - `getOptimizationBleWifiCode()`

---

### IBleActivator [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.api.IBleActivator`
- **Package**: `com.thingclips.smart.sdk.api`
- **Methods**: 3
- **Fields**: 0
- **Source**: `smart\sdk\api\IBleActivator.java`

**Key Methods**:
  - `startActivator()`
  - `startBeaconActivator()`
  - `stopActivator()`

---

### IBleActivatorListener [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.api.IBleActivatorListener`
- **Package**: `com.thingclips.smart.sdk.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `smart\sdk\api\IBleActivatorListener.java`

**Key Methods**:
  - `onFailure()`
  - `onSuccess()`

---

### IBleWifiActivator [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.api.IBleWifiActivator`
- **Package**: `com.thingclips.smart.sdk.api`
- **Methods**: 2
- **Fields**: 0
- **Source**: `smart\sdk\api\IBleWifiActivator.java`

**Key Methods**:
  - `startActivator()`
  - `stopActivator()`

---

### IMultiModeActivator [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.api.IMultiModeActivator`
- **Package**: `com.thingclips.smart.sdk.api`
- **Methods**: 9
- **Fields**: 0
- **Source**: `smart\sdk\api\IMultiModeActivator.java`

**Key Methods**:
  - `changeZigBeeSubToOldModel()`
  - `queryDeviceConfigState()`
  - `resetDevice()`
  - `resumeActivator()`
  - `startActivator()`
  - `startBleActivator()`
  - `startOptimizationActivator()`
  - `startWifiEnable()`
  - `stopActivator()`

---

### IMultiModeParallelActivator [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.api.IMultiModeParallelActivator`
- **Package**: `com.thingclips.smart.sdk.api`
- **Methods**: 7
- **Fields**: 0
- **Source**: `smart\sdk\api\IMultiModeParallelActivator.java`

**Key Methods**:
  - `addMultiModeParallelListener()`
  - `appendDevice()`
  - `config()`
  - `removeDevice()`
  - `removeMultiModeParallelListener()`
  - `startConfigWifi()`
  - `stopConfigWifi()`

---

### IThingDeviceBizPropBeanListManager [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.api.IThingDeviceBizPropBeanListManager`
- **Package**: `com.thingclips.smart.sdk.api`
- **Methods**: 10
- **Fields**: 0
- **Source**: `smart\sdk\api\IThingDeviceBizPropBeanListManager.java`

**Key Methods**:
  - `clear()`
  - `clearByDevId()`
  - `getDeviceBizPropBean()`
  - `getDeviceBizPropBeanList()`
  - `getDeviceBizPropBeanListFromLocal()`
  - `getDeviceBizPropBeanMap()`
  - `putDeviceBizPropList()`
  - `remove()`
  - `remove()`
  - `update()`

---

### IThingMatterAvailableWiFiListCallback [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.api.IThingMatterAvailableWiFiListCallback`
- **Package**: `com.thingclips.smart.sdk.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `smart\sdk\api\IThingMatterAvailableWiFiListCallback.java`

**Key Methods**:
  - `onMatterDeviceAvailableWiFiList()`

---

### IThingMatterDevice [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.api.IThingMatterDevice`
- **Package**: `com.thingclips.smart.sdk.api`
- **Extends**: `IThingDevice`
- **Methods**: 4
- **Fields**: 0
- **Source**: `smart\sdk\api\IThingMatterDevice.java`

**Key Methods**:
  - `checkPipelineAvailable()`
  - `isMatterOnline()`
  - `isSubscribe()`
  - `isThingMatter()`

---

### IThingOTACenter [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.api.IThingOTACenter`
- **Package**: `com.thingclips.smart.sdk.api`
- **Methods**: 5
- **Fields**: 0
- **Source**: `smart\sdk\api\IThingOTACenter.java`

**Key Methods**:
  - `confirmWarningUpgradeTask()`
  - `onDestroy()`
  - `setOTAListener()`
  - `startFirmwareUpdate()`
  - `startFirmwareUpdate()`

---

### IThingOTAService [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.api.IThingOTAService`
- **Package**: `com.thingclips.smart.sdk.api`
- **Methods**: 14
- **Fields**: 0
- **Source**: `smart\sdk\api\IThingOTAService.java`

**Key Methods**:
  - `cancelFirmwareUpgrade()`
  - `cancelFirmwareUpgrade()`
  - `changeAutoUpgradeSwitchState()`
  - `confirmWarningUpgradeTask()`
  - `getAutoUpgradeSwitchState()`
  - `getDeviceLocalFirmwareInfo()`
  - `getFirmwareUpgradeInfo()`
  - `getFirmwareUpgradeInfo()`
  - `getUpgradeProgress()`
  - `memberCheckFirmwareStatus()`
  - *(... and 4 more)*

---

### IThingOtaServicePlugin [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.api.IThingOtaServicePlugin`
- **Package**: `com.thingclips.smart.sdk.api`
- **Methods**: 1
- **Fields**: 0
- **Source**: `smart\sdk\api\IThingOtaServicePlugin.java`

**Key Methods**:
  - `newOTAServiceInstance()`

---

### IThingSmartRequest [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.api.IThingSmartRequest`
- **Package**: `com.thingclips.smart.sdk.api`
- **Methods**: 7
- **Fields**: 0
- **Source**: `smart\sdk\api\IThingSmartRequest.java`

**Key Methods**:
  - `onDestroy()`
  - `queryDeviceOperateLogs()`
  - `requestWithApiName()`
  - `requestWithApiName()`
  - `requestWithApiNameWithoutSession()`
  - `requestWithApiNameWithoutSession()`
  - `sendCacheDps()`

---

### BackupWifiBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.api.wifibackup.api.bean.BackupWifiBean`
- **Package**: `com.thingclips.smart.sdk.api.wifibackup.api.bean`
- **Methods**: 2
- **Fields**: 4
- **Source**: `wifibackup\api\bean\BackupWifiBean.java`

**Key Methods**:
  - `toString()`
  - `StringBuilder()`

---

### C0031R [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.apimodule.C0031R`
- **Package**: `com.thingclips.smart.sdk.apimodule`
- **Methods**: 14
- **Fields**: 1676
- **Source**: `smart\sdk\apimodule\C0031R.java`

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
  - *(... and 4 more)*

---

### C0032R [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.base.apimodule.C0032R`
- **Package**: `com.thingclips.smart.sdk.base.apimodule`
- **Methods**: 14
- **Fields**: 1676
- **Source**: `sdk\base\apimodule\C0032R.java`

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
  - *(... and 4 more)*

---

### BaseDiscoveryInfo [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.BaseDiscoveryInfo`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 0
- **Fields**: 2
- **Source**: `smart\sdk\bean\BaseDiscoveryInfo.java`

---

### BleActivatorBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.BleActivatorBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 3
- **Fields**: 9
- **Source**: `smart\sdk\bean\BleActivatorBean.java`

**Key Methods**:
  - `BleActivatorBean()`
  - `getScanDeviceBean()`
  - `BleActivatorBean()`

---

### BluetoothStatusBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.BluetoothStatusBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 4
- **Fields**: 2
- **Source**: `smart\sdk\bean\BluetoothStatusBean.java`

**Key Methods**:
  - `getIsOnline()`
  - `getVerSw()`
  - `setIsOnline()`
  - `setVerSw()`

---

### CommissioningParameters [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.CommissioningParameters`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 23
- **Fields**: 28
- **Source**: `smart\sdk\bean\CommissioningParameters.java`

**Key Methods**:
  - `build()`
  - `CommissioningParameters()`
  - `connectDeviceResult()`
  - `discoveryResult()`
  - `gwId()`
  - `password()`
  - `setupPayload()`
  - `spaceId()`
  - `ssid()`
  - `timeOut()`
  - *(... and 13 more)*

---

### ConnectDeviceBuilder [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.ConnectDeviceBuilder`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 13
- **Fields**: 11
- **Source**: `smart\sdk\bean\ConnectDeviceBuilder.java`

**Key Methods**:
  - `getCallback()`
  - `getConnectCallback()`
  - `getGwId()`
  - `getSetupPayload()`
  - `getSpaceId()`
  - `getTimeout()`
  - `setCallback()`
  - `setConnectCallback()`
  - `setGwId()`
  - `setSetupPayload()`
  - *(... and 3 more)*

---

### ConnectResult [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.ConnectResult`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 2
- **Fields**: 13
- **Source**: `smart\sdk\bean\ConnectResult.java`

**Key Methods**:
  - `toString()`
  - `StringBuilder()`

**Notable Strings**:
  - `", uuid='"`

---

### DiscoveryResult [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.DiscoveryResult`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Extends**: `BaseDiscoveryInfo`
- **Implements**: `Serializable`
- **Methods**: 3
- **Fields**: 14
- **Source**: `smart\sdk\bean\DiscoveryResult.java`

**Key Methods**:
  - `BleDiscoveryResult()`
  - `toString()`
  - `StringBuilder()`

---

### EstablishResult [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.EstablishResult`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 2
- **Fields**: 4
- **Source**: `smart\sdk\bean\EstablishResult.java`

**Key Methods**:
  - `EstablishResult()`
  - `toString()`

---

### LocationInfo [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.LocationInfo`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Parcelable`
- **Methods**: 29
- **Fields**: 12
- **Source**: `smart\sdk\bean\LocationInfo.java`

**Key Methods**:
  - `createFromParcel()`
  - `LocationInfo()`
  - `newArray()`
  - `LocationInfo()`
  - `describeContents()`
  - `getAddress()`
  - `getCity()`
  - `getCountry()`
  - `getDistrict()`
  - `getGeoFenceId()`
  - *(... and 19 more)*

---

### MatterDiscoveryInfo [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.MatterDiscoveryInfo`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Extends**: `BaseDiscoveryInfo`
- **Methods**: 3
- **Fields**: 18
- **Source**: `smart\sdk\bean\MatterDiscoveryInfo.java`

**Key Methods**:
  - `isBasicCommissioningMethod()`
  - `isEnhanceCommissioningMethod()`
  - `toString()`

**Notable Strings**:
  - `", uuidInfo="`

---

### MatterQrCodeInfo [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.MatterQrCodeInfo`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 8
- **Fields**: 4
- **Source**: `smart\sdk\bean\MatterQrCodeInfo.java`

**Key Methods**:
  - `getData()`
  - `getIntDataValue()`
  - `getTag()`
  - `getType()`
  - `setData()`
  - `setIntDataValue()`
  - `setTag()`
  - `setType()`

---

### MultiModeActivatorBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.MultiModeActivatorBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 3
- **Fields**: 16
- **Source**: `smart\sdk\bean\MultiModeActivatorBean.java`

**Key Methods**:
  - `MultiModeActivatorBean()`
  - `getScanDeviceBean()`
  - `MultiModeActivatorBean()`

---

### MultiModeQueryBuilder [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.MultiModeQueryBuilder`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 8
- **Fields**: 11
- **Source**: `smart\sdk\bean\MultiModeQueryBuilder.java`

**Key Methods**:
  - `build()`
  - `MultiModeQueryBuilder()`
  - `setHomeId()`
  - `setScanDeviceBean()`
  - `setTimeout()`
  - `getHomeId()`
  - `getScanDeviceBean()`
  - `getTimeout()`

---

### OffLineStatusBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.OffLineStatusBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 12
- **Fields**: 6
- **Source**: `smart\sdk\bean\OffLineStatusBean.java`

**Key Methods**:
  - `getDevId()`
  - `getDpId()`
  - `getDpValue()`
  - `getFunctionType()`
  - `getLogicRuleId()`
  - `isEnabled()`
  - `setDevId()`
  - `setDpId()`
  - `setDpValue()`
  - `setEnabled()`
  - *(... and 2 more)*

---

### PairMatterBuilder [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.PairMatterBuilder`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 17
- **Fields**: 16
- **Source**: `smart\sdk\bean\PairMatterBuilder.java`

**Key Methods**:
  - `getGwId()`
  - `getListener()`
  - `getPassword()`
  - `getSetupPayload()`
  - `getSpaceId()`
  - `getSsid()`
  - `getTimeOut()`
  - `getToken()`
  - `setGwId()`
  - `setListener()`
  - *(... and 7 more)*

---

### PASEParameters [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.PASEParameters`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 13
- **Fields**: 17
- **Source**: `smart\sdk\bean\PASEParameters.java`

**Key Methods**:
  - `build()`
  - `PASEParameters()`
  - `discoveryResult()`
  - `gwId()`
  - `setupPinCode()`
  - `spaceId()`
  - `timeout()`
  - `getDiscoveryResult()`
  - `getGwId()`
  - `getSetupPinCode()`
  - *(... and 3 more)*

---

### ProductCloudFileBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.ProductCloudFileBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 14
- **Fields**: 7
- **Source**: `smart\sdk\bean\ProductCloudFileBean.java`

**Key Methods**:
  - `getLatestVersion()`
  - `getName()`
  - `getProductId()`
  - `getSize()`
  - `getType()`
  - `getUrl()`
  - `isNeedUpgrade()`
  - `setLatestVersion()`
  - `setName()`
  - `setNeedUpgrade()`
  - *(... and 4 more)*

---

### ProductStandardConfig [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.ProductStandardConfig`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 1
- **Fields**: 19
- **Source**: `smart\sdk\bean\ProductStandardConfig.java`

**Key Methods**:
  - `isProductCompatibled()`

---

### ResumeActivatorBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.ResumeActivatorBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 11
- **Fields**: 11
- **Source**: `smart\sdk\bean\ResumeActivatorBean.java`

**Key Methods**:
  - `ResumeActivatorBean()`
  - `build()`
  - `setPassword()`
  - `setResumeType()`
  - `setSsid()`
  - `setUuid()`
  - `getPwd()`
  - `getResumeType()`
  - `getSsid()`
  - `getUuid()`
  - *(... and 1 more)*

---

### StandSchema [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.StandSchema`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 21
- **Fields**: 11
- **Source**: `smart\sdk\bean\StandSchema.java`

**Key Methods**:
  - `getStandardCode()`
  - `getStandardType()`
  - `getStrategyCode()`
  - `getStrategyValue()`
  - `setStandardCode()`
  - `setStandardType()`
  - `setStrategyCode()`
  - `setStrategyValue()`
  - `getDpCode()`
  - `getStandardType()`
  - *(... and 11 more)*

---

### ThingGeoFence [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.ThingGeoFence`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Parcelable`
- **Methods**: 13
- **Fields**: 4
- **Source**: `smart\sdk\bean\ThingGeoFence.java`

**Key Methods**:
  - `createFromParcel()`
  - `ThingGeoFence()`
  - `newArray()`
  - `ThingGeoFence()`
  - `describeContents()`
  - `getExpr()`
  - `getExtraInfo()`
  - `getFenceId()`
  - `setExpr()`
  - `setExtraInfo()`
  - *(... and 3 more)*

---

### ThingMatterAttributeBasicInfo [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.ThingMatterAttributeBasicInfo`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 30
- **Fields**: 15
- **Source**: `smart\sdk\bean\ThingMatterAttributeBasicInfo.java`

**Key Methods**:
  - `getHardwareVersion()`
  - `getHardwareVersionString()`
  - `getLocation()`
  - `getNodeLabel()`
  - `getProductId()`
  - `getProductLabel()`
  - `getProductName()`
  - `getProductURL()`
  - `getSerialNumber()`
  - `getSoftwareVersion()`
  - *(... and 20 more)*

---

### ThingMatterDeviceBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.ThingMatterDeviceBean`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 25
- **Fields**: 12
- **Source**: `smart\sdk\bean\ThingMatterDeviceBean.java`

**Key Methods**:
  - `getAccessType()`
  - `getDevId()`
  - `getDeviceTypeEnum()`
  - `getFabricId()`
  - `getMatterDevUuid()`
  - `getNodeId()`
  - `getParentDevId()`
  - `getThingProductId()`
  - `isBelongGateway()`
  - `isCloudOnline()`
  - *(... and 15 more)*

**Notable Strings**:
  - `"', matterDevUuid='"`

---

### ThingMatterDiscovery [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.ThingMatterDiscovery`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 12
- **Fields**: 6
- **Source**: `smart\sdk\bean\ThingMatterDiscovery.java`

**Key Methods**:
  - `getDeviceType()`
  - `getIconUrlStr()`
  - `getPayload()`
  - `getProductName()`
  - `isThingMatter()`
  - `setDeviceType()`
  - `setIconUrlStr()`
  - `setPayload()`
  - `setProductName()`
  - `setThingMatter()`
  - *(... and 2 more)*

---

### ThingSmartThingModel [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.ThingSmartThingModel`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 10
- **Fields**: 5
- **Source**: `smart\sdk\bean\ThingSmartThingModel.java`

**Key Methods**:
  - `getExtensions()`
  - `getModelId()`
  - `getProductId()`
  - `getProductVersion()`
  - `getServices()`
  - `setExtensions()`
  - `setModelId()`
  - `setProductId()`
  - `setProductVersion()`
  - `setServices()`

---

### ThingSmartThingServiceModel [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.ThingSmartThingServiceModel`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Methods**: 6
- **Fields**: 3
- **Source**: `smart\sdk\bean\ThingSmartThingServiceModel.java`

**Key Methods**:
  - `getActions()`
  - `getEvents()`
  - `getProperties()`
  - `setActions()`
  - `setEvents()`
  - `setProperties()`

---

### ThreadNetworkScanResult [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.ThreadNetworkScanResult`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 3
- **Source**: `smart\sdk\bean\ThreadNetworkScanResult.java`

**Key Methods**:
  - `ThreadNetworkScanResult()`
  - `toString()`
  - `StringBuilder()`
  - `ThreadNetworkScanResult()`

---

### UiInfo [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.UiInfo`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 27
- **Fields**: 21
- **Source**: `smart\sdk\bean\UiInfo.java`

**Key Methods**:
  - `HashMap()`
  - `getAppRnVersion()`
  - `getBizClientId()`
  - `getContent()`
  - `getFileMd5()`
  - `getFileSize()`
  - `getName()`
  - `getPhase()`
  - `getRnBizPack()`
  - `getRnFind()`
  - *(... and 17 more)*

---

### UuidInfo [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.UuidInfo`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 0
- **Fields**: 4
- **Source**: `smart\sdk\bean\UuidInfo.java`

---

### WiFiScanResult [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.WiFiScanResult`
- **Package**: `com.thingclips.smart.sdk.bean`
- **Implements**: `Serializable`
- **Methods**: 3
- **Fields**: 16
- **Source**: `smart\sdk\bean\WiFiScanResult.java`

**Key Methods**:
  - `WiFiScanResult()`
  - `toString()`
  - `StringBuilder()`

---

### FeedbackMsgBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.feedback.FeedbackMsgBean`
- **Package**: `com.thingclips.smart.sdk.bean.feedback`
- **Implements**: `Parcelable`
- **Methods**: 17
- **Fields**: 9
- **Source**: `sdk\bean\feedback\FeedbackMsgBean.java`

**Key Methods**:
  - `createFromParcel()`
  - `FeedbackMsgBean()`
  - `newArray()`
  - `describeContents()`
  - `getContent()`
  - `getCtime()`
  - `getHdId()`
  - `getHdType()`
  - `getId()`
  - `getType()`
  - *(... and 7 more)*

---

### DeviceAlarmNotDisturbVO [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.message.DeviceAlarmNotDisturbVO`
- **Package**: `com.thingclips.smart.sdk.bean.message`
- **Implements**: `Serializable`
- **Methods**: 16
- **Fields**: 8
- **Source**: `sdk\bean\message\DeviceAlarmNotDisturbVO.java`

**Key Methods**:
  - `getDevIds()`
  - `getEndTime()`
  - `getId()`
  - `getLoops()`
  - `getStartTime()`
  - `getTimezone()`
  - `getTimezoneId()`
  - `isAllDevIds()`
  - `setAllDevIds()`
  - `setDevIds()`
  - *(... and 6 more)*

---

### PrivacyAuthorizationBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.privacy.PrivacyAuthorizationBean`
- **Package**: `com.thingclips.smart.sdk.bean.privacy`
- **Implements**: `Serializable`
- **Methods**: 4
- **Fields**: 2
- **Source**: `sdk\bean\privacy\PrivacyAuthorizationBean.java`

**Key Methods**:
  - `getStatusMap()`
  - `isHasDefaultValue()`
  - `setHasDefaultValue()`
  - `setStatusMap()`

---

### PushStatusBean [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bean.push.PushStatusBean`
- **Package**: `com.thingclips.smart.sdk.bean.push`
- **Methods**: 4
- **Fields**: 2
- **Source**: `sdk\bean\push\PushStatusBean.java`

**Key Methods**:
  - `getDeviceId()`
  - `getIsPushEnable()`
  - `setDeviceId()`
  - `setIsPushEnable()`

---

### BuildConfig [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bluetooth.api.BuildConfig`
- **Package**: `com.thingclips.smart.sdk.bluetooth.api`
- **Methods**: 0
- **Fields**: 3
- **Source**: `sdk\bluetooth\api\BuildConfig.java`

**Notable Strings**:
  - `"com.thingclips.smart.sdk.bluetooth.api"`

---

### BuildConfig [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.bluetooth.business.api.BuildConfig`
- **Package**: `com.thingclips.smart.sdk.bluetooth.business.api`
- **Methods**: 0
- **Fields**: 3
- **Source**: `bluetooth\business\api\BuildConfig.java`

**Notable Strings**:
  - `"com.thingclips.smart.sdk.bluetooth.business.api"`

---

### ServiceNotification [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.constant.ServiceNotification`
- **Package**: `com.thingclips.smart.sdk.constant`
- **Methods**: 6
- **Fields**: 6
- **Source**: `smart\sdk\constant\ServiceNotification.java`

**Key Methods**:
  - `ServiceNotification()`
  - `ServiceNotification()`
  - `getInstance()`
  - `getNotification()`
  - `getNotificationId()`
  - `setNotification()`

---

### C0040R [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.geofence.api.C0040R`
- **Package**: `com.thingclips.smart.sdk.geofence.api`
- **Methods**: 14
- **Fields**: 1676
- **Source**: `sdk\geofence\api\C0040R.java`

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
  - *(... and 4 more)*

---

### C0041R [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.hardware.api.C0041R`
- **Package**: `com.thingclips.smart.sdk.hardware.api`
- **Methods**: 14
- **Fields**: 1676
- **Source**: `sdk\hardware\api\C0041R.java`

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
  - *(... and 4 more)*

---

### C0044R [MEDIUM]


- **Full Name**: `com.thingclips.smart.sdk.mqtt.api.C0044R`
- **Package**: `com.thingclips.smart.sdk.mqtt.api`
- **Methods**: 14
- **Fields**: 1676
- **Source**: `sdk\mqtt\api\C0044R.java`

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
  - *(... and 4 more)*

---

## Package Structure

### Package Hierarchy

```
com/ (497 classes)
        ├── api/ (5 classes)
          ├── service/ (11 classes)
        ├── execute/ (27 classes)
          ├── model/ (3 classes)
        ├── lib/ (4 classes)
          ├── constant/ (1 classes)
          ├── service/ (4 classes)
            ├── action/ (1 classes)
            ├── base/ (1 classes)
            ├── condition/ (1 classes)
  └── ... and 53 more packages

```

### Top 20 Packages by Class Count

| Package | Classes |
| --- | --- |
| com.thingclips.smart.sdk.api | 120 |
| com.thingclips.smart.sdk.bean | 88 |
| com.thingclips.smart.scene.execute | 27 |
| com.thingclips.smart.sdk.api.bluemesh | 27 |
| com.thingclips.smart.scene.model.device | 26 |
| com.thingclips.smart.scene.model.condition | 16 |
| com.thingclips.smart.scene.model.constant | 16 |
| com.thingclips.smart.scene.api.service | 11 |
| com.thingclips.smart.scene.model.action | 11 |
| com.thingclips.smart.scene.model | 8 |
| com.thingclips.smart.scene.lib.util | 7 |
| com.thingclips.smart.sdk.bean.message | 7 |
| com.thingclips.smart.scene.model.p000rn | 6 |
| com.thingclips.smart.sdk.api.bluemesh.message | 6 |
| com.thingclips.smart.sdk.api.wifibackup.api.bean | 6 |
| com.thingclips.smart.scene.api | 5 |
| com.thingclips.smart.scene.model.ext | 5 |
| com.thingclips.smart.scene.model.home | 5 |
| com.thingclips.smart.sdk.bean.feedback | 5 |
| com.thingclips.smart.scene.lib | 4 |

## String Constants & UUIDs

*No UUIDs found in this DEX file.*

## BLE Write Operations

*No BLE write operations found in this DEX file.*

## Command Sequences

*No command sequences found in this DEX file.*

## Method Index

### Write/Send Methods

- `CopyOnWriteArrayList()` in `ExecuteAnalysisUtil`
- `sendCacheDps()` in `IThingSmartRequest`
- `sendMessage()` in `IMeshActionTransmitter`
- `writeToParcel()` in `LocationInfo`
- `writeToParcel()` in `ThingGeoFence`
- `writeToParcel()` in `FeedbackMsgBean`

### Callback/Event Methods

- `onError()` in `IResultCallback`
- `onSuccess()` in `IResultCallback`
- `onDestroy()` in `ISceneService`
- `onDestroy()` in `IActionService`
- `onDestroy()` in `DefaultImpls`
- `onDestroy()` in `DefaultImpls`
- `onDestroy()` in `IDeviceService`
- `onDestroy()` in `DefaultImpls`
- `onDestroy()` in `DefaultImpls`
- `onDestroy()` in `ILogService`
- `onDestroy()` in `DefaultImpls`
- `onAddScene()` in `SceneChangeCallback`
- `onDeleteScene()` in `SceneChangeCallback`
- `onDisableScene()` in `SceneChangeCallback`
- `onEnableScene()` in `SceneChangeCallback`
- *(... and 364 more)*

## Full Class List

<details>
<summary>Click to expand full class list (497 classes)</summary>

Total: 497 classes

### com.thingclips.smart.scene.api

- `com.thingclips.smart.scene.api.BuildConfig`
- `com.thingclips.smart.scene.api.C0000R`
- `com.thingclips.smart.scene.api.IResultCallback`
- `com.thingclips.smart.scene.api.ISceneService`
- `com.thingclips.smart.scene.api.IThingNewScenePlugin`

### com.thingclips.smart.scene.api.service

- `com.thingclips.smart.scene.api.service.DefaultImpls`
- `com.thingclips.smart.scene.api.service.DefaultImpls`
- `com.thingclips.smart.scene.api.service.DefaultImpls`
- `com.thingclips.smart.scene.api.service.DefaultImpls`
- `com.thingclips.smart.scene.api.service.DefaultImpls`
- `com.thingclips.smart.scene.api.service.DefaultImpls`
- `com.thingclips.smart.scene.api.service.IActionService`
- `com.thingclips.smart.scene.api.service.IDeviceService`
- `com.thingclips.smart.scene.api.service.ILogService`
- `com.thingclips.smart.scene.api.service.IRestfulUrlConfig`
- `com.thingclips.smart.scene.api.service.SceneChangeCallback`

### com.thingclips.smart.scene.execute

- `com.thingclips.smart.scene.execute.BuildConfig`
- `com.thingclips.smart.scene.execute.C0009R`
- `com.thingclips.smart.scene.execute.DeviceUtil`
- `com.thingclips.smart.scene.execute.ExecuteAnalysisUtil`
- `com.thingclips.smart.scene.execute.ExecuteNetUtils`
- `com.thingclips.smart.scene.execute.ExecuteSceneExtensionsKt`
- `com.thingclips.smart.scene.execute.ExecuteSceneExtensionsKt`
- `com.thingclips.smart.scene.execute.ExecuteSceneExtensionsKt`
- `com.thingclips.smart.scene.execute.ExecuteSceneExtensionsKt`
- `com.thingclips.smart.scene.execute.ExecuteSceneExtensionsKt`
- `com.thingclips.smart.scene.execute.ExecuteSceneExtensionsKt`
- `com.thingclips.smart.scene.execute.ExecuteUtil`
- `com.thingclips.smart.scene.execute.ExecuteUtil`
- `com.thingclips.smart.scene.execute.ExecuteUtil`
- `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- `com.thingclips.smart.scene.execute.MonitorResultExtensionsKt`
- `com.thingclips.smart.scene.execute.SceneExecuteUseCase`
- `com.thingclips.smart.scene.execute.SceneExecuteUseCase`
- `com.thingclips.smart.scene.execute.SceneExecuteUseCase`

### com.thingclips.smart.scene.execute.model

- `com.thingclips.smart.scene.execute.model.ActionExecuteResult`
- `com.thingclips.smart.scene.execute.model.ExecuteActionInfoBean`
- `com.thingclips.smart.scene.execute.model.ExecuteScene`

### com.thingclips.smart.scene.lib

- `com.thingclips.smart.scene.lib.BuildConfig`
- `com.thingclips.smart.scene.lib.C0011R`
- `com.thingclips.smart.scene.lib.SceneService`
- `com.thingclips.smart.scene.lib.ThingNewScenePlugin`

### com.thingclips.smart.scene.lib.constant

- `com.thingclips.smart.scene.lib.constant.ApiConstantKt`

### com.thingclips.smart.scene.lib.service

- `com.thingclips.smart.scene.lib.service.SceneAtopUrlConfig`
- `com.thingclips.smart.scene.lib.service.SceneBusiness`
- `com.thingclips.smart.scene.lib.service.SceneFusionBusiness`
- `com.thingclips.smart.scene.lib.service.SceneRestfulUrlConfig`

### com.thingclips.smart.scene.lib.service.action

- `com.thingclips.smart.scene.lib.service.action.ActionService`

### com.thingclips.smart.scene.lib.service.base

- `com.thingclips.smart.scene.lib.service.base.BaseService`

### com.thingclips.smart.scene.lib.service.condition

- `com.thingclips.smart.scene.lib.service.condition.ConditionService`

### com.thingclips.smart.scene.lib.service.device

- `com.thingclips.smart.scene.lib.service.device.DeviceService`

### com.thingclips.smart.scene.lib.service.execute

- `com.thingclips.smart.scene.lib.service.execute.ExecuteService`

### com.thingclips.smart.scene.lib.service.ext

- `com.thingclips.smart.scene.lib.service.ext.ExtService`

### com.thingclips.smart.scene.lib.service.log

- `com.thingclips.smart.scene.lib.service.log.LogService`

### com.thingclips.smart.scene.lib.service.recommend

- `com.thingclips.smart.scene.lib.service.recommend.RecommendService`

### com.thingclips.smart.scene.lib.util

- `com.thingclips.smart.scene.lib.util.C0018b`
- `com.thingclips.smart.scene.lib.util.DeviceUtil`
- `com.thingclips.smart.scene.lib.util.GeofenceUtil`
- `com.thingclips.smart.scene.lib.util.MqttSubscribeUtil`
- `com.thingclips.smart.scene.lib.util.MqttSubscribeUtil`
- `com.thingclips.smart.scene.lib.util.MqttSubscribeUtil`
- `com.thingclips.smart.scene.lib.util.MqttSubscribeUtil`

### com.thingclips.smart.scene.model

- `com.thingclips.smart.scene.model.BuildConfig`
- `com.thingclips.smart.scene.model.C0021R`
- `com.thingclips.smart.scene.model.FusionPageNormalScenes`
- `com.thingclips.smart.scene.model.NormalScene`
- `com.thingclips.smart.scene.model.NormalSceneExtBean`
- `com.thingclips.smart.scene.model.PageNormalSceneReqParams`
- `com.thingclips.smart.scene.model.RecommendScene`
- `com.thingclips.smart.scene.model.StatusConditions`

### com.thingclips.smart.scene.model.action

- `com.thingclips.smart.scene.model.action.ActionItem`
- `com.thingclips.smart.scene.model.action.LinkLightScene`
- `com.thingclips.smart.scene.model.action.PushItemData`
- `com.thingclips.smart.scene.model.action.RelationGroup`
- `com.thingclips.smart.scene.model.action.SMSServiceInfo`
- `com.thingclips.smart.scene.model.action.SceneAction`
- `com.thingclips.smart.scene.model.action.SceneActionExtBean`
- `com.thingclips.smart.scene.model.action.ServiceInfo`
- `com.thingclips.smart.scene.model.action.ServiceLeftTime`
- `com.thingclips.smart.scene.model.action.ServiceMember`
- `com.thingclips.smart.scene.model.action.VoiceServiceInfo`

### com.thingclips.smart.scene.model.condition

- `com.thingclips.smart.scene.model.condition.ConditionExtraInfo`
- `com.thingclips.smart.scene.model.condition.ConditionInnerProperty`
- `com.thingclips.smart.scene.model.condition.ConditionItem`
- `com.thingclips.smart.scene.model.condition.ConditionItemDetail`
- `com.thingclips.smart.scene.model.condition.ConditionItemList`
- `com.thingclips.smart.scene.model.condition.ConditionOuterProperty`
- `com.thingclips.smart.scene.model.condition.DeviceData`
- `com.thingclips.smart.scene.model.condition.GeoPermissionProperty`
- `com.thingclips.smart.scene.model.condition.LocationCity`
- `com.thingclips.smart.scene.model.condition.LockDeviceMember`
- `com.thingclips.smart.scene.model.condition.NewMCGroup`
- `com.thingclips.smart.scene.model.condition.SceneCondition`
- `com.thingclips.smart.scene.model.condition.SceneConditionExtBean`
- `com.thingclips.smart.scene.model.condition.WeatherData`
- `com.thingclips.smart.scene.model.condition.WeatherEnumData`
- `com.thingclips.smart.scene.model.condition.WeatherValueData`

### com.thingclips.smart.scene.model.constant

- `com.thingclips.smart.scene.model.constant.ActionConstantKt`
- `com.thingclips.smart.scene.model.constant.CalTypeKt`
- `com.thingclips.smart.scene.model.constant.Companion`
- `com.thingclips.smart.scene.model.constant.Companion`
- `com.thingclips.smart.scene.model.constant.Companion`
- `com.thingclips.smart.scene.model.constant.Companion`
- `com.thingclips.smart.scene.model.constant.Companion`
- `com.thingclips.smart.scene.model.constant.Companion`
- `com.thingclips.smart.scene.model.constant.Companion`
- `com.thingclips.smart.scene.model.constant.Companion`
- `com.thingclips.smart.scene.model.constant.Companion`
- `com.thingclips.smart.scene.model.constant.Companion`
- `com.thingclips.smart.scene.model.constant.ConditionConstantKt`
- `com.thingclips.smart.scene.model.constant.RecommendConstant`
- `com.thingclips.smart.scene.model.constant.StateKey`
- `com.thingclips.smart.scene.model.constant.removed`

### com.thingclips.smart.scene.model.constant.createSceneType

- `com.thingclips.smart.scene.model.constant.createSceneType.ValidateSceneResultBean`
- `com.thingclips.smart.scene.model.constant.createSceneType.ValidateSceneResultItemBean`

### com.thingclips.smart.scene.model.core

- `com.thingclips.smart.scene.model.core.BuildConfig`
- `com.thingclips.smart.scene.model.core.C0025R`

### com.thingclips.smart.scene.model.device

- `com.thingclips.smart.scene.model.device.ActionDeviceDataPointDetail`
- `com.thingclips.smart.scene.model.device.ActionDeviceDataPointList`
- `com.thingclips.smart.scene.model.device.ActionDeviceGroup`
- `com.thingclips.smart.scene.model.device.ActionDeviceGroupId`
- `com.thingclips.smart.scene.model.device.BleIotData`
- `com.thingclips.smart.scene.model.device.CategoryChooseItem`
- `com.thingclips.smart.scene.model.device.DeviceActionData`
- `com.thingclips.smart.scene.model.device.DeviceActionDetailBean`
- `com.thingclips.smart.scene.model.device.DeviceChooseItem`
- `com.thingclips.smart.scene.model.device.DeviceChooseParams`
- `com.thingclips.smart.scene.model.device.DeviceConditionData`
- `com.thingclips.smart.scene.model.device.DpEnumTypeData`
- `com.thingclips.smart.scene.model.device.DpValueTypeData`
- `com.thingclips.smart.scene.model.device.FaceDeviceMember`
- `com.thingclips.smart.scene.model.device.InfraredUiData`
- `com.thingclips.smart.scene.model.device.IrPanelExtBean`
- `com.thingclips.smart.scene.model.device.LightDeviceChooseBean`
- `com.thingclips.smart.scene.model.device.OtherTypeData`
- `com.thingclips.smart.scene.model.device.SceneValidateResultBean`
- `com.thingclips.smart.scene.model.device.SceneZigbeeValidateDialogBean`
- `com.thingclips.smart.scene.model.device.SchemaExt`
- `com.thingclips.smart.scene.model.device.StandardSceneInfo`
- `com.thingclips.smart.scene.model.device.StepDpProperty`
- `com.thingclips.smart.scene.model.device.ValueTypeData`
- `com.thingclips.smart.scene.model.device.WholeHouseDeviceGroupIds`
- `com.thingclips.smart.scene.model.device.WirelessSwitchBean`

### com.thingclips.smart.scene.model.edit

- `com.thingclips.smart.scene.model.edit.PreCondition`
- `com.thingclips.smart.scene.model.edit.PreConditionExpr`
- `com.thingclips.smart.scene.model.edit.PreConditionExtBean`
- `com.thingclips.smart.scene.model.edit.SceneStyle`

### com.thingclips.smart.scene.model.ext

- `com.thingclips.smart.scene.model.ext.BannerList`
- `com.thingclips.smart.scene.model.ext.CountLimit`
- `com.thingclips.smart.scene.model.ext.GuideBanner`
- `com.thingclips.smart.scene.model.ext.ProductUrl`
- `com.thingclips.smart.scene.model.ext.PublicProductUrl`

### com.thingclips.smart.scene.model.home

- `com.thingclips.smart.scene.model.home.GeoFilterProperty`
- `com.thingclips.smart.scene.model.home.RecommendSceneUpdateModel`
- `com.thingclips.smart.scene.model.home.SceneChangeV1`
- `com.thingclips.smart.scene.model.home.SceneUpdateModel`
- `com.thingclips.smart.scene.model.home.SelectionsParams`

### com.thingclips.smart.scene.model.log

- `com.thingclips.smart.scene.model.log.ExecuteLogDetail`
- `com.thingclips.smart.scene.model.log.ExecuteLogItem`
- `com.thingclips.smart.scene.model.log.ExecuteLogList`
- `com.thingclips.smart.scene.model.log.LogDetail`

### com.thingclips.smart.scene.model.manage

- `com.thingclips.smart.scene.model.manage.NormalSceneChooseItem`

### com.thingclips.smart.scene.model.p000rn

- `com.thingclips.smart.scene.model.p000rn.LocalSceneParamBean`
- `com.thingclips.smart.scene.model.p000rn.PassThroughByLocalParamBean`
- `com.thingclips.smart.scene.model.p000rn.RecommendCallbackBean`
- `com.thingclips.smart.scene.model.p000rn.WithoutGatewayCallbackFailBean`
- `com.thingclips.smart.scene.model.p000rn.WithoutGatewayCallbackSuccessBean`
- `com.thingclips.smart.scene.model.p000rn.WithoutGatewayParamBean`

### com.thingclips.smart.scene.model.recommend

- `com.thingclips.smart.scene.model.recommend.DeviceRecommendScene`
- `com.thingclips.smart.scene.model.recommend.RecommendPlainScene`
- `com.thingclips.smart.scene.model.recommend.RecommendRuleData`

### com.thingclips.smart.scene.model.result

- `com.thingclips.smart.scene.model.result.Event`
- `com.thingclips.smart.scene.model.result.Result`
- `com.thingclips.smart.scene.model.result.ResultKt`

### com.thingclips.smart.sdk

- `com.thingclips.smart.sdk.BluetoothPermissionUtil`
- `com.thingclips.smart.sdk.ByteProcessingUtil`
- `com.thingclips.smart.sdk.ThingBaseSdk`
- `com.thingclips.smart.sdk.ThingSdk`

### com.thingclips.smart.sdk.api

- `com.thingclips.smart.sdk.api.ActivatorErrorCode`
- `com.thingclips.smart.sdk.api.IBatchExecutionManager`
- `com.thingclips.smart.sdk.api.IBleActivator`
- `com.thingclips.smart.sdk.api.IBleActivatorListener`
- `com.thingclips.smart.sdk.api.IBleWifiActivator`
- `com.thingclips.smart.sdk.api.ICreateGroupAlarmCallback`
- `com.thingclips.smart.sdk.api.ICreateGroupCallback`
- `com.thingclips.smart.sdk.api.IDevListener`
- `com.thingclips.smart.sdk.api.IDevOTAListener`
- `com.thingclips.smart.sdk.api.IDevSceneListUpdateListener`
- `com.thingclips.smart.sdk.api.IDevUpdateListener`
- `com.thingclips.smart.sdk.api.IDeviceListener`
- `com.thingclips.smart.sdk.api.IDiscoveryServiceListener`
- `com.thingclips.smart.sdk.api.IEventCenter`
- `com.thingclips.smart.sdk.api.IExtDevListener`
- `com.thingclips.smart.sdk.api.IExtMultiModeActivatorListener`
- `com.thingclips.smart.sdk.api.IExtOtaListener`
- `com.thingclips.smart.sdk.api.IFirmwareUpgradeListener`
- `com.thingclips.smart.sdk.api.IGetAllTimerWithDevIdCallback`
- `com.thingclips.smart.sdk.api.IGetDeviceTimerStatusCallback`
- `com.thingclips.smart.sdk.api.IGetDevicesInGroupCallback`
- `com.thingclips.smart.sdk.api.IGetDevsFromGroupByPidCallback`
- `com.thingclips.smart.sdk.api.IGetGroupAlarmCallback`
- `com.thingclips.smart.sdk.api.IGetOtaInfoCallback`
- `com.thingclips.smart.sdk.api.IGetSubDevListCallback`
- `com.thingclips.smart.sdk.api.IGetTimerWithTaskCallback`
- `com.thingclips.smart.sdk.api.IGroupListener`
- `com.thingclips.smart.sdk.api.IMatterAttributeCallback`
- `com.thingclips.smart.sdk.api.IMatterConnectedCallback`
- `com.thingclips.smart.sdk.api.IMatterDeviceNetworkCallback`
- `com.thingclips.smart.sdk.api.IMeshRegister`
- `com.thingclips.smart.sdk.api.IMultiModeActivator`
- `com.thingclips.smart.sdk.api.IMultiModeActivatorListener`
- `com.thingclips.smart.sdk.api.IMultiModeParallelActivator`
- `com.thingclips.smart.sdk.api.IMultiModeParallelListener`
- `com.thingclips.smart.sdk.api.INeedLoginListener`
- `com.thingclips.smart.sdk.api.IOperationalDeviceDiscoveryListener`
- `com.thingclips.smart.sdk.api.IOtaListener`
- `com.thingclips.smart.sdk.api.IOtaProgressCallback`
- `com.thingclips.smart.sdk.api.IParallelActivator`
- `com.thingclips.smart.sdk.api.IRequestCallback`
- `com.thingclips.smart.sdk.api.IResultCallback`
- `com.thingclips.smart.sdk.api.IResultStatusCallback`
- `com.thingclips.smart.sdk.api.ISmartUpdateListener`
- `com.thingclips.smart.sdk.api.IStandardConverter`
- `com.thingclips.smart.sdk.api.IStorageCache`
- `com.thingclips.smart.sdk.api.ISubDevListener`
- `com.thingclips.smart.sdk.api.ITemporaryCallBack`
- `com.thingclips.smart.sdk.api.IThingActivator`
- `com.thingclips.smart.sdk.api.IThingActivatorCreateToken`
- `com.thingclips.smart.sdk.api.IThingActivatorGetToken`
- `com.thingclips.smart.sdk.api.IThingBroadbandConfigListener`
- `com.thingclips.smart.sdk.api.IThingBroadbandConnectTypeListener`
- `com.thingclips.smart.sdk.api.IThingCameraDevActivator`
- `com.thingclips.smart.sdk.api.IThingCommonTimer`
- `com.thingclips.smart.sdk.api.IThingConnectDeviceCallback`
- `com.thingclips.smart.sdk.api.IThingDataCallback`
- `com.thingclips.smart.sdk.api.IThingDevActivatorListener`
- `com.thingclips.smart.sdk.api.IThingDevDirectActivatorListener`
- `com.thingclips.smart.sdk.api.IThingDevEventListener`
- `com.thingclips.smart.sdk.api.IThingDevice`
- `com.thingclips.smart.sdk.api.IThingDeviceBizPropBeanListManager`
- `com.thingclips.smart.sdk.api.IThingDeviceDataManager`
- `com.thingclips.smart.sdk.api.IThingDeviceListManager`
- `com.thingclips.smart.sdk.api.IThingDeviceOperator`
- `com.thingclips.smart.sdk.api.IThingDirectActivator`
- `com.thingclips.smart.sdk.api.IThingDirectlyDeviceActivatorListener`
- `com.thingclips.smart.sdk.api.IThingFeedback`
- `com.thingclips.smart.sdk.api.IThingFeedbackMag`
- `com.thingclips.smart.sdk.api.IThingFeedbackManager`
- `com.thingclips.smart.sdk.api.IThingGateway`
- `com.thingclips.smart.sdk.api.IThingGeoFence`
- `com.thingclips.smart.sdk.api.IThingGeoFenceOperate`
- `com.thingclips.smart.sdk.api.IThingGetBeanCallback`
- `com.thingclips.smart.sdk.api.IThingGroup`
- `com.thingclips.smart.sdk.api.IThingLinkDeviceListener`
- `com.thingclips.smart.sdk.api.IThingLitePresenter`
- `com.thingclips.smart.sdk.api.IThingMatterAvailableWiFiListCallback`
- `com.thingclips.smart.sdk.api.IThingMatterConnectCallback`
- `com.thingclips.smart.sdk.api.IThingMatterDevice`
- `com.thingclips.smart.sdk.api.IThingMatterDeviceCacheManager`
- `com.thingclips.smart.sdk.api.IThingMatterDeviceConnectManager`
- `com.thingclips.smart.sdk.api.IThingMatterDevicePlugin`
- `com.thingclips.smart.sdk.api.IThingMatterFabricManager`
- `com.thingclips.smart.sdk.api.IThingMatterOperation`
- `com.thingclips.smart.sdk.api.IThingMessage`
- `com.thingclips.smart.sdk.api.IThingMultipleFabricCallback`
- `com.thingclips.smart.sdk.api.IThingOTACenter`
- `com.thingclips.smart.sdk.api.IThingOTAService`
- `com.thingclips.smart.sdk.api.IThingOptimizedActivator`
- `com.thingclips.smart.sdk.api.IThingOta`
- `com.thingclips.smart.sdk.api.IThingOtaPlugin`
- `com.thingclips.smart.sdk.api.IThingOtaServicePlugin`
- `com.thingclips.smart.sdk.api.IThingProductPanelManager`
- `com.thingclips.smart.sdk.api.IThingPush`
- `com.thingclips.smart.sdk.api.IThingQRCodeDevActivator`
- `com.thingclips.smart.sdk.api.IThingRouterDiscoverListener`
- `com.thingclips.smart.sdk.api.IThingSearchDeviceListener`
- `com.thingclips.smart.sdk.api.IThingSmartAPSendInfoListener`
- `com.thingclips.smart.sdk.api.IThingSmartActivatorListener`
- `com.thingclips.smart.sdk.api.IThingSmartBroadbandActivator`
- `com.thingclips.smart.sdk.api.IThingSmartCameraActivatorListener`
- `com.thingclips.smart.sdk.api.IThingSmartExtActivatorListener`
- `com.thingclips.smart.sdk.api.IThingSmartExtCameraActivatorListener`
- `com.thingclips.smart.sdk.api.IThingSmartQRCodeActivatorListener`
- `com.thingclips.smart.sdk.api.IThingSmartRequest`
- `com.thingclips.smart.sdk.api.IThingSmartTimer`
- `com.thingclips.smart.sdk.api.IThingTimer`
- `com.thingclips.smart.sdk.api.IThingUser`
- `com.thingclips.smart.sdk.api.IThingWifiGroup`
- `com.thingclips.smart.sdk.api.IThingZigbeeGroup`
- `com.thingclips.smart.sdk.api.MatterActivatorCallback`
- `com.thingclips.smart.sdk.api.MatterActivatorExtCallback`
- `com.thingclips.smart.sdk.api.MatterDevicePairCallback`
- `com.thingclips.smart.sdk.api.MatterDiscoveryCallback`
- `com.thingclips.smart.sdk.api.MatterOnlineListener`
- `com.thingclips.smart.sdk.api.MultipleFabricPasscode`
- `com.thingclips.smart.sdk.api.OnThingGeoFenceStatusListener`
- `com.thingclips.smart.sdk.api.OnThingGeoFencesListener`
- `com.thingclips.smart.sdk.api.WifiSignalListener`

### com.thingclips.smart.sdk.api.bluemesh

- `com.thingclips.smart.sdk.api.bluemesh.IAddGroupCallback`
- `com.thingclips.smart.sdk.api.bluemesh.IAddRemoteBindSubDevCallback`
- `com.thingclips.smart.sdk.api.bluemesh.IAddRoomCallback`
- `com.thingclips.smart.sdk.api.bluemesh.IAddSubDevCallback`
- `com.thingclips.smart.sdk.api.bluemesh.IBlueMeshActivatorListener`
- `com.thingclips.smart.sdk.api.bluemesh.IBlueMeshCreateCallback`
- `com.thingclips.smart.sdk.api.bluemesh.IBlueMeshManager`
- `com.thingclips.smart.sdk.api.bluemesh.IGetGroupAndDevListCallback`
- `com.thingclips.smart.sdk.api.bluemesh.IGetMeshRoomAndGroupListCallback`
- `com.thingclips.smart.sdk.api.bluemesh.IGroupDevCallback`
- `com.thingclips.smart.sdk.api.bluemesh.IMeshActionTransmitter`
- `com.thingclips.smart.sdk.api.bluemesh.IMeshDevListener`
- `com.thingclips.smart.sdk.api.bluemesh.IMeshDevListenerV2`
- `com.thingclips.smart.sdk.api.bluemesh.IMeshDevListenerV3`
- `com.thingclips.smart.sdk.api.bluemesh.IMeshDeviceListener`
- `com.thingclips.smart.sdk.api.bluemesh.IMeshDeviceRssiCallback`
- `com.thingclips.smart.sdk.api.bluemesh.IMeshStatusListener`
- `com.thingclips.smart.sdk.api.bluemesh.IRequestMeshListCallback`
- `com.thingclips.smart.sdk.api.bluemesh.IRequestSigMeshListCallback`
- `com.thingclips.smart.sdk.api.bluemesh.IRequestUpgradeInfoCallback`
- `com.thingclips.smart.sdk.api.bluemesh.ISigMeshConnect`
- `com.thingclips.smart.sdk.api.bluemesh.ISigMeshCreateCallback`
- `com.thingclips.smart.sdk.api.bluemesh.ISigMeshManager`
- `com.thingclips.smart.sdk.api.bluemesh.IThingBlueMesh`
- `com.thingclips.smart.sdk.api.bluemesh.IThingBlueMeshActivator`
- `com.thingclips.smart.sdk.api.bluemesh.IThingMeshGroup`
- `com.thingclips.smart.sdk.api.bluemesh.IThingRoomManager`

### com.thingclips.smart.sdk.api.bluemesh.advertise

- `com.thingclips.smart.sdk.api.bluemesh.advertise.IMeshAdvPreControl`
- `com.thingclips.smart.sdk.api.bluemesh.advertise.IMeshAdvTransmitter`

### com.thingclips.smart.sdk.api.bluemesh.message

- `com.thingclips.smart.sdk.api.bluemesh.message.GenericAction`
- `com.thingclips.smart.sdk.api.bluemesh.message.GenericOnOffAction`
- `com.thingclips.smart.sdk.api.bluemesh.message.MeshAction`
- `com.thingclips.smart.sdk.api.bluemesh.message.SearchForGenericAction`
- `com.thingclips.smart.sdk.api.bluemesh.message.VendorAction`
- `com.thingclips.smart.sdk.api.bluemesh.message.VendorDpAction`

### com.thingclips.smart.sdk.api.bluemesh.precontrol

- `com.thingclips.smart.sdk.api.bluemesh.precontrol.ISigMeshPreCtrl`
- `com.thingclips.smart.sdk.api.bluemesh.precontrol.PreCtrlProvision`

### com.thingclips.smart.sdk.api.cache

- `com.thingclips.smart.sdk.api.cache.ISmartCacheManager`
- `com.thingclips.smart.sdk.api.cache.ISmartStatusChangeListener`
- `com.thingclips.smart.sdk.api.cache.ISmartStatusManager`
- `com.thingclips.smart.sdk.api.cache.IThingCachePlugin`

### com.thingclips.smart.sdk.api.wifibackup.api

- `com.thingclips.smart.sdk.api.wifibackup.api.IThingWifiBackup`
- `com.thingclips.smart.sdk.api.wifibackup.api.IThingWifiBase`
- `com.thingclips.smart.sdk.api.wifibackup.api.IThingWifiSwitch`

### com.thingclips.smart.sdk.api.wifibackup.api.bean

- `com.thingclips.smart.sdk.api.wifibackup.api.bean.BackupWifiBean`
- `com.thingclips.smart.sdk.api.wifibackup.api.bean.BackupWifiListInfo`
- `com.thingclips.smart.sdk.api.wifibackup.api.bean.BackupWifiResultBean`
- `com.thingclips.smart.sdk.api.wifibackup.api.bean.BaseInfo`
- `com.thingclips.smart.sdk.api.wifibackup.api.bean.CurrentWifiInfoBean`
- `com.thingclips.smart.sdk.api.wifibackup.api.bean.SwitchWifiResultBean`

### com.thingclips.smart.sdk.apimodule

- `com.thingclips.smart.sdk.apimodule.BuildConfig`
- `com.thingclips.smart.sdk.apimodule.C0031R`

### com.thingclips.smart.sdk.base.apimodule

- `com.thingclips.smart.sdk.base.apimodule.BuildConfig`
- `com.thingclips.smart.sdk.base.apimodule.C0032R`

### com.thingclips.smart.sdk.bean

- `com.thingclips.smart.sdk.bean.ApActivatorBuilder`
- `com.thingclips.smart.sdk.bean.ApQueryBuilder`
- `com.thingclips.smart.sdk.bean.BaseDiscoveryInfo`
- `com.thingclips.smart.sdk.bean.BatchExecutionDps`
- `com.thingclips.smart.sdk.bean.BatchQuery`
- `com.thingclips.smart.sdk.bean.BeaconMeshBean`
- `com.thingclips.smart.sdk.bean.BleActivatorBean`
- `com.thingclips.smart.sdk.bean.BlueMeshBean`
- `com.thingclips.smart.sdk.bean.BlueMeshGroupBean`
- `com.thingclips.smart.sdk.bean.BlueMeshModuleMapBean`
- `com.thingclips.smart.sdk.bean.BlueMeshRelationDevBean`
- `com.thingclips.smart.sdk.bean.BlueMeshRoomBean`
- `com.thingclips.smart.sdk.bean.BlueMeshShareBean`
- `com.thingclips.smart.sdk.bean.BlueMeshSubDevBean`
- `com.thingclips.smart.sdk.bean.BlueMeshWifiStatusBean`
- `com.thingclips.smart.sdk.bean.BluetoothStatusBean`
- `com.thingclips.smart.sdk.bean.BroadResponseConType`
- `com.thingclips.smart.sdk.bean.CloudZigbeeGroupCreateBean`
- `com.thingclips.smart.sdk.bean.CommissioningParameters`
- `com.thingclips.smart.sdk.bean.ConnectDeviceBuilder`
- `com.thingclips.smart.sdk.bean.ConnectResult`
- `com.thingclips.smart.sdk.bean.ConnectTypeBean`
- `com.thingclips.smart.sdk.bean.DeviceBean`
- `com.thingclips.smart.sdk.bean.DeviceNodeBean`
- `com.thingclips.smart.sdk.bean.DiscoveryResult`
- `com.thingclips.smart.sdk.bean.DpBean`
- `com.thingclips.smart.sdk.bean.DpsInfoBean`
- `com.thingclips.smart.sdk.bean.EstablishResult`
- `com.thingclips.smart.sdk.bean.GroupBean`
- `com.thingclips.smart.sdk.bean.GroupDeviceBean`
- `com.thingclips.smart.sdk.bean.GroupShareBean`
- `com.thingclips.smart.sdk.bean.IsSupportOffLineBean`
- `com.thingclips.smart.sdk.bean.LocalKeyBean`
- `com.thingclips.smart.sdk.bean.LocationInfo`
- `com.thingclips.smart.sdk.bean.MatterDiscoveryInfo`
- `com.thingclips.smart.sdk.bean.MatterProductInfoBean`
- `com.thingclips.smart.sdk.bean.MatterQrCodeInfo`
- `com.thingclips.smart.sdk.bean.MultiModeActivatorBean`
- `com.thingclips.smart.sdk.bean.MultiModeActivatorBuilder`
- `com.thingclips.smart.sdk.bean.MultiModeActivatorConfig`
- `com.thingclips.smart.sdk.bean.MultiModeQueryBuilder`
- `com.thingclips.smart.sdk.bean.NocChainInfo`
- `com.thingclips.smart.sdk.bean.OTAErrorMessageBean`
- `com.thingclips.smart.sdk.bean.OffLineStatusBean`
- `com.thingclips.smart.sdk.bean.OpenFabricInfo`
- `com.thingclips.smart.sdk.bean.OperationalFabricInfo`
- `com.thingclips.smart.sdk.bean.PASEParameters`
- `com.thingclips.smart.sdk.bean.PairMatterBuilder`
- `com.thingclips.smart.sdk.bean.PauseStateData`
- `com.thingclips.smart.sdk.bean.ProductBean`
- `com.thingclips.smart.sdk.bean.ProductCloudFileBean`
- `com.thingclips.smart.sdk.bean.ProductPanelInfoBean`
- `com.thingclips.smart.sdk.bean.ProductStandardConfig`
- `com.thingclips.smart.sdk.bean.PushBean`
- `com.thingclips.smart.sdk.bean.QrScanBean`
- `com.thingclips.smart.sdk.bean.ResumeActivatorBean`
- `com.thingclips.smart.sdk.bean.RouterConfigData`
- `com.thingclips.smart.sdk.bean.RouterResponseConfig`
- `com.thingclips.smart.sdk.bean.ShareIdBean`
- `com.thingclips.smart.sdk.bean.ShortCutBean`
- `com.thingclips.smart.sdk.bean.SigMeshBean`
- `com.thingclips.smart.sdk.bean.SpeechTTSBean`
- `com.thingclips.smart.sdk.bean.StandSchema`
- `com.thingclips.smart.sdk.bean.SubDevInstallBean`
- `com.thingclips.smart.sdk.bean.SubDeviceDpEvent`
- `com.thingclips.smart.sdk.bean.ThingGeoFence`
- `com.thingclips.smart.sdk.bean.ThingMatterAttributeBasicInfo`
- `com.thingclips.smart.sdk.bean.ThingMatterDataPoint`
- `com.thingclips.smart.sdk.bean.ThingMatterDeviceBean`
- `com.thingclips.smart.sdk.bean.ThingMatterDiscovery`
- `com.thingclips.smart.sdk.bean.ThingMatterPairInfoBean`
- `com.thingclips.smart.sdk.bean.ThingMatterProductInfoBean`
- `com.thingclips.smart.sdk.bean.ThingSmartThingAction`
- `com.thingclips.smart.sdk.bean.ThingSmartThingEvent`
- `com.thingclips.smart.sdk.bean.ThingSmartThingModel`
- `com.thingclips.smart.sdk.bean.ThingSmartThingProperty`
- `com.thingclips.smart.sdk.bean.ThingSmartThingServiceModel`
- `com.thingclips.smart.sdk.bean.ThirdMatterActiveBean`
- `com.thingclips.smart.sdk.bean.ThreadNetworkInfoBean`
- `com.thingclips.smart.sdk.bean.ThreadNetworkScanResult`
- `com.thingclips.smart.sdk.bean.Timer`
- `com.thingclips.smart.sdk.bean.TimerControlBean`
- `com.thingclips.smart.sdk.bean.TimerTask`
- `com.thingclips.smart.sdk.bean.TimerTaskStatus`
- `com.thingclips.smart.sdk.bean.UiInfo`
- `com.thingclips.smart.sdk.bean.UuidInfo`
- `com.thingclips.smart.sdk.bean.WiFiScanResult`
- `com.thingclips.smart.sdk.bean.ZigbeeGroupCreateResultBean`

### com.thingclips.smart.sdk.bean.cache

- `com.thingclips.smart.sdk.bean.cache.DevUpgradeStatus`
- `com.thingclips.smart.sdk.bean.cache.IBlueMeshProperty`
- `com.thingclips.smart.sdk.bean.cache.IGroupProperty`
- `com.thingclips.smart.sdk.bean.cache.ISigMeshProperty`

### com.thingclips.smart.sdk.bean.feedback

- `com.thingclips.smart.sdk.bean.feedback.FeedbackBean`
- `com.thingclips.smart.sdk.bean.feedback.FeedbackMsgBean`
- `com.thingclips.smart.sdk.bean.feedback.FeedbackMsgListBean`
- `com.thingclips.smart.sdk.bean.feedback.FeedbackTypeBean`
- `com.thingclips.smart.sdk.bean.feedback.FeedbackTypeRespBean`

### com.thingclips.smart.sdk.bean.message

- `com.thingclips.smart.sdk.bean.message.DeviceAlarmNotDisturbVO`
- `com.thingclips.smart.sdk.bean.message.MessageAttach`
- `com.thingclips.smart.sdk.bean.message.MessageBean`
- `com.thingclips.smart.sdk.bean.message.MessageEncryptImageKeyBean`
- `com.thingclips.smart.sdk.bean.message.MessageEncryptImageKeyRequest`
- `com.thingclips.smart.sdk.bean.message.MessageListBean`
- `com.thingclips.smart.sdk.bean.message.NodisturbDevicesBean`

### com.thingclips.smart.sdk.bean.privacy

- `com.thingclips.smart.sdk.bean.privacy.PrivacyAuthorizationBean`

### com.thingclips.smart.sdk.bean.push

- `com.thingclips.smart.sdk.bean.push.AlarmRemindBean`
- `com.thingclips.smart.sdk.bean.push.MQCompensationBean`
- `com.thingclips.smart.sdk.bean.push.PushStatusBean`
- `com.thingclips.smart.sdk.bean.push.ThingPushBean`

### com.thingclips.smart.sdk.bluetooth.api

- `com.thingclips.smart.sdk.bluetooth.api.BuildConfig`
- `com.thingclips.smart.sdk.bluetooth.api.C0036R`

### com.thingclips.smart.sdk.bluetooth.business.api

- `com.thingclips.smart.sdk.bluetooth.business.api.BuildConfig`
- `com.thingclips.smart.sdk.bluetooth.business.api.C0037R`

### com.thingclips.smart.sdk.builder

- `com.thingclips.smart.sdk.builder.ConnectStrategy`
- `com.thingclips.smart.sdk.builder.MeshConnectBuilder`

### com.thingclips.smart.sdk.camera.api

- `com.thingclips.smart.sdk.camera.api.BuildConfig`
- `com.thingclips.smart.sdk.camera.api.C0038R`

### com.thingclips.smart.sdk.constant

- `com.thingclips.smart.sdk.constant.ServiceNotification`

### com.thingclips.smart.sdk.depercated.api

- `com.thingclips.smart.sdk.depercated.api.BuildConfig`

### com.thingclips.smart.sdk.device.api

- `com.thingclips.smart.sdk.device.api.BuildConfig`
- `com.thingclips.smart.sdk.device.api.C0039R`

### com.thingclips.smart.sdk.enums

- `com.thingclips.smart.sdk.enums.ActivatorAPStepCode`
- `com.thingclips.smart.sdk.enums.ActivatorEZStepCode`
- `com.thingclips.smart.sdk.enums.ActivatorMeshStepCode`
- `com.thingclips.smart.sdk.enums.SubDevExtensionKey`

### com.thingclips.smart.sdk.geofence.api

- `com.thingclips.smart.sdk.geofence.api.BuildConfig`
- `com.thingclips.smart.sdk.geofence.api.C0040R`

### com.thingclips.smart.sdk.hardware.api

- `com.thingclips.smart.sdk.hardware.api.BuildConfig`
- `com.thingclips.smart.sdk.hardware.api.C0041R`

### com.thingclips.smart.sdk.hardware.base.api

- `com.thingclips.smart.sdk.hardware.base.api.BuildConfig`

### com.thingclips.smart.sdk.hardware.business.api

- `com.thingclips.smart.sdk.hardware.business.api.BuildConfig`
- `com.thingclips.smart.sdk.hardware.business.api.C0042R`

### com.thingclips.smart.sdk.homelib.api

- `com.thingclips.smart.sdk.homelib.api.BuildConfig`
- `com.thingclips.smart.sdk.homelib.api.C0043R`

### com.thingclips.smart.sdk.logmodule

- `com.thingclips.smart.sdk.logmodule.BuildConfig`

### com.thingclips.smart.sdk.mqtt.api

- `com.thingclips.smart.sdk.mqtt.api.BuildConfig`
- `com.thingclips.smart.sdk.mqtt.api.C0044R`


</details>
