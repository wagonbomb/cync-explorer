# How to Get Cync APK

## Option 1: From Android Device (Easiest)
If you have an Android device with Cync installed:

1. Install APK Extractor from Play Store
2. Open APK Extractor, find "Cync" app
3. Extract the APK
4. Transfer to PC: `C:\Users\Meow\Documents\Projects\cync-explorer\artifacts\com.ge.cbyge.apk`

## Option 2: Google Play Store Direct
Use online APK downloader:
1. Go to: https://apps.evozi.com/apk-downloader/
2. Enter Play Store URL: `https://play.google.com/store/apps/details?id=com.gelighting.cync`
3. Click "Generate Download Link"
4. Download and save as: `C:\Users\Meow\Documents\Projects\cync-explorer\artifacts\com.ge.cbyge.apk`

## Option 3: APKPure
1. Go to: https://apkpure.com/
2. Search for "Cync" or "GE Cync"
3. Download latest version
4. Save as: `C:\Users\Meow\Documents\Projects\cync-explorer\artifacts\com.ge.cbyge.apk`

## Option 4: APKCombo
1. Go to: https://apkcombo.com/
2. Search for "Cync"
3. Download latest version
4. Save as: `C:\Users\Meow\Documents\Projects\cync-explorer\artifacts\com.ge.cbyge.apk`

## Package Name
The app package name is: **com.gelighting.cync**

## Once Downloaded
Run decompilation:
```powershell
cd C:\Users\Meow\Documents\Projects\cync-explorer
.\tools-local\jadx\bin\jadx.bat -d .\artifacts\cync_decompiled .\artifacts\com.ge.cbyge.apk
```
