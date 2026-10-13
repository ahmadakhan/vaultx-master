# Native mobile build integration

This directory contains native adapter libraries only. It does **not** contain
an iOS application, Android application, manifests, UI, or a complete upload
client. The adapters are intentionally separate from the browser frontend.

## iOS

`ios/Package.swift` exposes `VaultXTransfer` as an iOS 15 Swift Package. On a
macOS host with Xcode and the iOS SDK installed:

```sh
cd mobile/ios
swift package resolve
swift build
```

For an Xcode-compatible package build, open `mobile/ios/Package.swift` in
Xcode and select an iOS simulator/device destination. The `Security` framework
is linked by the package manifest.

On Linux, the source cannot be fully compiled because Apple's `Security`
framework and iOS SDK are unavailable. `swift package dump-package` can still
validate the manifest when Swift is installed.

## Android

`android/` is a standalone Android library project. It targets SDK 35, Java 17,
and contains the WorkManager and AndroidX Security Crypto dependencies used by
`VaultXBackgroundTransfer.kt`.

With Android Studio/SDK, Java 17, and Gradle available:

```sh
cd mobile/android
gradle :vaultx-transfer:assemble
gradle :vaultx-transfer:compileDebugKotlin
```

There is no Gradle wrapper checked in yet, so these commands require a locally
installed Gradle (or opening the directory in Android Studio, which can create
and use a wrapper). Dependency resolution also requires access to Google's and
Maven Central's repositories. No Android build is claimed unless these commands
complete on a configured Android host.
