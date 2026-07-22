# Android 9 Compatibility Session

## Scope

Target device: ASUS I01WD / WW ZS630KL, Android 9, API 28, Qualcomm Keymaster.
Target failures: hardware attestation either returns vendor-specific `-10003` or succeeds with an
untrusted/unlocked OEM certificate chain.
Target behavior: preserve real Keystore private keys, rebuild successful certificate chains with the
configured keybox, and synthesize a certificate chain after `attestKey` fails with `-10003`.

This is an attestation compatibility layer, not a repair of OEM TEE provisioning.

## Evidence

- `qseecomd` and `android.hardware.keymaster@4.0-service-qti` are running on the device.
- Existing device logs show `KeyMasterHalDevice: resp->status: -10003`.
- Android 9 uses the synchronous pre-Q `android.security.IKeystoreService` Binder contract.
- Current TEESimulator-RS routes only API 29/30 to the legacy interceptor and declares `minSdk=29`.
- Upstream Android 8/9 support request was closed because maintainers lacked test devices, not because the design was impossible: https://github.com/JingMatrix/TEESimulator/issues/69

## Changes in This Session

- Lowered app/stub/module minimum SDK from 29 to 28.
- Added Android Pie dispatch to `KeystorePInterceptor`.
- Added a compile-only Android 9 `IKeystoreService` declaration and `KeymasterBlob` declaration.
- Added Pie synchronous transaction handling for `generateKey` and `attestKey`.
- Added fallback path: export the generated hardware public key, generate a chain, and return it only when the original result is `-10003`.
- Added successful-response handling: parse the synchronous Pie certificate-chain parcel, preserve
  the original leaf public key and attestation parameters, then rebuild the chain with the configured
  keybox.
- Added synthesis fallback for malformed or unpatchable successful chains.
- Added synthesis attempts for other negative QTI `attestKey` results; the original error is
  preserved if no valid replacement can be produced.
- Added stored `USRCERT_` public-key recovery when direct `exportKey` is unavailable.
- Added EC/RSA cross-algorithm keybox signing and keybox integrity preflight.
- Preserved requested legacy device-ID attestation fields when a QTI error is synthesized.
- Fail closed for targeted Pie attestation when neither patching nor synthesis can replace a
  successful OEM reply, preventing the real chain from being returned unchanged.
- Added Android 9 OS/attestation version fallbacks.
- Removed a direct runtime dependency on `KeyStoreException.isTransientFailure()` for API 28.
- Added fail-closed module disable marker after repeated injection/backdoor failure.
- Updated the native supervisor to stop when `<module>/disable` exists.

## Files Changed

- `app/build.gradle.kts`
- `stub/build.gradle.kts`
- `module/customize.sh`
- `app/src/main/java/org/matrix/TEESimulator/App.kt`
- `app/src/main/java/org/matrix/TEESimulator/interception/keystore/KeystorePInterceptor.kt`
- `app/src/main/java/org/matrix/TEESimulator/interception/keystore/KeystoreInterceptor.kt`
- `app/src/main/java/org/matrix/TEESimulator/interception/keystore/AbstractKeystoreInterceptor.kt`
- `app/src/main/java/org/matrix/TEESimulator/attestation/DeviceAttestationService.kt`
- `app/src/main/java/org/matrix/TEESimulator/util/AndroidDeviceUtils.kt`
- `app/src/main/cpp/supervisor.cpp`
- `stub/src/main/java/android/security/IKeystoreService.java`
- `stub/src/main/java/android/security/KeyStore.java`
- `stub/src/main/java/android/security/keymaster/KeymasterBlob.java`

## Verification Status

- `git diff --check`: passed.
- Successful-chain parcel reader checked against the Android 9 AOSP
  `KeymasterCertificateChain.writeToParcel` layout.
- Gradle compile/build: not run, per request; cloud CI is the build authority for this branch.
- Android 9 device test: pending.

## Next Actions

1. Run cloud/CI build with JDK 21 and Android SDK/NDK configured by the repository.
2. Fix any Kotlin/API-28 compile or verifier issues.
3. Install only on a recoverable test setup; keep the module disabled until a clean boot is confirmed.
4. Test Key Attestation with all other Zygisk/LSPosed/PIF modules disabled.
5. Capture `logcat -b all -s TEESimulator KeyMasterHalDevice keystore` and verify either
   `Replaced successful QTI Pie attestation` or the existing `Replaced QTI Pie attestation failure`
   path.
6. Test WorldFirst only after Key Attestation and ordinary hardware key operations are stable.

## Safety Rules

- Do not delete `/data/misc/keystore`.
- Do not flash another device's `persist`, EFS, RPMB, keybox, or TEE data.
- Do not relock the bootloader while any modified partition is installed.
- A valid keybox is required for strict certificate-chain verification; no keybox is bundled in this worktree.
