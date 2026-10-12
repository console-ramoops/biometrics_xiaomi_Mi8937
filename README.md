# Xiaomi MSM8937 Biometrics Fingerprint HAL

Native AIDL Biometrics Fingerprint HAL service (`android.hardware.biometrics.fingerprint`) replacing legacy HIDL 2.1 for Xiaomi MSM8937 devices (*santoni*, *land*, *prada*, *ugg*, *ugglite*) on modern Android versions (Android 14, 15, 16+).

This repository contains the standalone biometrics module that sits directly at `biometrics/` inside the Xiaomi MSM8937 unified device tree.

## Targets

- **`aidl-wt8937`**: For *santoni*, *land*, and *prada*.
  - Userspace sensor detection via `persist.sys.fp.vendor` (`switchf` vs `goodix`)
  - Goodix GPIO cleanup via ioctls (`GF_IOC_RESET`, `GF_IOC_DISABLE_IRQ`, `GF_IOC_RELEASE_GPIO`)
  - Sysfs `fpc_enable` controls (`compatible_all`, `spi_prepare`)
  - Synchronous 2.0 template enumeration array handling
- **`aidl-ulysse`**: For *ugg* and *ugglite*.
  - Bootloader sensor detection via `ro.boot.fpsensor` (`fpc` vs Goodix)
  - Sysfs `hw_reset` FPC cleanup for Goodix
  - Standard 2.1 asynchronous streaming enumeration via `FINGERPRINT_TEMPLATE_ENUMERATING`

## Repository Structure

```
├── aidl-ulysse/
│   ├── Android.bp
│   ├── CancellationSignal.h
│   ├── Fingerprint.cpp
│   ├── Fingerprint.h
│   ├── Session.cpp
│   ├── Session.h
│   ├── android.hardware.biometrics.fingerprint-service.xiaomi_ulysse.rc
│   ├── android.hardware.biometrics.fingerprint-service.xiaomi_ulysse.xml
│   └── service.cpp
├── aidl-wt8937/
│   ├── Android.bp
│   ├── CancellationSignal.h
│   ├── Fingerprint.cpp
│   ├── Fingerprint.h
│   ├── Session.cpp
│   ├── Session.h
│   ├── android.hardware.biometrics.fingerprint-service.xiaomi_wt8937.rc
│   ├── android.hardware.biometrics.fingerprint-service.xiaomi_wt8937.xml
│   ├── gf_ioctl.h
│   └── service.cpp
├── sepolicy/
└── sepolicy-odm/
    ├── file_contexts
    └── hal_fingerprint_default.te
```

## Device Tree Integration

In `device.mk`:
```makefile
PRODUCT_PACKAGES += \
    android.hardware.biometrics.fingerprint-service.xiaomi_ulysse \
    android.hardware.biometrics.fingerprint-service.xiaomi_wt8937
```

In `BoardConfig.mk`:
```makefile
BOARD_ODM_SEPOLICY_DIRS += $(DEVICE_PATH)/biometrics/sepolicy-odm
BOARD_VENDOR_SEPOLICY_DIRS += $(DEVICE_PATH)/biometrics/sepolicy
```

## VINTF & Compatibility

- Target FCM Level: 7 (Android 13 / SDK 33).
- VINTF declaration: `<version>2</version>`, satisfying SDK 33 vendor FCM constraints while supporting runtime AIDL V4 contracts across Android 14, 15, and 16.

---

> /!\ **Disclaimer**: Made with AI. Please test thoroughly on target hardware before production use.

