#include "Fingerprint.h"

#include <aidl/android/hardware/biometrics/common/SensorStrength.h>
#include <aidl/android/hardware/biometrics/fingerprint/FingerprintSensorType.h>
#include <aidl/android/hardware/biometrics/fingerprint/SensorLocation.h>
#include <aidl/android/hardware/biometrics/fingerprint/SensorShape.h>

#include <android/log.h>
#include <dlfcn.h>
#include <sys/system_properties.h>

#define LOG_TAG "FingerprintHal"
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace aidl::android::hardware::biometrics::fingerprint {

Fingerprint* Fingerprint::sInstance = nullptr;

Fingerprint::Fingerprint()
    : mDevice(nullptr), mHalHandle(nullptr) {
    sInstance = this;
    ALOGI("Fingerprint HAL instance created");
    initHal();
}

Fingerprint::~Fingerprint() {
    ALOGI("Fingerprint HAL destroyed");
    if (mDevice && mDevice->common.close) {
        mDevice->common.close(reinterpret_cast<hw_device_t*>(mDevice));
        mDevice = nullptr;
    }
    if (mHalHandle) {
        dlclose(mHalHandle);
        mHalHandle = nullptr;
    }
    sInstance = nullptr;
}

bool Fingerprint::initHal() {
    char hwFp[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.hardware.fingerprint", hwFp);

    char hwGf[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.hardware.gf_fingerprint", hwGf);

    std::vector<std::string> halPaths;
    if (strlen(hwFp) > 0) {
        halPaths.push_back(std::string("/odm/lib64/hw/fingerprint.") + hwFp + ".so");
        halPaths.push_back(std::string("/vendor/lib64/hw/fingerprint.") + hwFp + ".so");
    }
    if (strlen(hwGf) > 0) {
        halPaths.push_back(std::string("/odm/lib64/hw/gf_fingerprint.") + hwGf + ".so");
        halPaths.push_back(std::string("/vendor/lib64/hw/gf_fingerprint.") + hwGf + ".so");
    }

    // Direct fallback candidates
    halPaths.push_back("/odm/lib64/hw/fingerprint.santoni_fpc.so");
    halPaths.push_back("/vendor/lib64/hw/fingerprint.santoni_fpc.so");
    halPaths.push_back("/odm/lib64/hw/fingerprint.ugg_fpc.so");
    halPaths.push_back("/vendor/lib64/hw/fingerprint.ugg_fpc.so");
    halPaths.push_back("/odm/lib64/hw/gf_fingerprint.ugg.so");
    halPaths.push_back("/vendor/lib64/hw/gf_fingerprint.ugg.so");
    halPaths.push_back("/odm/lib64/hw/fingerprint.land_fpc.so");
    halPaths.push_back("/vendor/lib64/hw/fingerprint.land_fpc.so");
    halPaths.push_back("/odm/lib64/hw/fingerprint.prada_fpc.so");
    halPaths.push_back("/vendor/lib64/hw/fingerprint.prada_fpc.so");
    halPaths.push_back("/odm/lib64/hw/fingerprint.wt8937.so");
    halPaths.push_back("/vendor/lib64/hw/fingerprint.wt8937.so");

    for (const auto& path : halPaths) {
        mHalHandle = dlopen(path.c_str(), RTLD_NOW);
        if (mHalHandle) {
            ALOGI("Successfully dlopened legacy HAL: %s", path.c_str());
            break;
        } else {
            ALOGD("dlopen(%s) failed: %s", path.c_str(), dlerror());
        }
    }

    if (!mHalHandle) {
        ALOGE("Failed to dlopen any legacy fingerprint HAL library");
        return false;
    }

    const fingerprint_module_t* module = static_cast<const fingerprint_module_t*>(dlsym(mHalHandle, "HMI"));
    if (!module) {
        ALOGE("Failed to find HMI symbol in legacy HAL");
        dlclose(mHalHandle);
        mHalHandle = nullptr;
        return false;
    }

    if (!module->common.methods || !module->common.methods->open) {
        ALOGE("Legacy module missing open method");
        dlclose(mHalHandle);
        mHalHandle = nullptr;
        return false;
    }

    hw_device_t* dev = nullptr;
    int err = module->common.methods->open(reinterpret_cast<const hw_module_t*>(module), nullptr, &dev);
    if (err != 0 || !dev) {
        ALOGE("Legacy module open failed with error: %d", err);
        dlclose(mHalHandle);
        mHalHandle = nullptr;
        return false;
    }

    mDevice = reinterpret_cast<fingerprint_device_t*>(dev);
    ALOGI("Legacy fingerprint_device_t opened successfully");

    if (mDevice->set_notify) {
        err = mDevice->set_notify(mDevice, Fingerprint::onLegacyNotify);
        if (err != 0) {
            ALOGE("set_notify failed with error: %d", err);
        } else {
            ALOGI("set_notify callback registered with legacy HAL");
        }
    }

    return true;
}

void Fingerprint::onLegacyNotify(const fingerprint_msg_t* msg) {
    if (!sInstance) return;

    std::shared_ptr<Session> session;
    {
        std::lock_guard<std::mutex> lock(sInstance->mSessionMutex);
        session = sInstance->mCurrentSession.lock();
    }

    if (session) {
        session->handleLegacyNotify(msg);
    } else {
        ALOGD("onLegacyNotify: No active session to receive notification");
    }
}

::ndk::ScopedAStatus Fingerprint::getSensorProps(
        std::vector<SensorProps>* _aidl_return) {
    ALOGD("getSensorProps called");

    SensorProps props;
    props.commonProps.sensorId = 0;
    props.commonProps.sensorStrength = common::SensorStrength::STRONG;
    props.commonProps.maxEnrollmentsPerUser = 5;
    props.commonProps.componentInfo = {};

    props.sensorType = FingerprintSensorType::REAR;
    props.supportsNavigationGestures = false;
    props.supportsDetectInteraction = false;
    props.halHandlesDisplayTouches = false;
    props.halControlsIllumination = false;

    SensorLocation loc;
    loc.sensorLocationX = 540;
    loc.sensorLocationY = 1600;
    loc.sensorRadius = 100;
    loc.display = "";
    loc.sensorShape = SensorShape::CIRCLE;

    props.sensorLocations.push_back(loc);

    _aidl_return->clear();
    _aidl_return->push_back(props);

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Fingerprint::createSession(
        int32_t in_sensorId, int32_t in_userId,
        const std::shared_ptr<ISessionCallback>& in_cb,
        std::shared_ptr<ISession>* _aidl_return) {
    ALOGI("createSession: sensorId=%d, userId=%d", in_sensorId, in_userId);

    auto session = ::ndk::SharedRefBase::make<Session>(in_sensorId, in_userId, in_cb, mDevice);
    session->setSelf(session);
    session->initSession();

    {
        std::lock_guard<std::mutex> lock(mSessionMutex);
        mCurrentSession = session;
    }

    *_aidl_return = session;
    return ::ndk::ScopedAStatus::ok();
}

}  // namespace aidl::android::hardware::biometrics::fingerprint
