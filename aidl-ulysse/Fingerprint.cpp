#include "Fingerprint.h"

#include <aidl/android/hardware/biometrics/common/SensorStrength.h>
#include <aidl/android/hardware/biometrics/fingerprint/FingerprintSensorType.h>
#include <aidl/android/hardware/biometrics/fingerprint/SensorLocation.h>
#include <aidl/android/hardware/biometrics/fingerprint/SensorShape.h>

#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <cstring>

#define LOG_TAG "FingerprintHalUlysse"
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace aidl::android::hardware::biometrics::fingerprint {

Fingerprint* Fingerprint::sInstance = nullptr;

Fingerprint::Fingerprint()
    : mDevice(nullptr), mHalHandle(nullptr) {
    sInstance = this;
    ALOGI("Fingerprint HAL ulysse instance created");
    initHal();
}

Fingerprint::~Fingerprint() {
    ALOGI("Fingerprint HAL ulysse destroyed");
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
    char bootFpsensor[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.boot.fpsensor", bootFpsensor);
    ALOGI("ro.boot.fpsensor = %s", bootFpsensor);

    std::vector<std::string> halPaths;
    if (strcmp(bootFpsensor, "fpc") == 0) {
        ALOGI("Loading FPC Fingerprint HAL for ulysse");
        halPaths.push_back("/odm/lib64/hw/fingerprint.ugg_fpc.so");
        halPaths.push_back("/vendor/lib64/hw/fingerprint.ugg_fpc.so");
        halPaths.push_back("/odm/lib64/hw/fingerprint.default.so");
        halPaths.push_back("/vendor/lib64/hw/fingerprint.default.so");
    } else {
        ALOGI("Cleaning up FPC and loading Goodix HAL for ulysse");
        const char* resetNodes[] = {
            "/sys/devices/soc/soc:fpc1020/hw_reset",
            "/sys/devices/platform/soc/soc:fpc1020/hw_reset"
        };
        for (const char* node : resetNodes) {
            int resetFd = open(node, O_WRONLY);
            if (resetFd >= 0) {
                write(resetFd, "reset", 5);
                close(resetFd);
                break;
            }
        }
        halPaths.push_back("/odm/lib64/hw/gf_fingerprint.ugg.so");
        halPaths.push_back("/vendor/lib64/hw/gf_fingerprint.ugg.so");
        halPaths.push_back("/odm/lib64/hw/gf_fingerprint.default.so");
        halPaths.push_back("/vendor/lib64/hw/gf_fingerprint.default.so");
    }

    // Fallbacks
    halPaths.push_back("/odm/lib64/hw/fingerprint.ugg_fpc.so");
    halPaths.push_back("/vendor/lib64/hw/fingerprint.ugg_fpc.so");
    halPaths.push_back("/odm/lib64/hw/gf_fingerprint.ugg.so");
    halPaths.push_back("/vendor/lib64/hw/gf_fingerprint.ugg.so");

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
        ALOGE("Failed to dlopen any legacy fingerprint HAL library for ulysse");
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

    hw_device_t* device = nullptr;
    int err = module->common.methods->open(
            reinterpret_cast<const hw_module_t*>(module),
            nullptr,
            &device);
    if (err != 0 || !device) {
        ALOGE("Failed to open legacy fingerprint device: %d", err);
        dlclose(mHalHandle);
        mHalHandle = nullptr;
        return false;
    }

    mDevice = reinterpret_cast<fingerprint_device_t*>(device);
    ALOGI("Legacy fingerprint device opened successfully (HAL API %u.%u)",
          (mDevice->common.version >> 8) & 0xff, mDevice->common.version & 0xff);

    mDevice->set_notify(mDevice, onLegacyNotify);
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
        ALOGD("Legacy notify received without active session (type=%d)", msg ? msg->type : -1);
    }
}

::ndk::ScopedAStatus Fingerprint::getSensorProps(
        std::vector<SensorProps>* _aidl_return) {
    ALOGD("getSensorProps");
    SensorProps props;
    props.commonProps.sensorId = 0;
    props.commonProps.sensorStrength = common::SensorStrength::STRONG;
    props.commonProps.maxEnrollmentsPerUser = 5;
    props.commonProps.componentInfo = {};
    props.commonProps.resetLockoutRequiresHardwareAuthToken = false;
    props.commonProps.resetLockoutRequiresChallenge = false;

    props.sensorType = FingerprintSensorType::REAR;

    SensorLocation loc;
    loc.sensorId = 0;
    loc.sensorLocationX = 540;
    loc.sensorLocationY = 800;
    loc.sensorRadius = 60;
    loc.display = "";
    loc.sensorShape = SensorShape::CIRCLE;
    props.sensorLocations = {loc};

    props.navigationGuesture = false;
    props.detectInteraction = false;
    props.displayImages = false;
    props.supportsHalControls = false;

    _aidl_return->clear();
    _aidl_return->push_back(props);
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Fingerprint::createSession(
        int32_t sensorId, int32_t userId,
        const std::shared_ptr<ISessionCallback>& cb,
        std::shared_ptr<ISession>* _aidl_return) {
    ALOGD("createSession for sensorId=%d, userId=%d", sensorId, userId);
    if (!cb) {
        return ::ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
    }

    if (!mDevice) {
        if (!initHal()) {
            ALOGE("Cannot create session: HAL initialization failed");
            return ::ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
        }
    }

    auto session = ndk::SharedRefBase::make<Session>(sensorId, userId, cb, mDevice);
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
