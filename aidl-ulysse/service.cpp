#include "Fingerprint.h"

#include <android/binder_ibinder.h>
#include <android/log.h>
#include <fcntl.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <cstring>
#include <string>

#define LOG_TAG "android.hardware.biometrics.fingerprint-service.xiaomi_ulysse"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" {
binder_status_t AServiceManager_addService(AIBinder* binder, const char* instance);
void ABinderProcess_setThreadPoolMaxThreadCount(uint32_t numThreads);
void ABinderProcess_startThreadPool();
void ABinderProcess_joinThreadPool();
}

using aidl::android::hardware::biometrics::fingerprint::Fingerprint;

static void ulysse_hw_init() {
    char bootFpsensor[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.boot.fpsensor", bootFpsensor);
    ALOGI("ro.boot.fpsensor = %s", bootFpsensor);

    if (strcmp(bootFpsensor, "fpc") != 0) {
        // Clean up FPC for Goodix
        const char* resetNodes[] = {
            "/sys/devices/soc/soc:fpc1020/hw_reset",
            "/sys/devices/platform/soc/soc:fpc1020/hw_reset"
        };
        for (const char* node : resetNodes) {
            int fd = open(node, O_WRONLY);
            if (fd >= 0) {
                write(fd, "reset", 5);
                close(fd);
                ALOGI("Cleaned up FPC on %s", node);
                break;
            }
        }
    }
}

int main() {
    ALOGI("Starting android.hardware.biometrics.fingerprint-service.xiaomi_ulysse...");

    ulysse_hw_init();

    ABinderProcess_setThreadPoolMaxThreadCount(4);
    ABinderProcess_startThreadPool();

    std::shared_ptr<Fingerprint> service = ::ndk::SharedRefBase::make<Fingerprint>();
    const std::string instance = std::string(Fingerprint::descriptor) + "/default";

    binder_status_t status = AServiceManager_addService(service->asBinder().get(), instance.c_str());
    if (status != STATUS_OK) {
        ALOGE("Failed to register service %s with error %d", instance.c_str(), status);
        return 1;
    }

    ALOGI("Service %s registered successfully", instance.c_str());
    __system_property_set("ro.vendor.fingerprint.succeed", "1");
    __system_property_set("ro.vendor.fingerprint.state", "1");

    ABinderProcess_joinThreadPool();
    return 0;
}
