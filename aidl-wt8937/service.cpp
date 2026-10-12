#include "Fingerprint.h"
#include "gf_ioctl.h"

#include <android/binder_ibinder.h>
#include <android/log.h>
#include <fcntl.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <cstring>
#include <string>

#define LOG_TAG "android.hardware.biometrics.fingerprint-service.xiaomi_wt8937"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" {
binder_status_t AServiceManager_addService(AIBinder* binder, const char* instance);
void ABinderProcess_setThreadPoolMaxThreadCount(uint32_t numThreads);
void ABinderProcess_startThreadPool();
void ABinderProcess_joinThreadPool();
}

using aidl::android::hardware::biometrics::fingerprint::Fingerprint;

static constexpr char kGoodixFpDev[] = "/dev/goodix_fp";

static void fpc_enable(bool enable) {
    const char* val = enable ? "enable" : "disable";

    const char* compNodes[] = {
        "/sys/devices/soc/soc:fpc1020/compatible_all",
        "/sys/devices/platform/soc/soc:fpc1020/compatible_all"
    };
    for (const char* node : compNodes) {
        int fd = open(node, O_WRONLY);
        if (fd >= 0) {
            write(fd, val, strlen(val));
            close(fd);
            break;
        }
    }

    const char* spiNodes[] = {
        "/sys/devices/soc/soc:fpc1020/spi_prepare",
        "/sys/devices/platform/soc/soc:fpc1020/spi_prepare"
    };
    for (const char* node : spiNodes) {
        int fd = open(node, O_WRONLY);
        if (fd >= 0) {
            write(fd, val, strlen(val));
            close(fd);
            break;
        }
    }
}

static void goodix_cleanup() {
    int fd = open(kGoodixFpDev, O_RDWR);
    if (fd >= 0) {
        int val = 1;
        ioctl(fd, GF_IOC_RESET, &val);
        ioctl(fd, GF_IOC_DISABLE_IRQ, &val);
        ioctl(fd, GF_IOC_RELEASE_GPIO, &val);
        close(fd);
        ALOGI("Cleaned up goodix device node");
    }
}

int main() {
    ALOGI("Starting android.hardware.biometrics.fingerprint-service.xiaomi_wt8937...");

    char vendorProp[PROP_VALUE_MAX] = {0};
    __system_property_get("persist.sys.fp.vendor", vendorProp);
    ALOGI("persist.sys.fp.vendor = %s", vendorProp);

    if (strcmp(vendorProp, "goodix") != 0) {
        goodix_cleanup();
        fpc_enable(true);
    } else {
        fpc_enable(false);
    }

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
