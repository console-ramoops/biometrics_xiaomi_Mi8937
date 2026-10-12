#pragma once

#include <aidl/android/hardware/biometrics/fingerprint/BnFingerprint.h>
#include <hardware/fingerprint.h>
#include "Session.h"

#include <memory>
#include <mutex>

namespace aidl::android::hardware::biometrics::fingerprint {

class Fingerprint : public BnFingerprint {
public:
    Fingerprint();
    virtual ~Fingerprint();

    bool initHal();

    ::ndk::ScopedAStatus getSensorProps(
            std::vector<SensorProps>* _aidl_return) override;

    ::ndk::ScopedAStatus createSession(
            int32_t sensorId, int32_t userId,
            const std::shared_ptr<ISessionCallback>& cb,
            std::shared_ptr<ISession>* _aidl_return) override;

    static void onLegacyNotify(const fingerprint_msg_t* msg);

private:
    static Fingerprint* sInstance;
    fingerprint_device_t* mDevice;
    void* mHalHandle;
    std::mutex mSessionMutex;
    std::weak_ptr<Session> mCurrentSession;
};

}  // namespace aidl::android::hardware::biometrics::fingerprint
