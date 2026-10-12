#pragma once

#include <aidl/android/hardware/biometrics/fingerprint/BnSession.h>
#include <aidl/android/hardware/biometrics/fingerprint/ISessionCallback.h>
#include <aidl/android/hardware/biometrics/common/ICancellationSignal.h>
#include <aidl/android/hardware/keymaster/HardwareAuthToken.h>

#include <hardware/fingerprint.h>
#include <hardware/hw_auth_token.h>

#include <memory>
#include <mutex>
#include <vector>

namespace aidl::android::hardware::biometrics::fingerprint {

class Session : public BnSession {
public:
    Session(int32_t sensorId, int32_t userId,
            std::shared_ptr<ISessionCallback> cb,
            fingerprint_device_t* device);
    virtual ~Session();

    void setSelf(std::weak_ptr<Session> self) { mSelf = self; }
    void initSession();
    void handleLegacyNotify(const fingerprint_msg_t* msg);

    // ISession overrides
    ::ndk::ScopedAStatus generateChallenge() override;
    ::ndk::ScopedAStatus revokeChallenge(int64_t challenge) override;
    ::ndk::ScopedAStatus enroll(
            const keymaster::HardwareAuthToken& hat,
            std::shared_ptr<common::ICancellationSignal>* _aidl_return) override;
    ::ndk::ScopedAStatus authenticate(
            int64_t operationId,
            std::shared_ptr<common::ICancellationSignal>* _aidl_return) override;
    ::ndk::ScopedAStatus detectInteraction(
            std::shared_ptr<common::ICancellationSignal>* _aidl_return) override;
    ::ndk::ScopedAStatus enumerateEnrollments() override;
    ::ndk::ScopedAStatus removeEnrollments(
            const std::vector<int32_t>& enrollmentIds) override;
    ::ndk::ScopedAStatus getAuthenticatorId() override;
    ::ndk::ScopedAStatus invalidateAuthenticatorId() override;
    ::ndk::ScopedAStatus resetLockout(
            const keymaster::HardwareAuthToken& hat) override;
    ::ndk::ScopedAStatus close() override;

    // Deprecated UDFPS callbacks
    ::ndk::ScopedAStatus onPointerDown(
            int32_t pointerId, int32_t x, int32_t y, float minor, float major) override;
    ::ndk::ScopedAStatus onPointerUp(int32_t pointerId) override;
    ::ndk::ScopedAStatus onUiReady() override;

    // *WithContext methods
    ::ndk::ScopedAStatus authenticateWithContext(
            int64_t operationId,
            const common::OperationContext& context,
            std::shared_ptr<common::ICancellationSignal>* _aidl_return) override;
    ::ndk::ScopedAStatus enrollWithContext(
            const keymaster::HardwareAuthToken& hat,
            const common::OperationContext& context,
            std::shared_ptr<common::ICancellationSignal>* _aidl_return) override;
    ::ndk::ScopedAStatus detectInteractionWithContext(
            const common::OperationContext& context,
            std::shared_ptr<common::ICancellationSignal>* _aidl_return) override;
    ::ndk::ScopedAStatus onPointerDownWithContext(
            const PointerContext& context) override;
    ::ndk::ScopedAStatus onPointerUpWithContext(
            const PointerContext& context) override;
    ::ndk::ScopedAStatus onContextChanged(
            const common::OperationContext& context) override;
    ::ndk::ScopedAStatus onPointerCancelWithContext(
            const PointerContext& context) override;
    ::ndk::ScopedAStatus setIgnoreDisplayTouches(
            bool shouldIgnore) override;

    int32_t getUserId() const { return mUserId; }
    int32_t getSensorId() const { return mSensorId; }

private:
    void startLockoutTimer();

    int32_t mSensorId;
    int32_t mUserId;
    std::shared_ptr<ISessionCallback> mCallback;
    fingerprint_device_t* mDevice;
    std::weak_ptr<Session> mSelf;

    std::mutex mMutex;
    bool mIsClosed;
    int32_t mFailedAttempts;
    bool mLockoutTimed;
    bool mLockoutPermanent;

    std::vector<int32_t> mPendingRemovals;
    std::vector<int32_t> mRemovedEnrollments;
    std::vector<int32_t> mEnumeratedEnrollments;
};

}  // namespace aidl::android::hardware::biometrics::fingerprint
