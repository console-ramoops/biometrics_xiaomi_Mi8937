#include "Session.h"
#include "CancellationSignal.h"

#include <android/log.h>
#include <arpa/inet.h>
#include <endian.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <thread>
#include <chrono>

#define LOG_TAG "FingerprintHalSession"
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace aidl::android::hardware::biometrics::fingerprint {

namespace {

void aidlToLegacyHat(const keymaster::HardwareAuthToken& aidlHat, hw_auth_token_t& legacyHat) {
    memset(&legacyHat, 0, sizeof(legacyHat));
    legacyHat.version = 0;
    legacyHat.challenge = static_cast<uint64_t>(aidlHat.challenge);
    legacyHat.user_id = static_cast<uint64_t>(aidlHat.userId);
    legacyHat.authenticator_id = static_cast<uint64_t>(aidlHat.authenticatorId);
    legacyHat.authenticator_type = htonl(static_cast<uint32_t>(aidlHat.authenticatorType));
    legacyHat.timestamp = htobe64(static_cast<uint64_t>(aidlHat.timestamp.milliSeconds));
    if (aidlHat.mac.size() == 32) {
        memcpy(legacyHat.hmac, aidlHat.mac.data(), 32);
    }
}

void legacyToAidlHat(const hw_auth_token_t& legacyHat, keymaster::HardwareAuthToken& aidlHat) {
    aidlHat.challenge = static_cast<int64_t>(legacyHat.challenge);
    aidlHat.userId = static_cast<int64_t>(legacyHat.user_id);
    aidlHat.authenticatorId = static_cast<int64_t>(legacyHat.authenticator_id);
    aidlHat.authenticatorType = static_cast<keymaster::HardwareAuthenticatorType>(ntohl(legacyHat.authenticator_type));
    aidlHat.timestamp.milliSeconds = static_cast<int64_t>(be64toh(legacyHat.timestamp));
    aidlHat.mac.assign(legacyHat.hmac, legacyHat.hmac + 32);
}

void mapLegacyAcquired(int32_t legacyCode, AcquiredInfo& aidlInfo, int32_t& vendorCode) {
    vendorCode = 0;
    if (legacyCode >= 1000) {
        aidlInfo = AcquiredInfo::VENDOR;
        vendorCode = legacyCode - 1000;
        return;
    }
    switch (legacyCode) {
        case 0: aidlInfo = AcquiredInfo::GOOD; break;
        case 1: aidlInfo = AcquiredInfo::PARTIAL; break;
        case 2: aidlInfo = AcquiredInfo::INSUFFICIENT; break;
        case 3: aidlInfo = AcquiredInfo::SENSOR_DIRTY; break;
        case 4: aidlInfo = AcquiredInfo::TOO_SLOW; break;
        case 5: aidlInfo = AcquiredInfo::TOO_FAST; break;
        default: aidlInfo = AcquiredInfo::UNKNOWN; break;
    }
}

}  // namespace

Session::Session(int32_t sensorId, int32_t userId,
                 std::shared_ptr<ISessionCallback> cb,
                 fingerprint_device_t* device)
    : mSensorId(sensorId),
      mUserId(userId),
      mCallback(std::move(cb)),
      mDevice(device),
      mIsClosed(false),
      mFailedAttempts(0),
      mLockoutTimed(false),
      mLockoutPermanent(false) {
    ALOGD("Session created for sensorId: %d, userId: %d", mSensorId, mUserId);
}

Session::~Session() {
    ALOGD("Session destroyed for sensorId: %d, userId: %d", mSensorId, mUserId);
}

void Session::initSession() {
    if (!mDevice) return;

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/data/vendor_de/%d/fpdata", mUserId);
    mkdir("/data/vendor_de", 0771);
    char userDir[PATH_MAX];
    snprintf(userDir, sizeof(userDir), "/data/vendor_de/%d", mUserId);
    mkdir(userDir, 0700);
    mkdir(path, 0700);

    int ret = mDevice->set_active_group(mDevice, mUserId, path);
    ALOGD("set_active_group(userId=%d, path=%s) returned %d", mUserId, path, ret);
}

void Session::startLockoutTimer() {
    std::weak_ptr<Session> weakSelf = mSelf;
    std::thread([weakSelf]() {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        if (auto self = weakSelf.lock()) {
            std::shared_ptr<ISessionCallback> cb;
            {
                std::lock_guard<std::mutex> lock(self->mMutex);
                if (self->mLockoutTimed) {
                    self->mLockoutTimed = false;
                    self->mFailedAttempts = 0;
                    cb = self->mCallback;
                }
            }
            if (cb) {
                ALOGD("Timed lockout expired, dispatching onLockoutCleared");
                cb->onLockoutCleared();
            }
        }
    }).detach();
}

::ndk::ScopedAStatus Session::generateChallenge() {
    ALOGD("generateChallenge");
    uint64_t challenge = 0;
    if (mDevice && mDevice->pre_enroll) {
        challenge = mDevice->pre_enroll(mDevice);
    }
    std::shared_ptr<ISessionCallback> cb;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        cb = mCallback;
    }
    if (cb) {
        cb->onChallengeGenerated(static_cast<int64_t>(challenge));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Session::revokeChallenge(int64_t challenge) {
    ALOGD("revokeChallenge: %lld", (long long)challenge);
    if (mDevice && mDevice->post_enroll) {
        mDevice->post_enroll(mDevice);
    }
    std::shared_ptr<ISessionCallback> cb;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        cb = mCallback;
    }
    if (cb) {
        cb->onChallengeRevoked(challenge);
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Session::enroll(
        const keymaster::HardwareAuthToken& hat,
        std::shared_ptr<common::ICancellationSignal>* _aidl_return) {
    ALOGD("enroll");
    if (!mDevice || !mDevice->enroll) {
        return ::ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }

    hw_auth_token_t legacyHat;
    aidlToLegacyHat(hat, legacyHat);

    int ret = mDevice->enroll(mDevice, &legacyHat, mUserId, 60);
    ALOGD("mDevice->enroll returned %d", ret);

    fingerprint_device_t* dev = mDevice;
    *_aidl_return = ::ndk::SharedRefBase::make<CancellationSignal>([dev]() {
        ALOGD("enroll canceled by client");
        if (dev && dev->cancel) {
            dev->cancel(dev);
        }
    });

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Session::authenticate(
        int64_t operationId,
        std::shared_ptr<common::ICancellationSignal>* _aidl_return) {
    ALOGD("authenticate: opId=%lld", (long long)operationId);
    if (!mDevice || !mDevice->authenticate) {
        return ::ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }

    int ret = mDevice->authenticate(mDevice, static_cast<uint64_t>(operationId), mUserId);
    ALOGD("mDevice->authenticate returned %d", ret);

    fingerprint_device_t* dev = mDevice;
    *_aidl_return = ::ndk::SharedRefBase::make<CancellationSignal>([dev]() {
        ALOGD("authenticate canceled by client");
        if (dev && dev->cancel) {
            dev->cancel(dev);
        }
    });

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Session::detectInteraction(
        std::shared_ptr<common::ICancellationSignal>* /*_aidl_return*/) {
    ALOGD("detectInteraction not supported");
    return ::ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
}

::ndk::ScopedAStatus Session::enumerateEnrollments() {
    ALOGD("enumerateEnrollments");
    {
        std::lock_guard<std::mutex> lock(mMutex);
        mEnumeratedEnrollments.clear();
    }
    std::vector<int32_t> enrolled;
    bool synchronous = false;
    if (mDevice && mDevice->enumerate) {
        fingerprint_finger_id_t results[100];
        memset(results, 0, sizeof(results));
        uint32_t n = 100;
        using enumerate_2_0 = int (*)(struct fingerprint_device*, fingerprint_finger_id_t*, uint32_t*);
        auto enumerate_fn = reinterpret_cast<enumerate_2_0>(reinterpret_cast<void*>(mDevice->enumerate));
        int total = enumerate_fn(mDevice, results, &n);
        ALOGD("enumerate: total=%d, count=%u", total, n);
        if (total >= 0 && n <= 100 && (n > 0 || total == 0)) {
            for (uint32_t i = 0; i < n; i++) {
                if (results[i].fid != 0) {
                    enrolled.push_back(results[i].fid);
                }
            }
            synchronous = true;
        }
    }
    if (synchronous) {
        std::shared_ptr<ISessionCallback> cb;
        {
            std::lock_guard<std::mutex> lock(mMutex);
            cb = mCallback;
        }
        if (cb) {
            cb->onEnrollmentsEnumerated(enrolled);
        }
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Session::removeEnrollments(
        const std::vector<int32_t>& enrollmentIds) {
    ALOGD("removeEnrollments: count=%zu", enrollmentIds.size());
    if (!mDevice || !mDevice->remove) {
        return ::ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }

    {
        std::lock_guard<std::mutex> lock(mMutex);
        mPendingRemovals = enrollmentIds;
        mRemovedEnrollments.clear();
    }

    if (enrollmentIds.empty()) {
        mDevice->remove(mDevice, mUserId, 0);
    } else {
        for (int32_t fid : enrollmentIds) {
            mDevice->remove(mDevice, mUserId, fid);
        }
    }

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Session::getAuthenticatorId() {
    ALOGD("getAuthenticatorId");
    uint64_t authId = 0;
    if (mDevice && mDevice->get_authenticator_id) {
        usleep(140000);
        authId = mDevice->get_authenticator_id(mDevice);
    }
    std::shared_ptr<ISessionCallback> cb;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        cb = mCallback;
    }
    if (cb) {
        cb->onAuthenticatorIdRetrieved(static_cast<int64_t>(authId));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Session::invalidateAuthenticatorId() {
    ALOGD("invalidateAuthenticatorId");
    uint64_t newId = 0;
    if (mDevice) {
        if (mDevice->pre_enroll) mDevice->pre_enroll(mDevice);
        if (mDevice->post_enroll) mDevice->post_enroll(mDevice);
        usleep(140000);
        if (mDevice->get_authenticator_id) newId = mDevice->get_authenticator_id(mDevice);
    }
    std::shared_ptr<ISessionCallback> cb;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        cb = mCallback;
    }
    if (cb) {
        cb->onAuthenticatorIdInvalidated(static_cast<int64_t>(newId));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Session::resetLockout(
        const keymaster::HardwareAuthToken& /*hat*/) {
    ALOGD("resetLockout");
    {
        std::lock_guard<std::mutex> lock(mMutex);
        mFailedAttempts = 0;
        mLockoutTimed = false;
        mLockoutPermanent = false;
    }
    std::shared_ptr<ISessionCallback> cb;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        cb = mCallback;
    }
    if (cb) {
        cb->onLockoutCleared();
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Session::close() {
    ALOGD("close");
    std::shared_ptr<ISessionCallback> cb;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        if (!mIsClosed) {
            mIsClosed = true;
            cb = mCallback;
            mCallback = nullptr;
        }
    }
    if (cb) {
        cb->onSessionClosed();
    }
    return ::ndk::ScopedAStatus::ok();
}

void Session::handleLegacyNotify(const fingerprint_msg_t* msg) {
    if (!msg) return;

    std::shared_ptr<ISessionCallback> cb;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        cb = mCallback;
    }
    if (!cb) {
        ALOGE("handleLegacyNotify: No active client callback");
        return;
    }

    switch (msg->type) {
        case FINGERPRINT_ERROR: {
            int32_t legacyErr = msg->data.error;
            ALOGD("Legacy FINGERPRINT_ERROR: %d", legacyErr);
            if (legacyErr == FINGERPRINT_ERROR_LOCKOUT) {
                {
                    std::lock_guard<std::mutex> lock(mMutex);
                    mLockoutTimed = true;
                }
                startLockoutTimer();
                cb->onLockoutTimed(30000);
            } else if (legacyErr == 8 /* legacy permanent lockout on some HALs */) {
                {
                    std::lock_guard<std::mutex> lock(mMutex);
                    mLockoutPermanent = true;
                }
                cb->onLockoutPermanent();
            } else if (legacyErr >= 1000) {
                cb->onError(Error::VENDOR, legacyErr - 1000);
            } else {
                Error aidlErr = Error::UNKNOWN;
                switch (legacyErr) {
                    case FINGERPRINT_ERROR_HW_UNAVAILABLE: aidlErr = Error::HW_UNAVAILABLE; break;
                    case FINGERPRINT_ERROR_UNABLE_TO_PROCESS: aidlErr = Error::UNABLE_TO_PROCESS; break;
                    case FINGERPRINT_ERROR_TIMEOUT: aidlErr = Error::TIMEOUT; break;
                    case FINGERPRINT_ERROR_NO_SPACE: aidlErr = Error::NO_SPACE; break;
                    case FINGERPRINT_ERROR_CANCELED: aidlErr = Error::CANCELED; break;
                    case FINGERPRINT_ERROR_UNABLE_TO_REMOVE: aidlErr = Error::UNABLE_TO_REMOVE; break;
                    default: aidlErr = Error::UNKNOWN; break;
                }
                cb->onError(aidlErr, 0);
            }
            break;
        }
        case FINGERPRINT_ACQUIRED: {
            int32_t legacyAcquired = msg->data.acquired.acquired_info;
            ALOGD("Legacy FINGERPRINT_ACQUIRED: %d", legacyAcquired);
            AcquiredInfo aidlAcquired;
            int32_t vendorCode = 0;
            mapLegacyAcquired(legacyAcquired, aidlAcquired, vendorCode);
            cb->onAcquired(aidlAcquired, vendorCode);
            break;
        }
        case FINGERPRINT_TEMPLATE_ENROLLING: {
            int32_t fid = msg->data.enroll.finger.fid;
            int32_t remaining = msg->data.enroll.samples_remaining;
            ALOGD("Legacy ENROLLING: fid=%d, remaining=%d", fid, remaining);
            cb->onEnrollmentProgress(fid, remaining);
            break;
        }
        case FINGERPRINT_TEMPLATE_REMOVED: {
            int32_t fid = msg->data.removed.finger.fid;
            ALOGD("Legacy REMOVED: fid=%d", fid);
            std::vector<int32_t> removed;
            bool shouldNotify = false;
            {
                std::lock_guard<std::mutex> lock(mMutex);
                mRemovedEnrollments.push_back(fid);
                auto it = std::find(mPendingRemovals.begin(), mPendingRemovals.end(), fid);
                if (it != mPendingRemovals.end()) {
                    mPendingRemovals.erase(it);
                }
                if (mPendingRemovals.empty()) {
                    removed = mRemovedEnrollments;
                    shouldNotify = true;
                }
            }
            if (shouldNotify) {
                cb->onEnrollmentsRemoved(removed);
            }
            break;
        }
        case FINGERPRINT_AUTHENTICATED: {
            int32_t fid = msg->data.authenticated.finger.fid;
            ALOGD("Legacy AUTHENTICATED: fid=%d", fid);
            if (fid != 0) {
                {
                    std::lock_guard<std::mutex> lock(mMutex);
                    mFailedAttempts = 0;
                }
                keymaster::HardwareAuthToken aidlHat;
                legacyToAidlHat(msg->data.authenticated.hat, aidlHat);
                cb->onAuthenticationSucceeded(fid, aidlHat);
            } else {
                int failed = 0;
                {
                    std::lock_guard<std::mutex> lock(mMutex);
                    failed = ++mFailedAttempts;
                }
                cb->onAuthenticationFailed();
                if (failed >= 5) {
                    {
                        std::lock_guard<std::mutex> lock(mMutex);
                        mLockoutTimed = true;
                    }
                    startLockoutTimer();
                    cb->onLockoutTimed(30000);
                }
            }
            break;
        }
        case FINGERPRINT_TEMPLATE_ENUMERATING: {
            int32_t fid = msg->data.enumerated.finger.fid;
            int32_t remaining = msg->data.enumerated.remaining_templates;
            ALOGD("Legacy ENUMERATING: fid=%d, remaining=%d", fid, remaining);
            std::vector<int32_t> enumerated;
            bool finished = false;
            {
                std::lock_guard<std::mutex> lock(mMutex);
                if (fid != 0) {
                    mEnumeratedEnrollments.push_back(fid);
                }
                if (remaining == 0) {
                    enumerated = mEnumeratedEnrollments;
                    mEnumeratedEnrollments.clear();
                    finished = true;
                }
            }
            if (finished) {
                cb->onEnrollmentsEnumerated(enumerated);
            }
            break;
        }
    }
}

// Deprecated UDFPS callbacks
::ndk::ScopedAStatus Session::onPointerDown(
        int32_t /*pointerId*/, int32_t /*x*/, int32_t /*y*/, float /*minor*/, float /*major*/) {
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Session::onPointerUp(int32_t /*pointerId*/) {
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Session::onUiReady() {
    return ::ndk::ScopedAStatus::ok();
}

// *WithContext methods
::ndk::ScopedAStatus Session::authenticateWithContext(
        int64_t operationId,
        const common::OperationContext& /*context*/,
        std::shared_ptr<common::ICancellationSignal>* _aidl_return) {
    return authenticate(operationId, _aidl_return);
}

::ndk::ScopedAStatus Session::enrollWithContext(
        const keymaster::HardwareAuthToken& hat,
        const common::OperationContext& /*context*/,
        std::shared_ptr<common::ICancellationSignal>* _aidl_return) {
    return enroll(hat, _aidl_return);
}

::ndk::ScopedAStatus Session::detectInteractionWithContext(
        const common::OperationContext& /*context*/,
        std::shared_ptr<common::ICancellationSignal>* _aidl_return) {
    return detectInteraction(_aidl_return);
}

::ndk::ScopedAStatus Session::onPointerDownWithContext(
        const PointerContext& /*context*/) {
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Session::onPointerUpWithContext(
        const PointerContext& /*context*/) {
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Session::onContextChanged(
        const common::OperationContext& /*context*/) {
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Session::onPointerCancelWithContext(
        const PointerContext& /*context*/) {
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Session::setIgnoreDisplayTouches(bool /*shouldIgnore*/) {
    return ::ndk::ScopedAStatus::ok();
}

}  // namespace aidl::android::hardware::biometrics::fingerprint
