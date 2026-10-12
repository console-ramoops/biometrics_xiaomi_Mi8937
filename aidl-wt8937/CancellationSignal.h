#pragma once

#include <aidl/android/hardware/biometrics/common/BnCancellationSignal.h>
#include <functional>
#include <mutex>

namespace aidl::android::hardware::biometrics::fingerprint {

class CancellationSignal : public common::BnCancellationSignal {
public:
    using OnCancelCallback = std::function<void()>;

    explicit CancellationSignal(OnCancelCallback onCancel)
        : mOnCancel(std::move(onCancel)), mIsCanceled(false) {}

    ::ndk::ScopedAStatus cancel() override {
        OnCancelCallback callback;
        {
            std::lock_guard<std::mutex> lock(mMutex);
            if (!mIsCanceled) {
                mIsCanceled = true;
                callback = mOnCancel;
            }
        }
        if (callback) {
            callback();
        }
        return ::ndk::ScopedAStatus::ok();
    }

private:
    std::mutex mMutex;
    OnCancelCallback mOnCancel;
    bool mIsCanceled;
};

}  // namespace aidl::android::hardware::biometrics::fingerprint
