#pragma once

#include <aidl/android/hardware/biometrics/common/BnCancellationSignal.h>
#include <functional>
#include <utility>

namespace aidl::android::hardware::biometrics::fingerprint {

class CancellationSignal : public common::BnCancellationSignal {
public:
    CancellationSignal(std::function<void()> onCancel)
        : mOnCancel(std::move(onCancel)) {}

    ::ndk::ScopedAStatus cancel() override {
        if (mOnCancel) {
            mOnCancel();
            mOnCancel = nullptr;
        }
        return ::ndk::ScopedAStatus::ok();
    }

private:
    std::function<void()> mOnCancel;
};

}  // namespace aidl::android::hardware::biometrics::fingerprint
