#include "FrameQueue.hpp"

void FrameQueue::pushFrame(const std::vector<uint8_t>& frame) {
    std::lock_guard<std::mutex> lock(mtx);
    queue.push(frame);
    cv.notify_one();
}

std::vector<uint8_t> FrameQueue::popFrame() {
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock, [this] { return !queue.empty(); });
    auto frame = queue.front();
    queue.pop();
    return frame;
}