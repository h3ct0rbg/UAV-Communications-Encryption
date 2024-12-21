#ifndef FRAMEQUEUE_HPP
#define FRAMEQUEUE_HPP

#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>

class FrameQueue {
public:
    void pushFrame(const std::vector<uint8_t>& frame);
    std::vector<uint8_t> popFrame();

private:
    std::queue<std::vector<uint8_t>> queue;
    std::mutex mtx;
    std::condition_variable cv;
};

#endif // FRAMEQUEUE_HPP