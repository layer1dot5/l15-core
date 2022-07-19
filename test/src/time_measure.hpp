#pragma once

#include <string>
#include <chrono>
#include <vector>
#include <functional>
#include <iostream>
#include <algorithm>
#include <mutex>


namespace l15 {


class TimeMeasure : std::chrono::high_resolution_clock {
    const std::string m_title;
    std::vector<size_t> m_measures;
    std::mutex m_mutex;


    size_t Total() {
        size_t res = 0;
        std::for_each(m_measures.begin(), m_measures.end(), [&](size_t d){ res += d; });
        return res;
    }

    size_t Mean() {
        return Total() / m_measures.size();
    }
public:
    TimeMeasure(std::string&& title, size_t count = 1) : m_title(std::move(title)), m_measures()
    { m_measures.reserve(count); }

    int Measure(std::function<int()> sample) {
        const time_point start_time = now();
        int res = sample();
        {
            const std::lock_guard<std::mutex> lock(m_mutex);
            m_measures.push_back(duration_cast<std::chrono::milliseconds>(now() - start_time).count());
        }
        return res;
    }

    template <typename STREAM>
    void Report(STREAM& s) {
        s << '\n' << m_title << std::endl;
        s << "Total time:\t\t\t" << Total() << " ms" << std::endl;
        s << "Mean time per sample:\t" << Mean() << " ms\n" << std::endl;
    }

    template <typename STREAM>
    void ShortReport(STREAM& s) {
        s << '\n' << m_title << ": " << Total() << " ms" << std::endl;
    }

};

}