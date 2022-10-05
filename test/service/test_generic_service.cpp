
#include <random>
#include <thread>
#include <atomic>

#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"

#include "smartinserter.hpp"

#include "generic_service.hpp"

using namespace l15::service;

TEST_CASE("Single worker's result")
{
    GenericService service(1);

    std::function<int()> task = [](){ return 10;};

    std::future<int> res = service.Serve(task);

    int intres = res.get();

    CHECK(intres == 10);
}

TEST_CASE("Two workers' results")
{
    GenericService service(1);

    std::function<int()> task0 = [](){ return 10;};
    std::function<int()> task1 = [](){ return 20;};

    std::future<int> res0 = service.Serve(task0);
    std::future<int> res1 = service.Serve(task1);

    CHECK(res0.get() == 10);
    CHECK(res1.get() == 20);
}

TEST_CASE("Single blocking worker's result")
{
    GenericService service(1);

    std::function<int()> task = []()
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return 10;
    };

    std::future<int> res = service.Serve(task);

    int intres = res.get();

    CHECK(intres == 10);
}

TEST_CASE("Two blocking workers' results")
{
    GenericService service(1);

    std::function<int()> task0 = []()
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return 10;
    };
    std::function<int()> task1 = []()
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        return 20;
    };

    std::future<int> res0 = service.Serve(task0);
    std::future<int> res1 = service.Serve(task1);

    CHECK(res0.get() == 10);
    CHECK(res1.get() == 20);
}

TEST_CASE("Blocking workers on several threads")
{
    GenericService service(3);

    std::function<int()> task0 = []()
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        return 10;
    };
    std::function<int()> task1 = []()
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(125));
        return 20;
    };
    std::function<int()> task2 = []()
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return 30;
    };
    std::function<int()> task3 = []()
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(75));
        return 40;
    };

    std::future<int> res0 = service.Serve(task0);
    std::future<int> res1 = service.Serve(task1);
    std::future<int> res2 = service.Serve(task2);
    std::future<int> res3 = service.Serve(task3);

    CHECK(res0.get() == 10);
    CHECK(res1.get() == 20);
    CHECK(res2.get() == 30);
    CHECK(res3.get() == 40);
}


TEST_CASE("Test concurent workers")
{
    GenericService service(4);

    std::vector<std::function<int()>> tasks(10);
    for (auto& t: tasks) {
        t = []() {
            std::random_device r;

            std::default_random_engine e1(r());
            std::uniform_int_distribution<int> uniform_dist(10, 200);
            int rnd = uniform_dist(e1);

            std::this_thread::sleep_for(std::chrono::milliseconds(rnd));

            return rnd;
        };
    }

    std::vector<std::future<int>> results;

    std::transform(tasks.begin(), tasks.end(), cex::smartinserter(results, results.end()), [&](auto& fn){ return service.Serve(fn); });

    std::atomic<bool> completed = false;

    std::thread watchdog([&completed]()
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!completed) {
            FAIL("Workers were failed to complete");
        }
    });

    std::for_each(results.begin(), results.end(), [](auto& r)
    {
        std::clog << "task result: " << r.get() << std::endl;
    });
    completed = true;

    watchdog.join();

}
