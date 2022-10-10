
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

    std::promise<int> p;
    auto res = p.get_future();

    std::function<void(std::promise<int>&&)> task = [](std::promise<int>&& p){ p.set_value(10); };

    service.Serve(task, move(p));

    CHECK(res.get() == 10);
}

TEST_CASE("Two workers' results")
{
    GenericService service(1);

    std::promise<int> p1;
    auto res1 = p1.get_future();
    std::promise<int> p2;
    auto res2 = p2.get_future();

    std::function<void(std::promise<int>&&)> task1 = [](std::promise<int>&& p){ p.set_value(10); };
    std::function<void(std::promise<int>&&)> task2 = [](std::promise<int>&& p){ p.set_value(20); };

    service.Serve(task1, move(p1));
    service.Serve(task2, move(p2));

    CHECK(res1.get() == 10);
    CHECK(res2.get() == 20);
}

TEST_CASE("Single blocking worker's result")
{
    GenericService service(1);

    std::function<void(std::promise<int>&&)> task = [](std::promise<int>&& p)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        p.set_value(10);
    };

    std::promise<int> p;
    auto res = p.get_future();

    service.Serve(task, move(p));

    int intres = res.get();

    CHECK(intres == 10);
}

TEST_CASE("Two blocking workers' results")
{
    GenericService service(1);

    std::function<void(std::promise<int>&&)> task0 = [](std::promise<int>&& p)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        p.set_value(10);
    };
    std::function<void(std::promise<int>&&)> task1 = [](std::promise<int>&& p)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        p.set_value(20);
    };

    std::promise<int> p0;
    auto res0 = p0.get_future();
    std::promise<int> p1;
    auto res1 = p1.get_future();

    service.Serve(task0, move(p0));
    service.Serve(task1, move(p1));

    CHECK(res0.get() == 10);
    CHECK(res1.get() == 20);
}

TEST_CASE("Blocking workers on several threads")
{
    GenericService service(3);

    std::promise<int> p0;
    std::promise<int> p1;
    std::promise<int> p2;
    std::promise<int> p3;
    auto res0 = p0.get_future();
    auto res1 = p1.get_future();
    auto res2 = p2.get_future();
    auto res3 = p3.get_future();

    std::function<void(std::promise<int>&&)> task0 = [](std::promise<int>&& p)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        p.set_value(10);
    };
    std::function<void(std::promise<int>&&)> task1 = [](std::promise<int>&& p)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(125));
        p.set_value(20);
    };
    std::function<void(std::promise<int>&&)> task2 = [](std::promise<int>&& p)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        p.set_value(30);
    };
    std::function<void(std::promise<int>&&)> task3 = [](std::promise<int>&& p)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(75));
        p.set_value(40);
    };

    service.Serve(task0, move(p0));
    service.Serve(task1, move(p1));
    service.Serve(task2, move(p2));
    service.Serve(task3, move(p3));

    CHECK(res0.get() == 10);
    CHECK(res1.get() == 20);
    CHECK(res2.get() == 30);
    CHECK(res3.get() == 40);
}


TEST_CASE("Test concurent workers")
{
    GenericService service(4);

    std::vector<std::function<void(std::promise<int>&&)>> tasks(10);

    for (auto& t: tasks) {
        t = [](std::promise<int>&& p) {
            std::random_device r;

            std::default_random_engine e1(r());
            std::uniform_int_distribution<int> uniform_dist(10, 200);
            int rnd = uniform_dist(e1);

            std::this_thread::sleep_for(std::chrono::milliseconds(rnd));

            p.set_value(rnd);
        };
    }

    std::vector<std::future<int>> results;

    std::transform(tasks.begin(), tasks.end(), cex::smartinserter(results, results.end()), [&](auto& fn)
    {
        std::promise<int> p;
        auto r = p.get_future();

        service.Serve(fn, move(p));

        return move(r);
    });

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


TEST_CASE("Task deffered by independent thread calculation")
{
    GenericService service(1);

    std::promise<int> p;
    std::future<int> res = p.get_future();

    service.Serve([&service](std::promise<int>&& p1)->void{

        std::clog << "> First level" << std::endl;

        std::thread defering_thread([&](std::promise<int>&& p2) {
            std::clog << ">> Independent thread" << std::endl;

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            service.Serve([&](std::promise<int>&& p3)
            {
                std::clog << ">>> Third level" << std::endl;
                p3.set_value(10);
                std::clog << "<<< Third level completed" << std::endl;
            }, move(p2));

            std::clog << "<< Independent thread completed" << std::endl;

        }, move(p1));

        std::clog << "< First level completed" << std::endl;

        defering_thread.detach();

    }, move(p));

    int intres = res.get();

    CHECK(intres == 10);
}

