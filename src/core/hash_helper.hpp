#pragma once

#include "serialize.h"
#include "span.h"
#include "crypto/sha256.h"

namespace l15 {


template <typename D>
class Writer
{
public:
    typedef D data_type;
private:
    D mData;
public:
    Writer(const D& data) : mData(data) {}
    virtual ~Writer() = default;

    virtual void write(Span<const std::byte> src)
    {
        mData.Write(reinterpret_cast<const unsigned char *>(src.data()), src.size());
    }
    D& get() { return mData; }
    const D& get() const { return mData; }

    template <typename T>
    Writer& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return *this;
    }

};

//template <typename D>
//class Writer <D&>
//{
//public:
//    typedef D data_type;
//private:
//    D& mData;
//public:
//    Writer(D& data): mData(data) {}
//    virtual ~Writer() = default;
//
//    virtual void write(Span<const uint8_t> src)
//    {
//        mData.Write(src.data(), src.size());
//    }
//    D& get() { return mData; }
//    const D& get() const { return mData; }
//
//};

template <typename H>
class HashWriter : public Writer<H>
{
public:
    HashWriter(const H& hashcache) : Writer<H>(hashcache) {}

    template <typename R>
    operator R()
    {
        R result;
        Writer<H>::get().Finalize(result.begin());
        return result;
    }

    using Writer<H>::operator<<;
};

inline CSHA256 PrecalculatedTaggedHash(const std::string &tag) noexcept
{
    uint256 taghash;
    CSHA256().Write((const unsigned char*)tag.data(), tag.size()).Finalize(taghash.data());
    return CSHA256().Write(taghash.data(), uint256::size()).Write(taghash.data(), uint256::size());
}


}