#ifndef IBEUTILS_HPP
#define IBEUTILS_HPP
#include <QByteArray>
#include "Crypto/CryptoFactory.hpp"
#include "Crypto/Integer.hpp"

using namespace Dissent::Crypto;


namespace Dissent{
namespace Utils{

    class IBEUtils{
    public:
        static QByteArray calculateXor(const QByteArray& data, const QByteArray& key);
        static  Integer HashToZr(Integer GroupOrder,QByteArray &data);
        static void Randn(char *sigma);

    };



}
}








#endif // XOROPERATION_HPP
