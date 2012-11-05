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
        static int htoi(char a);
        static void Xor(int size,const char* a,const char* b, char* xor_result);
        static  Integer HashToZr(Integer GroupOrder,QByteArray &data);
        static void Randn(char *sigma);

    };



}
}








#endif // XOROPERATION_HPP
