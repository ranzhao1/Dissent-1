#ifndef IBEPRIVATEKEY_HPP
#define IBEPRIVATEKEY_HPP

#include <QByteArray>
#include <QDebug>
#include <QString>

#include "AsymmetricKey.hpp"
#include "SystemParam.hpp"
#include "AbstractGroup/Element.hpp"
#include "CryptoFactory.hpp"
#include "Utils/IBEUtils.hpp"

using namespace Dissent::Crypto::AbstractGroup;

namespace Dissent{
namespace Crypto{

    class IBEPrivateKey : public AsymmetricKey{

    public:

        /**
         *Default constructor of IBE Private Key
         */
        explicit IBEPrivateKey(){}

        /**
         *Read the IBEPrivate Key from file
         */
        explicit IBEPrivateKey(const QString &filename);

        /**
         *Read the IBEPrivate Key from memeory
         */
        explicit IBEPrivateKey(const QByteArray &data);
//        /**
//         *Read the IBEPrivate Key from ByteArray
//         */
//        explicit IBEPrivateKey(const QByteArray &data);

        /**
         *Pkg set the private key
         *@param key the private key
         */
        void SetPrivateKey(const Element &key);

        /**
         *Set the system parameter
         */
         void SetSysParam(SystemParam Sysparam);

         /**
         *Deconstructor
         */
        virtual ~IBEPrivateKey();

        /**
         *Get the ByteArray of IBEPrivateKey for serilization
         */
        virtual QByteArray GetByteArray() const;

        /**
         *Not support for the GetPublick Key
         */
        virtual AsymmetricKey* GetPublicKey() const{}

        /**
         *Private Key not support Encrypt
         */
        virtual QByteArray Encrypt(const QByteArray &data) const{return QByteArray();}

        /**
         *Private key to decrypt the encrypted message
         *@param data encrypted message
         */
        virtual QByteArray Decrypt(const QByteArray &data) const;

        /**
         *Not support these function, return nothing
         */
        virtual QByteArray Sign(const QByteArray &data) const{return QByteArray();}
        virtual bool Verify(const QByteArray &data, const QByteArray &sig) const{return false;}

        virtual bool IsPrivateKey() const{return true;}
        virtual KeyTypes GetKeyType() const { return OTHER; }

        /**
         *Not support these function, return nothing
         */
        virtual bool VerifyKey(AsymmetricKey &key) const {return true;}
        virtual bool IsValid() const { return true; }
        virtual int GetKeySize() const { return 0; }

         /**
          *Get the private key element
          */
         Element GetPrivateKey()const {return _privatekey;}

         /**
          *Get the system parameter of this private key
          */
         SystemParam GetParam() const {return _sysparam;}

    private:
         Element _privatekey;
         SystemParam _sysparam;


    };

    QDataStream &operator<<(QDataStream &out, const IBEPrivateKey &PrivateKey);
    QDataStream &operator>>(QDataStream &in, IBEPrivateKey &PrivateKey);







}
}

#endif // IBEPRIVATEKEY_HPP
