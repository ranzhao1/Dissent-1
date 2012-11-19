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

    /**
     *Implementation of IBE Private Key
     */
    class IBEPrivateKey : public AsymmetricKey{

    public:

        /**
         *Read the IBEPrivate Key from file
         *@param file anme the file soring the key
         */
        explicit IBEPrivateKey(const QString &filename);

        /**
         *Loads a key from memory
         *@param data byte array holding the key
         */
        explicit IBEPrivateKey(const QByteArray &data);

        /**
         *Copy private key
         *@param PrivateKey
         *@param Param system parameter
         */
        explicit IBEPrivateKey(const QByteArray PrivateKey,const SystemParam Param);

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
         /**
          *Loads a key from the provided byte array
          *@param data key byte array
          */
         bool InitFromByteArray(const QByteArray &data);

         /**
          *Initialize the private key
          *@param PrivateKey
          *@param Param system parameter
          */
         bool InitPrivatekey(const QByteArray PrivateKey,const SystemParam Param);
         Element _privatekey;
         SystemParam _sysparam;
    };

    /**
     *Overload operator<< and >> for serialization
     */
    QDataStream &operator<<(QDataStream &out, const IBEPrivateKey &PrivateKey);
    QDataStream &operator>>(QDataStream &in, IBEPrivateKey &PrivateKey);
}
}

#endif // IBEPRIVATEKEY_HPP
