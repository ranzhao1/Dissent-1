#ifndef IBEPUBLICKEY_HPP
#define IBEPUBLICKEY_HPP

#include <QByteArray>
#include <QDebug>
#include <QString>

#include "AsymmetricKey.hpp"
#include "SystemParam.hpp"
#include "AbstractGroup/Element.hpp"

using namespace Dissent::Crypto::AbstractGroup;

namespace Dissent{
namespace Crypto{

        /**
         *Implementation of IBE Publick Key
         */
        class IBEPublicKey : public AsymmetricKey{

        public:

            /**
             *loads IBE public keyfrom memory
             *@param data memory to store the public key
             */
            explicit IBEPublicKey(const QByteArray&data);

            /**
             *Initilize Publick Key based on user ID and system parameter
             *@param ID user Identifiction
             *@param Sysparam system parameter
             */
            explicit IBEPublicKey(const QString ID, const SystemParam Sysparam);

            /**
             * Copy the Publick Key
             *@param PublicKey
             *@param Param system parameter
             *@param UserID user Identification
             */
            explicit IBEPublicKey(const QByteArray PublicKey,const SystemParam Param,const QString UserID);

            /**
             *Get the User Identification
             */
            QString GetUserId()const{return ID;}

            /**
             *Deconstructor
             */
            virtual ~IBEPublicKey();

            /**
             *Get the ByteArray of IBEPublicKey for serilization
             */
            virtual QByteArray GetByteArray() const;

            /**
             * Not support this function
             */
             virtual AsymmetricKey* GetPublicKey() const{}

            /**
             *Publick Key encrypt the message hash
             *@param data message hash to encrypted
             */
            virtual QByteArray Encrypt(const QByteArray &data) const;

            /**
             *Public Key not support Decrypt
             */
            virtual QByteArray Decrypt(const QByteArray &data) const{return QByteArray();}

            /**
             *Not support these function, return nothing
             */
            virtual QByteArray Sign(const QByteArray &data) const{return QByteArray();}
            virtual bool Verify(const QByteArray &data, const QByteArray &sig) const {return false;}

            virtual bool IsPrivateKey() const{return false;}
            virtual KeyTypes GetKeyType() const { return OTHER; }

            /**
             *Not support these function, return nothing
             */
            virtual bool VerifyKey(AsymmetricKey &key) const {return true;}
            virtual bool IsValid() const { return true; }
            virtual int GetKeySize() const { return 0; }

            /**
             *Get the publickey element
             */
            Element GetPublicKeyElement()const {return _publickey;}

            /**
             *Get system parameter of the public key
             */
            SystemParam GetParam()const{return _sysparam;}

        private:
            /**
             *Initialize the public key
             *@param PublicKey
             *@param Param system parameter
             *@param UserID user Identification
             */
            bool InitPublickey(const QByteArray PublicKey,const SystemParam Param,const QString UserID);
            Element _publickey;
            SystemParam _sysparam;
            QString ID;

    };

        QDataStream &operator<<(QDataStream &out, const IBEPublicKey &PublicKey);
        QDataStream &operator>>(QDataStream &in, IBEPublicKey &PublicKey);
}
}


#endif // IBEPUBLICKEY_HPP
