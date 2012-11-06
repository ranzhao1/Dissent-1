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

        class IBEPublicKey : public AsymmetricKey{

        public:
            /**
             *Constrct Publick Key based on user ID and system parameter
             *@param ID user Identifiction
             *@param Sysparam system parameter
             */
            explicit IBEPublicKey(const char* ID,SystemParam Sysparam);

            /**
             *Read IBE public keyfrom memory
             *@param data memory to store the public key
             */
            explicit IBEPublicKey(const QByteArray&data);

            explicit IBEPublicKey(){}

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

            void SetID(QString UserID){ID=UserID;}
            Element GetPublicKeyElement()const {return _publickey;}
            SystemParam GetParam()const{return _sysparam;}
            void SetPublicKey(Element publicKey){_publickey=publicKey;}
            void SetSysParam(SystemParam &SysParam) {_sysparam=SysParam;}

        private:
            Element _publickey;
            SystemParam _sysparam;
            QString ID;

    };

        QDataStream &operator<<(QDataStream &out, const IBEPublicKey &PublicKey);
        QDataStream &operator>>(QDataStream &in, IBEPublicKey &PublicKey);
}
}


#endif // IBEPUBLICKEY_HPP
