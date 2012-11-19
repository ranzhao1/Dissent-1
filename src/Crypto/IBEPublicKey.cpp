#include "IBEPublicKey.hpp"
#include "AbstractGroup/Element.hpp"
#include <QByteArray>
#include <QDebug>
#include <QString>
#include <QFile>
#include <QSharedPointer>
#include "AbstractGroup/PairingG1Group.hpp"
#include "AbstractGroup/PairingGTGroup.hpp"
#include "CryptoFactory.hpp"
#include "Utils/IBEUtils.hpp"

namespace Dissent{
namespace Crypto{

IBEPublicKey::IBEPublicKey(const QByteArray &data)
{
    SystemParam Param;
    QByteArray tempPublicKey;
    QString UserID;
    QDataStream stream(data);
    stream>>tempPublicKey>>Param>>UserID;
    InitPublickey(tempPublicKey,Param,UserID);
}

IBEPublicKey::IBEPublicKey(const QString ID,const SystemParam Sysparam)
{
     Element Qid=Sysparam.GetGroup1()->ElementFromHash(ID);
     _publickey=Qid;
     _sysparam=Sysparam;
     this->ID=ID;
}

IBEPublicKey::IBEPublicKey(const QByteArray PublicKey,const SystemParam Param,const QString UserID)
{
    InitPublickey(PublicKey,Param,UserID);
}

bool IBEPublicKey::InitPublickey(const QByteArray PublicKey,const SystemParam Param,const QString UserID)
{
    _sysparam=Param;
    _publickey=_sysparam.GetGroup1()->ElementFromByteArray(PublicKey);
    ID=UserID;
    return true;
}

IBEPublicKey::~IBEPublicKey(){}

QByteArray IBEPublicKey:: GetByteArray() const
{
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream<<*this;
    return data;
}

QByteArray IBEPublicKey::Encrypt(const QByteArray &data) const
{
    Element generator=_sysparam.GetGroup1()->GetGenerator();
    Hash *hash=CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    QByteArray sigma;

    int i;
    char tempr[10];
    int unit;
    //Randomize the sigma
    for (i = 0; i < hash->GetDigestSize()*8/4; i++){
        unit= qrand() % 16;
        sprintf(tempr, "%x", unit);
        sigma.append(QByteArray(tempr));
    }

    QByteArray hashSigma=sigma;
    hashSigma.append(data);
   //Get Integer r
    Integer r=Utils::IBEUtils::HashToZr(_sysparam.GetGroup1()->GetOrder(),hashSigma);

    //Get Element of rP
    Element U=_sysparam.GetGroup1()->Exponentiate(generator,r);
    //Calculte (gid)^r
    Element Gid=_sysparam.GetGroupT()->ApplyPairing(_publickey,_sysparam.GetPpub());
    Element Gidr=_sysparam.GetGroupT()->Exponentiate(Gid,r);
    QByteArray PreGidr=_sysparam.GetGroupT()->ElementToByteArray(Gidr);
    //Got H2(Gidr)
    QByteArray HashGidr=hash->ComputeHash(PreGidr);
    //Got H4(sigma)
    QByteArray HashSigma=hash->ComputeHash(sigma);

    QByteArray Vsend=Utils::IBEUtils::calculateXor(sigma,HashGidr);
    QByteArray Wsend=Utils::IBEUtils::calculateXor(data,HashSigma);
    QByteArray Usend=_sysparam.GetGroup1()->ElementToByteArray(U).toHex();
    QByteArray DataToSend;
    QDataStream stream(&DataToSend,QIODevice::WriteOnly);
    stream<<Usend<<Vsend<<Wsend;
    return DataToSend;
}

QDataStream &operator<<(QDataStream &out, const IBEPublicKey &PublicKey)
{
    out <<PublicKey.GetParam().GetGroup1()->ElementToByteArray(PublicKey.GetPublicKeyElement())
        <<PublicKey.GetParam()<<PublicKey.GetUserId();
    return out;
}

QDataStream &operator>>(QDataStream &in, IBEPublicKey &PublicKey)
{
    SystemParam Param;
    QByteArray tempPublicKey;
    QString UserID;
    in >> tempPublicKey >>Param>>UserID;
    PublicKey=IBEPublicKey(tempPublicKey,Param,UserID);
    return in;
}

}
}
