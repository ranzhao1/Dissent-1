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
#include <iostream>




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

IBEPublicKey::~IBEPublicKey()
{

}


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

    char* sigma=(char*)malloc(hash->GetDigestSize()*8*sizeof(char));

    Utils::IBEUtils::Randn(sigma);
    //qDebug()<<"The Sigma is "<<sigma<<endl;
    QByteArray hashSigma=QByteArray(sigma);
    hashSigma.append(data);


    //Get Integer r
    Integer r=Utils::IBEUtils::HashToZr(_sysparam.GetGroup1()->GetOrder(),hashSigma);

    //Get Element of rP
    Element U=_sysparam.GetGroup1()->Exponentiate(generator,r);
    //qDebug()<<"r is"<< r.GetByteArray().toHex().constData();

    //Calculte (gid)^r
    Element Gid=_sysparam.GetGroupT()->ApplyPairing(_publickey,_sysparam.GetPpub());
    Element Gidr=_sysparam.GetGroupT()->Exponentiate(Gid,r);
    QByteArray PreGidr=_sysparam.GetGroupT()->ElementToByteArray(Gidr);


    //Got H2(Gidr)
    QByteArray HashGidr=hash->ComputeHash(PreGidr);
   //Got H4(sigma)
    QByteArray HashSigma=hash->ComputeHash(QByteArray(sigma));

    QByteArray Vsend=Utils::IBEUtils::calculateXor(QByteArray(sigma),HashGidr);
    QByteArray Wsend=Utils::IBEUtils::calculateXor(data,HashSigma);



    QByteArray Usend=_sysparam.GetGroup1()->ElementToByteArray(U).toHex();


    QByteArray DataToSend;
    QDataStream stream(&DataToSend,QIODevice::WriteOnly);

    stream<<Usend<<Vsend<<Wsend;
    free(sigma);
//    qDebug()<<"Usend "<<Usend.constData()<<endl;
//    qDebug()<<"Vsend "<<Vsend.toHex().constData()<<endl;
//    qDebug()<<"Wsend "<<Wsend.toHex().constData()<<endl;

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
