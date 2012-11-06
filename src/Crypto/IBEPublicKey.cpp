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

#define SIZE 160



namespace Dissent{
namespace Crypto{

IBEPublicKey::IBEPublicKey(const QByteArray &data)
{
    SystemParam Param;
    QByteArray tempPublicKey;
    char* UserID;
    QDataStream stream(data);
    stream>>tempPublicKey>>Param>>UserID;
    _sysparam=Param;
    _publickey=_sysparam.GetGroup1()->ElementFromByteArray(tempPublicKey);
    ID=QString(UserID);
}

IBEPublicKey::IBEPublicKey(const char* ID,SystemParam Sysparam)
{
     Element Qid=Sysparam.GetGroup1()->ElementFromHash(ID);
     qDebug()<<"(IBEPublicKey)The public key is "<<Sysparam.GetGroup1()->ElementToByteArray(Qid).toHex().constData()<<endl;

     this->_publickey=Qid;
     this->_sysparam=Sysparam;
     this->ID=QString(ID);
}


IBEPublicKey::~IBEPublicKey()
{

}


QByteArray IBEPublicKey:: GetByteArray() const
{

}


QByteArray IBEPublicKey::Encrypt(const QByteArray &data) const
{
    Element generator=this->_sysparam.GetGroup1()->GetGenerator();
    char sigma[SIZE];
    char V[SIZE];
    char W[SIZE];
    memset(W, 0, sizeof(char)*SIZE);
    memset(V, 0, sizeof(char)*SIZE);
    Utils::IBEUtils::Randn(sigma);
    //qDebug()<<"The Sigma is "<<sigma<<endl;
    QByteArray hashSigma=QByteArray(sigma);
    hashSigma.append(data);


    //Get Integer r
    Integer r=Utils::IBEUtils::HashToZr(this->_sysparam.GetGroup1()->GetOrder(),hashSigma);

    //Get Element of rP
    Element U=this->_sysparam.GetGroup1()->Exponentiate(generator,r);
    //qDebug()<<"r is"<< r.GetByteArray().toHex().constData();
    //Calculte (gid)^r
    Element Gid=this->_sysparam.GetGroupT()->ApplyPairing(this->_publickey,this->_sysparam.GetPpub());
    Element Gidr=this->_sysparam.GetGroupT()->Exponentiate(Gid,r);
    QByteArray PreGidr=this->_sysparam.GetGroupT()->ElementToByteArray(Gidr);

    Hash *hash=CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    //Got H2(Gidr)
    QByteArray HashGidr=hash->ComputeHash(PreGidr);
    //qDebug()<<"GTDidU is "<<PreGidr.toHex().constData()<<endl;
   //Got H4(sigma)
    QByteArray HashSigma=hash->ComputeHash(QByteArray(sigma));

    QByteArray Vsend=Utils::IBEUtils::calculateXor(QByteArray(sigma),HashGidr);
    QByteArray Wsend=Utils::IBEUtils::calculateXor(data,HashSigma);

  //  Utils::IBEUtils::Xor(SIZE,sigma,HashGidr.toHex().constData(),V);
  //  Utils::IBEUtils::Xor(SIZE,data.constData(),HashSigma.toHex().constData(),W);


    QByteArray Usend=this->_sysparam.GetGroup1()->ElementToByteArray(U).toHex();


    QByteArray DataToSend;
    QDataStream stream(&DataToSend,QIODevice::WriteOnly);

    stream<<Usend<<Vsend<<Wsend;
    qDebug()<<"Usend "<<Usend.constData()<<endl;
    qDebug()<<"Vsend "<<Vsend.toHex().constData()<<endl;
    qDebug()<<"Wsend "<<Wsend.toHex().constData()<<endl;

    return DataToSend;
}

QDataStream &operator<<(QDataStream &out, const IBEPublicKey &PublicKey)
{
    out <<PublicKey.GetParam().GetGroup1()->ElementToByteArray(PublicKey.GetPublicKeyElement())
        <<PublicKey.GetParam()<<PublicKey.GetUserId().data();
    return out;
}

QDataStream &operator>>(QDataStream &in, IBEPublicKey &PublicKey)
{
    SystemParam Param;
    QByteArray tempPublicKey;
    char* UserID;
    in >> tempPublicKey >>Param>>UserID;

    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream<<tempPublicKey<<Param<<UserID;

    PublicKey=IBEPublicKey(data);
    return in;
}


}
}
