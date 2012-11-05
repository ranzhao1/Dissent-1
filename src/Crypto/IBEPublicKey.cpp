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


IBEPublicKey::IBEPublicKey(const char* ID,SystemParam Sysparam)
{
     Element Qid=Sysparam.getGroup1()->ElementFromHash(ID);
     qDebug()<<"(IBEPublicKey)The public key is "<<Sysparam.getGroup1()->ElementToByteArray(Qid).toHex().constData()<<endl;

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
    Element generator=this->_sysparam.getGroup1()->GetGenerator();
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
    Integer r=Utils::IBEUtils::HashToZr(this->_sysparam.getGroup1()->GetOrder(),hashSigma);

    //Get Element of rP
    Element U=this->_sysparam.getGroup1()->Exponentiate(generator,r);
    //qDebug()<<"r is"<< r.GetByteArray().toHex().constData();
    //Calculte (gid)^r
    Element Gid=this->_sysparam.getGroupT()->ApplyPairing(this->_publickey,this->_sysparam.getPpub());
    Element Gidr=this->_sysparam.getGroupT()->Exponentiate(Gid,r);
    QByteArray PreGidr=this->_sysparam.getGroupT()->ElementToByteArray(Gidr);

    Hash *hash=CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    //Got H2(Gidr)
    QByteArray HashGidr=hash->ComputeHash(PreGidr);
    //qDebug()<<"GTDidU is "<<PreGidr.toHex().constData()<<endl;
   //Got H4(sigma)
    QByteArray HashSigma=hash->ComputeHash(QByteArray(sigma));


    Utils::IBEUtils::Xor(SIZE,sigma,HashGidr.toHex().constData(),V);
    Utils::IBEUtils::Xor(SIZE,data.constData(),HashSigma.toHex().constData(),W);


    QByteArray Usend=this->_sysparam.getGroup1()->ElementToByteArray(U).toHex();
    QByteArray Vsend=QByteArray(V).append("\n");
    QByteArray Wsend=QByteArray(W).append("\n");

    return Usend.append("\n").append(Vsend).append(Wsend);
}

QDataStream &operator<<(QDataStream &out, const IBEPublicKey &PublicKey)
{
    out <<PublicKey.GetParam().getGroup1()->ElementToByteArray(PublicKey.GetPublicKeyElement()).constData()
        <<PublicKey.GetParam()<<PublicKey.GetUserId().data();
    return out;
}

QDataStream &operator>>(QDataStream &in, IBEPublicKey &PublicKey)
{
    SystemParam Param;
    char* tempPublicKey;
    char* UserID;
    in >> tempPublicKey >>Param>>UserID;
    PublicKey.SetSysParam(Param);
    PublicKey.SetPublicKey(PublicKey.GetParam().getGroup1()->ElementFromByteArray(QByteArray(tempPublicKey)));
    PublicKey.SetID(QString(UserID));
    return in;
}


}
}
