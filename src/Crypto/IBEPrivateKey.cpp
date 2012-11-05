#include  "IBEPrivateKey.hpp"


#define SIZE 160

namespace Dissent{
namespace Crypto{


//Read key from a file




IBEPrivateKey::IBEPrivateKey(const QString &filename)
{
    _sysparam=SystemParam(filename);
}

//IBEPrivateKey::IBEPrivateKey(const QByteArray &data)
//{
//    QByteArray Compactdata=QByteArray::fromHex(data);
//    QList<QByteArray> CombineData=Compactdata.split('\n');
//    qDebug()<<"Size of QList is "<<CombineData.size()<<endl;
//    qDebug()<<CombineData[0].toHex().constData();
//    _sysparam=SystemParam(CombineData[1]);
//    _privatekey=_sysparam.getGroup1()->ElementFromByteArray(CombineData[0]);
//}


IBEPrivateKey::~IBEPrivateKey()
{

}



QByteArray IBEPrivateKey::Decrypt(const QByteArray &data) const
{

    QList<QByteArray> Compact = data.split('\n');
    //Receive the data and split it into three pieces
    QByteArray Ureceive=QByteArray::fromHex(Compact[0]);
    QByteArray Vreceive=Compact[1];
    QByteArray Wreceive=Compact[2];

  //  qDebug()<<"Enter Into IBEPrivateKey-Decrypt\n";
//    qDebug()<<Ureceive.constData();
//    qDebug()<<strlen(Vreceive.constData());
//    qDebug()<<strlen(Wreceive.constData());

    char Sigma[SIZE];
    char M[SIZE];

    memset(Sigma,0,sizeof(char)*SIZE);
    memset(M,0,sizeof(char)*SIZE);

    Element U=this->_sysparam.getGroup1()->ElementFromByteArray(Ureceive);
    //If U is not a element of Gourp1 then reject the ciphertext
    if(!this->_sysparam.getGroup1()->IsElement(U)){
        return NULL;
    }

    Element PairDidU=this->_sysparam.getGroupT()->ApplyPairing(this->_privatekey,U);
    //qDebug()<<"The privatekey element is "<<QByteArray((this->_sysparam.getGroup1())->ElementToByteArray(this->_privatekey)).toHex().constData();
    QByteArray GTDidU=this->_sysparam.getGroupT()->ElementToByteArray(PairDidU);
    Hash *hash=CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    //Get H2(e(dID,U))
    QByteArray HashGTDidU=hash->ComputeHash(GTDidU);
    //qDebug()<<"GTDidU is "<<GTDidU.toHex().constData()<<endl;
    //Get sigma
    Utils::IBEUtils::Xor(SIZE,Vreceive.data(),HashGTDidU.toHex().data(),Sigma);

    //qDebug()<<"The sigma is "<<Sigma<<endl;
    //H4(sigma)
     QByteArray HashSigma=hash->ComputeHash(QByteArray(Sigma));

     //Get Message M
     Utils::IBEUtils::Xor(SIZE,Wreceive.data(),HashSigma.toHex().data(),M);

     QByteArray hashSigmaM=QByteArray(Sigma);
     hashSigmaM.append(QByteArray(M));
     Integer r=Utils::IBEUtils::HashToZr(this->_sysparam.getGroup1()->GetOrder(),hashSigmaM);
    // qDebug()<<"r is"<< r.GetByteArray().toHex().constData();
     Element generator=this->_sysparam.getGroup1()->GetGenerator();
     //qDebug()<<"U"<<(this->_sysparam.getGroup1()->ElementToByteArray(U).toHex().constData());
     //qDebug()<<"rP"<<(this->_sysparam.getGroup1()->ElementToByteArray(this->_sysparam.getGroup1()->Exponentiate(generator,r)).toHex().constData());
     if(U!=this->_sysparam.getGroup1()->Exponentiate(generator,r))
     {

         return NULL;
     }


     return QByteArray(M);


}

void IBEPrivateKey:: SetSysParam(SystemParam Sysparam)
{
    _sysparam=Sysparam;
}

void IBEPrivateKey::SetPrivateKey(const Element &key)
{
    _privatekey=key;
}

QByteArray IBEPrivateKey::GetByteArray() const
{
    QByteArray PrivateKey=_sysparam.getGroup1()->ElementToByteArray(_privatekey).append("\n");
    QByteArray SystemPara=_sysparam.GetByteArray().append("\n");
    return PrivateKey.append(SystemPara);
}

QDataStream &operator<<(QDataStream &out, const IBEPrivateKey &PrivateKey)
{
    out <<PrivateKey.GetParam().getGroup1()->ElementToByteArray(PrivateKey.GetPrivateKey()).constData()
        <<PrivateKey.GetParam();
    return out;
}

QDataStream &operator>>(QDataStream &in, IBEPrivateKey &PrivateKey)
{
    SystemParam Param;
    char* tempPrivateKey;
    in >> tempPrivateKey >>Param;
    PrivateKey.SetSysParam(Param);
    PrivateKey.SetPrivateKey(PrivateKey.GetParam().getGroup1()->ElementFromByteArray(QByteArray(tempPrivateKey)));
    return in;
}


}
}
