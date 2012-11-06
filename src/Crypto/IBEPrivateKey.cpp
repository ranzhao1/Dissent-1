#include  "IBEPrivateKey.hpp"


#define SIZE 160

namespace Dissent{
namespace Crypto{


//Read key from a file


IBEPrivateKey::IBEPrivateKey(const QByteArray &data)
{
    SystemParam Param;
    QByteArray tempPrivateKey;
    QDataStream stream(data);
    stream>>tempPrivateKey>>Param;
    qDebug()<<"Main Point tempPrivateKey "<<tempPrivateKey;
    _sysparam=Param;
    qDebug()<<"Private Key is "<<strlen(tempPrivateKey);
    _privatekey=_sysparam.GetGroup1()->ElementFromByteArray(tempPrivateKey);
    qDebug()<<"Calucluate led private key is "<<QByteArray((_sysparam.GetGroup1())->ElementToByteArray(this->_privatekey)).toHex().constData()<<endl;
}


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
    QDataStream stream(data);
    char* Ustring;
    char* Vstring;
    char* Wstring;



    //Receive the data and split it into three pieces
    QByteArray Ureceive;
    QByteArray Vreceive;
    QByteArray Wreceive;

     stream>>Ureceive>>Vreceive>>Wreceive;

     qDebug()<<"Usend "<<Ureceive.constData()<<endl;
     qDebug()<<"Vsend "<<Vreceive.toHex().constData()<<endl;
     qDebug()<<"Wsend "<<Wreceive.toHex().constData()<<endl;

     Ureceive=QByteArray::fromHex(Ureceive);
  //  qDebug()<<"Enter Into IBEPrivateKey-Decrypt\n";
//    qDebug()<<Ureceive.constData();
//    qDebug()<<strlen(Vreceive.constData());
//    qDebug()<<strlen(Wreceive.constData());

   //char Sigma[SIZE];
    QByteArray Sigma;
    QByteArray M;
    //char M[SIZE];

 //   memset(Sigma,0,sizeof(char)*SIZE);
  //  memset(M,0,sizeof(char)*SIZE);

    Element U=this->_sysparam.GetGroup1()->ElementFromByteArray(Ureceive);
    //If U is not a element of Gourp1 then reject the ciphertext
    if(!this->_sysparam.GetGroup1()->IsElement(U)){
        return NULL;
    }

    Element PairDidU=this->_sysparam.GetGroupT()->ApplyPairing(this->_privatekey,U);
    qDebug()<<"The privatekey element is "<<QByteArray((_sysparam.GetGroup1())->ElementToByteArray(this->_privatekey)).toHex().constData();
    QByteArray GTDidU=this->_sysparam.GetGroupT()->ElementToByteArray(PairDidU);
    Hash *hash=CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    //Get H2(e(dID,U))
    QByteArray HashGTDidU=hash->ComputeHash(GTDidU);
  //  qDebug()<<"GTDidU is "<<GTDidU.constData()<<endl;

    //Get sigma
    //Utils::IBEUtils::Xor(SIZE,Vreceive.data(),HashGTDidU.toHex().data(),Sigma);

      Sigma=Utils::IBEUtils::calculateXor(Vreceive,HashGTDidU);
    qDebug()<<"The sigma is "<<Sigma<<endl;
    //H4(sigma)
     QByteArray HashSigma=hash->ComputeHash(Sigma);


     //Get Message M
    // Utils::IBEUtils::Xor(SIZE,Wreceive.data(),HashSigma.toHex().data(),M);
       M=Utils::IBEUtils::calculateXor(Wreceive,HashSigma);



     QByteArray hashSigmaM=Sigma;
     hashSigmaM.append(M);

     qDebug()<<"Before return "<<M.constData();
     Integer r=Utils::IBEUtils::HashToZr(this->_sysparam.GetGroup1()->GetOrder(),hashSigmaM);
    // qDebug()<<"r is"<< r.GetByteArray().toHex().constData();
     Element generator=this->_sysparam.GetGroup1()->GetGenerator();
     //qDebug()<<"U"<<(this->_sysparam.getGroup1()->ElementToByteArray(U).toHex().constData());
     //qDebug()<<"rP"<<(this->_sysparam.getGroup1()->ElementToByteArray(this->_sysparam.getGroup1()->Exponentiate(generator,r)).toHex().constData());

     qDebug()<<"U is "<<_sysparam.GetGroup1()->ElementToByteArray(U).toHex().constData()<<endl;
     qDebug()<<"epression is "<<_sysparam.GetGroup1()->ElementToByteArray(this->_sysparam.GetGroup1()->Exponentiate(generator,r)).toHex().constData()<<endl;

     if(U!=this->_sysparam.GetGroup1()->Exponentiate(generator,r))
     {
         return NULL;
     }


     return M;


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
//    QByteArray PrivateKey=_sysparam.GetGroup1()->ElementToByteArray(_privatekey).append("\n");
//    QByteArray SystemPara=_sysparam.GetByteArray().append("\n");
//    return PrivateKey.append(SystemPara);
    return QByteArray();
}

QDataStream &operator<<(QDataStream &out, const IBEPrivateKey &PrivateKey)
{
    out <<PrivateKey.GetParam().GetGroup1()->ElementToByteArray(PrivateKey.GetPrivateKey())
        <<PrivateKey.GetParam();
    return out;
}

QDataStream &operator>>(QDataStream &in, IBEPrivateKey &PrivateKey)
{
    SystemParam Param;
    QByteArray tempPrivateKey;
    in >> tempPrivateKey >>Param;
//    PrivateKey.SetSysParam(Param);
//    PrivateKey.SetPrivateKey(PrivateKey.GetParam().GetGroup1()->ElementFromByteArray(QByteArray(tempPrivateKey)));
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream<<tempPrivateKey<<Param;
    PrivateKey=IBEPrivateKey(data);
    return in;
}


}
}
