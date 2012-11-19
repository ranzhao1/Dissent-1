#include  "IBEPrivateKey.hpp"


namespace Dissent{
namespace Crypto{



IBEPrivateKey::IBEPrivateKey(const QString &filename)
{
    QByteArray data;
    QFile file(filename);
    if(file.open(QIODevice::ReadOnly)) {
        data = file.readAll();
        file.close();
        InitFromByteArray(data);
    }
}

IBEPrivateKey::IBEPrivateKey(const QByteArray &data)
{
    InitFromByteArray(data);
}

IBEPrivateKey::IBEPrivateKey(const QByteArray PrivateKey,const SystemParam Param)
{
    InitPrivatekey(PrivateKey,Param);
}

bool IBEPrivateKey::InitFromByteArray(const QByteArray &data)
{
    SystemParam Param;
    QByteArray tempPrivateKey;
    QDataStream stream(data);
    stream>>tempPrivateKey>>Param;
    InitPrivatekey(tempPrivateKey,Param);
}

bool IBEPrivateKey::InitPrivatekey(const QByteArray PrivateKey,const SystemParam Param)
{
    _sysparam = Param;
    _privatekey = _sysparam.GetGroup1()->ElementFromByteArray(PrivateKey);
}


IBEPrivateKey::~IBEPrivateKey(){}

QByteArray IBEPrivateKey::Decrypt(const QByteArray &data) const
{
    QDataStream stream(data);

    //Receive the data and split it into three pieces
    QByteArray Ureceive;
    QByteArray Vreceive;
    QByteArray Wreceive;

    stream>>Ureceive>>Vreceive>>Wreceive;
    QByteArray Sigma;
    QByteArray M;

    Element U=this->_sysparam.GetGroup1()->ElementFromByteArray(Ureceive);
    //If U is not a element of Gourp1 then reject the ciphertext
    if(!this->_sysparam.GetGroup1()->IsElement(U)){
        return QByteArray();
    }

    Element PairDidU=this->_sysparam.GetGroupT()->ApplyPairing(this->_privatekey,U);
    QByteArray GTDidU=this->_sysparam.GetGroupT()->ElementToByteArray(PairDidU);
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    //Get H2(e(dID,U))
    QByteArray HashGTDidU = hash->ComputeHash(GTDidU);

    Sigma = Utils::IBEUtils::calculateXor(Vreceive,HashGTDidU);
    //H4(sigma)
    QByteArray HashSigma = hash->ComputeHash(Sigma);
     //Get Message M
    M = Utils::IBEUtils::calculateXor(Wreceive,HashSigma);
    QByteArray hashSigmaM = Sigma;
    hashSigmaM.append(M);

    Integer r = Utils::IBEUtils::HashToZr(this->_sysparam.GetGroup1()->GetOrder(),hashSigmaM);
    Element generator = this->_sysparam.GetGroup1()->GetGenerator();

    if(U!= this->_sysparam.GetGroup1()->Exponentiate(generator,r)){
       return QByteArray();
     }
    free(hash);
     return M;
}

QByteArray IBEPrivateKey::GetByteArray() const
{
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream<<*this;
    return data;
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

    PrivateKey = IBEPrivateKey(tempPrivateKey,Param);
    return in;
}

}
}
