#include "AbstractGroup/PairingG1Group.hpp"
#include "AbstractGroup/PairingGTGroup.hpp"
#include "CryptoFactory.hpp"
#include "CppHash.hpp"
#include "PkgServer.hpp"
#include "IBEPublicKey.hpp"
#include <QByteArray>
#include<QDebug>
#include"AbstractGroup/ByteElementData.hpp"

using namespace Dissent::Crypto;
using namespace Dissent::Crypto::AbstractGroup;

int main()
{
    //Fake facebookID
    const QString ID="1223989894530";
    //Original Message
    const char message[]="It is good for you!";

    Hash *hash=CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    //Compute the message hash
    QByteArray MessageHash=hash->ComputeHash(message).toHex();


    qDebug()<<"Pkg Server Set Up..."<<endl;
    PkgServer Pkg=PkgServer("Param.txt");
    IBEPublicKey PublicKey(ID,Pkg.GetParam());
    qDebug()<<"Get the PrivateKey from Pkg Server..."<<endl;
    IBEPrivateKey PrivateKey=Pkg.GetPrivateKey(ID);

    qDebug()<<"Original Message: \n"<<message<<endl;
    qDebug()<<"Original Message Hash:\n"<<MessageHash.constData();
    QByteArray Ciphertext=PublicKey.Encrypt(MessageHash);
    qDebug()<<"The ciphertext: \n"<<Ciphertext.constData()<<endl;
    QByteArray text=PrivateKey.Decrypt(Ciphertext);


    qDebug()<<"The length of text is "<<strlen(text.constData());
    qDebug()<<"Original Message Hash:\n"<<MessageHash.constData();
    qDebug()<<"Decrpted Message Hash:\n"<<text.constData();
    if(QString(text.constData())==QString(MessageHash.constData())){
        qDebug()<<"\nCongratulations! Sucessfully Decrypted the Message Hash!"<<endl;
    }
    return 0;
}
