#include "PkgServer.hpp"
#include <iostream>
#include <string>
#include <QByteArray>
#include <QString>
#include <QSharedPointer>
#include <QDir>
#include "AbstractGroup/PairingG1Group.hpp"
#include "AbstractGroup/PairingGTGroup.hpp"


namespace Dissent{
namespace Crypto{

PkgServer:: PkgServer(const QString &filename)
{
    //Initialize the system parameter from File
    QByteArray data;
    QFile file(filename);
   // QDir::setCurrent("/");
   // qDebug()<< QDir::currentPath()<< endl;
    if(!file.open(QIODevice::ReadOnly)) {
      qWarning() << "Error (" << file.error() << ") reading file: " << filename;
    }

    data = file.readAll();
    QString Param=QString(data.constData());
    qDebug()<<Param;


    if(Param=="TESTING_128"){
        this->_s=PairingGroup::TESTING_128;

    }else if(Param=="TESTING_256"){

        this->_s=PairingGroup::TESTING_256;

    }else if(Param=="PRODUCTION_512"){
         this->_s=PairingGroup::PRODUCTION_512;

    }else if(Param=="PRODUCTION_768"){

        this->_s=PairingGroup::PRODUCTION_768;
    }else if(Param=="PRODUCTION_1024"){

        this->_s=PairingGroup::PRODUCTION_1024;
    }else if(Param=="PRODUCTION_1280"){

         this->_s=PairingGroup::PRODUCTION_1280;
    }else if(Param=="PRODUCTION_1536"){

        this->_s=PairingGroup::PRODUCTION_1536;
    }else{
        qFatal("Unknown parameter type");
    }


    _sysparam.SetGroupSize(_s);
    _sysparam.SetGroup1();
    _sysparam.SetGroupT();
    SetMasterKey();
    _sysparam.SetPpub(_masterkey);

}



PkgServer::~PkgServer()
{
}


IBEPrivateKey PkgServer::GetPrivateKey(const char* ID) const
{
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    Element Qid=_sysparam.GetGroup1()->ElementFromHash(ID);
    qDebug()<<"Group Order is "<<_sysparam.GetGroup1()->GetOrder().ToString()<<endl;
    qDebug()<<"Qid is "<<strlen(_sysparam.GetGroup1()->ElementToByteArray(_sysparam.GetGroup1()->Exponentiate(Qid,_masterkey)).constData())<<endl;
    stream<<_sysparam.GetGroup1()->ElementToByteArray(_sysparam.GetGroup1()->Exponentiate(Qid,_masterkey))
            <<_sysparam;
//    IBEPrivateKey PrivateKey=IBEPrivateKey();
//    PrivateKey.SetSysParam(getParam());
//    Element Qid=_sysparam.GetGroup1()->ElementFromHash(ID);
//    PrivateKey.SetPrivateKey(_sysparam.GetGroup1()->Exponentiate(Qid,_masterkey));
    IBEPrivateKey PrivateKey=IBEPrivateKey(data);
    return PrivateKey;
}


SystemParam PkgServer::getParam() const
{
    return _sysparam;
}

void PkgServer::setParam(const SystemParam &Param)
{
    _sysparam=Param;
}

void PkgServer::SetMasterKey()
{
    _masterkey=_sysparam.GetGroup1()->RandomExponent();
}


}
}

