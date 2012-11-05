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
        this->s=PairingGroup::TESTING_128;

    }else if(Param=="TESTING_256"){

        this->s=PairingGroup::TESTING_256;

    }else if(Param=="PRODUCTION_512"){
         this->s=PairingGroup::PRODUCTION_512;

    }else if(Param=="PRODUCTION_768"){

        this->s=PairingGroup::PRODUCTION_768;
    }else if(Param=="PRODUCTION_1024"){

        this->s=PairingGroup::PRODUCTION_1024;
    }else if(Param=="PRODUCTION_1280"){

         this->s=PairingGroup::PRODUCTION_1280;
    }else if(Param=="PRODUCTION_1536"){

        this->s=PairingGroup::PRODUCTION_1536;
    }else{
        qFatal("Unknown parameter type");
    }

    this->_sysparam.SetGroupSize(this->s);
    //Set the Group1 of system parameter
    this->_sysparam.SetGroup1();
    this->_sysparam.SetGroupT();
    this->SetMasterKey();
    this->_sysparam.setPpub(MasterKey);

}



PkgServer::~PkgServer()
{
}


IBEPrivateKey PkgServer::GetPrivateKey(const char* ID) const
{
    IBEPrivateKey PrivateKey=IBEPrivateKey();
    PrivateKey.SetSysParam(this->getParam());
    Element Qid=this->_sysparam.getGroup1()->ElementFromHash(ID);
    PrivateKey.SetPrivateKey(_sysparam.getGroup1()->Exponentiate(Qid,this->MasterKey));
    return PrivateKey;
}


SystemParam PkgServer::getParam() const
{
    return this->_sysparam;
}

void PkgServer::setParam(const SystemParam &Param)
{
    this->_sysparam=Param;
}

void PkgServer::SetMasterKey()
{
    this->MasterKey=this->_sysparam.getGroup1()->RandomExponent();
}


}
}

