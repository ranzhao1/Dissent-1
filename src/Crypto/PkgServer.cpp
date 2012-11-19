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
    QByteArray data;
    QFile file(filename);

    if(!file.open(QIODevice::ReadOnly)) {
       qFatal("Error reading file");
    }

    data = file.readAll();
    file.close();
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

    /**
     *Can not use system parameter constructor here:
     *Because we should firstly generate the Group1
     *and GroupT of system parameter, then use
     *Group1 to generate the Master key of Pkg,
     *eventually using the Master key to generate
     *Ppub of system parameter, there are cross over
     *process between system parameter and pkg class
     *so we can not use system constructor at the begining.
     */

    _sysparam.SetGroupSize(_s);
    _sysparam.SetGroup1();
    _sysparam.SetGroupT();
    _masterkey=_sysparam.GetGroup1()->RandomExponent();
    _sysparam.SetPpub(_masterkey);

    QFile Secondfile("System_Parameter.txt");
    if(!Secondfile.open(QIODevice::WriteOnly)) {
      qFatal("Error reading file");
    }
    QDataStream stream(&Secondfile);
    stream<<_sysparam;
    Secondfile.close();
}

PkgServer::~PkgServer(){}

IBEPrivateKey PkgServer::GetPrivateKey(const QString ID) const
{
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    Element Qid=_sysparam.GetGroup1()->ElementFromHash(ID);
    stream<<_sysparam.GetGroup1()->ElementToByteArray(_sysparam.GetGroup1()->Exponentiate(Qid,_masterkey))
            <<_sysparam;
    IBEPrivateKey PrivateKey=IBEPrivateKey(data);
    return PrivateKey;
}

SystemParam PkgServer::GetParam() const
{
    return _sysparam;
}

void PkgServer::SetParam(const SystemParam &Param)
{
    _sysparam=Param;
}

void PkgServer::SetMasterKey()
{
    _masterkey=_sysparam.GetGroup1()->RandomExponent();
}

}
}

