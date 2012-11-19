#include "SystemParam.hpp"

namespace Dissent{
namespace Crypto{

//Read SystemParam from a file
SystemParam::SystemParam(const QString &filename)
{
    QByteArray data;
    QFile file(filename);
    if(!file.open(QIODevice::ReadOnly)) {
        qFatal("Error reading file");
    }

    data = file.readAll();
    file.close();
    InitFromByteArray(data);
}

//Read system parameter from the ByteArrray data
SystemParam::SystemParam(const QByteArray &data)
{
    InitFromByteArray(data);
}

SystemParam::SystemParam(const int size,const QByteArray Ppub)
{
    InitSystemParameter(size,Ppub);
}

bool SystemParam::InitFromByteArray(const QByteArray &data)
{
    int size;
    QByteArray TempPpub;
    QDataStream stream(data);
    stream >> size >> TempPpub;
    InitSystemParameter(size,TempPpub);
    return true;
}

bool SystemParam::InitSystemParameter(const int size,const QByteArray Ppub)
{
    _s = (PairingGroup::GroupSize)size;
    _group1 = PairingG1Group::GetGroup(_s);
    _group_t = PairingGTGroup::GetGroup(_s);
    CopyPpub(GetGroup1()->ElementFromByteArray(Ppub));
    return true;
}

void SystemParam::SetGroup1()
{
    _group1 = PairingG1Group::GetGroup(_s);

}

void SystemParam::SetGroupT()
{
    _group_t = PairingGTGroup::GetGroup(_s);

}


void SystemParam::SetPpub(Integer MasterKey)
{
   Element generator = _group1->GetGenerator();
   p_pub = _group1->Exponentiate(generator,MasterKey);
}

Element SystemParam::GetPpub() const
{
    return p_pub;

}

QSharedPointer<PairingG1Group> SystemParam:: GetGroup1() const
{
    return _group1;
}

QSharedPointer<PairingGTGroup> SystemParam:: GetGroupT() const
{
    return _group_t;
}

SystemParam:: ~SystemParam(){}

QDataStream &operator<<(QDataStream &out, const SystemParam &Sysparam)
{
    out <<Sysparam.GetSize()<<Sysparam.GetGroup1()->ElementToByteArray(Sysparam.GetPpub());

    return out;
}

QDataStream &operator>>(QDataStream &in, SystemParam &Sysparam)
{
    int size;
    QByteArray TempPpub;
    in >>size >> TempPpub;
    Sysparam = SystemParam(size,TempPpub);
    return in;
}

}
}
