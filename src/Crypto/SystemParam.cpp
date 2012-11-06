#include "SystemParam.hpp"



namespace Dissent{
namespace Crypto{


//Read SystemParam from a file
SystemParam::SystemParam(const QString &filename)
{

}


//Read system parameter from the ByteArrray data
SystemParam::SystemParam(const QByteArray &data)
{
    int size;
    QByteArray TempPpub;
    QDataStream stream(data);
    stream >> size >> TempPpub;
    _s=(PairingGroup::GroupSize)size;
     _group1=PairingG1Group::GetGroup(_s);
    _group_t=PairingGTGroup::GetGroup(_s);
    CopyPpub(GetGroup1()->ElementFromByteArray(TempPpub));
}

void SystemParam::SetGroup1()
{
    _group1=PairingG1Group::GetGroup(_s);

}

void SystemParam::SetGroupT()
{
    _group_t=PairingGTGroup::GetGroup(_s);

}


void SystemParam::SetPpub(Integer MasterKey)
{
   Element generator=_group1->GetGenerator();
   p_pub=_group1->Exponentiate(generator,MasterKey);
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

SystemParam:: ~SystemParam()
{

}

QDataStream &operator<<(QDataStream &out, const SystemParam &Sysparam)
{
    out <<Sysparam.GetSize()<<Sysparam.GetGroup1()->ElementToByteArray(Sysparam.GetPpub());

    return out;
}

QDataStream &operator>>(QDataStream &in, SystemParam &Sysparam)
{
    int size;
    QByteArray TempPpub;
    in >> size >> TempPpub;

    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream<<size<<TempPpub;
    Sysparam=SystemParam(data);
//    Sysparam.SetGroupSize((PairingGroup::GroupSize)size);
//    Sysparam.SetGroup1();
//    Sysparam.SetGroupT();
//    Sysparam.CopyPpub(Sysparam.GetGroup1()->ElementFromByteArray(QByteArray(TempPpub)));
    return in;
}


}
}
