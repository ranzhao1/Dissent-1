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
    QList<QByteArray> CompactData=data.split('\n');
    _s=(PairingGroup::GroupSize)CompactData[3].toInt();
    _group1=PairingG1Group::GetGroup(_s);
    _group_t=PairingGTGroup::GetGroup(_s);
    p_pub=_group1->ElementFromByteArray(CompactData[2]);
}

void SystemParam::SetGroup1()
{
    _group1=PairingG1Group::GetGroup(this->_s);

}

void SystemParam::SetGroupT()
{
    _group_t=PairingGTGroup::GetGroup(this->_s);

}


void SystemParam::setPpub(Integer MasterKey)
{
   Element generator=_group1->GetGenerator();
   p_pub=_group1->Exponentiate(generator,MasterKey);
}

Element SystemParam::getPpub() const
{
    return p_pub;

}

QSharedPointer<PairingG1Group> SystemParam:: getGroup1() const
{
    return _group1;
}

QSharedPointer<PairingGTGroup> SystemParam:: getGroupT() const
{
    return _group_t;
}

SystemParam:: ~SystemParam()
{

}

QByteArray SystemParam::GetByteArray()const
{
    QByteArray Group1Array=_group1->GetByteArray().append("\n");
    QByteArray GroupTArray=_group_t->GetByteArray().append("\n");
    QByteArray PpubArray=_group1->ElementToByteArray(p_pub).append("\n");
    QByteArray size=QByteArray::number(_s);
    return Group1Array.append(GroupTArray).append(PpubArray).append(size);
}

QDataStream &operator<<(QDataStream &out, const SystemParam &Sysparam)
{
    out <<Sysparam.getGroup1()->GetByteArray().constData() << Sysparam.getGroupT()->GetByteArray().constData()
       <<Sysparam.getGroup1()->ElementToByteArray(Sysparam.getPpub()).constData()<<QByteArray::number(Sysparam.getSize()).constData();

    return out;
}

QDataStream &operator>>(QDataStream &in, SystemParam &Sysparam)
{
    QByteArray size;
    char* tempGroup1;
    char* tempGroupT;
    char* tempPpub;
    char* tempSize;
    in >> tempGroup1 >> tempGroupT >> tempPpub >>tempSize;
    Sysparam.SetGroupSize((PairingGroup::GroupSize)QByteArray(tempSize).toInt());
    Sysparam.SetGroup1();
    Sysparam.SetGroupT();
    Sysparam.CopyPpub(Sysparam.getGroup1()->ElementFromByteArray(QByteArray(tempPpub)));
    return in;
}


}
}
