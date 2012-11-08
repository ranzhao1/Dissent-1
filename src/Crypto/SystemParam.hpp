#ifndef SYSTEMPARAM_HPP
#define SYSTEMPARAM_HPP
#include <QByteArray>
#include <QDebug>
#include <QString>
#include <QFile>
#include <QDataStream>
#include <QSharedPointer>
#include "AbstractGroup/PairingG1Group.hpp"
#include "AbstractGroup/PairingGTGroup.hpp"

using namespace Dissent::Crypto::AbstractGroup;

namespace Dissent{
namespace Crypto{

    /**
     *Implementation of System Parameter
     */
    class SystemParam{

    public:

        /**
         *Empty constructor use in key serialization function
         */
        explicit SystemParam(){}

        /**
         *Read the system parameter from a file
         *@param filename file stores the system parameter
         */
        explicit SystemParam(const QString &filename);

        /**
         *Load the system param from ByteArray
         *@param data ByteArray data of system parameter
         */
        explicit SystemParam(const QByteArray &data);

        /**
         *Initialize by size and Ppub
         */
        explicit SystemParam(const int size,const QByteArray Ppub);

        /**
         *Deconstructor
         */
        virtual ~SystemParam();

        /**
         *Set up the group1
         */
        void SetGroup1();

        /**
         *Set up groupT
         */
        void SetGroupT();

        /**
         *Set up Group Size
         */
        void SetGroupSize(PairingGroup::GroupSize Size){_s=Size;}


        /**
         *Set up the Ppub for system parameter
         *@param MasterKey PKG server Master Key to set the Ppub
         */
        void SetPpub(Integer MasterKey);

        /**
         *Get group1 pointer
         */
        QSharedPointer<PairingG1Group> GetGroup1() const;

        /**
         *Get grouptT pointer
         */
        QSharedPointer<PairingGTGroup> GetGroupT() const;

        /**
         * Get the Ppub paramter of the system paramter
         */
        Element GetPpub() const;

        /**
         *Get the group size
         */
        PairingGroup::GroupSize GetSize() const{return _s;}

        /**
         *Copy Ppub to this system parameter
         *@param NewPpub copy it to this systme parameter
         */
        void CopyPpub(Element NewPpub) {p_pub=NewPpub;}

    private:
        /**
         *Initialize the system parameter from memory
         *@param data stores the system parameter
         */
        bool InitFromByteArray(const QByteArray &data);

        /**
         *Initialize the system parameter by size and Ppub
         *@param size group size
         *@param Ppub
         */
        bool InitSystemParameter(const int size,const QByteArray Ppub);

        QSharedPointer<PairingG1Group> _group1;
        QSharedPointer<PairingGTGroup> _group_t;
        PairingGroup::GroupSize _s;
        Element p_pub;


    };

    QDataStream &operator<<(QDataStream &out, const SystemParam &Sysparam);
    QDataStream &operator>>(QDataStream &in, SystemParam &Sysparam);

}
}






#endif // SYSTEMPARAM_HPP
