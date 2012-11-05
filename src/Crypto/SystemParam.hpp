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


    class SystemParam{

    public:


        explicit SystemParam(){}

        /**
         *Load the system parameter from a file
         *@param filename file stores the system parameter
         */
        explicit SystemParam(const QString &filename);

        /**
         *Load the system param from ByteArray
         *@param data ByteArray data of system parameter
         */
        explicit SystemParam(const QByteArray &data);

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
        void setPpub(Integer MasterKey);

        /**
         *Get group1 pointer
         */
        QSharedPointer<PairingG1Group> getGroup1() const;

        /**
         *Get grouptT pointer
         */
        QSharedPointer<PairingGTGroup> getGroupT() const;

        /**
         * Get the Ppub paramter of the system paramter
         */
        Element getPpub() const;

        QByteArray GetByteArray() const;

        PairingGroup::GroupSize getSize() const{return _s;}


        void CopyPpub(Element NewPpub) {p_pub=NewPpub;}

    private:
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
