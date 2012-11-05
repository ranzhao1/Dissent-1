#ifndef PKGSERVER_HPP
#define PKGSERVER_HPP

#include <QString>
#include <QByteArray>
#include <QDebug>
#include <QFile>
#include "IBEPrivateKey.hpp"
#include "SystemParam.hpp"

using namespace Dissent::Crypto::AbstractGroup;

namespace Dissent{
namespace Crypto{


    class PkgServer{

    public:

        /**
         *Read  parameter from the file and set up system
         *@param filename the file storing the system parameter
         */
        explicit PkgServer(const QString &filename);

        /**
         *Deconstructor
         */
        virtual ~PkgServer();

        /**
         *Get the PrivateKey from PKG Server
         *@param ID user Identification
         */
        IBEPrivateKey GetPrivateKey(const char* ID) const;

        /**
         *Get the system parameter of PKG Server
         */
        SystemParam getParam() const;

        /**
         *Set the system parameter fo PKG Server
         *@param Param the PKG Server system parameter
         */
        void setParam(const SystemParam &Param);

        /**
         *Set the Master Key for the PKG server
         */
        void SetMasterKey();






     private:

        SystemParam _sysparam;
        PairingGroup::GroupSize s;
        Integer MasterKey;

    };

}
}


#endif // PKGSERVER_HPP
