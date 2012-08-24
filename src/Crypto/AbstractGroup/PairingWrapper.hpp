#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_PAIRING_WRAPPER_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_PAIRING_WRAPPER_H_GUARD

#include <QSharedPointer>
#include <gmp.h>
#include <PBC.h>

#include "PairingG1Group.hpp"
#include "PairingGTGroup.hpp"
#include "PairingElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  class PairingWrapper {

    public:

      /**
       * Constructor
       * @param g1 first group (note: the second group is equal 
       *           to the first since we're using symmetric
       *           pairings only)
       * @param gT target group
       */
      PairingWrapper(QSharedPointer<const PairingG1Group> g1, QSharedPointer<const PairingGTGroup> gT);

      /**
       * Destructor
       */
      virtual ~PairingWrapper() {}

      /**
       * Compute pairing e(a1, a2)
       * @param a1 first operand -- must be in group G1
       * @param a2 second operand -- must be in group G1
       * @returns element of GT
       */
      virtual Element Apply(const Element &a1, const Element &a2) const;

      inline QByteArray GetByteArray() const { return _g1->GetByteArray(); }

    private:

      QSharedPointer<const PairingG1Group> _g1;
      QSharedPointer<const PairingGTGroup> _gT;

      Pairing _pairing;

  };

}
}
}

#endif
