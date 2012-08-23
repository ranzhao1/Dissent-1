#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_PAIRING_ELEMENT_DATA_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_PAIRING_ELEMENT_DATA_H_GUARD

#include <PBC.h>
#include <QByteArray>
#include <QSharedPointer>
#include "ElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  class PairingElementData : public ElementData {

    public:

      PairingElementData(QSharedPointer<G> element) {
        _element = element;
      }

      /**
       * Destructor
       */
      virtual ~PairingElementData() {}

      /**
       * Equality operator
       * @param other the ElementData to compare
       */
      virtual bool operator==(const ElementData *other) const
      {
        QSharedPointer<G> e = GetElement(other);
        return (_element == e);
      }

      /**
       * Get the point associated with this ElementData
       * @param data data element to query
       */
      inline static QSharedPointer<G> GetElement(const ElementData *data) 
      {
        const PairingElementData *elmdata = dynamic_cast<const PairingElementData*>(data);
        if(elmdata) {
          return elmdata->_element;
        } else {
          qFatal("Invalid cast");
        }

        return QSharedPointer<G>();
      }

    private:

      QSharedPointer<G> _element;

  };

}
}
}

#endif
