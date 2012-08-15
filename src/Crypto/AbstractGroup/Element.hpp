#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_ELEMENT_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_ELEMENT_H_GUARD

#include <QByteArray>
#include "ElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  class Element {

    public:

      Element() {}

      explicit Element(ElementData *data) : _data(data) {}

      virtual ~Element() {}

      inline QByteArray GetByteArray() const
      {
        return _data->GetByteArray();
      }

      /**
       * Equality operator
       * @param other the Element to compare
       */
      bool operator==(const Element &other) const
      {
        return _data->operator==(other._data.constData());
      }

      inline const ElementData *GetData() const { return _data.constData(); }

    private:

      QExplicitlySharedDataPointer<ElementData> _data;

  };

}
}
}

#endif
