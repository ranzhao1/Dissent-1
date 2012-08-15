#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_ELEMENT_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_ELEMENT_H_GUARD

#include "ElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  class Element {

    public:

      Element() {}

      explicit Element(ElementData *data) : _data(data) {}

      virtual ~Element() {}

      inline bool IsEqual(const Element &other) { 
        return (_data->IsEqual(other._data.constData()));
      }

      inline const ElementData *GetData() const { return _data.constData(); }

    private:

      QExplicitlySharedDataPointer<ElementData> _data;

  };

}
}
}

#endif
