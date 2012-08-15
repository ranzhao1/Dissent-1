#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_ELEMENT_DATA_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_ELEMENT_DATA_H_GUARD

#include <QSharedData>

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  class ElementData : public QSharedData {
    public:
      
      explicit ElementData() {}

      /**
       * Destructor
       */
      virtual ~ElementData() {}

      virtual bool IsEqual(const ElementData *other) const = 0;

    protected:

    private:

  };
}
}
}

#endif
