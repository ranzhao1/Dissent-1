#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_INTEGER_ELEMENT_DATA_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_INTEGER_ELEMENT_DATA_H_GUARD

#include "Crypto/Integer.hpp"
#include "ElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  class IntegerElementData : public ElementData {

    public:

      IntegerElementData(Integer integer) : _integer(integer) {}

      virtual ~IntegerElementData() {}

      /**
       * Equality operator
       * @param other the ElementData to compare
       */
      virtual bool operator==(const ElementData *other) const
      {
        return _integer == GetInteger(other);
      }

      inline static Integer GetInteger(const ElementData *data)
      {
        const IntegerElementData *elmdata =
          dynamic_cast<const IntegerElementData*>(data);
        if(elmdata) {
          return elmdata->_integer;
        } else {
          qFatal("Invalid cast");
        }

        return Integer();
      }

      virtual inline QByteArray GetByteArray() const 
      {
        return _integer.GetByteArray();
      }

    private:

      Integer _integer;
  };

}
}
}

#endif
