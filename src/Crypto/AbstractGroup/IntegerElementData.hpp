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

      virtual inline bool IsEqual(const ElementData *other) const
      { 
        qDebug() << _integer.GetByteArray().toHex() << "," << GetInteger(other).GetByteArray().toHex();
        return (_integer == GetInteger(other));
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

    private:

      Integer _integer;
  };

}
}
}

#endif
