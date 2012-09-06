#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_BOTAN_EC_ELEMENT_DATA_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_BOTAN_EC_ELEMENT_DATA_H_GUARD

#include <botan/point_gfp.h>
#include <QByteArray>
#include "ElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  /**
   * This is a point on an elliptic curve
   * implemented using Botan
   */
  class BotanECElementData : public ElementData {

    public:

      /**
       * Constructor
       * @param point elliptic curve point
       */
      BotanECElementData(Botan::PointGFp point) : _point(point) {}

      /**
       * Destructor
       */
      virtual ~BotanECElementData() {}

      /**
       * Equality operator
       * @param other the ElementData to compare
       */
      virtual bool operator==(const ElementData *other) const
      {
        return (_point == GetPoint(other));
      }

      /**
       * Get the point associated with this ElementData
       * @param data data element to query
       */
      inline static Botan::PointGFp GetPoint(const ElementData *data)
      {
        const BotanECElementData *elmdata =
          dynamic_cast<const BotanECElementData*>(data);
        if(elmdata) {
          return elmdata->_point;
        } else {
          qFatal("Invalid cast");
        }

        return Botan::PointGFp();
      }

    private:

      Botan::PointGFp _point;
  };

}
}
}

#endif
