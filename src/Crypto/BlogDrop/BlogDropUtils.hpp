#ifndef DISSENT_CRYPTO_BLOGDROP_BLOGDROP_UTILS_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_BLOGDROP_UTILS_H_GUARD

#include <QList>

#include "Crypto/Integer.hpp"
#include "Parameters.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop utility methods
   */
  class BlogDropUtils {

    public:

      typedef Dissent::Crypto::Integer Integer;
      typedef Dissent::Crypto::AbstractGroup::Element Element;

      static Integer Commit(const QSharedPointer<const Parameters> &params,
          const QList<Element> &gs, 
          const QList<Element> &ys, 
          const QList<Element> &ts);

      static Integer Commit(const QSharedPointer<const Parameters> &params,
          const Element &g, 
          const Element &y, 
          const Element &t);

  };

}
}
}

#endif
