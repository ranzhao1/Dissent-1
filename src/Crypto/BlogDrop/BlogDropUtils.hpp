#ifndef DISSENT_CRYPTO_BLOGDROP_BLOGDROP_UTILS_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_BLOGDROP_UTILS_H_GUARD

#include <QHash>
#include <QList>
#include <QSharedPointer>

#include "Crypto/AbstractGroup/Element.hpp"
#include "Crypto/Integer.hpp"
#include "Parameters.hpp"
#include "PublicKey.hpp"
#include "PublicKeySet.hpp"

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

      /**
       * Return hash of the elements mod q (the order of the group)
       */
      static Integer Commit(const QSharedPointer<const Parameters> &params,
          const QList<Element> &gs, 
          const QList<Element> &ys, 
          const QList<Element> &ts);

      /**
       * Return hash of the elements mod q (the order of the group)
       */
      static Integer Commit(const QSharedPointer<const Parameters> &params,
          const Element &g, 
          const Element &y, 
          const Element &t);

      /**
       * Compute e(prod_pks, Hash(round_id, group)), save it 
       * in the cache, and return it
       */
      static Element GetPairedBase(QSharedPointer<const Parameters> params,
          QHash<int, Element> &cache,
          const QSharedPointer<const PublicKeySet> prod_pks, 
          const QSharedPointer<const PublicKey> author_pk, 
          int phase, 
          int element_idx);

  };

}
}
}

#endif
