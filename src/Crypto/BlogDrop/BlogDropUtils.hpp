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
       * Return hash of the elements mod q (the order of the group) for a
       * Camenisch-Stadler NIZK proof. The first item in each list should
       * be an element of the key group. The rest of the items should be from 
       * the message group.
       * @param params BlogDrop parameters
       * @param gs group generators
       * @param ys public keys
       * @param ts commits
       */
      static Integer Commit(const QSharedPointer<const Parameters> &params,
          const QList<Element> &gs, 
          const QList<Element> &ys, 
          const QList<Element> &ts);

      /**
       * Return hash of the elements mod q (the order of the group)
       * @param params BlogDrop parameters
       * @param g group generator
       * @param y public key
       * @param t commit
       */
      static Integer Commit(const QSharedPointer<const Parameters> &params,
          const Element &g, 
          const Element &y, 
          const Element &t);

      /**
       * Get a nonce for this phase and round
       * @param params BlogDrop parameters
       * @param author_pk author public key
       * @param phase the phase index
       * @param element_idx the element index within a phase
       */
      static Integer GetPhaseHash(QSharedPointer<const Parameters> params,
          const QSharedPointer<const PublicKey> author_pk, 
          int phase, 
          int element_idx);

      /**
       * Compute a generator as a function of H(params, ...)
       * @param params BlogDrop parameters
       * @param author_pk author public key
       * @param phase the phase index
       * @param element_idx the element index within a phase
       */
      static Element GetHashedGenerator(QSharedPointer<const Parameters> params,
          const QSharedPointer<const PublicKey> author_pk, 
          int phase, 
          int element_idx);

      /**
       * This method is used in the "Hashed generator" proof construction.
       * For our secret a, and for public keys g^x, g^y, g^z, we compute
       * the DH shared secret with each of these keys:
       *   g^ax, g^ay, g^az
       * We then hash each of these secrets, and add them mod q
       *   out = H(g^ax) + H(g^ay) + H(g^az)  (mod q)
       * @param params BlogDrop parameters
       * @param priv this user's secret
       * @param pubs the public keys of the other users
       * @param master_priv output master secret
       * @param master_pub output commitment to master secret
       * @param master_pub output commitments to each secret
       */
      static void GetMasterSharedSecrets(const QSharedPointer<const Parameters> &params,
          const QSharedPointer<const PrivateKey> &priv, 
          const QList<QSharedPointer<const PublicKey> > &pubs,
          QSharedPointer<const PrivateKey> &master_priv,
          QSharedPointer<const PublicKey> &master_pub,
          QList<QSharedPointer<const PublicKey> > &commits);
  };

}
}
}

#endif
