#ifndef DISSENT_LRS_RING_SIGNATURE_H_GUARD
#define DISSENT_LRS_RING_SIGNATURE_H_GUARD

#include <QSharedPointer>

#include "Crypto/AbstractGroup/AbstractGroup.hpp"
#include "SigmaProof.hpp"

namespace Dissent {
namespace LRS {

  class RingSignature {

    public:

      typedef Dissent::Crypto::AbstractGroup::AbstractGroup AbstractGroup;

      /**
       * Constructor
       */
      RingSignature(QSharedPointer<AbstractGroup> group,
          QSharedPointer<SigmaProof> real, 
          QList<QSharedPointer<SigmaProof> > fakes);

      /**
       * Destructor
       */
      virtual ~RingSignature();

      QByteArray Sign(const QByteArray msg);

      bool Verify(const QByteArray msg, const QByteArray sig);

    private:

      QByteArray CreateChallenge(const QByteArray &msg, const QList<QByteArray> &commits) const;
      QByteArray Xor(const QByteArray &a, const QByteArray &b) const;

      QSharedPointer<AbstractGroup> _group;
      QSharedPointer<SigmaProof> _real_proof;
      QList<QSharedPointer<SigmaProof> > _fake_proofs;
      QList<QByteArray> _witness_images;
  };

}
}

#endif
