#ifndef DISSENT_LRS_SCHNORR_PROTOCOL_H_GUARD
#define DISSENT_LRS_SCHNORR_PROTOCOL_H_GUARD

#include "Crypto/AbstractGroup/AbstractGroup.hpp"
#include "Crypto/AbstractGroup/Element.hpp"

#include "SigmaProtocol.hpp"

namespace Dissent {
namespace LRS {

  typedef Dissent::Crypto::AbstractGroup::Element Element;

  class SchnorrProtocol : public SigmaProtocol {

    public:

      typedef Dissent::Crypto::AbstractGroup::AbstractGroup AbstractGroup;

      /**
       * Constructor
       */
      SchnorrProtocol(QSharedPointer<AbstractGroup> g);

      /**
       * Destructor
       */
      virtual ~SchnorrProtocol();

      virtual void GenerateWitness(SigmaProof &p); 

      virtual void GenerateCommit(SigmaProof &p);

      virtual void GenerateChallenge(SigmaProof &p);

      virtual void Prove(SigmaProof &p);

      virtual void FakeProve(SigmaProof &p);

      virtual bool Verify(SigmaProof &p);

    private:

      QVariant ElementToVariant(Element e);
      Element VariantToElement(QVariant v);

      QSharedPointer<AbstractGroup> _group;

  };

}
}

#endif
