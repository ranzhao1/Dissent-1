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

      virtual void GenerateWitness(SigmaProof &p) = 0; 

      virtual void GenerateCommit(SigmaProof &p) = 0;

      virtual void GenerateChallenge(SigmaProof &p) = 0;

      virtual void Prove(SigmaProof &p) = 0;

      virtual void FakeProve(SigmaProof &p) = 0;

      virtual bool Verify(SigmaProof &p) = 0;

    private:

      QSharedPointer<AbstractGroup> _group;

      QVariant IntegerToVariant(Integer i);
      Integer VariantToInteger(QVariant v);
      QVariant ElementToVariant(Element e);
      Element VariantToElement(QVariant v);

  };

}
}

#endif
