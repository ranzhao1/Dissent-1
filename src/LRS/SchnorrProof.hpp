#ifndef DISSENT_LRS_SCHNORR_PROOF_H_GUARD
#define DISSENT_LRS_SCHNORR_PROOF_H_GUARD

#include "Crypto/AbstractGroup/AbstractGroup.hpp"
#include "Crypto/AbstractGroup/Element.hpp"

#include "SigmaProof.hpp"

namespace Dissent {
namespace LRS {

  typedef Dissent::Crypto::AbstractGroup::Element Element;

  class SchnorrProof : public SigmaProof {

    public:

      typedef Dissent::Crypto::AbstractGroup::AbstractGroup AbstractGroup;

      /**
       * Constructor
       */
      SchnorrProof(QSharedPointer<AbstractGroup> g);

      /**
       * Destructor
       */
      virtual ~SchnorrProof();

      virtual void GenerateWitness(); 

      virtual void GenerateCommit();

      virtual void GenerateChallenge();

      virtual void Prove();
      virtual void Prove(QByteArray challenge);
      virtual void Prove(Integer challenge);

      virtual void FakeProve();

      virtual bool Verify() const;

      inline void SetWitness(Integer w) { _witness = w; }

      virtual QByteArray GetCommit() const { return _group->ElementToByteArray(_commit); }
      virtual inline Integer GetChallenge() const { return _challenge; }

    private:

      QVariant ElementToVariant(Element e) const;
      Element VariantToElement(QVariant v) const;

      QSharedPointer<AbstractGroup> _group;

      Integer _witness;
      Element _witness_image;
      Element _commit;
      Integer _commit_secret;
      Integer _challenge;
      Integer _response;

  };

}
}

#endif