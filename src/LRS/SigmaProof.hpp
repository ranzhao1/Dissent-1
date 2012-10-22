#ifndef DISSENT_LRS_SIGMA_PROOF_H_GUARD
#define DISSENT_LRS_SIGMA_PROOF_H_GUARD

#include <QVariant>

#include "Crypto/Integer.hpp"

namespace Dissent {
namespace LRS {

  typedef Dissent::Crypto::Integer Integer;

  class SigmaProof {

    public:

      /**
       * Constructor
       */
      SigmaProof() {}

      /**
       * Destructor
       */
      virtual ~SigmaProof() {}

      /**
       * Generate a random witness and witness
       * image for the relation represented by this
       * Sigma protocol. For example, if we're using
       * proof-of-knowledge for discrete log,
       * generate a pair (x, g^x) for a random x.
       */
      virtual void GenerateWitness() = 0; 

      /**
       * Generate the commitment for the start of
       * a Sigma protocol
       */
      virtual void GenerateCommit() = 0;

      /**
       * Generate a random challenge for a Sigma
       * protocol
       */
      virtual void GenerateChallenge() = 0;

      /**
       * Prove using a random challenge
       */
      virtual void Prove() = 0;

      /** 
       * Prove using the specified challenge.
       * Should pad the challenge with random bits 
       * up to the maximum length.
       */
      virtual void Prove(QByteArray challenge) = 0;
      virtual void Prove(Integer challenge) = 0;

      /**
       * Create a (commit, challenge, response) tuple
       * that is valid
       */
      virtual void FakeProve() = 0;

      /**
       * Verify the (commit, challenge, response) tuple
       */
      virtual bool Verify() const = 0;

      virtual QByteArray GetCommit() const = 0;
      virtual Integer GetChallenge() const = 0;

      static QByteArray CreateChallenge(QList<QByteArray> commits);

    protected:

      QVariant IntegerToVariant(Integer i) const;
      
      Integer VariantToInteger(QVariant v) const;

    private:

  };

}
}

#endif
