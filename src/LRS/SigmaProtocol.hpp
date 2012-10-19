#ifndef DISSENT_LRS_SIGMA_PROTOCOL_H_GUARD
#define DISSENT_LRS_SIGMA_PROTOCOL_H_GUARD

#include <QVariant>

#include "Crypto/Integer.hpp"

namespace Dissent {
namespace LRS {

  typedef Dissent::Crypto::Integer Integer;

  class SigmaProtocol {

    public:

      typedef struct {
        QVariant witness;
        QVariant witness_image;
        QVariant commit;
        QVariant commit_secret;
        Integer challenge;
        QVariant response;
      } SigmaProof;
      
      /**
       * Constructor
       */
      SigmaProtocol() {}

      /**
       * Destructor
       */
      virtual ~SigmaProtocol() {}

      /**
       *
       */
      virtual void GenerateWitness(SigmaProof &p) = 0; 

      virtual void GenerateCommit(SigmaProof &p) = 0;

      virtual void GenerateChallenge(SigmaProof &p) = 0;

      virtual void Prove(SigmaProof &p) = 0;

      virtual void FakeProve(SigmaProof &p) = 0;

      virtual bool Verify(SigmaProof &p) = 0;

    private:

  };

}
}

#endif
