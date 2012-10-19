#ifndef DISSENT_LRS_GQ_PROTOCOL_H_GUARD
#define DISSENT_LRS_GQ_PROTOCOL_H_GUARD

#include "SigmaProtocol.hpp"

namespace Dissent {
namespace LRS {

  class GQProtocol : public SigmaProtocol {

    public:

      /**
       * length of RSA modulus
       */
      static const int modulus_bits = 1024;

      /**
       * Participant proves that she knows the e-th root 
       * of this number modulo n
       */
      static const int prover_y = 20; 

      /**
       * Constructor
       */
      GQProtocol();

      /**
       * Destructor
       */
      virtual ~GQProtocol();

      virtual void GenerateWitness(SigmaProof &p); 

      virtual void GenerateCommit(SigmaProof &p);

      virtual void GenerateChallenge(SigmaProof &p);

      virtual void Prove(SigmaProof &p);

      virtual void FakeProve(SigmaProof &p);

      virtual bool Verify(SigmaProof &p);

    private:

  };

}
}

#endif
