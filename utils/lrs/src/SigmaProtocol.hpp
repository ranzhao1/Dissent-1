#ifndef DISSENT_LRS_SIGMA_PROTOCOL_H_GUARD
#define DISSENT_LRS_SIGMA_PROTOCOL_H_GUARD

#include "Crypto/Integer.hpp"

namespace Dissent {
namespace LRS {

  class SigmaProtocol {

    public:

      typedef struct {
        QVariant commit;
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
      QVariant GenerateWitness();

      Integer GenerateCommit();

      QVariant Prove(const QVariant witness, const QVariant commit, const Integer challenge);

      SigmaProof FakeProve(const QVariant challenge);

      WitnessImage Evaluate(const QVariant witness);

    private:

  };

}
}

#endif
