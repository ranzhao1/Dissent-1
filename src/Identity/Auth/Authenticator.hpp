#ifndef DISSENT_IDENTITY_AUTH_AUTHENTICATOR_GUARD
#define DISSENT_IDENTITY_AUTH_AUTHENTICATOR_GUARD

#include <QSharedPointer>
#include <QVariant>

#include "Identity/Group.hpp"
#include "Messaging/ISender.hpp"

namespace Dissent {

namespace Identity {
  class Group;
  class PrivateIdentity;

namespace Auth {

  class Authenticator {
    /**
     * This is an abstract base class for a Dissent authentication
     * module. Implementers of new authentication modules should
     * override the three private virtual methods.
     */

    public:

      typedef Identity::Group Group;
      typedef Identity::PrivateIdentity PrivateIdentity;
      typedef Messaging::ISender ISender;

      /**
       * Constructor
       */
      explicit Authenticator() {}
      
      virtual ~Authenticator() {}

      /**
       * Called by the group leader to start the authentication process.
       * This method returns a QVariantHash containing some challenge
       * data for the authenticator.
       * @param group into which the prover wants to enter. This group
       *        contains the prover's public identity
       * @param ISender object pointing to the prover
       */
      QVariantHash MakeChallenge(const Group &group, const QSharedPointer<ISender> client);

      /**
       * Called by the prover to respond to the leader's authentication challenge.
       * @param group into which the prover wants to enter. This group
       *        contains the prover's public identity
       * @param private identity of the prover
       * @param the challenge sent by the verifier (group leader)
       */
      QVariantHash MakeResponse(const Group &group, const PrivateIdentity &me, 
          const QVariantHash &challenge);

      /**
       * Called by the group leader to validate the prover's response message.
       * @param private identity of the verifier (group leader)
       * @param group into which the prover wants to enter
       * @param ISender pointing to the prover
       * @param the response sent by the prover
       */
      bool VerifyResponse(const PrivateIdentity &verifier,
          const Group &group, const QSharedPointer<ISender> client, 
          const QVariantHash &response);

    private:

      /** 
       * These private methods are wrapped by the public methods above.
       */
      
      virtual QVariantHash MakeChallengeLogic(const Group &group, 
          const QSharedPointer<ISender> client) = 0;

      virtual QVariantHash MakeResponseLogic(const Group &group, 
          const PrivateIdentity &me, const QVariantHash &challenge) = 0;

      virtual bool VerifyResponseLogic(const PrivateIdentity &verifier,
          const Group &group, const QSharedPointer<ISender> client, 
          const QVariantHash &challenge, const QVariantHash &response) = 0;


    private: 

      QHash<QSharedPointer<ISender>,QVariantHash> _challenges;

  };
}
}
}

#endif
