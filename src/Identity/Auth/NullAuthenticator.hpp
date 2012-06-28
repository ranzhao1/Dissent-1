#ifndef DISSENT_IDENTITY_AUTH_NULL_AUTHENTICATOR_GUARD
#define DISSENT_IDENTITY_AUTH_NULL_AUTHENTICATOR_GUARD

#include "Authenticator.hpp"

namespace Dissent {
namespace Identity {
namespace Auth {

  class NullAuthenticator : public Authenticator {
    /**
     * This is a stub authenticator that lets anyone into
     * the group
     */

    public:

      /**
       * Constructor
       */
      NullAuthenticator();
      
      virtual ~NullAuthenticator() {}

    private:

      virtual QVariantHash MakeChallengeLogic(const Group &group, const QSharedPointer<ISender> client);

      virtual QVariantHash MakeResponseLogic(const Group &group, 
          const PrivateIdentity &me, const QVariantHash &challenge);

      virtual bool VerifyResponseLogic(const PrivateIdentity &verifier,
          const Group &group, const QSharedPointer<ISender> client, 
          const QVariantHash &challenge, const QVariantHash &response);

  };
}
}
}

#endif
