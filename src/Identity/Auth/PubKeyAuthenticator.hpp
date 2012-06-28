#ifndef DISSENT_IDENTITY_AUTH_PUB_KEY_AUTHENTICATOR_GUARD
#define DISSENT_IDENTITY_AUTH_PUB_KEY_AUTHENTICATOR_GUARD

#include "Authenticator.hpp"

namespace Dissent {

namespace Crypto {
  class Hash;
  class Library;
}

namespace Identity {
namespace Auth {

  class PubKeyAuthenticator : public Authenticator {
    /**
     * This is a simple authenticator that implements a challenge/response
     * protocol using DH keys. Since Dissent has no static group roster,
     * anyone can enter the group.
     */

    typedef Crypto::Library Library;

    public:

      /**
       * Constructor
       */
      PubKeyAuthenticator();
      
      virtual ~PubKeyAuthenticator() {}

    private:

      virtual QVariantHash MakeChallengeLogic(const Group &group, const QSharedPointer<ISender> client);

      virtual QVariantHash MakeResponseLogic(const Group &group, 
          const PrivateIdentity &me, const QVariantHash &challenge);

      virtual bool VerifyResponseLogic(const PrivateIdentity &verifier,
          const Group &group, const QSharedPointer<ISender> client, 
          const QVariantHash &challenge, const QVariantHash &response);

      Library *_crypto;

  };
}
}
}

#endif
