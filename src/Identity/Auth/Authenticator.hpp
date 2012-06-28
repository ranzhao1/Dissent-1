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

    public:

      typedef Identity::Group Group;
      typedef Identity::PrivateIdentity PrivateIdentity;
      typedef Messaging::ISender ISender;

      /**
       * Constructor
       */
      explicit Authenticator() {}
      
      virtual ~Authenticator() {}

      QVariantHash MakeChallenge(const Group &group, const QSharedPointer<ISender> client);

      QVariantHash MakeResponse(const Group &group, const PrivateIdentity &me, 
          const QVariantHash &challenge);

      bool VerifyResponse(const PrivateIdentity &verifier,
          const Group &group, const QSharedPointer<ISender> client, 
          const QVariantHash &response);

    private:

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
