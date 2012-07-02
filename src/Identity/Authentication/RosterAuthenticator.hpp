#ifndef DISSENT_IDENTITY_ROSTER_AUTHENTICATOR_GUARD
#define DISSENT_IDENTITY_Roster_AUTHENTICATOR_GUARD

#include <QHash>
#include <QVariant>

#include "Connections/Id.hpp"
#include "Identity/PrivateIdentity.hpp"
#include "Identity/PublicIdentity.hpp"

#include "IAuthenticator.hpp"

namespace Dissent {

namespace Crypto {
  class Library;
}

namespace Identity {
namespace Authentication {

  /**
   * Implements an authenticating agent that authenticates against
   * a list of public keys
   */
  class RosterAuthenticator : public IAuthenticator {

    public:

      RosterAuthenticator(const PrivateIdentity &ident, const QList<PublicIdentity> &roster);

      virtual ~RosterAuthenticator() {}

      /**
       * Generate a challenge request
       * @param member the authenticating member
       * @param data optional data for making the challenge
       */
      virtual QVariant RequestChallenge(const Id &member, const QVariant &data);

      /**
       * Always returns true if the identity is valid
       * @param member the authenticating member
       * @param data the response data
       * @returns returns true and a valid members identity or
       * false and nothing
       */
      virtual QPair<bool, PublicIdentity> VerifyResponse(const Id &member,
          const QVariant &data);

      const PrivateIdentity _ident;
      QByteArray _pub_ident_bytes;
      const QList<PublicIdentity> _roster;

      QHash<Id,QPair<QByteArray, QByteArray> > _nonces;

      Crypto::Library *_lib;
  };
}
}
}

#endif
