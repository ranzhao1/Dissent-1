#ifndef DISSENT_IDENTITY_ROSTER_AUTHENTICATE_GUARD
#define DISSENT_IDENTITY_ROSTER_AUTHENTICATE_GUARD

#include <QVariant>

#include "Connections/Id.hpp"
#include "Identity/PublicIdentity.hpp"

#include "IAuthenticate.hpp"

namespace Dissent {

namespace Crypto {
  class Library;
}

namespace Identity {
namespace Authentication {

  /**
   * Implements a authenticating member who is a member of a group roster
   */
  class RosterAuthenticate : public IAuthenticate {

    public:
      RosterAuthenticate(const PrivateIdentity &ident, const PublicIdentity &leader);

      virtual ~RosterAuthenticate() {}

      /**
       * This is a two-phase authentication process (challenge, response)
       */
      inline virtual bool RequireRequestChallenge() { return true; }

      /**
       * Bob sends Alice a random nonce r1
       */
      virtual QVariant PrepareForChallenge();

      /**
       * 
       */
      virtual QPair<bool, QVariant> ProcessChallenge(const QVariant &);

      /**
       * Returns the PrivateIdentity, potentially updated
       * due to the authentication process
       */
      inline virtual PrivateIdentity GetPrivateIdentity() const
      {
        return _ident;
      }

      static const int ChallengeNonceLength = 32;

    protected:
      PrivateIdentity _ident;
      const PublicIdentity _leader;
      QByteArray _leader_bytes;
      QByteArray _ident_var;
      Crypto::Library *_lib;

    private:
      
      QByteArray _nonce_1;

  };
}
}
}

#endif
