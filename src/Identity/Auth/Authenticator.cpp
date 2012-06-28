#include <QDebug>

#include "Identity/Group.hpp"
#include "Identity/PrivateIdentity.hpp"
#include "Messaging/ISender.hpp"

#include "Authenticator.hpp"

namespace Dissent {
namespace Identity {
namespace Auth {

  QVariantHash Authenticator::MakeChallenge(const Group &group, const QSharedPointer<ISender> client)
  {
    _challenges.remove(client);

    QVariantHash chal = MakeChallengeLogic(group, client);
    _challenges[client] = chal;

    return chal; 
  }

  QVariantHash Authenticator::MakeResponse(const Group &group, 
      const PrivateIdentity &me, const QVariantHash &challenge)
  {
    return MakeResponseLogic(group, me, challenge);
  }

  bool Authenticator::VerifyResponse(const PrivateIdentity &verifier, const Group &group, 
      const QSharedPointer<ISender> client, const QVariantHash &response)
  {
    bool authenticated = false;

    if(_challenges.contains(client)) {
      authenticated = VerifyResponseLogic(verifier, group, client, _challenges[client], response);
      _challenges.remove(client);
    } else {
      qWarning() << "No stored challenge found for client" << client->ToString();
    }

    return authenticated;
  }
}
}
}
