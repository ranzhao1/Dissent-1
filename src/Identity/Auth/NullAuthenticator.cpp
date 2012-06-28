#include "NullAuthenticator.hpp"

namespace Dissent {
namespace Identity {
namespace Auth {

  NullAuthenticator::NullAuthenticator() :
    Authenticator()
  {}

  QVariantHash NullAuthenticator::MakeChallengeLogic(const Group &, const QSharedPointer<ISender>)
  {
    return QVariantHash();
  }

  QVariantHash NullAuthenticator::MakeResponseLogic(const Group &, 
      const PrivateIdentity &, const QVariantHash &)
  {
    return QVariantHash();
  }

  bool NullAuthenticator::VerifyResponseLogic(const Group &, const QSharedPointer<ISender>, 
    const QVariantHash &, const QVariantHash &)
  {
    return true;
  }
}
}
}
