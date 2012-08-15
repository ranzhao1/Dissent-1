
#include "PublicKey.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  PublicKey::PublicKey() :
    _params(Parameters::Empty()) {}

  PublicKey::PublicKey(const QSharedPointer<const PrivateKey> key) :
    _params(key->GetParameters()),
    _public_key(_params->GetGroup()->Exponentiate(
          _params->GetGroup()->GetGenerator(), key->GetInteger()))
  {
  }
  
  PublicKey::PublicKey(const PrivateKey &key) :
    _params(key.GetParameters()),
    _public_key(_params->GetGroup()->Exponentiate(
          _params->GetGroup()->GetGenerator(), key.GetInteger()))
  {
  }

  PublicKey::PublicKey(const QSharedPointer<const Parameters> params, const QByteArray &key) :
    _params(params),
    _public_key(_params->GetGroup()->ElementFromByteArray(key))
  {
  }

  PublicKey::PublicKey(const QSharedPointer<const Parameters> params, const Element key) :
    _params(params),
    _public_key(key)
  {
  }
}
}
}
