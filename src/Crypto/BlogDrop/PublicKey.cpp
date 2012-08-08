
#include "PublicKey.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  PublicKey::PublicKey() :
    _params(Parameters::Zero()) {}

  PublicKey::PublicKey(const QSharedPointer<const PrivateKey> key) :
    _params(key->GetParameters()),
    _public_key(_params->GetG().Pow(key->GetInteger(), _params->GetP()))
  {
  }
  
  PublicKey::PublicKey(const PrivateKey &key) :
    _params(key.GetParameters()),
    _public_key(_params->GetG().Pow(key.GetInteger(), _params->GetP()))
  {
  }

  PublicKey::PublicKey(const QSharedPointer<const Parameters> params, const QByteArray key) :
    _params(params),
    _public_key(Integer(key))
  {
  }

  PublicKey::PublicKey(const QSharedPointer<const Parameters> params, const Integer key) :
    _params(params),
    _public_key(key)
  {
  }
}
}
}
