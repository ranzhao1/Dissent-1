
#include "PublicKey.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  PublicKey::PublicKey() :
    _params(Parameters::Zero()) {}

  PublicKey::PublicKey(const PrivateKey &key) :
    _params(key.GetParameters()),
    _public_key(_params.GetG().Pow(key.GetInteger(), _params.GetP()))
  {}

  PublicKey::PublicKey(const Parameters params, const QByteArray key) :
    _params(params),
    _public_key(Integer(key))
  {}

}
}
}
