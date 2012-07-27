
#include "PublicKey.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  PublicKey::PublicKey(const PrivateKey &key) :
    _params(key.GetParameters()),
    _public_key(_params.GetG().Pow(key.GetInteger(), _params.GetP()))
  {}

}
}
}
