
#include "PrivateKey.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  PrivateKey::PrivateKey(const Parameters &params) :
    _params(params),
    _key(params.RandomExponent())
  {}

}
}
}
