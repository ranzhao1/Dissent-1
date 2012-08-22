
#include "PrivateKey.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  PrivateKey::PrivateKey(const QSharedPointer<const Parameters> params) :
    _params(params),
    _key(params->GetKeyGroup()->RandomExponent())
  {
  }

}
}
}
