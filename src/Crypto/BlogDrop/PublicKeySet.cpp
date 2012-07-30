
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  PublicKeySet::PublicKeySet(const Parameters params, const QSet<PublicKey> &keys) :
    _params(params)
  {
    _key = 1;
    for(QSet<PublicKey>::const_iterator i=keys.begin(); i!=keys.end(); i++) {
      // TODO XXX: Use mulmod instead of naive *
      _key = (_key.Multiply(i->GetInteger())) % params.GetP();
    }
  }

}
}
}
