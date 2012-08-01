
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  PublicKeySet::PublicKeySet(const Parameters params, const QList<PublicKey> &keys) :
    _params(params)
  {
    _key = 1;
    for(int i=0; i<keys.count(); i++) {
      _key = _key.MultiplyMod(keys[i].GetInteger(), params.GetP());
    }
  }

}
}
}
