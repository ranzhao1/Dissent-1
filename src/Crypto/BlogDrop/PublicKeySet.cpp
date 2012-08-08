
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  PublicKeySet::PublicKeySet(const QSharedPointer<const Parameters> params, 
      const QList<QSharedPointer<const PublicKey> > &keys) :
    _params(params)
  {
    _key = 1;
    for(int i=0; i<keys.count(); i++) {
      _key = _key.MultiplyMod(keys[i]->GetInteger(), params->GetP());
    }
  }

}
}
}
