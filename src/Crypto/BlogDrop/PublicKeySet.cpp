
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  PublicKeySet::PublicKeySet(const QSharedPointer<const Parameters> params, 
      const QList<QSharedPointer<const PublicKey> > &keys) :
    _params(params)
  {
    _key = _params->GetGroup()->GetIdentity();
    for(int i=0; i<keys.count(); i++) {
      _key = _params->GetGroup()->Multiply(_key, keys[i]->GetElement());
    }
  }

}
}
}
