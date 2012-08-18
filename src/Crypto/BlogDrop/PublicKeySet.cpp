
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

  QList<QSharedPointer<const PublicKeySet> > PublicKeySet::CreateClientKeySets(
          const QSharedPointer<const Parameters> params, 
          const QList<QList<QSharedPointer<const PublicKey> > > &keys)
  {
    QList<QSharedPointer<const PublicKeySet> > out;

    // pks[element] = PublicKeySet for element
    for(int element_idx=0; element_idx<params->GetNElements(); element_idx++) {
      QList<QSharedPointer<const PublicKey> > tmp;
      for(int client_idx=0; client_idx<keys.count(); client_idx++) {
        tmp.append(keys[client_idx][element_idx]);
      }
      out.append(QSharedPointer<const PublicKeySet>(new PublicKeySet(params, tmp)));
    }

    return out;
  }

}
}
}
