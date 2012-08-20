
#include "Crypto/CryptoFactory.hpp"
#include "BlogDropUtils.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  Integer BlogDropUtils::Commit(const QSharedPointer<const Parameters> &params,
      const QList<Element> &gs, 
      const QList<Element> &ys, 
      const QList<Element> &ts) 
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();

    hash->Restart();
    hash->Update(params->GetGroup()->GetByteArray());

    Q_ASSERT(gs.count() == ys.count());
    Q_ASSERT(gs.count() == ts.count());

    for(int i=0; i<gs.count(); i++) {
      hash->Update(params->GetGroup()->ElementToByteArray(gs[i]));
      hash->Update(params->GetGroup()->ElementToByteArray(ys[i]));
      hash->Update(params->GetGroup()->ElementToByteArray(ts[i]));
    }

    return Integer(hash->ComputeHash()) % params->GetGroup()->GetOrder();
  }

  Integer BlogDropUtils::Commit(const QSharedPointer<const Parameters> &params,
      const Element &g, 
      const Element &y, 
      const Element &t)
  {
    QList<Element> gs;
    gs.append(g);

    QList<Element> ys;
    ys.append(y);

    QList<Element> ts;
    ts.append(t);

    return Commit(params, gs, ys, ts);
  }

}
}
}
