
#include <QtCore>

#include "Crypto/CryptoFactory.hpp"

#include "BlogDropUtils.hpp"
#include "ClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  QSet<int> ClientCiphertext::VerifyProofs(const QList<QSharedPointer<const ClientCiphertext> > &c)
  {
    // XXX Only allowing single-threaded mode for now. Need to add
    // synchronization to ECGroup classes if for multi-threading to
    // work.
    // CryptoFactory::ThreadingType t = CryptoFactory::GetInstance().GetThreadingType();
    CryptoFactory::ThreadingType t = CryptoFactory::SingleThreaded;
    QSet<int> valid;

    if(t == CryptoFactory::SingleThreaded) {
      for(int idx=0; idx<c.count(); idx++) {
        if(c[idx]->VerifyProof()) valid.insert(idx);
      }
    } else if(t == CryptoFactory::MultiThreaded) {
      QList<bool> results = QtConcurrent::blockingMapped(c, &VerifyOnce);
      for(int idx=0; idx<c.count(); idx++) {
        if(results[idx]) valid.insert(idx);
      }
    } else {
      qFatal("Unknown threading type");
    }

    return valid;
  }

  bool ClientCiphertext::VerifyOnce(QSharedPointer<const ClientCiphertext> c) 
  {
    return c->VerifyProof();
  }

}
}
}
