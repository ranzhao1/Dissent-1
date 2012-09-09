
#include <QtConcurrentMap>

#include "Crypto/AbstractGroup/Element.hpp"
#include "Crypto/CryptoFactory.hpp"

#include "BlogDropUtils.hpp"
#include "CiphertextFactory.hpp" 
#include "ServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  ServerCiphertext::ServerCiphertext(const QSharedPointer<const Parameters> params,
      const QSharedPointer<const PublicKey> author_pub, 
      int n_elms) :
    _params(params),
    _author_pub(author_pub),
    _n_elms(n_elms)
  {}

  void ServerCiphertext::VerifyProofs(
      const QSharedPointer<const Parameters> params,
      const QSharedPointer<const PublicKeySet> pk_set,
      const QSharedPointer<const PublicKey> author_pk,
      const QList<QSharedPointer<const ClientCiphertext> > client_ctexts,
      int phase, 
      const QList<QSharedPointer<const PublicKey> > &pubs,
      const QList<QByteArray> &c,
      QList<QSharedPointer<const ServerCiphertext> > &c_out)
  {
    Q_ASSERT(pubs.count() == c.count());

    CryptoFactory::ThreadingType tt = CryptoFactory::GetInstance().GetThreadingType();

    if(tt == CryptoFactory::SingleThreaded) {
      QList<QSharedPointer<const ServerCiphertext> > list;

      // Unpack each ciphertext
      for(int server_idx=0; server_idx<c.count(); server_idx++) {
        list.append(CiphertextFactory::CreateServerCiphertext(params, 
              pk_set, author_pk, client_ctexts, c[server_idx]));
      }

      // Verify each proof
      for(int idx=0; idx<c.count(); idx++) {
        if(list[idx]->VerifyProof(phase, pubs[idx])) {
          c_out.append(list[idx]);
        }
      }

    } else if(tt == CryptoFactory::MultiThreaded) {
      QList<MapData> m;

      // Unpack each ciphertext copying parameters to
      // avoid shared data
      for(int server_idx=0; server_idx<c.count(); server_idx++) {
        QSharedPointer<const Parameters> newp(new Parameters(*params));
        MapData item = {CiphertextFactory::CreateServerCiphertext(
              newp,
              //QSharedPointer<const PublicKeySet>(new PublicKeySet(newp, pk_set->GetByteArray())), 
              pk_set,
              //QSharedPointer<const PublicKey>(new PublicKey(newp, author_pk->GetByteArray())), 
              author_pk,
              client_ctexts,
              c[server_idx]), 
              //QSharedPointer<const PublicKey>(new PublicKey(newp, pubs[server_idx]->GetByteArray())),
              pubs[server_idx],
              phase};
        m.append(item);
      }

      QList<bool> valid_list = QtConcurrent::blockingMapped(m, VerifyOnce);

      for(int server_idx=0; server_idx<valid_list.count(); server_idx++) {
        if(valid_list[server_idx]) {
          c_out.append(m[server_idx].c);
        }
      }

    } else {
      qFatal("Unknown threading type");
    }
  }

  bool ServerCiphertext::VerifyOnce(MapData m)
  {
    return m.c->VerifyProof(m.phase, m.pub);
  }
}
}
}
