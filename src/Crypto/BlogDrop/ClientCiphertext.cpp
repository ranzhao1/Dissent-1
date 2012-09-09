
#include <QtCore>

#include "Crypto/CryptoFactory.hpp"

#include "BlogDropUtils.hpp"
#include "CiphertextFactory.hpp"
#include "ClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  ClientCiphertext::ClientCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub,
      int n_elms) :
    _params(params),
    _server_pks(server_pks),
    _author_pub(author_pub),
    _n_elms(n_elms)
  {
  }

  void ClientCiphertext::VerifyProofs(const QSharedPointer<const Parameters> params,
          const QSharedPointer<const PublicKeySet> server_pk_set,
          const QSharedPointer<const PublicKey> author_pk,
          int phase, 
          const QList<QSharedPointer<const PublicKey> > &pubs,
          const QList<QByteArray> &c,
          QList<QSharedPointer<const ClientCiphertext> > &c_out,
          QList<QSharedPointer<const PublicKey> > &pubs_out)
  {
    Q_ASSERT(pubs.count() == c.count());

    CryptoFactory::ThreadingType tt = CryptoFactory::GetInstance().GetThreadingType();

    if(tt == CryptoFactory::SingleThreaded) {
      QList<QSharedPointer<const ClientCiphertext> > list;

      // Unpack each ciphertext
      for(int client_idx=0; client_idx<c.count(); client_idx++) {
        list.append(CiphertextFactory::CreateClientCiphertext(params, 
              server_pk_set, author_pk, c[client_idx]));
      }

      // Verify each proof
      for(int idx=0; idx<c.count(); idx++) {
        if(list[idx]->VerifyProof(phase, pubs[idx])) {
          c_out.append(list[idx]);
          pubs_out.append(pubs[idx]);
        }
      }

    } else if(tt == CryptoFactory::MultiThreaded) {
      QList<MapData> m;

      // Unpack each ciphertext copying parameters to
      // avoid shared data
      for(int client_idx=0; client_idx<c.count(); client_idx++) {
        QSharedPointer<const Parameters> newp(new Parameters(*params));
        MapData item = {CiphertextFactory::CreateClientCiphertext(
              newp,
              QSharedPointer<const PublicKeySet>(new PublicKeySet(newp, server_pk_set->GetByteArray())), 
              QSharedPointer<const PublicKey>(new PublicKey(newp, author_pk->GetByteArray())), 
              c[client_idx]), 
              QSharedPointer<const PublicKey>(new PublicKey(newp, pubs[client_idx]->GetByteArray())),
              phase};
        m.append(item);
      }

      QList<bool> valid_list = QtConcurrent::blockingMapped(m, VerifyOnce);

      for(int client_idx=0; client_idx<valid_list.count(); client_idx++) {
        if(valid_list[client_idx]) {
          c_out.append(m[client_idx].c);
          pubs_out.append(pubs[client_idx]);
        }
      }

    } else {
      qFatal("Unknown threading type");
    }
  }

  bool ClientCiphertext::VerifyOnce(MapData m)
  {
    return m.c->VerifyProof(m.phase, m.pub);
  }

}
}
}
