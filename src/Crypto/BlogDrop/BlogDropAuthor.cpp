
#include "BlogDropAuthor.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  BlogDropAuthor::BlogDropAuthor(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PrivateKey> author_priv) :
    BlogDropClient(params, server_pks, QSharedPointer<const PublicKey>(new PublicKey(author_priv))),
    _author_priv(author_priv)
  {
  }

  bool BlogDropAuthor::GenerateAuthorCiphertext(QSharedPointer<ClientCiphertext> &out,
      const QByteArray &in) const
  {
    if(in.count() > MaxPlaintextLength()) return false;

    Plaintext m(GetParameters()); 
    QByteArray extra = m.Encode(in);
    if(extra.count()) return false;

    out = QSharedPointer<ClientCiphertext>(new ClientCiphertext(GetParameters(), 
          GetServerKeys(), GetAuthorKey()));
    out->SetAuthorProof(_author_priv, m);
    return true;
  }

}
}
}
