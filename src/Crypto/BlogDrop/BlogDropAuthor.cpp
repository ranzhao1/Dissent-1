
#include "BlogDropAuthor.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  BlogDropAuthor::BlogDropAuthor(const Parameters params, const PublicKeySet server_pks,
      const PrivateKey author_priv) :
    BlogDropClient(params, server_pks, PublicKey(author_priv)),
    _author_priv(author_priv)
  {
  }

  bool BlogDropAuthor::GenerateAuthorCiphertext(ClientCiphertext &out, const QByteArray &in) const
  {
    if(in.count() > MaxPlaintextLength()) return false;

    Plaintext m(GetParameters()); 
    QByteArray extra = m.Encode(in);
    if(extra.count()) return false;

    out = ClientCiphertext(GetParameters(), GetServerKeys(), GetAuthorKey());
    out.SetAuthorProof(_author_priv, m);
    return true;
  }

}
}
}
