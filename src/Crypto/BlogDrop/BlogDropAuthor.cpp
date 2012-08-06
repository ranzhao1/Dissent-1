
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

  ClientCiphertext BlogDropAuthor::GenerateAuthorCiphertext(const QByteArray &in, QByteArray &out) const
  {
    Plaintext m(GetParameters()); 
    out = m.Encode(in);
    ClientCiphertext c(GetParameters(), GetServerKeys(), GetAuthorKey());
    c.SetAuthorProof(_author_priv, m);
    return c;
  }

}
}
}
