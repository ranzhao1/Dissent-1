#ifndef DISSENT_CRYPTO_BLOGDROP_SERVER_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_SERVER_CIPHERTEXT_H_GUARD

#include "Crypto/AbstractGroup/Element.hpp"
#include "Crypto/Integer.hpp"
#include "ClientCiphertext.hpp"
#include "Parameters.hpp"
#include "PrivateKey.hpp"
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop server ciphertext
   */
  class ServerCiphertext {

    public:

      typedef Dissent::Crypto::AbstractGroup::Element Element;

      typedef struct {
        Parameters *params;
        QByteArray client_ciphertext_list;
        QByteArray server_pk_set;
        QByteArray author_pk;
        QByteArray server_pk;
        QByteArray server_ciphertext;
        int phase;
      } MapData;

      /**
       * Constructor: Initialize a ciphertext
       * @param params Group parameters
       * @param author_pub Author public key
       * @param n_elms number of elements per ciphertext */
      ServerCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKey> author_pub,
          int n_elms);

      /**
       * Destructor
       */
      virtual ~ServerCiphertext() {}

      /**
       * Initialize elements proving correctness of ciphertext
       * @param phase transmisssion round/phase index
       * @param Server private key used to generate proof
       */
      virtual void SetProof(int phase, const QSharedPointer<const PrivateKey> priv) = 0;

      /**
       * Check ciphertext proof
       * @param phase transmisssion round/phase index
       * @param pub public key of server
       * @returns true if proof is okay
       */
      virtual bool VerifyProof(int phase, const QSharedPointer<const PublicKey> pub) const = 0;

      /**
       * Verify a set of proofs. Uses threading if available, so this might
       * be much faster than verifying each proof in turn
       * @param params BlogDrop parameters
       * @param server_pk_set server public keys
       * @param author_pk Author public key
       * @param client_ctexts the client ciphertexts in the bin
       * @param phase the phase index
       * @param pubs the server public keys
       * @param server_ctexts the server ciphertexts
       * @param c_out output server ciphertexts
       */
      static void VerifyProofs(
          const QSharedPointer<const Parameters> params,
          const QSharedPointer<const PublicKeySet> server_pk_set,
          const QSharedPointer<const PublicKey> author_pk,
          const QList<QSharedPointer<const ClientCiphertext> > client_ctexts,
          int phase, 
          const QList<QSharedPointer<const PublicKey> > &pubs,
          const QList<QByteArray> &server_ctexts,
          QList<QSharedPointer<const ServerCiphertext> > &c_out);

      /**
       * Get serialized version
       */
      virtual QByteArray GetByteArray() const = 0;

      /** 
       * Get the ciphertext elements
       */
      virtual inline QList<Element> GetElements() const { return _elements; }

      /** 
       * Get the author public key
       */
      virtual inline QSharedPointer<const PublicKey> GetAuthorKey() const { return _author_pub; }

      /** 
       * Get the BlogDrop parameters
       */
      virtual inline QSharedPointer<const Parameters> GetParameters() const { return _params; }

    protected:

      QSharedPointer<const Parameters> _params;
      QSharedPointer<const PublicKey> _author_pub;
      QList<Element> _elements;
      const int _n_elms;

    private: 

      static bool VerifyOnce(QSharedPointer<MapData> m);
  };
}
}
}

#endif
