#ifndef DISSENT_CRYPTO_BLOGDROP_CLIENT_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_CLIENT_CIPHERTEXT_H_GUARD

#include <QSet>
#include "Crypto/AbstractGroup/Element.hpp"
#include "Crypto/Integer.hpp"
#include "Parameters.hpp"
#include "Plaintext.hpp"
#include "PrivateKey.hpp"
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop client ciphertext
   */
  class ClientCiphertext {

    public:

      typedef Dissent::Crypto::AbstractGroup::Element Element;

      /**
       * Constructor: Initialize a ciphertext with a fresh
       * one-time public key
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       */
      explicit ClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub);

      /**
       * Constructor: Initialize a ciphertext from a serialized bytearray
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       * @param the byte array
       */
      explicit ClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub, 
          const QByteArray &serialized);

      /**
       * Constructor: Initialize a ciphertext with an existing
       * set of one-time public keys
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       * @param one_time_pubs the client's one-time public keys
       */
      explicit ClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub, 
          QList<QSharedPointer<const PublicKey> > one_time_pubs);

      /**
       * Destructor
       */
      virtual ~ClientCiphertext() {}

      /**
       * Initialize elements proving correctness of ciphertext
       * @param author_priv author private key used to generate proof
       * @param m author's plaintext message
       */
      void SetAuthorProof(const QSharedPointer<const PrivateKey> author_priv, const Plaintext &m);

      /**
       * Initialize elements proving correctness of ciphertext
       */
      void SetProof();

      /**
       * Check ciphertext proof
       * @returns true if proof is okay
       */
      bool VerifyProof() const;

      /**
       * Get a byte array for this ciphertext
       */
      QByteArray GetByteArray() const;

      inline QList<QSharedPointer<const PublicKey> > GetOneTimeKeys() const { 
          return _one_time_pubs; 
      }

      inline QList<Element> GetElements() const { return _elements; }
      inline QList<Integer> GetResponses() const { return _responses; }
      inline Integer GetChallenge1() const { return _challenge_1; }
      inline Integer GetChallenge2() const { return _challenge_2; }

      /**
       * Verify a set of proofs. Uses threading if available, so this might
       * be much faster than verifying each proof in turn
       * @param c list of ciphertexts
       * @returns set of indices of valid proofs
       */
      static QSet<int> VerifyProofs(const QList<QSharedPointer<const ClientCiphertext> > &c);

    private:

      void InitializeLists(QList<Element> &gs, QList<Element> &ys) const;
      static bool VerifyOnce(QSharedPointer<const ClientCiphertext> c); 

      Integer Commit(const QList<Element> &gs, const QList<Element> &ys, 
          const QList<Element> &ts) const;

      QSharedPointer<const Parameters> _params;
      QSharedPointer<const PublicKeySet> _server_pks;
      QSharedPointer<const PublicKey> _author_pub;

      QList<QSharedPointer<const PrivateKey> > _one_time_privs;
      QList<QSharedPointer<const PublicKey> > _one_time_pubs;

      QList<Element> _elements;
      Integer _challenge_1, _challenge_2;
      QList<Integer> _responses;

      const int _nelms;
  };
}
}
}

#endif
