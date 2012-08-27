#ifndef DISSENT_CRYPTO_BLOGDROP_PAIRING_CLIENT_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PAIRING_CLIENT_CIPHERTEXT_H_GUARD

#include "ClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop client ciphertext using
   * pairing-based construction. Every ciphertext 
   * element is an element of the pairing target group GT
   *   
   * The proof for a ciphertext of length k has the form:
   *   PoK{ a, y: 
   *      ( C1 = e(prod_server_pks, t1)^a AND
   *        ... AND
   *        Ck = e(prod_server_pks, tk)^a AND A = g^a )
   *      OR
   *        Y = g^y
   *   }
   * where C1, ..., Ck are the k ciphertext elements, 
   * prod_server_pks is the product of server public keys,
   * A is the client's public key, and Y is 
   * the author public key.
   */
  class ElGamalClientCiphertext : public ClientCiphertext {

    public:

      /**
       * Constructor: Initialize a ciphertext with a fresh
       * one-time public key
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       */
      explicit ElGamalClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub);

      /**
       * Constructor: Initialize a ciphertext from a serialized bytearray
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       * @param the byte array
       */
      explicit ElGamalClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub, 
          const QByteArray &serialized);

      /**
       * Destructor
       */
      virtual ~ElGamalClientCiphertext() {}

      /**
       * Initialize elements proving correctness of ciphertext
       * @param author_priv author private key used to generate proof
       * @param m author's plaintext message
       */
      virtual void SetAuthorProof(const QSharedPointer<const PrivateKey> author_priv, const Plaintext &m);

      /**
       * Initialize elements proving correctness of ciphertext
       */
      virtual void SetProof();

      /**
       * Check ciphertext proof
       * @returns true if proof is okay
       */
      virtual bool VerifyProof() const;

      /**
       * Get a byte array for this ciphertext
       */
      virtual QByteArray GetByteArray() const;

      /**
       * Get the one-time public keys for this ciphertext
       */
      inline QList<QSharedPointer<const PublicKey> > GetOneTimeKeys() const { 
        return _one_time_pubs;
      }

      inline Integer GetChallenge1() const { return _challenge_1; }
      inline Integer GetChallenge2() const { return _challenge_2; }
      inline QList<Integer> GetResponses() const { return _responses; }

    private:
      Integer Commit(const QSharedPointer<const Parameters> &params,
          const QList<Element> &gs, 
          const QList<Element> &ys, 
          const QList<Element> &ts) const;

      void InitializeLists(QList<Element> &gs, QList<Element> &ys) const;

      Integer _challenge_1, _challenge_2;
      QList<Integer> _responses;

      QList<QSharedPointer<const PrivateKey> > _one_time_privs;
      QList<QSharedPointer<const PublicKey> > _one_time_pubs;

  };
}
}
}

#endif
