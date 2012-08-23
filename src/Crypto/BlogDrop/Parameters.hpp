#ifndef DISSENT_CRYPTO_BLOGDROP_PARAMETERS_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PARAMETERS_H_GUARD

#include <QSharedPointer>

#include "Crypto/AbstractGroup/AbstractGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding group definition
   */
  class Parameters {

    public:

      typedef Dissent::Crypto::AbstractGroup::AbstractGroup AbstractGroup;
      typedef Dissent::Crypto::AbstractGroup::Element Element;

      /**
       * Constructor that uses 512-bit integer group (for testing)
       */
      static QSharedPointer<Parameters> IntegerTestingFixed();

      /**
       * Constructor that uses 1024-bit fixed integer group 
       */
      static QSharedPointer<Parameters> IntegerProductionFixed();

      /**
       * Constructor that uses 256-bit fixed EC group 
       * (Supposedly 256-bit ECs are equivalent to 3072-bit 
       * RSA/DH groups)
       */
      static QSharedPointer<Parameters> ECProductionFixed();

      /**
       * Constructor that uses a type-A pairing group from
       * the Stanford PBC library
       *   qbits = 512
       *   rbits = 510
       */
      static QSharedPointer<Parameters> PairingProductionFixed();
      
      
      /**
       * Constructor that has empty/invalid parameters
       */
      static QSharedPointer<Parameters> Empty();

      /**
       * Destructor
       */
      virtual ~Parameters() {}

      /**
       * Get the group that contains the public key elements 
       */
      inline QSharedPointer<const AbstractGroup> GetKeyGroup() const { return _key_group; }

      /**
       * Get the group that contains the ciphertext and message elements
       */
      inline QSharedPointer<const AbstractGroup> GetMessageGroup() const { 
        return _msg_group;
      }

      int GetNElements() const { return _n_elements; }

      inline Integer GetGroupOrder() const { 
        // For proofs to work, the two groups must have the same order
        Q_ASSERT(_key_group->GetOrder() == _msg_group->GetOrder());
        return _key_group->GetOrder();
      }

    private:

      Parameters();

      Parameters(QSharedPointer<const AbstractGroup> key_group, 
          QSharedPointer<const AbstractGroup> msg_group, int n_elements);

      /**
       * The group containing the public keys
       */
      QSharedPointer<const AbstractGroup> _key_group;

      /**
       * The group containing the message elements (plaintexts + ciphertexts)
       */
      QSharedPointer<const AbstractGroup> _msg_group;

      /**
       * Number of ciphertext elements in a single ciphertext
       */
      const int _n_elements;
  };
}
}
}

#endif
