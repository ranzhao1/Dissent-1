#ifndef DISSENT_CRYPTO_BLOGDROP_PARAMETERS_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PARAMETERS_H_GUARD

#include <QSharedPointer>

#include "Crypto/AbstractGroup/IntegerGroup.hpp"

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
       * Number of group elements in a ciphertext
       */
      static const int ElementsPerCiphertext = 10;

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
       * Constructor that has empty/invalid parameters
       */
      static QSharedPointer<Parameters> Empty();

      /**
       * Destructor
       */
      virtual ~Parameters() {}

      inline QSharedPointer<const AbstractGroup> GetGroup() const { return _group; }

      int GetNElements() const { return _n_elements; }

    private:

      Parameters();

      Parameters(QSharedPointer<const AbstractGroup> group);

      QSharedPointer<const AbstractGroup> _group;

      /**
       * Number of ciphertext elements in a single ciphertext
       */
      const int _n_elements;
  };
}
}
}

#endif
