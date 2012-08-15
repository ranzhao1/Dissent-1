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
      typedef Dissent::Crypto::AbstractGroup::IntegerGroup IntegerGroup;
      typedef Dissent::Crypto::AbstractGroup::Element Element;

      /** 
       * Number of group elements in a ciphertext
       */
      static const int ElementsPerCiphertext = 1;

      /**
       * Constructor that uses small integer parameters for testing
       */
      static QSharedPointer<Parameters> IntegerTestingFixed();

      /**
       * Constructor that uses fixed parameters
       */
      static QSharedPointer<Parameters> IntegerProductionFixed();
      
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
