
#include <gmp.h>

#include "PairingElementData.hpp"
#include "PairingGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  QSharedPointer<PairingGroup> PairingGroup::Create(PairingElementType type)
  {
    const char param_str[] = "type a\n"
          "q 80446847579655582597444149989235076764876194923554360266341368662"
          "3305841804412818608112457890014205661401911491189163051225232968716"
          "794196786018682667008059\n"
          "h 60\n"
          "r 13407807929942597099574024998205846127479365820592393377723561443"
          "7217640300735469768018742981669034276900318581864860508537538828119"
          "46569946433644711116801\n"
          "exp2 512\n"
          "exp1 32\n"
          "sign1 -1\n"
          "sign0 1\n";
    return QSharedPointer<PairingGroup>(
        new PairingGroup(reinterpret_cast<const char*>(param_str), sizeof(param_str), type));
  }

  PairingGroup::PairingGroup(const char *param_str, int param_len, PairingElementType type) :
    _pairing(param_str, param_len),
    _type(type)
  { 
    const unsigned char generator1_str[] = 
          "[538712375173038183821555581631853844285352387919914453116399420454"
          "1137376522971355408731240080050842503736842668416236973599378729596"
          "02509687274080553103856, 340137139421134791414450797594868030166258"
          "5402549525116042526277980403076798915406057822392822856542520552755"
          "4751130920668111433102590008400638591817819442]";
    const unsigned char generatorT_str[] = 
          "[795021851328020033538485063506889346340348790473894916238866664663"
          "9150616295447802746802629878913026197716951475548418491838118674043"
          "19363059257332521718605, 678205493899729155525770728889429548658760"
          "4094995139744601370103366002392787037597944280636791426667700330308"
          "27851052673787698901892811486811655628074359316]";

    // Read parameters
    _param_str = QByteArray(param_str);

    if(_type == Type_GT) {
      _identity = Element(new PairingElementData(QSharedPointer<GT>(new GT(_pairing, true))));
      _generator = Element(new PairingElementData(QSharedPointer<GT>(
              new GT(_pairing, generatorT_str, sizeof(generatorT_str), 10))));
    } else {
      _identity = Element(new PairingElementData(QSharedPointer<G1>(new G1(_pairing, true))));
      _identity = Element(new PairingElementData(QSharedPointer<G1>(
              new G1(_pairing, generator1_str, sizeof(generator1_str), 10))));
    }
    _order = Integer(QByteArray("134078079299425970995740249982058461274793658205923933777235614437217"
                     "64030073546976801874298166903427690031858186486050853753882811946569946"
                     "433644711116801"));
  };

  PairingGroup::~PairingGroup() {}

  QSharedPointer<PairingGroup> PairingGroup::ProductionG1Fixed() 
  {
    return PairingGroup::Create(Type_G1);
  }

  QSharedPointer<PairingGroup> PairingGroup::ProductionGTFixed() 
  {
    return PairingGroup::Create(Type_GT);
  }

  Element PairingGroup::Multiply(const Element &a, const Element &b) const
  {
    QSharedPointer<G> e_a = GetElement(a);
    QSharedPointer<G> e_b = GetElement(b);

    QSharedPointer<G> out(new G((*e_a) * (*e_b)));

    return Element(new PairingElementData(out));
  }

  Element PairingGroup::Exponentiate(const Element &a, const Integer &exp) const
  {
    element_t e_a;
    GetElement(e_a, a);

    mpz_t exponent;
    mpz_init(exponent);
    IntegerToMpz(exponent, exp);

    element_t out;
    InitElement(out);

    element_pow_mpz(out, e_a, exponent);
    mpz_clear(exponent);

    return Element(new PairingElementData(out));
  }
  
  Element PairingGroup::CascadeExponentiate(const Element &a1, const Integer &e1,
      const Element &a2, const Integer &e2) const
  {
    element_t e_a1, e_a2;
    GetElement(e_a1, a1);
    GetElement(e_a2, a2);

    mpz_t exp1, exp2;
    mpz_init(exp1);
    mpz_init(exp2);
    IntegerToMpz(exp1, e1);
    IntegerToMpz(exp2, e2);

    element_t out;
    InitElement(out);

    element_pow2_mpz(out, e_a1, exp1, e_a2, exp2);
    mpz_clear(exp1);
    mpz_clear(exp2);

    return Element(new PairingElementData(out));
  }

  Element PairingGroup::Inverse(const Element &a) const
  {
    element_t e_a;
    GetElement(e_a, a);

    element_t out;
    InitElement(out);

    element_invert(out, e_a);

    return Element(new PairingElementData(out));
  }
  
  QByteArray PairingGroup::ElementToByteArray(const Element &a) const
  {
    element_t e_a;
    GetElement(e_a, a);

    const unsigned int nbytes = element_length_in_bytes(e_a);
    QByteArray out(nbytes, 0);
    element_to_bytes(reinterpret_cast<unsigned char*>(out.data()), e_a);
    return out;
  }
  
  Element PairingGroup::ElementFromByteArray(const QByteArray &bytes) const 
  { 
    element_t a;
    InitElement(a);

    QByteArray copy = bytes;
    element_from_bytes(a, reinterpret_cast<unsigned char*>(copy.data()));
    return Element(new PairingElementData(a));
  }

  bool PairingGroup::IsElement(const Element &) const 
  {
    // Doesn't work in pairing groups
    return true;
  }

  bool PairingGroup::IsIdentity(const Element &a) const 
  {
    element_t e_a;
    GetElement(e_a, a);
    return element_is1(e_a);
  }

  Integer PairingGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(1, GetOrder(), false); 
  }

  Element PairingGroup::RandomElement() const
  {
    element_t a;
    InitElement(a);
    element_random(a);
    return Element(new PairingElementData(a));
  }

  int PairingGroup::BytesPerElement() const
  {
    element_t a;
    GetElement(a, _generator);
    return element_length_in_bytes(a);
  }

  Element PairingGroup::EncodeBytes(const QByteArray &) const
  {
    return Element(new PairingElementData(NULL));
  }
 
  bool PairingGroup::DecodeBytes(const Element &, QByteArray &) const
  {
    return false;
  }

  bool PairingGroup::IsProbablyValid() const
  {
    // Can't check in pairing group
    return true;
  }

  QByteArray PairingGroup::GetByteArray() const
  {
    return _param_str;
  }

  void PairingGroup::InitElement(element_t e) const
  {
    pairing_s* unconst = const_cast<pairing_s*>(_pairing);
    Q_ASSERT(unconst);

    switch(_type) {
      case GROUP_G1:
        element_init_G1(e, unconst);
        return;
      case GROUP_G2:
        element_init_G2(e, unconst);
        return;
      case GROUP_GT:
        element_init_GT(e, unconst);
        return;
      default:
        qFatal("Unknown group type");
    }
  }

  void PairingGroup::IntegerToMpz(mpz_t out, const Integer &in) const
  {
    if(gmp_sscanf("%x", in.GetByteArray().toHex().constData(), out) != 1)
      qFatal("Could not convert integer");
  }

}
}
}
