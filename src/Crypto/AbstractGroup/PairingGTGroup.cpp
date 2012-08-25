
#include <gmp.h>

#include "PairingGTGroup.hpp"
#include "PairingElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  QSharedPointer<PairingGTGroup> PairingGTGroup::ProductionFixed()
  {
    return QSharedPointer<PairingGTGroup>(new PairingGTGroup());
  }

  PairingGTGroup::PairingGTGroup() :
    PairingGroup()
  {
    const unsigned char generatorT_str[] = "generator";

    GT identity(GetPairing(), true);
    Q_ASSERT(identity.isElementPresent());

    // Create generator from hash
    GT generator(GetPairing(), generatorT_str, sizeof(generatorT_str));
    Q_ASSERT(generator.isElementPresent());

    _identity = Element(new PairingElementData<GT>(identity));
    _generator = Element(new PairingElementData<GT>(generator));

    // Curve is y^2 = x^3 + ax + b
    // Group GT for type-A PBC curve has a = 1, b = 0
    Integer gx, gy;
    GetPBCElementCoordinates(_generator, gx, gy);

    Integer p = (-1) % GetFieldSize();
    Integer lhs = (gy*gy)%p;
    Integer rhs = ((gx*gx*gx)+gx)%p;

    qDebug() << "lhs" << lhs.GetByteArray().toHex();
    qDebug() << "rhs" << rhs.GetByteArray().toHex();

    qDebug() << "gx" << gx.GetByteArray().toHex();
    qDebug() << "gy" << gy.GetByteArray().toHex();

    // params: p, q, a, b, gx, gy, is_nist_curve
    _open_curve = OpenECGroup::NewGroup(
        GetFieldSize()*GetFieldSize(), // GT has field size p^2
        GetOrder(), // q = same as G1 and G2
        Integer(1), // a = 1
        Integer(0), // b = 0
        gx, gy,     // generator
        false);     // is not a NIST curve

    Q_ASSERT(_open_curve->IsElement(_open_curve->GetGenerator()));
  }

  PairingGTGroup::~PairingGTGroup() 
  {
  }

  Element PairingGTGroup::Multiply(const Element &a, const Element &b) const
  {
    GT e_a(GetElement(a));
    GT e_b(GetElement(b));

    return Element(new PairingElementData<GT>(e_a * e_b));
  }

  Element PairingGTGroup::Exponentiate(const Element &a, const Integer &exp) const
  { 
    Zr e_exp(IntegerToZr(exp));
    GT e_a(GetElement(a));

    return Element(new PairingElementData<GT>(e_a ^ e_exp));
  }
  
  Element PairingGTGroup::CascadeExponentiate(const Element &a1, const Integer &e1,
      const Element &a2, const Integer &e2) const
  {
    Zr e_exp1(IntegerToZr(e1));
    GT e_a1(GetElement(a1));
    Zr e_exp2(IntegerToZr(e2));
    GT e_a2(GetElement(a2));
    
    return Element(new PairingElementData<GT>((e_a1 ^ e_exp1)*(e_a2 ^ e_exp2)));
  }

  Element PairingGTGroup::Inverse(const Element &a) const
  {
    return Element(new PairingElementData<GT>(GetElement(a).inverse()));
  }
  
  QByteArray PairingGTGroup::ElementToByteArray(const Element &a) const
  {
    std::string s = GetElement(a).toString();
    Q_ASSERT(s.length() > 1);
    return QByteArray(s.c_str(), s.length());
  }
  
  Element PairingGTGroup::ElementFromByteArray(const QByteArray &bytes) const 
  { 
    Q_ASSERT(bytes.count());
    const unsigned char *data = (const unsigned char*)(bytes.constData());
    GT a(_pairing, data, bytes.count(), 16);
    Q_ASSERT(a.isElementPresent());
    return Element(new PairingElementData<GT>(a));
  }

  bool PairingGTGroup::IsIdentity(const Element &a) const 
  {
    return GetElement(a).isIdentity();
  }

  Element PairingGTGroup::RandomElement() const
  {
    return Element(new PairingElementData<GT>(GT(_pairing, false)));
  }

  int PairingGTGroup::BytesPerElement() const
  {
    return _open_curve->BytesPerElement();
  }

  Element PairingGTGroup::EncodeBytes(const QByteArray &bytes) const
  {
    // a is an OpenEC element
    Element a = _open_curve->EncodeBytes(bytes);

    // get coordinates of OpenEC point
    Integer x, y;
    _open_curve->GetCoordinates(a, x, y);

    // convert into string "[x, y]" in base 16
    QByteArray b;
    b.append("[");
    b.append(x.GetByteArray().toHex());
    b.append(",");
    b.append(y.GetByteArray().toHex());
    b.append("]");

    qDebug() << "gt" << b;
    GT gt(_pairing, (const unsigned char*)b.constData(), b.count(), 16);
    return Element(new PairingElementData<GT>(gt));
  }
 
  bool PairingGTGroup::DecodeBytes(const Element &a, QByteArray &bytes) const
  {
    // Get coordinates of PBC point
    Integer x, y;
    GetPBCElementCoordinates(a, x, y);

    // Convert into OpenSSL
    Element e = _open_curve->ElementFromCoordinates(x, y);

    // Decode bytes
    return _open_curve->DecodeBytes(e, bytes);
  }

  void PairingGTGroup::GetPBCElementCoordinates(const Element &a, 
      Integer &x_out, Integer &y_out) const
  {
    // Maxlen = 32 kb
    const int maxlen = 1024*32;
    GT e(GetElement(a));

    QByteArray bytes(maxlen, 0);
    int ret = e.dump(bytes.data(), bytes.count());

    qDebug() << "bytes" << bytes;

    if(ret >= maxlen) {
      qFatal("Failed to print an oversized element");
    }

    mpz_t x;
    mpz_t y;

    mpz_init(x);
    mpz_init(y);

    // bytes now holds base-10 pair [x, y]
    if(gmp_sscanf(bytes.data(), "[%Zd, %Zd]", x, y) != 2) 
      qFatal("Could not read integers");

    QByteArray hex_x(maxlen, 0);
    QByteArray hex_y(maxlen, 0);

    // base 10 --> hex
    if((ret = gmp_snprintf(hex_x.data(), hex_x.count(), "%Zx", x)) >= maxlen) 
      qFatal("Could not convert x to hex");
    hex_x = hex_x.left(ret);

    if((ret = gmp_snprintf(hex_y.data(), hex_y.count(), "%Zx", y)) >= maxlen) 
      qFatal("Could not convert y to hex");
    hex_y = hex_y.left(ret);

    Q_ASSERT(hex_x != hex_y);

    x_out = Integer(QByteArray::fromHex(hex_x));
    y_out = Integer(QByteArray::fromHex(hex_y));

    mpz_clear(x);
    mpz_clear(y);
  }

}
}
}
