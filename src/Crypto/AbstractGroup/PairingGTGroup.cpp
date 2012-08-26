
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
    GT a(_pairing, data, bytes.count(), 16, true);
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
    return (_field.GetByteArray().count() - 3)*2;
  }

  Element PairingGTGroup::EncodeBytes(const QByteArray &bytes) const
  {
    if(bytes.count() > BytesPerElement())
      qFatal("String is too long");

    const int bytes_per = _field.GetByteArray().count() - 2;
    QByteArray left = bytes.left(bytes_per);
    QByteArray right = bytes.mid(bytes_per);

    const QByteArray pad(1, 0xff);
    Integer x(pad+left+pad);
    Integer y(pad+right+pad);

    Element e;
    // convert into string "[x, y]" in base 16
    QByteArray b;
    b.append("[");
    b.append(x.GetByteArray().toHex());
    b.append(",");
    b.append(y.GetByteArray().toHex());
    b.append("]");

    qDebug() << "gt" << b;

    GT gt(_pairing, (const unsigned char*)b.constData(), b.count(), 16, false);

    e = Element(new PairingElementData<GT>(gt));
    GetElement(Exponentiate(e, GetOrder())).dump(stdout, "e", 10);

    Q_ASSERT((Exponentiate(e, GetOrder())) == GetIdentity());

    return e;
  }
 
  bool PairingGTGroup::DecodeBytes(const Element &a, QByteArray &bytes) const
  {
    bytes.clear();
    // Get coordinates of PBC point
    Integer x, y;
    GetPBCElementCoordinates(a, x, y);

    // Decode bytes
    QByteArray xbytes = x.GetByteArray();
    QByteArray ybytes = y.GetByteArray();

    const int xc = xbytes.count();
    const int yc = ybytes.count();
    if(xc < 2) return false;
    if(yc < 2) return false;

    const unsigned char pad = 0xff;
    const unsigned char x0 = xbytes[0], xl = xbytes[xc-1];
    const unsigned char y0 = ybytes[0], yl = ybytes[yc-1];

    if(x0 != pad || y0 != pad || xl != pad || yl != pad) {
      qWarning() << "Improper padding" << xbytes.toHex() << ybytes.toHex();
      return false; 
    }

    // Remove leading and trailing pads
    xbytes = xbytes.left(xc-1).mid(1);
    ybytes = ybytes.left(yc-1).mid(1);

    qDebug() << "out" << xbytes.toHex() << ybytes.toHex();
    bytes = (xbytes + bytes);
    return true;
  }

  void PairingGTGroup::GetPBCElementCoordinates(const Element &a, 
      Integer &x_out, Integer &y_out) const
  {
    // Maxlen = 32 kb
    const int maxlen = 1024*32;
    GT e(GetElement(a));

    QByteArray bytes(maxlen, 0);
    // bytes now holds base-10 pair [x, y]
    int ret = e.dump(bytes.data(), bytes.count());

    qDebug() << "bytes" << bytes;

    if(ret >= maxlen) {
      qFatal("Failed to print an oversized element");
    }

    mpz_t x;
    mpz_t y;

    mpz_init(x);
    mpz_init(y);

    // Read base-10 digits into integers x, y
    if(gmp_sscanf(bytes.data(), "[%Zd, %Zd]", x, y) != 2) 
      qFatal("Could not read integers");

    QByteArray hex_x(maxlen, 0);
    QByteArray hex_y(maxlen, 0);

    // write the integers out in hex
    if((ret = gmp_snprintf(hex_x.data(), hex_x.count(), "%Zx", x)) >= maxlen) 
      qFatal("Could not convert x to hex");
    hex_x = hex_x.left(ret);

    if((ret = gmp_snprintf(hex_y.data(), hex_y.count(), "%Zx", y)) >= maxlen) 
      qFatal("Could not convert y to hex");
    hex_y = hex_y.left(ret);

    x_out = Integer("0x"+hex_x);
    y_out = Integer("0x"+hex_y);

    mpz_clear(x);
    mpz_clear(y);
  }

}
}
}
