
#include "PairingElementData.hpp"
#include "PairingGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {
   const char PairingGroup::_param_bytes[] = "type a\n"
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

  const char PairingGroup::_order_bytes[] = 
            "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffff00000001";

  PairingGroup::PairingGroup() :
    _param_str(QByteArray(_param_bytes)),
    _pairing(_param_str.constData(), _param_str.count()),
    _order(Integer(QByteArray::fromHex(_order_bytes)))
  {
    Q_ASSERT(_pairing.isPairingPresent());

    // convert base 10 into base 16

  /*
    const unsigned char generatorT_str[] = 
          "[795021851328020033538485063506889346340348790473894916238866664663"
          "9150616295447802746802629878913026197716951475548418491838118674043"
          "19363059257332521718605, 678205493899729155525770728889429548658760"
          "4094995139744601370103366002392787037597944280636791426667700330308"
          "27851052673787698901892811486811655628074359316]";
*/
  };

  Integer PairingGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(1, GetOrder(), false); 
  }

}
}
}
