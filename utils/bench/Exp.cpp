#include <QDateTime>
#include <cryptopp/nbtheory.h>
#include "Benchmark.hpp"

namespace Dissent {
namespace Benchmarks {

  // Cycle through integer types
  TEST(Exp, VarySubgroup) {
    const int pbits = 2048;

    for(int qbits = 160; qbits<pbits; qbits+=64) {
      // Generate prime
      CryptoPP::AutoSeededX917RNG<CryptoPP::AES> rng(false, true);
      CryptoPP::PrimeAndGenerator pand(1, rng, pbits, qbits);

      const CryptoPP::Integer two(2);

      double total = 0.0f;
      // Do 1000 exps
      for(int i=0; i<1000; i++) {
        CryptoPP::Integer v = a_exp_b_mod_c(
            pand.Generator(),
            CryptoPP::Integer(rng, two, pand.SubPrime(), CryptoPP::Integer::ANY),
            pand.Prime());
        CryptoPP::Integer e(rng, two, pand.SubPrime(), CryptoPP::Integer::ANY);

        double start = QDateTime::currentMSecsSinceEpoch();
        CryptoPP::Integer r = a_exp_b_mod_c(v, e, pand.Prime());
        double end = QDateTime::currentMSecsSinceEpoch();

        total += (end-start);
      }

      qDebug() << qbits << total;

    }
  }

  TEST(Exp, VaryEC) {
    for(int i=0; i<ECParams::INVALID; i++) {
      QSharedPointer<OpenECGroup> g = OpenECGroup::GetGroup((ECParams::CurveName)i);

      int total = 0;

      for(int i=0; i<1000; i++) {
        Element v = g->RandomElement();
        Integer e = g->RandomExponent();
        int start = QDateTime::currentMSecsSinceEpoch();
        Element r = g->Exponentiate(v, e);
        int end = QDateTime::currentMSecsSinceEpoch();

        total += (end-start);
      }

      qDebug() << g->GetSecurityParameter() << total;
    }
  }

  TEST(Exp, VaryPairing) {
    QSharedPointer<PairingG1Group> g1 = PairingG1Group::GetGroup(PairingGroup::PRODUCTION_512);
    QSharedPointer<PairingGTGroup> gT = PairingGTGroup::GetGroup(PairingGroup::PRODUCTION_512);

    int total = 0;

    for(int i=0; i<1000; i++) {
      Element p = g1->RandomElement();
      Element q = g1->RandomElement();
      int start = QDateTime::currentMSecsSinceEpoch();
      Element r = gT->ApplyPairing(p, q);
      int end = QDateTime::currentMSecsSinceEpoch();

      total += (end-start);
    }
    qDebug() << gT->GetSecurityParameter() << total;

  }

}
}
