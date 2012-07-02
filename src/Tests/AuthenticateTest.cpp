#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Authenticate, Null) {
    PrivateIdentity client = PrivateIdentity::RandomIdentity();
   
    NullAuthenticate auth_client(client);
    NullAuthenticator auth_leader;

    QVariant m1 = auth_client.PrepareForChallenge();
    QVariant m2 = auth_leader.RequestChallenge(client.GetLocalId(), m1);
    QPair<bool,QVariant> r1 = auth_client.ProcessChallenge(m2);

    EXPECT_TRUE(r1.first);

    QPair<bool,PublicIdentity> r2 = auth_leader.VerifyResponse(client.GetLocalId(), r1.second);
    EXPECT_TRUE(r2.first);
    EXPECT_EQ(r2.second, GetPublicIdentity(client));
  }

  void RosterHelper(const PrivateIdentity &client, const PrivateIdentity &leader,
      const QList<PublicIdentity> &roster) {
    RosterAuthenticate auth_client(client, GetPublicIdentity(leader));
    RosterAuthenticator auth_leader(client, roster);

    QVariant m1 = auth_client.PrepareForChallenge();
    QVariant m2 = auth_leader.RequestChallenge(client.GetLocalId(), m1);
    QPair<bool,QVariant> r1 = auth_client.ProcessChallenge(m2);

    EXPECT_FALSE(r1.first);

    QPair<bool,PublicIdentity> r2 = auth_leader.VerifyResponse(client.GetLocalId(), r1.second);
    EXPECT_FALSE(r2.first);
  }

  TEST(Authenticate, RosterReject) {
    PrivateIdentity client = PrivateIdentity::RandomIdentity();
    PrivateIdentity leader = PrivateIdentity::RandomIdentity();
    
    QList<PublicIdentity> roster;
    for(int i=0; i<50; i++) {
      roster.append(GetPublicIdentity(PrivateIdentity::RandomIdentity())); 
    }

    RosterHelper(client, leader, roster);
  }

  TEST(Authenticate, RosterAccept) {
    PrivateIdentity client = PrivateIdentity::RandomIdentity();
    PrivateIdentity leader = PrivateIdentity::RandomIdentity();
    
    QList<PublicIdentity> roster;
    for(int i=0; i<50; i++) {
      roster.append(GetPublicIdentity(PrivateIdentity::RandomIdentity())); 
    }

    roster[Random::GetInstance().GetInt(0, roster.count())] = GetPublicIdentity(client);

    RosterHelper(client, leader, roster);
  }

}
}
