#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "BulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {
  TEST(BlogDropRound, NullFixed)
  {
    RoundTest_Null(SessionCreator(TCreateRound<BlogDropRound>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRound, BasicFixed)
  {
    RoundTest_Basic(SessionCreator(TCreateRound<BlogDropRound>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRound, MultiRoundFixed)
  {
    RoundTest_MultiRound(SessionCreator(TCreateRound<BlogDropRound>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRound, AddOne)
  {
    RoundTest_AddOne(SessionCreator(TCreateRound<BlogDropRound>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRound, PeerDisconnectEndFixed)
  {
    RoundTest_PeerDisconnectEnd(SessionCreator(TCreateRound<BlogDropRound>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRound, PeerDisconnectMiddleFixed)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateRound<BlogDropRound>),
        Group::ManagedSubgroup);
  }

}
}
