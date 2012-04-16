#include "DissentTest.hpp"

#include <QStringList>

namespace Dissent {
namespace Tests {
  TEST(Settings, Basic)
  {
    Id id;

    QStringList args; 
    args << "./dissent" << "dissent.ini";

    QFile file("dissent.ini");
    file.remove();

    Settings settings(args, false);
    EXPECT_EQ(settings.LocalEndPoints.count(), 0);
    EXPECT_EQ(settings.RemotePeers.count(), 0);
    settings.LocalEndPoints.append(QUrl("buffer://5"));
    settings.RemotePeers.append(QUrl("buffer://6"));
    settings.LocalId = id;
    settings.Save();

    Settings settings0(args, false);
    EXPECT_EQ(settings0.LocalEndPoints.count(), 1);
    EXPECT_EQ(settings0.RemotePeers.count(), 1);
    EXPECT_EQ(settings0.LocalEndPoints[0], QUrl("buffer://5"));
    EXPECT_EQ(settings0.RemotePeers[0], QUrl("buffer://6"));
    settings0.LocalEndPoints.append(QUrl("buffer://7"));
    settings0.RemotePeers.append(QUrl("buffer://8"));
    settings0.Save();

    Settings settings1(args, false);
    EXPECT_EQ(settings0.LocalEndPoints.count(), 2);
    EXPECT_EQ(settings0.RemotePeers.count(), 2);
    EXPECT_EQ(settings0.LocalEndPoints[0], QUrl("buffer://5"));
    EXPECT_EQ(settings0.LocalEndPoints[1], QUrl("buffer://7"));
    EXPECT_EQ(settings0.RemotePeers[0], QUrl("buffer://6"));
    EXPECT_EQ(settings0.RemotePeers[1], QUrl("buffer://8"));
    EXPECT_EQ(id, settings1.LocalId);
  }

  TEST(Settings, Invalid)
  {
    Settings settings;
    EXPECT_FALSE(settings.IsValid());

    settings.LocalEndPoints.append(QUrl("buffer://5"));
    EXPECT_FALSE(settings.IsValid());

    settings.LeaderId = Id();
    EXPECT_TRUE(settings.IsValid());

    settings.SubgroupPolicy = static_cast<Group::SubgroupPolicy>(-1);
    EXPECT_FALSE(settings.IsValid());

    settings.SubgroupPolicy = Group::CompleteGroup;
    EXPECT_TRUE(settings.IsValid());
  }

  TEST(Settings, WebServer)
  {
    Settings settings;
    settings.LocalEndPoints.append(QUrl("buffer://5"));
    settings.LeaderId = Id();
    EXPECT_TRUE(settings.IsValid());

    settings.Mode = Settings::Mode_WebServer;

    settings.WebServerUrl = "xyz://127.1.34.1:-y";
    EXPECT_FALSE(settings.IsValid());

    settings.WebServerUrl = "xyz://127.1.34.1:8080";
    EXPECT_TRUE(settings.IsValid());

    settings.WebServerUrl = "http://127.1.34.1:-1";
    EXPECT_FALSE(settings.IsValid());

    settings.WebServerUrl = "http://127.1.34.1:8888";
    EXPECT_TRUE(settings.IsValid());
  }

  TEST(Settings, CommandLine)
  {
    Id id;

    QStringList args; 
    args << "/path/to/dissent" 
      << "--mode=console" 
      << "--endpoints=tcp://1234" 
      << "--mode=local_tunnel"
      << "--mode=web_server"
      << "--mode=console"
      << "--web_server_url=http://www.google.com/"
      << "dissent.ini";

    QFile file("dissent.ini");
    file.remove();

    Settings settings(args, false);
    EXPECT_EQ(1, settings.LocalEndPoints.count());
    EXPECT_EQ(0, settings.RemotePeers.count());
    EXPECT_EQ(Settings::Mode_Console, settings.Mode);
    EXPECT_EQ(QUrl("http://www.google.com/"), settings.WebServerUrl);
    settings.LocalEndPoints.append(QUrl("buffer://5"));
    settings.RemotePeers.append(QUrl("buffer://6"));
    settings.LocalId = id;
    settings.Save();
  }

}
}
