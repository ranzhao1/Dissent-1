#include "Utils/Logging.hpp"

#include "Settings.hpp"

using Dissent::Utils::Logging;

namespace Dissent {
namespace Applications {
  
  const char* Settings::ParamNameMode = "mode";
  const char* Settings::ParamNameRemotePeers = "remote_peers";
  const char* Settings::ParamNameEndpoints = "endpoints";
  const char* Settings::ParamNameDemoMode = "demo_mode";
  const char* Settings::ParamNameLocalNodes = "local_nodes";
  const char* Settings::ParamNameSessionType = "session_type";
  const char* Settings::ParamNameSubgroupPolicy = "subgroup_policy";
  const char* Settings::ParamNameLog = "log";
  const char* Settings::ParamNameMultithreading = "multithreading";
  const char* Settings::ParamNameLocalId = "local_id";
  const char* Settings::ParamNameLeaderId = "leader_id";
  const char* Settings::ParamNameWebServerUrl = "web_server_url";
  const char* Settings::ParamNameEntryTunnelUrl = "entry_tunnel_url";
  const char* Settings::ParamNameSuperPeer = "super_peer";

  const char* Settings::StringMode_Null = "null";
  const char* Settings::StringMode_Console = "console";
  const char* Settings::StringMode_WebServer = "web_server";
  const char* Settings::StringMode_EntryTunnel = "entry_tunnel";
  const char* Settings::StringMode_ExitTunnel = "exit_tunnel";

  Settings::Settings(const QStringList &args, bool actions) :
    LocalId(Id::Zero()),
    LeaderId(Id::Zero()),
    SubgroupPolicy(Group::CompleteGroup),
    _actions(actions),
    _use_file(true),
    _args_valid(true),
    _settings(args[args.count()-1], QSettings::IniFormat),
    _reason()
  {
    QStringList valid_flags;
    valid_flags 
      << ParamNameMode 
      << ParamNameRemotePeers << ParamNameEndpoints << ParamNameDemoMode << ParamNameLocalNodes 
      << ParamNameSessionType << ParamNameSubgroupPolicy << ParamNameLog 
      << ParamNameMultithreading << ParamNameLocalId << ParamNameLeaderId 
      << ParamNameWebServerUrl << ParamNameEntryTunnelUrl << ParamNameSuperPeer;

    Init();

    if(args.count() < 2) {
      _args_valid = false;
      _reason = "Settings must be initialized with at least two arguments";
      return;
    }

    _settings_flags.clear();
    for(int i = 1; i < (args.count()-1); i++) {
      // Flags are of format --key=value
      const QString flag = QString(args[i]);
      const int equals_idx = flag.indexOf("=");
      if(equals_idx < 2) {
        _args_valid = false;
        _reason = QString("Invalid command line flag: %1").arg(flag);
        break;
      }

      const QString key = flag.mid(2, equals_idx-2);
      if(!(flag.count() > equals_idx)) {
        _args_valid = false;
        _reason = QString("Invalid command line flag: %1").arg(flag);
        break;
      }

      const QString value = flag.mid(equals_idx+1);

      if(!flag.startsWith("--") || !(flag.count() > 2) || !key.count() || !value.count()) {
        _args_valid = false;
        _reason = QString("Invalid command line flag: %1").arg(flag);
        break;
      }

      if(!valid_flags.contains(key)) {
        _args_valid = false;
        _reason = QString("Unknown command line argument: %1").arg(key);
        break;
      }

      _settings_flags.setValue(key, value);
    }

    ApplySettings(_settings);
    ApplySettings(_settings_flags);
  }

  void Settings::ApplySettings(const QSettings& settings) 
  {
    if(settings.contains(ParamNameMode)) {
      QString str = settings.value(ParamNameMode).toString();
      if(str == StringMode_Null) {
        Mode = Mode_Null;
      } else if(str == StringMode_Console) {
        Mode = Mode_Console;
      } else if(str == StringMode_WebServer) {
        Mode = Mode_WebServer;
      } else if(str == StringMode_EntryTunnel) {
        Mode = Mode_EntryTunnel;
      } else if(str == StringMode_ExitTunnel) {
        Mode = Mode_ExitTunnel;
      } else {
        _args_valid = false;
        _reason = QString("Invalid mode: %1").arg(str);
        return;
      }
    }

    if(settings.contains(ParamNameRemotePeers)) {
      QVariant peers = settings.value(ParamNameRemotePeers);
      ParseUrlList("RemotePeer", peers, RemotePeers);
    }

    if(settings.contains(ParamNameEndpoints)) {
      QVariant endpoints = settings.value(ParamNameEndpoints);
      ParseUrlList("EndPoint", endpoints, LocalEndPoints);
    }

    if(settings.contains(ParamNameLocalNodes)) {
      LocalNodeCount = settings.value(ParamNameLocalNodes).toInt();
    }

    ParseUrlType(settings, ParamNameWebServerUrl, "http", WebServerUrl);

    if(settings.contains(ParamNameSessionType)) {
      SessionType = settings.value(ParamNameSessionType).toString();
    }

    if(settings.contains(ParamNameSubgroupPolicy)) {
      QString ptype = settings.value(ParamNameSubgroupPolicy).toString();
      SubgroupPolicy = Group::StringToPolicyType(ptype);
    }

    if(settings.contains(ParamNameLog)) {
      Log = settings.value(ParamNameLog).toString();
      QString lower = Log.toLower();

      if(_actions) {
        if(lower == "stderr") {
          Logging::UseStderr();
        } else if(lower == "stdout") {
          Logging::UseStdout();
        } else if(Log.isEmpty()) {
          Logging::Disable();
        } else {
          Logging::UseFile(Log);
        }
      }
    }

    if(settings.contains(ParamNameDemoMode)) {
      DemoMode = settings.value(ParamNameDemoMode).toBool();
    }

    if(settings.contains(ParamNameMultithreading)) {
      Multithreading = settings.value(ParamNameMultithreading).toBool();
    }

    if(settings.contains(ParamNameLocalId)) {
      LocalId = Id(settings.value(ParamNameLocalId).toString());
    }

    if(settings.contains(ParamNameLeaderId)) {
      LeaderId = Id(settings.value(ParamNameLeaderId).toString());
    }

    if(settings.contains(ParamNameSuperPeer)) {
      SuperPeer = settings.value(ParamNameSuperPeer).toBool();
    }
    ParseUrlType(settings, ParamNameEntryTunnelUrl, "tcp", EntryTunnelUrl);
  }

  Settings::Settings() :
    LocalId(Id::Zero()),
    LeaderId(Id::Zero()),
    SubgroupPolicy(Group::CompleteGroup),
    _use_file(false),
    _args_valid(true)
  {
    Init();
  }

  void Settings::Init()
  {
    LocalNodeCount = 1;
    SessionType = "null";
    Mode = Mode_Null;
  }

  bool Settings::IsValid()
  {
    if(!_args_valid) return false;

    if(_use_file && (_settings.status() != QSettings::NoError)) {
      _reason = "File error";
      return false;
    }

    if(LocalEndPoints.count() == 0) {
      _reason = "No locally defined end points";
      return false;
    }

    if((Mode == Mode_WebServer) && !WebServerUrl.isValid()) {
      _reason = "Invalid WebServerUrl";
      return false;
    }

    if((Mode == Mode_EntryTunnel) && !EntryTunnelUrl.isValid()) {
      _reason = "Invalid EntryTunnelUrl";
      return false;
    }

    if(LeaderId == Id::Zero()) {
      qWarning() << "HERE?" << LeaderId.ToString();
      _reason = "No leader Id";
      return false;
    }

    if(SubgroupPolicy == -1) {
      qWarning() << "HERE?!" << SubgroupPolicy;
      _reason = "Invalid subgroup policy";
      return false;
    }

    return true;
  }

  QString Settings::GetError()
  {
    IsValid();
    return _reason;
  }

  void Settings::ParseUrlType(const QSettings &settings, 
      const QString &param_name, const QString &scheme, QUrl &target)
  {
    if(settings.contains(param_name)) {
      QString url = settings.value(param_name).toString();
      target = QUrl(url);
      if(target.toString() != url) {
        target = QUrl();
      }

      QString s = target.scheme();
      if(s != scheme) {
        target = QUrl();
      }
    }
  }

  void Settings::ParseUrlList(const QString &name, const QVariant &values,
          QList<QUrl> &list)
  {
    if(values.isNull()) {
      return;
    }

    QVariantList varlist = values.toList();
    if(!varlist.empty()) {
      foreach(QVariant value, varlist) {
        ParseUrl(name, value, list);
      }
    } else {
      ParseUrl(name, values, list);
    }
  }

  inline void Settings::ParseUrl(const QString &name, const QVariant &value,
          QList<QUrl> &list)
  {
    QUrl url(value.toString());
    if(url.isValid()) {
      list << url;
    } else {
      qCritical() << "Invalid " << name << ": " << value.toString();
    }
  }

  QUrl Settings::TryParseUrl(const QString &string_rep, const QString &scheme)
  {
    QUrl url = QUrl(string_rep);
    if(url.toString() != string_rep) {
      return QUrl();
    }

    if(url.scheme() != scheme) {
      return QUrl();
    }
    return url;
  }

  void Settings::Save()
  {
    if(!_use_file) {
      return;
    }

    QStringList peers;
    foreach(QUrl peer, RemotePeers) {
      peers << peer.toString();
    }

    if(!peers.empty()) {
      _settings.setValue(ParamNameRemotePeers, peers);
    }

    QStringList endpoints;
    foreach(QUrl endpoint, LocalEndPoints) {
      endpoints << endpoint.toString();
    }

    if(!endpoints.empty()) {
      _settings.setValue(ParamNameEndpoints, endpoints);
    }

    QString mstr;
    switch(Mode) {
      case Mode_Null: 
        mstr = StringMode_Null;
        break;
      case Mode_Console: 
        mstr = StringMode_Console;
        break;
      case Mode_WebServer:
        mstr = StringMode_WebServer;
        break;
      case Mode_EntryTunnel:
        mstr = StringMode_EntryTunnel;
        break;
      case Mode_ExitTunnel:
        mstr = StringMode_ExitTunnel;
        break;
    }
    _settings.setValue(ParamNameMode, mstr);

    _settings.setValue(ParamNameLocalNodes, LocalNodeCount);
    _settings.setValue(ParamNameWebServerUrl, WebServerUrl);
    _settings.setValue(ParamNameDemoMode, DemoMode);
    _settings.setValue(ParamNameLog, Log);
    _settings.setValue(ParamNameMultithreading, Multithreading);
    _settings.setValue(ParamNameLocalId, LocalId.ToString());
    _settings.setValue(ParamNameLeaderId, LeaderId.ToString());
    _settings.setValue(ParamNameSubgroupPolicy,
        Group::PolicyTypeToString(SubgroupPolicy));
  }
}
}
