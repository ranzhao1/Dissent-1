#ifndef DISSENT_APPLICATIONS_SETTINGS_H_GUARD
#define DISSENT_APPLICATIONS_SETTINGS_H_GUARD

#include <QtCore>
#include <QDebug>
#include <QHostAddress>
#include <QSettings>
#include <QStringList>

#include "Connections/Id.hpp"
#include "Identity/Group.hpp"

namespace Dissent {
namespace Applications {

  /**
   * Abstracts interaction with a configuration file
   */
  class Settings {
    public:
      typedef Connections::Id Id;
      typedef Identity::Group Group;

      /**
       * Setting parameter name strings
       */
      static const char* ParamNameMode;
      static const char* ParamNameRemotePeers;
      static const char* ParamNameEndpoints;
      static const char* ParamNameDemoMode;
      static const char* ParamNameLocalNodes;
      static const char* ParamNameSessionType;
      static const char* ParamNameSubgroupPolicy;
      static const char* ParamNameLog;
      static const char* ParamNameMultithreading;
      static const char* ParamNameLocalId;
      static const char* ParamNameLeaderId;
      static const char* ParamNameWebServerUrl;
      static const char* ParamNameEntryTunnelUrl;
      static const char* ParamNameSuperPeer;

      static const char* StringMode_Null;
      static const char* StringMode_Console;
      static const char* StringMode_WebServer;
      static const char* StringMode_EntryTunnel;
      static const char* StringMode_ExitTunnel;

      /**
       * Node operation mode
       */
      typedef enum {
        Mode_Null,
        Mode_Console,
        Mode_WebServer,
        Mode_EntryTunnel,
        Mode_ExitTunnel
      } ApplicationMode;


      /**
       * Mode strings
       */
      static const char* ParamNameMode_Console;
      static const char* ParamNameMode_WebServer;
      static const char* ParamNameMode_EntryTunnel;
      static const char* ParamNameMode_ExitTunnel;

      /**
       * Load configuration from disk and command line args.
       * The argument list should look like this:
       *    ./dissent-binary [flags] config_file
       * Or for example:
       *    ./dissent --console=true --web_server=false conf/myconfig.conf
       *
       * Command line arguments override settings given in the config
       * file to allow for easier scripting. Command line arguments
       * can be repeated, with the last argument taking precedence.
       * There must be a configuration file specified.
       *
       * @param command line arguments
       * @param actions whether or not the settings file should change system
       * configuration values or just be a container for configuration data,
       * the default (true) is the latter.
       */
      explicit Settings(const QStringList &arguments, bool actions = true);

      /**
       * Create configuration in memory
       */
      explicit Settings();

      /**
       * Store the configuration data back to the file
       */
      void Save();

      /**
       * True if the configuration file represents a valid configuration
       */
      bool IsValid();

      /**
       * If the configuration file is invalid, returns the reason why
       */
      QString GetError();

      /**
       * List of bootstrap peers
       */
      QList<QUrl> RemotePeers;
      
      /**
       * List of local urls to construct EdgeListeners from
       */
      QList<QUrl> LocalEndPoints;

      /**
       * The amount of nodes required before constructing an anonymity session
       */
      int GroupSize;

      /**
       * Amount of nodes to create locally
       */
      int LocalNodeCount;

      /**
       * Enable demo mode for evaluation / demo purposes
       */
      bool DemoMode;

      /**
       * The type of anonymity session / round to construct
       */
      QString SessionType;

      /**
       * Logging type: stderr, stdout, file, or empty (disabled)
       */
      QString Log;

      /**
       * What type of interface to run
       */
      ApplicationMode Mode;

      /**
       * IP:Port on which the HTTP server should listen
       */
      QUrl WebServerUrl;

      /**
       * Provide a IP Tunnel Entry point
       */
      bool EntryTunnel;

      /**
       * IP:Port on which the Tunnel Entry point will run
       */
      QUrl EntryTunnelUrl;

      /**
       * Provide a IP Tunnel Exit point
       */
      bool ExitTunnel;

      /**
       * Enable multhreaded operations
       */
      bool Multithreading;

      /**
       * Is a super peer
       */
      bool SuperPeer;

      /**
       * The id for the (first) local node, other nodes will be random
       */
      Id LocalId;

      /**
       * The id for the anonymity group's leader
       */
      Id LeaderId;

      /**
       * The subgroup policy employed at this node
       */
      Group::SubgroupPolicy SubgroupPolicy;


    private:
      void Init();
      void ApplySettings(const QSettings &settings);
      void ParseUrlType(const QSettings &settings, 
          const QString &param_name, const QString &scheme, QUrl &target);
      void ParseUrlList(const QString &name, const QVariant &values, QList<QUrl> &list);
      void ParseUrl(const QString &name, const QVariant &value, QList<QUrl> &list);
      QUrl TryParseUrl(const QString &string_rep, const QString &scheme);

      bool _actions;
      bool _use_file;
      bool _args_valid;
      QSettings _settings;
      QSettings _settings_flags;
      QString _reason;
  };
}
}

#endif
