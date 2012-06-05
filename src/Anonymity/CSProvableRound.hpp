#ifndef DISSENT_ANONYMITY_CS_PROVABLE_ROUND_H_GUARD
#define DISSENT_ANONYMITY_CS_PROVABLE_ROUND_H_GUARD

#include <QMetaEnum>

#include "Utils/TimerEvent.hpp"
#include "RoundStateMachine.hpp"
#include "BaseBulkRound.hpp"

namespace Dissent {
namespace Utils {
  class Random;
}

namespace Anonymity {
  class CSProvableRound : public BaseBulkRound
  {
    Q_OBJECT
    Q_ENUMS(States);
    Q_ENUMS(MessageType);

    public:
      friend class RoundStateMachine<CSProvableRound>;

      enum MessageType {
        CLIENT_CIPHERTEXT = 0,
        SERVER_CLIENT_LIST,
        SERVER_CIPHERTEXT,
        SERVER_VALIDATION,
        SERVER_CLEARTEXT,
      };

      enum States {
        OFFLINE = 0,
        PREPARE_FOR_ROUND,
        CLIENT_WAIT_FOR_CLEARTEXT,
        SERVER_WAIT_FOR_CLIENT_CIPHERTEXT,
        SERVER_WAIT_FOR_CLIENT_LISTS,
        SERVER_WAIT_FOR_SERVER_CIPHERTEXT,
        SERVER_WAIT_FOR_SERVER_VALIDATION,
        SERVER_PUSH_CLEARTEXT,
        FINISHED,
      };

      explicit CSProvable Round(const Group &group, const PrivateIdentity &ident,
          const Id &round_id, QSharedPointer<Network> network,
          GetDataCallback &get_data);
          

      /**
       * Destructor
       */
      virtual ~CSProvableRound();

      /**
       * Returns true if the local node is a member of the subgroup
       */
      inline bool IsServer() const
      {
        return GetGroup().GetSubgroup().Contains(GetLocalId());
      }

      /**
       * Converts a MessageType into a QString
       * @param mt value to convert
       */
      static QString StateToString(int state)
      {
        int index = staticMetaObject.indexOfEnumerator("States");
        return staticMetaObject.enumerator(index).valueToKey(state);
      }

      /**
       * Converts a MessageType into a QString
       * @param mt value to convert
       */
      static QString MessageTypeToString(int mtype)
      {
        int index = staticMetaObject.indexOfEnumerator("MessageType");
        return staticMetaObject.enumerator(index).valueToKey(mtype);
      }

      /**
       * Returns the string representation of the round
       */
      inline virtual QString ToString() const
      {
        return "CSProvableRound: " + GetRoundId().ToString() +
          " Phase: " + QString::number(_state_machine.GetPhase());
      }

      virtual void PeerJoined() { }

      virtual void HandleDisconnect(const Id &id);

      /**
       * Delay between the start of a round and when all clients are required
       * to have submitted a message in order to be valid
       */
      static const int CLIENT_SUBMISSION_WINDOW = 120000;

    protected:
      typedef Utils::Random Random;

      /**
       * Funnels data into the RoundStateMachine for evaluation
       * @param data Incoming data
       * @param from the remote peer sending the data
       */
      inline virtual void ProcessData(const Id &from, const QByteArray &data)
      {
        _state_machine.ProcessData(from, data);
      }

      virtual void OnStart();

      virtual void OnStop();

      /**
       * Server sends a message to all servers
       * @param data the message to send
       */
      void VerifiableBroadcastToServers(const QByteArray &data);

      /**
       * Server sends a message to all clients
       * @param data the message to send
       */
      void VerifiableBroadcastToClients(const QByteArray &data);

    private:
      /**
       * Holds the internal state for this round
       */
      class State {
        public:
          State() : accuse(false) {}
          virtual ~State() {}

          QVector<QSharedPointer<AsymmetricKey> > anonymous_keys;
          QList<QByteArray> base_seeds;
          QVector<QSharedPointer<Random> > anonymous_rngs;
          QMap<int, int> next_messages;
          QHash<int, QByteArray> signatures;
          QByteArray cleartext;

          QSharedPointer<AsymmetricKey> anonymous_key;
          QByteArray shuffle_data;
          bool read;
          bool slot_open;
          bool accuse;
          QByteArray next_msg;
          int msg_length;
          int base_msg_length;
          int my_idx;
          Id my_server;
      };

      /**
       * Holds the internal state for servers in this round
       */
      class ServerState : public State {
        public:
          virtual ~ServerState() {}

          Utils::TimerEvent client_ciphertext_period;
          qint64 start_of_phase;
          int expected_clients;

          int phase;

          QByteArray my_commit;
          QByteArray my_ciphertext;

          QSet<Id> allowed_clients;
          QSet<Id> handled_clients;
          QList<QByteArray> client_ciphertexts;

          QSet<Id> handled_servers;
          QHash<int, QByteArray> server_commits;
          QHash<int, QByteArray> server_ciphertexts;
      };

      /**
       * Called by the constructor to initialize the server state machine
       */
      void InitServer();

      /**
       * Called by the constructor to initialize the client state machine
       */
      void InitClient();

      /**
       * Called before each state transition
       */
      void BeforeStateTransition();

      /**
       * Called after each cycle, i.e., phase conclusion
       */
      bool CycleComplete();

      /**
       * Safety net, should never be called
       */
      void EmptyHandleMessage(const Id &, QDataStream &)
      {
        qDebug() << "Received a message into the empty handle message...";
      }
        
      /**
       * Some transitions don't require any state preparation, they are handled
       * by this
       */
      void EmptyTransitionCallback() {}

      /**
       * Submits the anonymous signing key into the shuffle
       */
      virtual QPair<QByteArray, bool> GetShuffleData(int max);

      /**
       * Called when the shuffle finishes
       */
      virtual void ShuffleFinished();

      /**
       * Server handles client ciphertext messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleClientCiphertext(const Id &from, QDataStream &stream);

      /**
       * Server handles other server client list messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerClientList(const Id &from, QDataStream &stream);

      /**
       * Server handles other server commit messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerCommit(const Id &from, QDataStream &stream);

      /**
       * Server handles other server ciphertext messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerCiphertext(const Id &from, QDataStream &stream);

      /**
       * Server handles other server validation messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerValidation(const Id &from, QDataStream &stream);

      /**
       * Client handles server cleartext message
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerCleartext(const Id &from, QDataStream &stream);

      /**
       * Decoupled as to not waste resources if the shuffle doesn't succeed
       */
      void SetupRngSeeds();

      /**
       * For clients, this is a trivial setup, one for each server, servers
       * need to set this after determining the online client set.
       */
      void SetupRngs();

      /* Below are the state transitions */
      void StartShuffle();
      void ProcessDataShuffle();
      void ProcessKeyShuffle();
      void PrepareForBulk();
      void SubmitClientCiphertext();
      void SetOnlineClients();
      void SubmitClientList();
      void SubmitCommit();
      void SubmitServerCiphertext();
      void SubmitValidation();
      void PushCleartext();

      /* Below are the ciphertext generation helpers */
      void GenerateServerCiphertext();
      QByteArray GenerateCiphertext();
      QByteArray GenerateSlotMessage();
      bool CheckData();

      void ProcessCleartext();
      void ConcludeClientCiphertextSubmission(const int &);

      inline int SlotHeaderLength(int slot_idx) const
      {
        Crypto::Library *lib = Crypto::CryptoFactory::GetInstance().GetLibrary();
        return 9 + lib->RngOptimalSeedSize() +
          (_state->anonymous_keys[slot_idx]->GetKeySize() / 8);
      }

      QSharedPointer<ServerState> _server_state;
      QSharedPointer<State> _state;
      RoundStateMachine<CSBulkRound> _state_machine;
      bool _stop_next;
  };
}
}

#endif
