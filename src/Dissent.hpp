#ifndef DISSENT_DISSENT_H_GUARD
#define DISSENT_DISSENT_H_GUARD

#include "Anonymity/BaseBulkRound.hpp"
#include "Anonymity/BlogDropRound.hpp"
#include "Anonymity/BulkRound.hpp"
#include "Anonymity/CSBulkRound.hpp"
#include "Anonymity/Log.hpp"
#include "Anonymity/NeffKeyShuffle.hpp"
#include "Anonymity/NeffShuffle.hpp"
#include "Anonymity/NullRound.hpp"
#include "Anonymity/RepeatingBulkRound.hpp"
#include "Anonymity/Round.hpp"
#include "Anonymity/RoundStateMachine.hpp"
#include "Anonymity/Sessions/Session.hpp"
#include "Anonymity/Sessions/SessionLeader.hpp"
#include "Anonymity/Sessions/SessionManager.hpp"
#include "Anonymity/ShuffleBlamer.hpp"
#include "Anonymity/ShuffleRound.hpp"
#include "Anonymity/ShuffleRoundBlame.hpp"

#include "Applications/AuthFactory.hpp"
#include "Applications/CommandLine.hpp"
#include "Applications/ConsoleSink.hpp"
#include "Applications/FileSink.hpp"
#include "Applications/Node.hpp"
#include "Applications/SessionFactory.hpp"
#include "Applications/Settings.hpp"

#include "ClientServer/CSBroadcast.hpp"
#include "ClientServer/CSConnectionAcquirer.hpp"
#include "ClientServer/CSForwarder.hpp"
#include "ClientServer/CSNetwork.hpp"
#include "ClientServer/CSOverlay.hpp"

#include "Connections/Bootstrapper.hpp"
#include "Connections/Connection.hpp"
#include "Connections/ConnectionAcquirer.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/ConnectionTable.hpp"
#include "Connections/DefaultNetwork.hpp"
#include "Connections/EmptyNetwork.hpp"
#include "Connections/FullyConnected.hpp"
#include "Connections/Id.hpp"
#include "Connections/IOverlaySender.hpp"
#include "Connections/Network.hpp"
#include "Connections/RelayAddress.hpp"
#include "Connections/RelayEdge.hpp"
#include "Connections/RelayEdgeListener.hpp"

#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/CppDiffieHellman.hpp"
#include "Crypto/CppDsaLibrary.hpp"
#include "Crypto/CppDsaPrivateKey.hpp"
#include "Crypto/CppDsaPublicKey.hpp"
#include "Crypto/CppHash.hpp"
#include "Crypto/CppIntegerData.hpp"
#include "Crypto/CppLibrary.hpp"
#include "Crypto/CppNeffShuffle.hpp"
#include "Crypto/CppPrivateKey.hpp"
#include "Crypto/CppPublicKey.hpp"
#include "Crypto/CppRandom.hpp"
#include "Crypto/CryptoFactory.hpp"
#include "Crypto/DiffieHellman.hpp"
#include "Crypto/CppHash.hpp"
#include "Crypto/Hash.hpp"
#include "Crypto/Integer.hpp"
#include "Crypto/IntegerData.hpp"
#include "Crypto/KeyShare.hpp"
#include "Crypto/Library.hpp"
#include "Crypto/LRSPrivateKey.hpp"
#include "Crypto/LRSPublicKey.hpp"
#include "Crypto/LRSSignature.hpp"
#include "Crypto/NullDiffieHellman.hpp"
#include "Crypto/NullHash.hpp"
#include "Crypto/NullLibrary.hpp"
#include "Crypto/NullPrivateKey.hpp"
#include "Crypto/NullPublicKey.hpp"
#include "Crypto/OpenIntegerData.hpp"
#include "Crypto/OpenLibrary.hpp"
#include "Crypto/OnionEncryptor.hpp"
#include "Crypto/Serialization.hpp"
#include "Crypto/ThreadedOnionEncryptor.hpp"
#include "Crypto/AbstractGroup/AbstractGroup.hpp"
#include "Crypto/AbstractGroup/ByteGroup.hpp"
#include "Crypto/AbstractGroup/BotanECElementData.hpp"
#include "Crypto/AbstractGroup/BotanECGroup.hpp"
#include "Crypto/AbstractGroup/ByteElementData.hpp"
#include "Crypto/AbstractGroup/CppECElementData.hpp"
#include "Crypto/AbstractGroup/CppECGroup.hpp"
#include "Crypto/AbstractGroup/ECParams.hpp"
#include "Crypto/AbstractGroup/Element.hpp"
#include "Crypto/AbstractGroup/ElementData.hpp"
#include "Crypto/AbstractGroup/IntegerElementData.hpp"
#include "Crypto/AbstractGroup/IntegerGroup.hpp"
#include "Crypto/AbstractGroup/OpenECElementData.hpp"
#include "Crypto/AbstractGroup/OpenECGroup.hpp"
#include "Crypto/AbstractGroup/PairingElementData.hpp"
#include "Crypto/AbstractGroup/PairingGroup.hpp"
#include "Crypto/AbstractGroup/PairingG1Group.hpp"
#include "Crypto/AbstractGroup/PairingGTGroup.hpp"
#include "Crypto/BlogDrop/BlogDropAuthor.hpp"
#include "Crypto/BlogDrop/BlogDropClient.hpp"
#include "Crypto/BlogDrop/BlogDropServer.hpp"
#include "Crypto/BlogDrop/BlogDropUtils.hpp"
#include "Crypto/BlogDrop/CiphertextFactory.hpp"
#include "Crypto/BlogDrop/ChangingGenClientCiphertext.hpp"
#include "Crypto/BlogDrop/ChangingGenServerCiphertext.hpp"
#include "Crypto/BlogDrop/ClientCiphertext.hpp"
#include "Crypto/BlogDrop/ElGamalClientCiphertext.hpp"
#include "Crypto/BlogDrop/ElGamalServerCiphertext.hpp"
#include "Crypto/BlogDrop/HashingGenClientCiphertext.hpp"
#include "Crypto/BlogDrop/HashingGenServerCiphertext.hpp"
#include "Crypto/BlogDrop/PairingClientCiphertext.hpp"
#include "Crypto/BlogDrop/PairingServerCiphertext.hpp"
#include "Crypto/BlogDrop/Parameters.hpp"
#include "Crypto/BlogDrop/Plaintext.hpp"
#include "Crypto/BlogDrop/PrivateKey.hpp"
#include "Crypto/BlogDrop/PublicKey.hpp"
#include "Crypto/BlogDrop/PublicKeySet.hpp"
#include "Crypto/BlogDrop/ServerCiphertext.hpp"
#include "Crypto/BlogDrop/XorClientCiphertext.hpp"
#include "Crypto/BlogDrop/XorServerCiphertext.hpp"

#include "Identity/Authentication/IAuthenticate.hpp"
#include "Identity/Authentication/IAuthenticator.hpp"
#include "Identity/Authentication/LRSAuthenticate.hpp"
#include "Identity/Authentication/LRSAuthenticator.hpp"
#include "Identity/Authentication/NullAuthenticate.hpp"
#include "Identity/Authentication/NullAuthenticator.hpp"
#include "Identity/Authentication/PreExchangedKeyAuthenticate.hpp"
#include "Identity/Authentication/PreExchangedKeyAuthenticator.hpp"
#include "Identity/Group.hpp"
#include "Identity/GroupHolder.hpp"
#include "Identity/PrivateIdentity.hpp"
#include "Identity/PublicIdentity.hpp"

#include "LRS/FactorProof.hpp"
#include "LRS/RingSignature.hpp"
#include "LRS/SchnorrProof.hpp"
#include "LRS/SigmaProof.hpp"

#include "Messaging/BufferSink.hpp"
#include "Messaging/DummySink.hpp"
#include "Messaging/Filter.hpp"
#include "Messaging/FilterObject.hpp"
#include "Messaging/GetDataCallback.hpp" 
#include "Messaging/ISender.hpp"
#include "Messaging/ISink.hpp"
#include "Messaging/ISinkObject.hpp"
#include "Messaging/Request.hpp"
#include "Messaging/RequestHandler.hpp"
#include "Messaging/Response.hpp"
#include "Messaging/ResponseHandler.hpp"
#include "Messaging/RpcHandler.hpp"
#include "Messaging/SignalSink.hpp"
#include "Messaging/Source.hpp"
#include "Messaging/SourceObject.hpp"

#include "Overlay/BaseOverlay.hpp"
#include "Overlay/BasicGossip.hpp"

#include "PeerReview/Acknowledgement.hpp"
#include "PeerReview/Entry.hpp"
#include "PeerReview/EntryParser.hpp"
#include "PeerReview/EntryLog.hpp"
#include "PeerReview/PRManager.hpp"
#include "PeerReview/ReceiveEntry.hpp"
#include "PeerReview/SendEntry.hpp"

#include "Transports/Address.hpp"
#include "Transports/AddressFactory.hpp"
#include "Transports/BufferAddress.hpp"
#include "Transports/BufferEdge.hpp"
#include "Transports/BufferEdgeListener.hpp"
#include "Transports/Edge.hpp"
#include "Transports/EdgeFactory.hpp"
#include "Transports/EdgeListener.hpp"
#include "Transports/EdgeListenerFactory.hpp"
#include "Transports/TcpAddress.hpp"
#include "Transports/TcpEdge.hpp"
#include "Transports/TcpEdgeListener.hpp"

#include "Tunnel/EntryTunnel.hpp"
#include "Tunnel/ExitTunnel.hpp"
#include "Tunnel/SocksConnection.hpp"
#include "Tunnel/SocksHostAddress.hpp"
#include "Tunnel/TunnelConnectionTable.hpp"
#include "Tunnel/Packets/Packet.hpp"
#include "Tunnel/Packets/FinishPacket.hpp"
#include "Tunnel/Packets/TcpRequestPacket.hpp"
#include "Tunnel/Packets/UdpRequestPacket.hpp"
#include "Tunnel/Packets/TcpResponsePacket.hpp"
#include "Tunnel/Packets/UdpResponsePacket.hpp"
#include "Tunnel/Packets/TcpStartPacket.hpp"
#include "Tunnel/Packets/UdpStartPacket.hpp"

#include "Utils/Logging.hpp"
#include "Utils/QRunTimeError.hpp"
#include "Utils/Random.hpp"
#include "Utils/Serialization.hpp"
#include "Utils/SignalCounter.hpp"
#include "Utils/Sleeper.hpp"
#include "Utils/StartStop.hpp"
#include "Utils/StartStopSlots.hpp"
#include "Utils/Time.hpp"
#include "Utils/Timer.hpp"
#include "Utils/TimerCallback.hpp"
#include "Utils/TimerEvent.hpp"
#include "Utils/Triggerable.hpp"
#include "Utils/Triple.hpp"
#include "Utils/Utils.hpp"

#include "Web/HttpRequest.hpp"
#include "Web/HttpResponse.hpp"
#include "Web/WebRequest.hpp"
#include "Web/WebServer.hpp"
#include "Web/Packagers/Packager.hpp"
#include "Web/Packagers/JsonPackager.hpp"
#include "Web/Services/GetFileService.hpp"
#include "Web/Services/GetMessagesService.hpp"
#include "Web/Services/MessageWebService.hpp"
#include "Web/Services/RoundIdService.hpp"
#include "Web/Services/SendMessageService.hpp"
#include "Web/Services/SessionIdService.hpp"
#include "Web/Services/SessionWebService.hpp"
#include "Web/Services/WebService.hpp"

using namespace Dissent::Anonymity;
using namespace Dissent::Anonymity::Sessions;
using namespace Dissent::Applications;
using namespace Dissent::ClientServer;
using namespace Dissent::Connections;
using namespace Dissent::Crypto;
using namespace Dissent::Crypto::AbstractGroup;
using namespace Dissent::Crypto::BlogDrop;
using namespace Dissent::Identity::Authentication;
using namespace Dissent::Identity;
using namespace Dissent::LRS;
using namespace Dissent::Messaging;
using namespace Dissent::Overlay;
using namespace Dissent::Transports;
using namespace Dissent::Tunnel;
using namespace Dissent::Tunnel::Packets;
using namespace Dissent::Utils;
using namespace Dissent::Web;
using namespace Dissent::Web::Services;
using namespace Dissent::Web::Packagers;

#endif
