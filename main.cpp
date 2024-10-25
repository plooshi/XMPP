#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdexcept>
#include <string.h>
#include <iostream>
#include <thread>
#include <libxml2/libxml/parser.h>
#include <libxml2/libxml/tree.h>
#include <unistd.h>
#include <string>
#include <uuid/uuid.h>
#include <functional>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "publicKey.h"
#include "privateKey.h"
#include <set>
#include <map>
#include <curl/curl.h>

size_t CurlWriteCallback(char *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

class Logger {
public:
    template<typename ...Args>
    static void Debug(Args... args) {
        std::cout << "LogXMPP: Verbose: ";
        (std::cout << ... << args);
        std::cout << std::endl;
    }
    
    template<typename ...Args>
    static void Info(Args... args) {
        std::cout << "LogXMPP: Display: ";
        (std::cout << ... << args);
        std::cout << std::endl;
    }
};

xmlBufferPtr createXmlNode(const char *rootName, std::function<void(xmlNodePtr)> rootInitializer) {
    auto root = xmlNewNode(nullptr, BAD_CAST rootName);
    rootInitializer(root);
    xmlBufferPtr buf = xmlBufferCreate();
    xmlNodeDump(buf, nullptr, root, 1, 0);
    return buf;
}

u_char *createXmlDoc(const char *rootName, std::function<void(xmlNodePtr)> rootInitializer) {
    auto root = xmlNewNode(nullptr, BAD_CAST rootName);
    rootInitializer(root);
    xmlBufferPtr buf = xmlBufferCreate();
    xmlNodeDump(buf, nullptr, root, 1, 0);
    std::string str = "<?xml version=\"1.0\"?>";
    str += (const char *) buf->content;
    free(buf);
    auto sdata = (char *) malloc(str.size() + 1);
    strcpy(sdata, str.c_str());
    return (u_char *) sdata;
}

u_char *startStream() {
    auto doc = createXmlDoc("stream:stream", [](xmlNodePtr root) {
        xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "jabber:client");
        xmlNewProp(root, BAD_CAST "from", BAD_CAST "prod.ol.epicgames.com");
        uuid_t b_uuid;
        uuid_generate_random(b_uuid);
        unsigned char uuid[37];
        uuid_unparse_lower(b_uuid, (char *) uuid);
        xmlNewProp(root, BAD_CAST "id", uuid);
        xmlNewProp(root, BAD_CAST "version", BAD_CAST "1.0");
        xmlNewProp(root, BAD_CAST "xml:lang", BAD_CAST "en");
        xmlNewProp(root, BAD_CAST "xmlns:stream", BAD_CAST "http://etherx.jabber.org/streams");
    });
    doc[strlen((const char *) doc) - 2] = '>';
    doc[strlen((const char *) doc) - 1] = 0;
    return doc;
}


const std::string b64decode(const void* data, const size_t &len)
{
    if (len == 0) return "";
    static const int B64index[256] =
    {
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  62, 63, 62, 62, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0,  0,  0,  0,  0,  0,
        0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0,  0,  0,  0,  63,
        0,  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
    };

    unsigned char *p = (unsigned char*) data;
    size_t j = 0,
        pad1 = len % 4 || p[len - 1] == '=',
        pad2 = pad1 && (len % 4 > 2 || p[len - 2] != '=');
    const size_t last = (len - pad1) / 4 << 2;
    std::string result(last / 4 * 3 + pad1 + pad2, '\0');
    unsigned char *str = (unsigned char*) &result[0];

    for (size_t i = 0; i < last; i += 4)
    {
        int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
        str[j++] = n >> 16;
        str[j++] = n >> 8 & 0xFF;
        str[j++] = n & 0xFF;
    }
    if (pad1)
    {
        int n = B64index[p[last]] << 18 | B64index[p[last + 1]] << 12;
        str[j++] = n >> 16;
        if (pad2)
        {
            n |= B64index[p[last + 2]] << 6;
            str[j++] = n >> 8 & 0xFF;
        }
    }
    return result;
}

std::set<class Socket *> clients;
std::map<std::string, class MUC *> MUCs;

class MUC {
public:
    std::set<class Socket *> members;
    std::string name;

    static MUC *CreateNew(std::string Name, class Socket *Sock) {
        auto muc = new MUC();
        muc->members.insert(Sock);
        muc->name = Name;
        MUCs[Name] = muc;
        return muc;
    }

    void RunOnAll(std::function<void(class Socket *)> func) {
        for (auto& member : members) {
            func(member);
        }
    }
};

class User {
public:
    std::string accountId;

    User(std::string accId) : accountId(accId) {};
};

class Socket {
public:
    int _sock = 0;
    bool bSSL = false;
    SSL *ssl = nullptr;
    bool bAuthenticated = false;
    std::string accountId;
    std::string jid;
    std::set<MUC *> JoinedMUCs;
    std::string MUCNickname;
    std::set<User *> Friends;

    std::string GetMUCName(MUC *muc) {
        return muc->name + "@muc.prod.ol.epicgames.com/" + MUCNickname;
    }

public:
    Socket(int fd) : _sock(fd) {};

    void Send(const char *data, int flags = 0) {
        if (bSSL) SSL_write(ssl, data, strlen(data));
        else send(_sock, data, strlen(data), 0);
    }
    void Send(unsigned char *data, int flags = 0) {
        if (bSSL) SSL_write(ssl, data, strlen((const char *) data));
        else send(_sock, data, strlen((const char *) data), 0);
    }

    void Send(void *data, size_t size, int flags = 0) {
        if (bSSL) SSL_write(ssl, data, size);
        else send(_sock, data, size, 0);
    }

    void Send(xmlBufferPtr data, int flags = 0) {
        if (bSSL) SSL_write(ssl, data->content, strlen((const char *) data->content));
        else send(_sock, data->content, strlen((const char *) data->content), 0);
        free(data);
    }

    
    void SendAndFree(u_char *data, int flags = 0) {
        if (bSSL) SSL_write(ssl, data, strlen((const char *) data));
        else send(_sock, data, strlen((const char *) data), 0);
        free(data);
    }

    int Read(void *buffer, size_t bufferSize) {
        if (bSSL) return SSL_read(ssl, buffer, bufferSize);
        else return recv(_sock, buffer, bufferSize, 0);
    }

    static void connectionThread(Socket *sock) {
        u_char buffer[4096];
        ssize_t bufferLen;
        while ((bufferLen = sock->Read(buffer, 4096)) > 0) {
            buffer[bufferLen] = 0;
            auto xmlDoc = xmlReadDoc((const u_char *) buffer, nullptr, "UTF-8", XML_PARSE_RECOVER | XML_PARSE_NOERROR);
            auto xmlRoot = xmlDocGetRootElement(xmlDoc);
            if (!xmlRoot) {
                sock->Send("</stream:stream>");
                break;
            }
            std::string rootName = (const char *) xmlRoot->name;
            if (rootName == "stream") {
                sock->SendAndFree(startStream());

                if (sock->bSSL) {
                    if (sock->bAuthenticated) {
                        sock->Send(createXmlNode("stream:features", [](xmlNodePtr root) {
                            xmlNewProp(root, BAD_CAST "xmlns:stream", BAD_CAST "http://etherx.jabber.org/streams");
                            auto currentNode = xmlNewChild(root, nullptr, BAD_CAST "ver", nullptr);
                            xmlNewProp(currentNode, BAD_CAST "xmlns", BAD_CAST "urn:xmpp:features:rosterver");
                            currentNode = xmlNewChild(root, nullptr, BAD_CAST "bind", nullptr);
                            xmlNewProp(currentNode, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:xmpp-bind");
                            currentNode = xmlNewChild(root, nullptr, BAD_CAST "session", nullptr);
                            xmlNewProp(currentNode, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:xmpp-session");
                        }));
                    } else {
                        sock->Send(createXmlNode("stream:features", [](xmlNodePtr root) {
                            xmlNewProp(root, BAD_CAST "xmlns:stream", BAD_CAST "http://etherx.jabber.org/streams");
                            auto currentNode = xmlNewChild(root, nullptr, BAD_CAST "mechanisms", nullptr);
                            xmlNewProp(currentNode, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:xmpp-sasl");
                            xmlNewChild(currentNode, nullptr, BAD_CAST "mechanism", BAD_CAST "PLAIN");
                            currentNode = xmlNewChild(root, nullptr, BAD_CAST "ver", nullptr);
                            xmlNewProp(currentNode, BAD_CAST "xmlns", BAD_CAST "urn:xmpp:features:rosterver");
                            currentNode = xmlNewChild(root, nullptr, BAD_CAST "auth", nullptr);
                            xmlNewProp(currentNode, BAD_CAST "xmlns", BAD_CAST "http://jabber.org/features/iq-auth");
                        }));
                    }
                } else {
                    sock->Send(createXmlNode("stream:features", [](xmlNodePtr root) {
                        xmlNewProp(root, BAD_CAST "xmlns:stream", BAD_CAST "http://etherx.jabber.org/streams");
                        auto currentNode = xmlNewChild(root, nullptr, BAD_CAST "starttls", nullptr);
                        xmlNewProp(currentNode, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:xmpp-tls");
                        xmlNewChild(currentNode, nullptr, BAD_CAST "required", nullptr);
                    }));
                }
            } else if (rootName == "starttls") {
                auto ctx = SSL_CTX_new(TLS_server_method());
                SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
                SSL_CTX_use_certificate_ASN1(ctx, sizeof(publicKey), publicKey);
                SSL_CTX_use_PrivateKey_ASN1(0, ctx, privateKey, sizeof(privateKey));

                sock->ssl = SSL_new(ctx);
                SSL_set_fd(sock->ssl, sock->_sock);
                
                sock->Send(createXmlNode("proceed", [](xmlNodePtr root) {
                    xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:xmpp-tls");
                }));
                sock->bSSL = true;
                SSL_accept(sock->ssl);
            } else if (rootName == "auth") {
                auto b64content = std::string((const char *) xmlRoot->children->content);
                auto content = b64decode(b64content.c_str(), b64content.size());
                auto accountIdEnd = content.find('\0', 1);
                auto accessToken = content.substr(accountIdEnd + 1);
                sock->accountId = content.substr(1, accountIdEnd - 1);
                sock->bAuthenticated = true;
                clients.insert(sock);
                std::vector<std::string> friends = {}; // list of account ids
                for (auto& Friend : friends) {
                    sock->Friends.insert(new User(Friend));
                }
                Logger::Info("Successfully logged in ", sock->accountId, "!");
                sock->Send(createXmlNode("success", [](xmlNodePtr root) {
                    xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:xmpp-sasl");
                }));
            } else if (rootName == "iq") {
                if (!sock->bAuthenticated) return sock->Send("</stream:stream>");
                auto subNode = xmlRoot->children;
                auto subName = std::string((const char *) subNode->name);
                if (subName == "bind") {
                    auto resource = std::string((const char *) subNode->children->children->content);
                    sock->jid = sock->accountId + "@prod.ol.epicgames.com/" + resource;
                    sock->Send(createXmlNode("iq", [sock](xmlNodePtr root) {
                        xmlNewProp(root, BAD_CAST "to", BAD_CAST sock->jid.c_str());
                        xmlNewProp(root, BAD_CAST "id", BAD_CAST "_xmpp_bind1");
                        xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "jabber:client");
                        xmlNewProp(root, BAD_CAST "type", BAD_CAST "result");
                        auto currentNode = xmlNewChild(root, nullptr, BAD_CAST "bind", nullptr);
                        xmlNewProp(currentNode, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:xmpp-bind");
                        xmlNewChild(currentNode, nullptr, BAD_CAST "jid", BAD_CAST sock->jid.c_str());
                    }));
                } else if (subName == "session") {
                    sock->Send(createXmlNode("iq", [sock](xmlNodePtr root) {
                        xmlNewProp(root, BAD_CAST "to", BAD_CAST sock->jid.c_str());
                        xmlNewProp(root, BAD_CAST "from", BAD_CAST "prod.ol.epicgames.com");
                        xmlNewProp(root, BAD_CAST "id", BAD_CAST "_xmpp_session1");
                        xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "jabber:client");
                        xmlNewProp(root, BAD_CAST "type", BAD_CAST "result");
                    }));

                    for (auto &Friend : sock->Friends) {
                        Socket *socket = nullptr;
                        for (auto& client : clients) {
                            if (socket->accountId == Friend->accountId) {
                                socket = client;
                                break;
                            }
                        }

                        if (socket) {
                            socket->Send(createXmlNode("presence", [sock, socket](xmlNodePtr root) {
                                xmlNewProp(root, BAD_CAST "to", BAD_CAST sock->jid.c_str());
                                xmlNewProp(root, BAD_CAST "from", BAD_CAST socket->jid.c_str());
                                xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "jabber:client");
                                xmlNewProp(root, BAD_CAST "type", BAD_CAST "available");
                                xmlNewChild(root, nullptr, BAD_CAST "status", BAD_CAST "{}");
                            }));
                        }
                    }
                } else {
                    auto id = xmlGetProp(xmlRoot, BAD_CAST "id");
                    sock->Send(createXmlNode("iq", [sock, id](xmlNodePtr root) {
                        xmlNewProp(root, BAD_CAST "to", BAD_CAST sock->jid.c_str());
                        xmlNewProp(root, BAD_CAST "from", BAD_CAST "prod.ol.epicgames.com");
                        xmlNewProp(root, BAD_CAST "id", id);
                        xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "jabber:client");
                        xmlNewProp(root, BAD_CAST "type", BAD_CAST "result");
                    }));
                }
            } else if (rootName == "presence") {
                if (!sock->bAuthenticated) return sock->Send("</stream:stream>");
                auto to = xmlGetProp(xmlRoot, BAD_CAST "to");
                if (to) {
                    // MUC
                    auto member = std::string((const char *) to);
                    auto atPos = member.find("@");
                    auto slashPos = member.find("/");
                    if (atPos != std::string::npos && member.substr(atPos + 1, 4) == "muc.") {
                        auto name = member.substr(0, atPos);
                        auto nick = member.substr(slashPos + 1);
                        auto type = xmlGetProp(xmlRoot, BAD_CAST "type");
                        if (sock->MUCNickname == "") sock->MUCNickname = nick;
                        if (type && strcmp((const char *) type, "unavailable") == 0) {
                            auto muc = MUCs[name];
                            sock->JoinedMUCs.erase(muc);
                            muc->members.erase(sock);

                            sock->Send(createXmlNode("presence", [sock, to, nick](xmlNodePtr root) {
                                xmlNewProp(root, BAD_CAST "to", BAD_CAST sock->jid.c_str());
                                xmlNewProp(root, BAD_CAST "from", to);
                                xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "jabber:client");
                                xmlNewProp(root, BAD_CAST "type", BAD_CAST "unavailable");
                                auto currentNode = xmlNewChild(root, nullptr, BAD_CAST "x", nullptr);
                                xmlNewProp(currentNode, BAD_CAST "xmlns", BAD_CAST "http://jabber.org/protocol/muc#user");
                                currentNode = xmlNewChild(currentNode, nullptr, BAD_CAST "item", nullptr);
                                xmlNewProp(currentNode, BAD_CAST "nick", BAD_CAST nick.c_str());
                                xmlNewProp(currentNode, BAD_CAST "jid", BAD_CAST sock->jid.c_str());
                                xmlNewProp(currentNode, BAD_CAST "role", BAD_CAST "none");
                                currentNode = xmlNewChild(root, nullptr, BAD_CAST "status", nullptr);
                                xmlNewProp(currentNode, BAD_CAST "code", BAD_CAST "100"); // users are not anonymous
                                currentNode = xmlNewChild(root, nullptr, BAD_CAST "status", nullptr);
                                xmlNewProp(currentNode, BAD_CAST "code", BAD_CAST "110"); // refers to self as occupant
                            }));
                        } else {
                            bool createNewMUC = !MUCs[name];
                            auto muc = MUCs[name];
                            if (createNewMUC) muc = MUC::CreateNew(name, sock);
                            else MUCs[name]->members.insert(sock);

                            sock->Send(createXmlNode("presence", [sock, to, nick, createNewMUC](xmlNodePtr root) {
                                xmlNewProp(root, BAD_CAST "to", BAD_CAST sock->jid.c_str());
                                xmlNewProp(root, BAD_CAST "from", to);
                                xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "jabber:client");
                                auto currentNode = xmlNewChild(root, nullptr, BAD_CAST "x", nullptr);
                                xmlNewProp(currentNode, BAD_CAST "xmlns", BAD_CAST "http://jabber.org/protocol/muc#user");
                                currentNode = xmlNewChild(currentNode, nullptr, BAD_CAST "item", nullptr);
                                xmlNewProp(currentNode, BAD_CAST "nick", BAD_CAST nick.c_str());
                                xmlNewProp(currentNode, BAD_CAST "jid", BAD_CAST sock->jid.c_str());
                                xmlNewProp(currentNode, BAD_CAST "affiliation", BAD_CAST "none");
                                xmlNewProp(currentNode, BAD_CAST "role", BAD_CAST "participant");
                                currentNode = xmlNewChild(root, nullptr, BAD_CAST "status", nullptr);
                                xmlNewProp(currentNode, BAD_CAST "code", BAD_CAST "100"); // users are not anonymous
                                currentNode = xmlNewChild(root, nullptr, BAD_CAST "status", nullptr);
                                xmlNewProp(currentNode, BAD_CAST "code", BAD_CAST "110"); // refers to self as occupant
                                if (createNewMUC) {
                                    currentNode = xmlNewChild(root, nullptr, BAD_CAST "status", nullptr);
                                    xmlNewProp(currentNode, BAD_CAST "code", BAD_CAST "201"); // if a new MUC was created
                                }
                            }));

                            muc->RunOnAll([sock, muc](Socket *memberSock) {
                                if (sock == memberSock) return;

                                sock->Send(createXmlNode("presence", [sock, memberSock, muc](xmlNodePtr root) {
                                    xmlNewProp(root, BAD_CAST "from", BAD_CAST memberSock->GetMUCName(muc).c_str());
                                    xmlNewProp(root, BAD_CAST "to", BAD_CAST sock->jid.c_str());
                                    xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "jabber:client");
                                    auto currentNode = xmlNewChild(root, nullptr, BAD_CAST "x", nullptr);
                                    xmlNewProp(currentNode, BAD_CAST "xmlns", BAD_CAST "http://jabber.org/protocol/muc#user");
                                    currentNode = xmlNewChild(currentNode, nullptr, BAD_CAST "item", nullptr);
                                    xmlNewProp(currentNode, BAD_CAST "nick", BAD_CAST memberSock->MUCNickname.c_str());
                                    xmlNewProp(currentNode, BAD_CAST "jid", BAD_CAST memberSock->jid.c_str());
                                    xmlNewProp(currentNode, BAD_CAST "affiliation", BAD_CAST "none");
                                    xmlNewProp(currentNode, BAD_CAST "role", BAD_CAST "participant");
                                }));

                                memberSock->Send(createXmlNode("presence", [sock, memberSock, muc](xmlNodePtr root) {
                                    xmlNewProp(root, BAD_CAST "from", BAD_CAST sock->GetMUCName(muc).c_str());
                                    xmlNewProp(root, BAD_CAST "to", BAD_CAST memberSock->jid.c_str());
                                    xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "jabber:client");
                                    auto currentNode = xmlNewChild(root, nullptr, BAD_CAST "x", nullptr);
                                    xmlNewProp(currentNode, BAD_CAST "xmlns", BAD_CAST "http://jabber.org/protocol/muc#user");
                                    currentNode = xmlNewChild(currentNode, nullptr, BAD_CAST "item", nullptr);
                                    xmlNewProp(currentNode, BAD_CAST "nick", BAD_CAST sock->MUCNickname.c_str());
                                    xmlNewProp(currentNode, BAD_CAST "jid", BAD_CAST sock->jid.c_str());
                                    xmlNewProp(currentNode, BAD_CAST "affiliation", BAD_CAST "none");
                                    xmlNewProp(currentNode, BAD_CAST "role", BAD_CAST "participant");
                                }));
                            });
                        }
                    }
                } else {
                    bool hasShow = false;
                    u_char *status = nullptr;
                    for (auto& child = xmlRoot->children; child; child = child->next) {
                        if (strcmp((const char *) child->name, "show") == 0) {
                            hasShow = true;
                        } else if (strcmp((const char *) child->name, "status") == 0) {
                            status = child->children->content;
                        }
                    }
                    
                    sock->Send(createXmlNode("presence", [sock, hasShow, status](xmlNodePtr root) {
                        xmlNewProp(root, BAD_CAST "to", BAD_CAST sock->jid.c_str());
                        xmlNewProp(root, BAD_CAST "from", BAD_CAST sock->jid.c_str());
                        xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "jabber:client");
                        xmlNewChild(root, nullptr, BAD_CAST "type", BAD_CAST "available");
                        if (hasShow) xmlNewChild(root, nullptr, BAD_CAST "show", BAD_CAST "away");
                        xmlNewChild(root, nullptr, BAD_CAST "status", status);
                    }));

                    for (auto &Friend : sock->Friends) {
                        Socket *socket = nullptr;
                        for (auto& client : clients) {
                            if (socket->accountId == Friend->accountId) {
                                socket = client;
                                break;
                            }
                        }

                        if (socket) {
                            socket->Send(createXmlNode("presence", [sock, socket, hasShow, status](xmlNodePtr root) {
                                xmlNewProp(root, BAD_CAST "to", BAD_CAST socket->jid.c_str());
                                xmlNewProp(root, BAD_CAST "from", BAD_CAST sock->jid.c_str());
                                xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "jabber:client");
                                xmlNewProp(root, BAD_CAST "type", BAD_CAST "available");
                                if (hasShow) xmlNewChild(root, nullptr, BAD_CAST "show", BAD_CAST "away");
                                xmlNewChild(root, nullptr, BAD_CAST "status", status);
                            }));
                        }
                    }
                }
            } else if (rootName == "message") {
                if (!sock->bAuthenticated) return sock->Send("</stream:stream>");
                u_char *body = nullptr;
                for (auto& child = xmlRoot->children; child; child = child->next) {
                    if (strcmp((const char *) child->name, "body") == 0) {
                        body = child->children->content;
                    }
                }
                auto type = xmlGetProp(xmlRoot, BAD_CAST "type");
                auto to = xmlGetProp(xmlRoot, BAD_CAST "to");
                if (to && body) {
                    if (type && strcmp((const char *) type, "groupchat") == 0) {
                        auto mucid = std::string((const char *) to);
                        auto atPos = mucid.find("@");
                        auto mucName = mucid.substr(0, atPos);
                        auto muc = MUCs[mucName];
                        if (muc) {
                            muc->RunOnAll([sock, body, muc](Socket *memberSock) {
                                memberSock->Send(createXmlNode("message", [sock, memberSock, body, muc](xmlNodePtr root) {
                                    xmlNewProp(root, BAD_CAST "to", BAD_CAST memberSock->jid.c_str());
                                    xmlNewProp(root, BAD_CAST "from", BAD_CAST sock->GetMUCName(muc).c_str());
                                    xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "jabber:client");
                                    xmlNewProp(root, BAD_CAST "type", BAD_CAST "groupchat");
                                    xmlNewChild(root, nullptr, BAD_CAST "body", body);
                                }));
                            });
                        }
                    } else if (type && strcmp((const char *) type, "chat") == 0) {
                        auto receiver = std::string((const char *) to);
                        for (auto& client : clients) {
                            auto slashPos = client->jid.find("/");
                            auto address = client->jid.substr(0, slashPos);

                            if (address == receiver) {
                                client->Send(createXmlNode("message", [sock, client, body](xmlNodePtr root) {
                                    xmlNewProp(root, BAD_CAST "to", BAD_CAST client->jid.c_str());
                                    xmlNewProp(root, BAD_CAST "from", BAD_CAST sock->jid.c_str());
                                    xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "jabber:client");
                                    xmlNewProp(root, BAD_CAST "type", BAD_CAST "chat");
                                    xmlNewChild(root, nullptr, BAD_CAST "body", body);
                                }));
                                break;
                            }
                        }
                    } else {
                        auto receiver = std::string((const char *) to);
                        auto id = xmlGetProp(xmlRoot, BAD_CAST "id");
                        if (id) for (auto& client : clients) {
                            auto slashPos = client->jid.find("/");
                            auto address = client->jid.substr(0, slashPos);
                            
                            if (address == receiver) {
                                client->Send(createXmlNode("message", [sock, client, body, id](xmlNodePtr root) {
                                    xmlNewProp(root, BAD_CAST "to", BAD_CAST client->jid.c_str());
                                    xmlNewProp(root, BAD_CAST "from", BAD_CAST sock->jid.c_str());
                                    xmlNewProp(root, BAD_CAST "id", id);
                                    xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "jabber:client");
                                    xmlNewChild(root, nullptr, BAD_CAST "body", body);
                                }));
                                break;
                            }
                        }
                    }
                }
            }
        }

        Logger::Info(sock->accountId, " has disconnected!");
        clients.erase(sock);
        SSL_free(sock->ssl);
        for (auto& Friend : sock->Friends) {
            delete Friend;
        }
        for (auto& muc : sock->JoinedMUCs) {
            muc->members.erase(sock);
        }
        for (auto &Friend : sock->Friends) {
            Socket *socket = nullptr;
            for (auto& client : clients) {
                if (socket->accountId == Friend->accountId) {
                    socket = client;
                    break;
                }
            }

            if (socket) {
                socket->Send(createXmlNode("presence", [sock, socket](xmlNodePtr root) {
                    xmlNewProp(root, BAD_CAST "to", BAD_CAST socket->jid.c_str());
                    xmlNewProp(root, BAD_CAST "from", BAD_CAST sock->jid.c_str());
                    xmlNewProp(root, BAD_CAST "xmlns", BAD_CAST "jabber:client");
                    xmlNewProp(root, BAD_CAST "type", BAD_CAST "unavailable");
                    xmlNewChild(root, nullptr, BAD_CAST "status", BAD_CAST "{}");
                }));
            }
        }
        shutdown(sock->_sock, SHUT_RDWR);
        close(sock->_sock);
        delete sock;
    }
};

class Server {
private:
    int _sock = 0;

public:
    Server() : _sock(socket(AF_INET, SOCK_STREAM, 0)) {};

    void setOpt(int opt, int value) {
        setsockopt(_sock, SOL_SOCKET, opt, &value, sizeof(value));
    }

    void listenOnPort(int port) {
        sockaddr_in addr{ AF_INET, htons(port), { htonl(INADDR_ANY) } };
        bool failedBind = bind(_sock, (sockaddr *) &addr, sizeof(addr)) == -1;
        if (failedBind) throw std::runtime_error(std::string("Failed to bind! ") + strerror(errno));
        else {
            bool failedListen = listen(_sock, 9999) == -1;
            if (failedListen) throw std::runtime_error(std::string("Failed to listen! ") + strerror(errno));
            else Logger::Info("Listening on port ", port, "!");
        }
    }
public:

    void waitForConnections() {
        socklen_t sockSize = sizeof(sockaddr_in);
        while (true) {
            sockaddr_in sockAddr;
            auto connfd = accept(_sock, (sockaddr *) &sockAddr, &sockSize);
            if (connfd == -1) throw std::runtime_error(std::string("Failed to handle connection! ") + strerror(errno));
            else {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sockAddr.sin_addr, ip, INET_ADDRSTRLEN);

                std::thread(Socket::connectionThread, new Socket(connfd)).detach();
            }
        }
    }
};

int main() {
    srand(time(0));
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    curl_global_init(CURL_GLOBAL_ALL);
    Server server = Server();

    server.setOpt(SO_REUSEADDR, true);
    server.listenOnPort(5222);
    server.waitForConnections();
}