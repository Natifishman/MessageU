/**
 * @file        ClientRegistry.cpp
 * @author      Natanel Maor Fishman
 * @brief       Implementation of client management and registry operations
 * @details     Provides client information storage, retrieval, key management,
 *              and lookup operations for the secure messaging system.
 * @date        2025
 */

#include "ClientRegistry.h"
#include <algorithm>
#include <cstring>

// ================================
// Registry Management Methods
// ================================

void ClientRegistry::clear()
{
    _clientRegistry.clear();
}

size_t ClientRegistry::size() const
{
    return _clientRegistry.size();
}

bool ClientRegistry::empty() const
{
    return _clientRegistry.empty();
}

bool ClientRegistry::addClient(const ClientInfo& client)
{
    // Check if client already exists
    if (hasClient(client.id)) {
        // Update existing client
        return updateClient(client);
    }

    // Add new client
    _clientRegistry.push_back(client);
    return true;
}

bool ClientRegistry::removeClient(const ClientIdStruct& clientId)
{
    auto it = findClientIteratorById(clientId);
    if (it != _clientRegistry.end()) {
        _clientRegistry.erase(it);
        return true;
    }
    return false;
}

bool ClientRegistry::updateClient(const ClientInfo& client)
{
    auto it = findClientIteratorById(client.id);
    if (it != _clientRegistry.end()) {
        // Preserve existing keys if they're set and new client doesn't have them
        bool preservePublicKey = it->publicKeySet && !client.publicKeySet;
        bool preserveSymmetricKey = it->symmetricKeySet && !client.symmetricKeySet;

        PublicKeyStruct savedPublicKey = it->publicKey;
        SymmetricKeyStruct savedSymmetricKey = it->symmetricKey;

        // Update client info
        *it = client;

        // Restore preserved keys
        if (preservePublicKey) {
            it->publicKey = savedPublicKey;
            it->publicKeySet = true;
        }
        if (preserveSymmetricKey) {
            it->symmetricKey = savedSymmetricKey;
            it->symmetricKeySet = true;
        }

        return true;
    }
    return false;
}

// ================================
// Client Lookup Methods
// ================================

bool ClientRegistry::findClientById(const ClientIdStruct& clientId, ClientInfo& client) const
{
    auto it = findClientIteratorById(clientId);
    if (it != _clientRegistry.end()) {
        client = *it;
        return true;
    }
    return false;
}

bool ClientRegistry::findClientByUsername(const std::string& username, ClientInfo& client) const
{
    auto it = std::find_if(_clientRegistry.begin(), _clientRegistry.end(),
        [&username](const ClientInfo& c) {
            return c.username == username;
        });

    if (it != _clientRegistry.end()) {
        client = *it;
        return true;
    }
    return false;
}

bool ClientRegistry::hasClient(const ClientIdStruct& clientId) const
{
    return findClientIteratorById(clientId) != _clientRegistry.end();
}

bool ClientRegistry::hasClient(const std::string& username) const
{
    return std::any_of(_clientRegistry.begin(), _clientRegistry.end(),
        [&username](const ClientInfo& client) {
            return client.username == username;
        });
}

// ================================
// Key Management Methods
// ================================

bool ClientRegistry::setClientPublicKey(const ClientIdStruct& clientId, const PublicKeyStruct& publicKey)
{
    auto it = findClientIteratorById(clientId);
    if (it != _clientRegistry.end()) {
        it->publicKey = publicKey;
        it->publicKeySet = true;
        return true;
    }
    return false;
}

bool ClientRegistry::setClientSymmetricKey(const ClientIdStruct& clientId, const SymmetricKeyStruct& symmetricKey)
{
    auto it = findClientIteratorById(clientId);
    if (it != _clientRegistry.end()) {
        it->symmetricKey = symmetricKey;
        it->symmetricKeySet = true;
        return true;
    }
    return false;
}

bool ClientRegistry::getClientPublicKey(const ClientIdStruct& clientId, PublicKeyStruct& publicKey) const
{
    auto it = findClientIteratorById(clientId);
    if (it != _clientRegistry.end() && it->publicKeySet) {
        publicKey = it->publicKey;
        return true;
    }
    return false;
}

bool ClientRegistry::getClientSymmetricKey(const ClientIdStruct& clientId, SymmetricKeyStruct& symmetricKey) const
{
    auto it = findClientIteratorById(clientId);
    if (it != _clientRegistry.end() && it->symmetricKeySet) {
        symmetricKey = it->symmetricKey;
        return true;
    }
    return false;
}

// ================================
// Utility Methods
// ================================

std::vector<std::string> ClientRegistry::getAllUsernames() const
{
    std::vector<std::string> usernames;
    usernames.reserve(_clientRegistry.size());

    for (const auto& client : _clientRegistry) {
        usernames.push_back(client.username);
    }

    // Sort alphabetically
    std::sort(usernames.begin(), usernames.end());
    return usernames;
}

std::vector<ClientRegistry::ClientInfo> ClientRegistry::getAllClients() const
{
    return _clientRegistry;
}

void ClientRegistry::replaceRegistry(const std::vector<ClientInfo>& clients)
{
    _clientRegistry = clients;
}

// ================================
// Helper Methods
// ================================

std::vector<ClientRegistry::ClientInfo>::iterator ClientRegistry::findClientIteratorById(const ClientIdStruct& clientId)
{
    return std::find_if(_clientRegistry.begin(), _clientRegistry.end(),
        [&clientId](const ClientInfo& client) {
            return memcmp(&client.id, &clientId, sizeof(ClientIdStruct)) == 0;
        });
}

std::vector<ClientRegistry::ClientInfo>::const_iterator ClientRegistry::findClientIteratorById(const ClientIdStruct& clientId) const
{
    return std::find_if(_clientRegistry.begin(), _clientRegistry.end(),
        [&clientId](const ClientInfo& client) {
            return memcmp(&client.id, &clientId, sizeof(ClientIdStruct)) == 0;
        });
}