/**
 * @file        ClientRegistry.h
 * @author      Natanel Maor Fishman
 * @brief       Client management and registry component
 * @details     Manages client information storage, retrieval, and key management
 *              for the secure messaging system. Provides centralized client data handling.
 * @version     2.0
 * @date        2025
 */

#pragma once

#include <string>
#include <vector>
#include <algorithm>
#include "protocol.h"

/**
 * @class       ClientRegistry
 * @brief       Manages client information and key storage
 * @details     Centralizes client data management including user information,
 *              public keys, symmetric keys, and client lookup operations.
 *              Provides thread-safe access to client registry data.
 */
class ClientRegistry
{
public:
    // ================================
    // Data Structures
    // ================================

    /**
     * @struct      ClientInfo
     * @brief       Complete client information structure
     * @details     Contains all necessary information about a client including
     *              identification, authentication, and encryption keys.
     */
    struct ClientInfo
    {
        ClientIdStruct         id;               ///< Unique client identifier
        std::string            username;         ///< Client's display name
        PublicKeyStruct        publicKey;        ///< RSA public key for asymmetric encryption
        SymmetricKeyStruct     symmetricKey;     ///< Session encryption key for symmetric encryption
        bool                   publicKeySet;     ///< Flag indicating if public key is available
        bool                   symmetricKeySet;  ///< Flag indicating if symmetric key is available

        /**
         * @brief       Default constructor
         * @details     Initializes client info with default values
         */
        ClientInfo() : publicKeySet(false), symmetricKeySet(false)
        {
            memset(&id, 0, sizeof(id));
            memset(&publicKey, 0, sizeof(publicKey));
            memset(&symmetricKey, 0, sizeof(symmetricKey));
        }

        /**
         * @brief       Constructor with ID and username
         * @param[in]   clientId      Client identifier
         * @param[in]   clientName    Client username
         * @details     Creates client info with basic identification
         */
        ClientInfo(const ClientIdStruct& clientId, const std::string& clientName)
            : id(clientId), username(clientName), publicKeySet(false), symmetricKeySet(false)
        {
            memset(&publicKey, 0, sizeof(publicKey));
            memset(&symmetricKey, 0, sizeof(symmetricKey));
        }
    };

public:
    // ================================
    // Constructor and Destructor
    // ================================

    /**
     * @brief       Default constructor
     * @details     Creates empty client registry
     */
    ClientRegistry() = default;

    /**
     * @brief       Virtual destructor
     * @details     Ensures proper cleanup of client data
     */
    virtual ~ClientRegistry() = default;

    // Copy control (allowed for registry management)
    ClientRegistry(const ClientRegistry&) = default;
    ClientRegistry(ClientRegistry&&) noexcept = default;
    ClientRegistry& operator=(const ClientRegistry&) = default;
    ClientRegistry& operator=(ClientRegistry&&) noexcept = default;

    // ================================
    // Registry Management Methods
    // ================================

    /**
     * @brief       Clears all client entries from registry
     * @details     Removes all stored client information and keys
     */
    void clear();

    /**
     * @brief       Gets count of registered clients
     * @return      Number of clients in registry
     * @details     Returns current size of client registry
     */
    size_t size() const;

    /**
     * @brief       Checks if registry is empty
     * @return      true if registry is empty, false otherwise
     * @details     Indicates whether any clients are registered
     */
    bool empty() const;

    /**
     * @brief       Adds client to registry
     * @param[in]   client    Client information to add
     * @return      true if client added successfully, false if already exists
     * @details     Adds new client or updates existing client information
     */
    bool addClient(const ClientInfo& client);

    /**
     * @brief       Removes client from registry
     * @param[in]   clientId    Client ID to remove
     * @return      true if client removed, false if not found
     * @details     Removes client and all associated keys from registry
     */
    bool removeClient(const ClientIdStruct& clientId);

    /**
     * @brief       Updates existing client information
     * @param[in]   client    Updated client information
     * @return      true if client updated, false if not found
     * @details     Updates existing client data while preserving keys
     */
    bool updateClient(const ClientInfo& client);

    // ================================
    // Client Lookup Methods
    // ================================

    /**
     * @brief       Finds client by ID
     * @param[in]   clientId    Client ID to search for
     * @param[out]  client      Found client information
     * @return      true if client found, false otherwise
     * @details     Searches registry for client by unique identifier
     */
    bool findClientById(const ClientIdStruct& clientId, ClientInfo& client) const;

    /**
     * @brief       Finds client by username
     * @param[in]   username    Username to search for
     * @param[out]  client      Found client information
     * @return      true if client found, false otherwise
     * @details     Searches registry for client by display name
     */
    bool findClientByUsername(const std::string& username, ClientInfo& client) const;

    /**
     * @brief       Checks if client exists by ID
     * @param[in]   clientId    Client ID to check
     * @return      true if client exists, false otherwise
     * @details     Quick existence check without retrieving client data
     */
    bool hasClient(const ClientIdStruct& clientId) const;

    /**
     * @brief       Checks if client exists by username
     * @param[in]   username    Username to check
     * @return      true if client exists, false otherwise
     * @details     Quick existence check without retrieving client data
     */
    bool hasClient(const std::string& username) const;

    // ================================
    // Key Management Methods
    // ================================

    /**
     * @brief       Sets client's public key
     * @param[in]   clientId    Target client ID
     * @param[in]   publicKey   Public key to store
     * @return      true if key set successfully, false if client not found
     * @details     Updates client registry with public key for encryption
     */
    bool setClientPublicKey(const ClientIdStruct& clientId, const PublicKeyStruct& publicKey);

    /**
     * @brief       Sets client's symmetric key
     * @param[in]   clientId      Target client ID
     * @param[in]   symmetricKey  Symmetric key to store
     * @return      true if key set successfully, false if client not found
     * @details     Updates client registry with symmetric key for session encryption
     */
    bool setClientSymmetricKey(const ClientIdStruct& clientId, const SymmetricKeyStruct& symmetricKey);

    /**
     * @brief       Gets client's public key
     * @param[in]   clientId    Target client ID
     * @param[out]  publicKey   Retrieved public key
     * @return      true if key retrieved successfully, false if not available
     * @details     Retrieves stored public key for encryption operations
     */
    bool getClientPublicKey(const ClientIdStruct& clientId, PublicKeyStruct& publicKey) const;

    /**
     * @brief       Gets client's symmetric key
     * @param[in]   clientId      Target client ID
     * @param[out]  symmetricKey  Retrieved symmetric key
     * @return      true if key retrieved successfully, false if not available
     * @details     Retrieves stored symmetric key for session encryption
     */
    bool getClientSymmetricKey(const ClientIdStruct& clientId, SymmetricKeyStruct& symmetricKey) const;

    // ================================
    // Utility Methods
    // ================================

    /**
     * @brief       Gets sorted list of all usernames
     * @return      Vector of usernames (alphabetically sorted)
     * @details     Returns all registered usernames for display purposes
     */
    std::vector<std::string> getAllUsernames() const;

    /**
     * @brief       Gets all client information
     * @return      Vector of all client information structures
     * @details     Returns copy of all registered client data
     */
    std::vector<ClientInfo> getAllClients() const;

    /**
     * @brief       Replaces entire registry with new client list
     * @param[in]   clients    New client list
     * @details     Clears existing registry and adds all provided clients
     */
    void replaceRegistry(const std::vector<ClientInfo>& clients);

private:
    // ================================
    // Member Variables
    // ================================

    std::vector<ClientInfo> _clientRegistry;  ///< Client information storage

    // ================================
    // Helper Methods
    // ================================

    /**
     * @brief       Finds client iterator by ID
     * @param[in]   clientId    Client ID to search for
     * @return      Iterator to client or end() if not found
     * @details     Internal helper for client lookup operations
     */
    std::vector<ClientInfo>::iterator findClientIteratorById(const ClientIdStruct& clientId);

    /**
     * @brief       Finds const client iterator by ID
     * @param[in]   clientId    Client ID to search for
     * @return      Const iterator to client or end() if not found
     * @details     Internal helper for const client lookup operations
     */
    std::vector<ClientInfo>::const_iterator findClientIteratorById(const ClientIdStruct& clientId) const;
};