/**
 * @file        MessageProcessor.h
 * @author      Natanel Maor Fishman
 * @brief       Message processing and handling component
 * @details     Handles message parsing, formatting, validation, and processing
 *              operations for different message types in the secure messaging system.
 * @version     2.0
 * @date        2025
 */

#pragma once

#include <string>
#include <vector>
#include "protocol.h"

// Forward declarations
class CryptoManager;
class ConfigManager;

/**
 * @class       MessageProcessor
 * @brief       Processes and handles different types of messages
 * @details     Centralizes message processing logic including parsing, validation,
 *              encryption/decryption, and formatting for display. Handles all
 *              message types supported by the messaging protocol.
 */
class MessageProcessor
{
public:
    // ================================
    // Data Structures
    // ================================

    /**
     * @struct      ProcessedMessage
     * @brief       Processed message data for display
     * @details     Contains formatted message information ready for user interface
     */
    struct ProcessedMessage
    {
        std::string username;   ///< Source username
        std::string content;    ///< Message content or file path
        bool        isValid;    ///< Message processing status
    };

    /**
     * @struct      ClientInfo
     * @brief       Client information structure (local copy)
     * @details     Contains client identification and cryptographic keys
     */
    struct ClientInfo
    {
        ClientIdStruct         id;               ///< Unique client identifier
        std::string            username;         ///< Client's display name
        PublicKeyStruct        publicKey;        ///< RSA public key
        SymmetricKeyStruct     symmetricKey;     ///< Session encryption key
        bool                   publicKeySet;     ///< Public key availability flag
        bool                   symmetricKeySet;  ///< Symmetric key availability flag
    };

public:
    // ================================
    // Constructor and Destructor
    // ================================

    /**
     * @brief       Constructor with dependencies
     * @param[in]   cryptoManager    Cryptographic operations manager
     * @param[in]   configManager    Configuration management interface
     * @details     Initializes message processor with required dependencies
     */
    MessageProcessor(CryptoManager* cryptoManager, ConfigManager* configManager);

    /**
     * @brief       Virtual destructor
     * @details     Cleans up resources and ensures proper destruction
     */
    virtual ~MessageProcessor() = default;

    // Copy control (deleted for safety)
    MessageProcessor(const MessageProcessor&) = delete;
    MessageProcessor(MessageProcessor&&) noexcept = delete;
    MessageProcessor& operator=(const MessageProcessor&) = delete;
    MessageProcessor& operator=(MessageProcessor&&) noexcept = delete;

    // ================================
    // Message Processing Methods
    // ================================

    /**
     * @brief       Processes a single message from server payload
     * @param[in]   header          Message header structure
     * @param[in]   payloadData     Raw message payload data
     * @param[in]   client          Sender client information
     * @param[out]  errorMessage    Error description if processing fails
     * @return      Processed message structure
     * @details     Handles decryption, validation, and formatting based on message type
     */
    ProcessedMessage processMessage(const PendingMessageStruct& header,
                                   const uint8_t* payloadData,
                                   const ClientInfo& client,
                                   std::string& errorMessage);

    /**
     * @brief       Processes symmetric key request message
     * @param[in]   header    Message header
     * @param[in]   client    Sender information
     * @return      Processed message structure
     * @details     Formats symmetric key request for display
     */
    ProcessedMessage processSymmetricKeyRequest(const PendingMessageStruct& header,
                                               const ClientInfo& client);

    /**
     * @brief       Processes symmetric key delivery message
     * @param[in]   header          Message header
     * @param[in]   payloadData     Encrypted symmetric key data
     * @param[in]   client          Sender information
     * @param[out]  symmetricKey    Extracted symmetric key
     * @param[out]  errorMessage    Error description if processing fails
     * @return      Processed message structure
     * @details     Decrypts and validates received symmetric key
     */
    ProcessedMessage processSymmetricKey(const PendingMessageStruct& header,
                                        const uint8_t* payloadData,
                                        const ClientInfo& client,
                                        SymmetricKeyStruct& symmetricKey,
                                        std::string& errorMessage);

    /**
     * @brief       Processes text message
     * @param[in]   header          Message header
     * @param[in]   payloadData     Encrypted message data
     * @param[in]   client          Sender information
     * @param[out]  errorMessage    Error description if processing fails
     * @return      Processed message structure
     * @details     Decrypts and formats text message for display
     */
    ProcessedMessage processTextMessage(const PendingMessageStruct& header,
                                       const uint8_t* payloadData,
                                       const ClientInfo& client,
                                       std::string& errorMessage);

    /**
     * @brief       Processes file message
     * @param[in]   header          Message header
     * @param[in]   payloadData     Encrypted file data
     * @param[in]   client          Sender information
     * @param[out]  errorMessage    Error description if processing fails
     * @return      Processed message structure
     * @details     Decrypts file data and saves to temporary location
     */
    ProcessedMessage processFileMessage(const PendingMessageStruct& header,
                                       const uint8_t* payloadData,
                                       const ClientInfo& client,
                                       std::string& errorMessage);

    // ================================
    // Message Creation Methods
    // ================================

    /**
     * @brief       Prepares symmetric key message for transmission
     * @param[in]   targetClient     Recipient client information
     * @param[out]  encryptedKey     Encrypted symmetric key data
     * @param[out]  keySize          Size of encrypted key
     * @param[out]  symmetricKey     Generated symmetric key for storage
     * @return      true if preparation successful, false otherwise
     * @details     Generates symmetric key and encrypts with recipient's public key
     */
    bool prepareSymmetricKeyMessage(const ClientInfo& targetClient,
                                   std::string& encryptedKey,
                                   SymmetricKeyStruct& symmetricKey);

    /**
     * @brief       Prepares text message for transmission
     * @param[in]   message          Plain text message
     * @param[in]   targetClient     Recipient client information
     * @param[out]  encryptedData    Encrypted message data
     * @return      true if preparation successful, false otherwise
     * @details     Encrypts text message with shared symmetric key
     */
    bool prepareTextMessage(const std::string& message,
                           const ClientInfo& targetClient,
                           std::string& encryptedData);

    /**
     * @brief       Prepares file message for transmission
     * @param[in]   filePath         Path to file to send
     * @param[in]   targetClient     Recipient client information
     * @param[out]  encryptedData    Encrypted file data
     * @return      true if preparation successful, false otherwise
     * @details     Reads file data and encrypts with shared symmetric key
     */
    bool prepareFileMessage(const std::string& filePath,
                           const ClientInfo& targetClient,
                           std::string& encryptedData);

    // ================================
    // Utility Methods
    // ================================

    /**
     * @brief       Generates file save path with timestamp
     * @param[in]   senderUsername    Sender's username
     * @return      Generated file path string
     * @details     Creates unique file path in temporary directory
     */
    std::string generateFilePath(const std::string& senderUsername);

private:
    // ================================
    // Member Variables
    // ================================

    CryptoManager* _cryptoManager;   ///< Cryptographic operations interface
    ConfigManager* _configManager;   ///< Configuration management interface

    // ================================
    // Helper Methods
    // ================================

    /**
     * @brief       Validates message structure integrity
     * @param[in]   header    Message header to validate
     * @return      true if header is valid, false otherwise
     * @details     Checks header fields for consistency and validity
     */
    bool validateMessageHeader(const PendingMessageStruct& header);

    /**
     * @brief       Creates error message structure
     * @param[in]   client        Client information
     * @param[in]   errorText     Error description
     * @return      Error message structure
     * @details     Creates standardized error message for display
     */
    ProcessedMessage createErrorMessage(const ClientInfo& client, const std::string& errorText);
};