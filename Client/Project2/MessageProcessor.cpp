/**
 * @file        MessageProcessor.cpp
 * @author      Natanel Maor Fishman
 * @brief       Implementation of message processing and handling
 * @details     Processes different message types with encryption/decryption,
 *              validation, and formatting for the secure messaging system.
 * @date        2025
 */

#include "MessageProcessor.h"
#include "CryptoManager.h"
#include "ConfigManager.h"
#include "StringUtility.h"
#include <sstream>
#include <cstring>

// ================================
// Constructor and Destructor
// ================================

MessageProcessor::MessageProcessor(CryptoManager* cryptoManager, ConfigManager* configManager)
    : _cryptoManager(cryptoManager), _configManager(configManager)
{
    // Initialize with provided dependencies
}

// ================================
// Message Processing Methods
// ================================

MessageProcessor::ProcessedMessage MessageProcessor::processMessage(
    const PendingMessageStruct& header,
    const uint8_t* payloadData,
    const ClientInfo& client,
    std::string& errorMessage)
{
    errorMessage.clear();

    if (!validateMessageHeader(header)) {
        errorMessage = "Invalid message header";
        return createErrorMessage(client, errorMessage);
    }

    switch (header.messageType) {
        case MSG_SYMMETRIC_KEY_REQUEST:
            return processSymmetricKeyRequest(header, client);

        case MSG_SYMMETRIC_KEY_SEND:
        {
            SymmetricKeyStruct symmetricKey;
            return processSymmetricKey(header, payloadData, client, symmetricKey, errorMessage);
        }

        case MSG_TEXT:
            return processTextMessage(header, payloadData, client, errorMessage);

        case MSG_FILE:
            return processFileMessage(header, payloadData, client, errorMessage);

        default:
            errorMessage = "Unknown message type";
            return createErrorMessage(client, errorMessage);
    }
}

MessageProcessor::ProcessedMessage MessageProcessor::processSymmetricKeyRequest(
    const PendingMessageStruct& header,
    const ClientInfo& client)
{
    ProcessedMessage message;
    message.username = client.username;
    message.content = "Request for symmetric key";
    message.isValid = true;
    return message;
}

MessageProcessor::ProcessedMessage MessageProcessor::processSymmetricKey(
    const PendingMessageStruct& header,
    const uint8_t* payloadData,
    const ClientInfo& client,
    SymmetricKeyStruct& symmetricKey,
    std::string& errorMessage)
{
    if (header.messageSize == 0 || !payloadData) {
        errorMessage = "Invalid symmetric key (empty content)";
        return createErrorMessage(client, errorMessage);
    }

    if (!_cryptoManager || !_cryptoManager->isRSAInitialized()) {
        errorMessage = "Cryptographic engine not available";
        return createErrorMessage(client, errorMessage);
    }

    std::string decryptedKey = _cryptoManager->decryptRSA(payloadData, header.messageSize);
    if (decryptedKey.empty()) {
        errorMessage = "Failed to decrypt symmetric key";
        return createErrorMessage(client, errorMessage);
    }

    if (decryptedKey.size() != SYMMETRIC_KEY_LENGTH) {
        std::stringstream ss;
        ss << "Invalid symmetric key length (" << decryptedKey.size() << ")";
        errorMessage = ss.str();
        return createErrorMessage(client, errorMessage);
    }

    // Extract symmetric key
    memcpy(symmetricKey.symmetricKey, decryptedKey.c_str(), SYMMETRIC_KEY_LENGTH);

    ProcessedMessage message;
    message.username = client.username;
    message.content = "Symmetric key received";
    message.isValid = true;
    return message;
}

MessageProcessor::ProcessedMessage MessageProcessor::processTextMessage(
    const PendingMessageStruct& header,
    const uint8_t* payloadData,
    const ClientInfo& client,
    std::string& errorMessage)
{
    if (header.messageSize == 0 || !payloadData) {
        errorMessage = "Empty message content";
        return createErrorMessage(client, errorMessage);
    }

    if (!client.symmetricKeySet) {
        errorMessage = "Cannot decrypt message";
        return createErrorMessage(client, errorMessage);
    }

    std::string decryptedText = _cryptoManager->decryptAES(client.symmetricKey, payloadData, header.messageSize);
    if (decryptedText.empty()) {
        errorMessage = "Failed to decrypt message";
        return createErrorMessage(client, errorMessage);
    }

    ProcessedMessage message;
    message.username = client.username;
    message.content = decryptedText;
    message.isValid = true;
    return message;
}

MessageProcessor::ProcessedMessage MessageProcessor::processFileMessage(
    const PendingMessageStruct& header,
    const uint8_t* payloadData,
    const ClientInfo& client,
    std::string& errorMessage)
{
    if (header.messageSize == 0 || !payloadData) {
        errorMessage = "Empty file content";
        return createErrorMessage(client, errorMessage);
    }

    if (!client.symmetricKeySet) {
        errorMessage = "Cannot decrypt file";
        return createErrorMessage(client, errorMessage);
    }

    std::string decryptedData = _cryptoManager->decryptAES(client.symmetricKey, payloadData, header.messageSize);
    if (decryptedData.empty()) {
        errorMessage = "Failed to decrypt file";
        return createErrorMessage(client, errorMessage);
    }

    // Generate file path and save
    std::string filePath = generateFilePath(client.username);
    if (!_configManager->writeFileComplete(filePath, decryptedData)) {
        errorMessage = "Failed to save file";
        return createErrorMessage(client, errorMessage);
    }

    ProcessedMessage message;
    message.username = client.username;
    message.content = filePath;
    message.isValid = true;
    return message;
}

// ================================
// Message Creation Methods
// ================================

bool MessageProcessor::prepareSymmetricKeyMessage(
    const ClientInfo& targetClient,
    std::string& encryptedKey,
    SymmetricKeyStruct& symmetricKey)
{
    if (!targetClient.publicKeySet) {
        return false;
    }

    // Generate new symmetric key
    symmetricKey = _cryptoManager->generateAESKey();

    // Encrypt symmetric key with recipient's public key
    encryptedKey = _cryptoManager->encryptRSA(targetClient.publicKey, 
                                             symmetricKey.symmetricKey, 
                                             sizeof(symmetricKey.symmetricKey));

    return !encryptedKey.empty();
}

bool MessageProcessor::prepareTextMessage(
    const std::string& message,
    const ClientInfo& targetClient,
    std::string& encryptedData)
{
    if (message.empty() || !targetClient.symmetricKeySet) {
        return false;
    }

    encryptedData = _cryptoManager->encryptAES(targetClient.symmetricKey, message);
    return !encryptedData.empty();
}

bool MessageProcessor::prepareFileMessage(
    const std::string& filePath,
    const ClientInfo& targetClient,
    std::string& encryptedData)
{
    if (filePath.empty() || !targetClient.symmetricKeySet) {
        return false;
    }

    uint8_t* fileData = nullptr;
    size_t fileSize = 0;

    if (!_configManager->readFileComplete(filePath, fileData, fileSize)) {
        return false;
    }

    encryptedData = _cryptoManager->encryptAES(targetClient.symmetricKey, fileData, fileSize);
    
    delete[] fileData;
    return !encryptedData.empty();
}

// ================================
// Utility Methods
// ================================

std::string MessageProcessor::generateFilePath(const std::string& senderUsername)
{
    if (!_configManager) {
        return "";
    }

    std::stringstream filepath;
    filepath << _configManager->getTemporaryDirectory() 
             << "\\MessageU\\" 
             << senderUsername 
             << "_" 
             << StringUtility::getTimestamp();
    
    return filepath.str();
}

// ================================
// Helper Methods
// ================================

bool MessageProcessor::validateMessageHeader(const PendingMessageStruct& header)
{
    // Basic validation of message header fields
    return (header.messageType >= MSG_SYMMETRIC_KEY_REQUEST && 
            header.messageType <= MSG_FILE);
}

MessageProcessor::ProcessedMessage MessageProcessor::createErrorMessage(
    const ClientInfo& client, 
    const std::string& errorText)
{
    ProcessedMessage message;
    message.username = client.username;
    message.content = errorText;
    message.isValid = false;
    return message;
}