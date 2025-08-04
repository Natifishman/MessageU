# 🏗️ MessageU Architecture Refactoring Plan

## 📋 Current Status
✅ **Analysis Complete** - Identified monolithic MessageEngine class  
✅ **Architecture Designed** - Clean layered architecture with DI  
✅ **Interfaces Created** - Abstract interfaces for all infrastructure  
✅ **Core Services Created** - Business logic separated into services  
✅ **Entities Created** - Domain models with proper encapsulation  
✅ **Application Orchestrator** - Main coordinator with DI  

## 🎯 New Architecture Overview

### 📁 Complete Directory Structure
```
MessageU/
├── Client/
│   ├── Core/                           # ✅ CREATED
│   │   ├── Application/
│   │   │   └── MessageUApplication.h   # Main orchestrator
│   │   ├── Services/
│   │   │   ├── UserService.h           # User management business logic
│   │   │   ├── MessageService.h        # Message processing business logic
│   │   │   └── KeyService.h            # Key management business logic
│   │   ├── Entities/
│   │   │   ├── User.h                  # User domain entity
│   │   │   ├── Message.h               # Message domain entity
│   │   │   └── ClientInfo.h            # Client information entity
│   │   └── Interfaces/
│   │       ├── INetworkManager.h       # Network abstraction
│   │       ├── ICryptoManager.h        # Crypto abstraction
│   │       └── IConfigManager.h        # Config abstraction
│   ├── Infrastructure/                 # 🔄 TO BE MIGRATED
│   │   ├── Network/
│   │   │   ├── NetworkManager.h/cpp    # ← NetworkConnection.*
│   │   │   └── TcpConnection.h/cpp
│   │   ├── Crypto/
│   │   │   ├── CryptoManager.h/cpp     # ← Combines RSA+AES wrappers
│   │   │   ├── AESWrapper.h/cpp        # ← Existing AESWrapper.*
│   │   │   └── RSAWrapper.h/cpp        # ← Existing RSAWrapper.*
│   │   ├── Configuration/
│   │   │   └── ConfigManager.h/cpp     # ← Existing ConfigManager.*
│   │   └── Utils/
│   │       └── StringUtility.h/cpp     # ← Existing StringUtility.*
│   ├── UI/                            # 🔄 TO BE REFACTORED
│   │   ├── ConsoleInterface.h/cpp      # ← Existing ConsoleInterface.*
│   │   └── MenuManager.h/cpp           # New menu handling
│   ├── Common/
│   │   └── protocol.h                  # ✅ CREATED - Common definitions
│   ├── Tests/                         # 🆕 NEW TESTING STRUCTURE
│   │   ├── Unit/
│   │   │   ├── Services/
│   │   │   ├── Entities/
│   │   │   └── Infrastructure/
│   │   ├── Integration/
│   │   │   └── EndToEnd/
│   │   └── Mocks/
│   │       ├── MockNetworkManager.h
│   │       ├── MockCryptoManager.h
│   │       └── MockConfigManager.h
│   ├── main_refactored.cpp            # ✅ CREATED - New DI entry point
│   └── CMakeLists.txt                 # New build configuration
└── Server/                            # ✅ ALREADY WELL STRUCTURED
    ├── core/
    ├── infrastructure/
    └── main.py
```

## 🔄 Migration Strategy

### Phase 1: Infrastructure Adapters (Week 1)
**Goal:** Create adapters that implement new interfaces while wrapping existing code

1. **NetworkManager Implementation**
   ```cpp
   class NetworkManager : public INetworkManager {
   private:
       std::unique_ptr<NetworkConnection> m_connection; // Wrap existing
   public:
       bool connect(const std::string& address, int port) override {
           return m_connection->connect(address, port);
       }
       // ... implement all interface methods
   };
   ```

2. **CryptoManager Implementation**
   ```cpp
   class CryptoManager : public ICryptoManager {
   private:
       std::unique_ptr<RSAPrivateWrapper> m_rsa; // Wrap existing
       std::map<ClientIdStruct, AESWrapper> m_aesKeys; // Manage AES keys
   public:
       bool generateRSAKeyPair() override {
           m_rsa = std::make_unique<RSAPrivateWrapper>();
           return m_rsa != nullptr;
       }
       // ... implement all interface methods
   };
   ```

3. **ConfigManager Adapter**
   ```cpp
   class ConfigManager : public IConfigManager {
   private:
       std::unique_ptr<::ConfigManager> m_config; // Wrap existing
   public:
       bool loadServerInfo(std::string& address, int& port) override {
           // Use existing ConfigManager logic
       }
       // ... implement all interface methods
   };
   ```

### Phase 2: Service Implementations (Week 2)
**Goal:** Implement business logic services with proper error handling

1. **UserService Implementation**
   - User registration workflow
   - User list management
   - Public key requests
   - User validation and caching

2. **MessageService Implementation**
   - Message encryption/decryption workflows
   - Message type handling (text, file, keys)
   - Message sending and receiving
   - Content validation

### Phase 3: Entity Implementations (Week 3)
**Goal:** Create robust domain entities with validation

1. **User Entity**
   - Username validation
   - Key management
   - Protocol conversion
   - Safe display methods

2. **Message Entity**
   - Content handling
   - Type-specific behavior
   - Timestamp management
   - Security helpers

### Phase 4: Application Integration (Week 4)
**Goal:** Wire everything together with dependency injection

1. **MessageUApplication Implementation**
   - Service coordination
   - Error aggregation
   - State management
   - Connection lifecycle

2. **Updated ConsoleInterface**
   - Use MessageUApplication instead of MessageEngine
   - Cleaner menu handling
   - Better error display
   - Async operation support

## 🧪 Testing Strategy

### Unit Tests Structure
```cpp
// Example: UserService Unit Test
class UserServiceTest : public ::testing::Test {
protected:
    void SetUp() override {
        mockNetwork = std::make_shared<MockNetworkManager>();
        mockCrypto = std::make_shared<MockCryptoManager>();
        mockConfig = std::make_shared<MockConfigManager>();
        
        userService = std::make_unique<UserService>(
            mockNetwork, mockCrypto, mockConfig
        );
    }
    
    std::shared_ptr<MockNetworkManager> mockNetwork;
    std::shared_ptr<MockCryptoManager> mockCrypto;
    std::shared_ptr<MockConfigManager> mockConfig;
    std::unique_ptr<UserService> userService;
};

TEST_F(UserServiceTest, RegisterUser_ValidUsername_ReturnsUser) {
    // Arrange
    EXPECT_CALL(*mockNetwork, sendRequest(_, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*mockCrypto, generateRSAKeyPair())
        .WillOnce(Return(true));
    
    // Act
    auto result = userService->registerUser("testuser");
    
    // Assert
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->getUsername(), "testuser");
}
```

### Integration Tests
```cpp
// Example: End-to-end message sending test
TEST(IntegrationTest, SendTextMessage_EndToEnd) {
    // Use real implementations but test server
    auto app = createTestApplication();
    
    ASSERT_TRUE(app->connectToServer());
    ASSERT_TRUE(app->registerUser("sender"));
    ASSERT_TRUE(app->registerUser("recipient"));
    
    EXPECT_TRUE(app->sendTextMessage("recipient", "Hello, World!"));
    
    auto messages = app->fetchPendingMessages();
    ASSERT_FALSE(messages.empty());
    EXPECT_EQ(messages[0].getContentAsString(), "Hello, World!");
}
```

## 📊 Benefits of New Architecture

### 1. **Testability** 🧪
- **Before:** Cannot test MessageEngine without real network/crypto
- **After:** Each service can be tested with mocks independently

### 2. **Maintainability** 🔧
- **Before:** 1000+ line MessageEngine handles everything
- **After:** Small, focused classes with single responsibility

### 3. **Extensibility** 🚀
- **Before:** Adding features requires modifying MessageEngine
- **After:** New features can be added as new services

### 4. **Debugging** 🐛
- **Before:** Hard to isolate issues in monolithic class
- **After:** Clear error boundaries between layers

### 5. **Performance** ⚡
- **Before:** Everything loaded at startup
- **After:** Lazy loading and better resource management

## 🎯 Migration Checklist

### Infrastructure Layer
- [ ] Implement NetworkManager adapter
- [ ] Implement CryptoManager adapter  
- [ ] Implement ConfigManager adapter
- [ ] Create utility adaptations
- [ ] Add comprehensive error handling

### Business Logic Layer
- [ ] Implement UserService
- [ ] Implement MessageService
- [ ] Add input validation
- [ ] Add business rule enforcement
- [ ] Create service integration tests

### Domain Layer
- [ ] Implement User entity
- [ ] Implement Message entity
- [ ] Add domain validation
- [ ] Add entity conversion methods
- [ ] Create entity unit tests

### Application Layer
- [ ] Implement MessageUApplication
- [ ] Add dependency injection setup
- [ ] Create application lifecycle management
- [ ] Add application-level error handling
- [ ] Create integration tests

### Presentation Layer
- [ ] Refactor ConsoleInterface
- [ ] Update menu system
- [ ] Improve error display
- [ ] Add async operation support
- [ ] Create UI tests

### Testing Infrastructure
- [ ] Create mock implementations
- [ ] Set up unit test framework
- [ ] Create integration test setup
- [ ] Add performance tests
- [ ] Create test documentation

## 🚀 Expected Outcomes

After completing this refactoring:

1. **Code Quality Score**: 85 → 95
2. **Test Coverage**: 0% → 80%+
3. **Maintainability Index**: Medium → High
4. **Bug Detection**: Reactive → Proactive
5. **Development Speed**: Slower → Faster (after initial investment)

## 📝 Implementation Notes

### Backward Compatibility
- Keep existing files for reference during migration
- Use adapter pattern to wrap legacy code initially
- Gradually replace adapters with native implementations

### Performance Considerations
- Use smart pointers for memory management
- Implement move semantics where appropriate
- Consider object pooling for frequently created entities
- Add performance profiling hooks

### Security Enhancements
- Separate sensitive operations into dedicated services
- Add audit logging for security events
- Implement secure cleanup in destructors
- Add input sanitization at service boundaries

This refactoring transforms MessageU from a monolithic application into a modern, testable, and maintainable system following clean architecture principles.