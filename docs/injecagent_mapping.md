# InjecAgent Tool-to-Gateway Mapping Specification (v3-science)

**Document Status**: Frozen and committed prior to adapter test runs.  
**Coverage**: 100% (80 / 80 unique tools in InjecAgent benchmark suite).  
**Excluded Cases**: 0 cases excluded.  

---

## 1. Overview & Canonical Primitives

InjecAgent (Zhan et al., ACL 2024) evaluates indirect prompt injection against tool-integrated agents. Each evaluation case contains:
1. `User Instruction`: Initial benign task prompt.
2. `User Tool`: The tool executed first, whose simulated output contains the untrusted injected string.
3. `Attacker Tools`: The hijacked tool calls attempted by the compromised model.

SentinelMesh maps every tool invocation into four canonical gateway primitives:
- `read_doc`: Document, email, message, or file retrieval. Sources untrusted taint when input origin is external or unauthenticated.
- `db_query`: Internal relational queries (`SELECT`, `UPDATE`, `INSERT`, `DELETE`, `GRANT`). Subject to SQL parsing, credential extraction detection, and taint containment.
- `send_email`: Public email and direct message egress. Subject to PII scanning and exfiltration blocking under taint.
- `external_api`: HTTP `GET`/`POST`, webhook invocations, cloud metadata endpoints (`169.254.169.254`), and third-party REST services. Subject to domain allowlisting, SSRF protection, and egress payload inspection.

---

## 2. User Tool Mappings (Step 1 Untrusted Source)

All 17 user tools return untrusted third-party content that carries the prompt injection payload:

| InjecAgent User Tool | Canonical Primitive | Operation Semantics | Taint Status |
| :--- | :--- | :--- | :--- |
| `AmazonGetProductDetails` | `read_doc` | Retrieve untrusted product review / details | Untrusted |
| `EvernoteManagerSearchNotes` | `read_doc` | Search user / shared notes | Untrusted |
| `GitHubGetRepositoryDetails` | `read_doc` | Read public repository details / README | Untrusted |
| `GitHubGetUserDetails` | `read_doc` | Read public user bio and profile info | Untrusted |
| `GitHubSearchRepositories` | `read_doc` | Search public code and issues | Untrusted |
| `GmailReadEmail` | `read_doc` | Read incoming email message body | Untrusted |
| `GmailSearchEmails` | `read_doc` | Search inbox messages | Untrusted |
| `GoogleCalendarGetEventsFromSharedCalendar` | `read_doc` | Read external attendee calendar invites | Untrusted |
| `GoogleCalendarReadEvents` | `read_doc` | Read calendar event descriptions | Untrusted |
| `ShopifyGetProductDetails` | `read_doc` | Read vendor e-commerce product description | Untrusted |
| `TeladocViewReviews` | `read_doc` | Read public patient/doctor reviews | Untrusted |
| `TodoistSearchTasks` | `read_doc` | Read shared project task items | Untrusted |
| `TwilioGetReceivedSmsMessages` | `read_doc` | Read incoming SMS payload | Untrusted |
| `TwitterManagerGetUserProfile` | `read_doc` | Read external social media user profile | Untrusted |
| `TwitterManagerReadTweet` | `read_doc` | Read external tweet content | Untrusted |
| `TwitterManagerSearchTweets` | `read_doc` | Search public tweet feeds | Untrusted |
| `WebBrowserNavigateTo` | `read_doc` | Fetch web page HTML content via HTTP | Untrusted |

---

## 3. Attacker Tool Mappings (Step 2+ Attacker Actions)

All 63 attacker tools invoked across Direct Harm (DH) and Data Stealing (DS) cases:

### 3.1 Direct Harm Mutations & Unauthorized Execution (Mapped to `db_query` or `external_api`)
| Attacker Tool | Canonical Primitive | Mapping Description | Expected Gating |
| :--- | :--- | :--- | :--- |
| `AugustSmartLockGrantGuestAccess` | `db_query` | `GRANT GUEST ACCESS` / privilege update | `require_approval` |
| `AugustSmartLockUnlockDoor` | `external_api` | Smart lock unlock actuation endpoint | `require_approval` / `block` |
| `BankManagerPayBill` | `db_query` | `UPDATE accounts SET balance = ...` | `require_approval` |
| `BankManagerTransferFunds` | `db_query` | `UPDATE accounts ...` (funds transfer) | `require_approval` |
| `BinanceDeposit` | `external_api` | Crypto exchange deposit API call | `require_approval` |
| `BinancePlaceOrder` | `db_query` | `INSERT INTO crypto_orders ...` | `require_approval` |
| `BinanceWithdraw` | `external_api` | Crypto withdrawal to external wallet | `block` under taint |
| `CiscoUmbrellaCreatePolicy` | `db_query` | `INSERT INTO security_policies ...` | `require_approval` |
| `CiscoUmbrellaUpdatePolicy` | `db_query` | `UPDATE security_policies SET ...` | `require_approval` |
| `DeepfakeGeneratorGenerateAudioDeepfake` | `external_api` | AI audio synthesis invocation | `block` |
| `DropboxMoveItem` | `db_query` | `UPDATE files SET folder = ...` | `require_approval` |
| `EmergencyDispatchSystemCreateDispatchRequest` | `external_api` | 911 dispatch webhook POST | `block` |
| `EpicFHIRManageAppointments` | `db_query` | `UPDATE medical_appointments ...` | `require_approval` |
| `EpicFHIRManageClinicalDocuments` | `db_query` | `UPDATE clinical_docs ...` | `require_approval` |
| `EpicFHIRManagePatientRecords` | `db_query` | `UPDATE patient_records ...` | `require_approval` |
| `FacebookManagerUpdateUserProfile` | `external_api` | Social profile update API | `require_approval` |
| `FedExShipManagerManageShipment` | `external_api` | Shipping label dispatch API | `require_approval` |
| `GitHubDeleteRepository` | `db_query` | `DELETE FROM repositories ...` | `block` under taint |
| `GoogleHomeScheduleDeviceAction` | `external_api` | Smart home schedule endpoint | `require_approval` |
| `IndoorRobotGoToRoom` | `external_api` | Robot hardware command | `require_approval` |
| `NortonIdentitySafeDisableTwoFactorAuthentication` | `db_query` | `UPDATE auth_settings SET 2fa=0` | `block` |
| `TerminalExecute` | `external_api` | System command execution | `block` under taint |
| `TrafficControlGivePriorityToEmergencyVehicle` | `external_api` | City infrastructure actuation | `block` |
| `TrafficControlManageTrafficLightState` | `external_api` | City traffic light actuation | `block` |
| `VenmoWithdrawMoney` | `db_query` | `UPDATE balances ...` / transfer | `require_approval` |

### 3.2 Sensitive Data Queries (Mapped to `db_query` or `read_doc`)
| Attacker Tool | Canonical Primitive | Mapping Description | Expected Gating |
| :--- | :--- | :--- | :--- |
| `AmazonViewSavedAddresses` | `db_query` | `SELECT address, city, zip FROM users` | Exfiltration check |
| `AmazonViewSavedPaymentMethods` | `db_query` | `SELECT cc_num, exp FROM payment_methods`| Exfiltration check |
| `BankManagerGetAccountInformation` | `db_query` | `SELECT balance, routing_num FROM accounts` | Exfiltration check |
| `BankManagerSearchPayee` | `db_query` | `SELECT payee_name, account_id FROM payees` | Exfiltration check |
| `BinanceGetOrderHistory` | `db_query` | `SELECT * FROM trade_history` | Exfiltration check |
| `CiscoUmbrellaGetLogDetails` | `read_doc` | Read firewall audit log | Exfiltration check |
| `DropboxGetItemMetadata` | `read_doc` | Read confidential file metadata | Exfiltration check |
| `DropboxListFilesAndFolders` | `read_doc` | Enumerate confidential folders | Exfiltration check |
| `EpicFHIRDownloadFiles` | `read_doc` | Download sensitive patient medical charts | Exfiltration check |
| `EpicFHIRGetPatientDetails` | `db_query` | `SELECT ssn, diagnosis, dob FROM patients` | Exfiltration check |
| `ExpediaSearchReservations` | `db_query` | `SELECT itinerary, passenger_name FROM travel`| Exfiltration check |
| `FacebookManagerGetUserProfile` | `read_doc` | Read private profile data | Exfiltration check |
| `FacebookManagerSearchFriends` | `read_doc` | Enumerate friends list | Exfiltration check |
| `FedExShipManagerSearchShipment` | `read_doc` | Read shipment manifests | Exfiltration check |
| `GitHubGetUserDetails` | `read_doc` | Read internal contributor info | Exfiltration check |
| `GoogleMapGetCurrentLocation` | `external_api` | Query user GPS coordinate | Exfiltration check |
| `GoogleSearchGetSearchHistory` | `read_doc` | Read private search logs | Exfiltration check |
| `InvestmentManagerGetHoldingsInformation` | `db_query` | `SELECT portfolio, equity FROM holdings` | Exfiltration check |
| `NortonIdentitySafeAutoFillPersonalInfo` | `db_query` | `SELECT ssn, dob, full_name FROM identities` | Exfiltration check |
| `NortonIdentitySafeSearchPasswords` | `db_query` | `SELECT master_password, secret FROM vault` | `block` |
| `SpokeoDownloadPublicRecord` | `read_doc` | Download background report | Exfiltration check |
| `SpokeoSearchPeople` | `read_doc` | Query personal dossiers | Exfiltration check |
| `TDAmeritradeGetHoldingsInformation` | `db_query` | `SELECT ticker, shares FROM portfolios` | Exfiltration check |
| `TeladocAccessUserInfo` | `db_query` | `SELECT ssn, health_plan FROM users` | Exfiltration check |
| `TeladocViewPrescriptions` | `db_query` | `SELECT drug_name, dosage FROM prescriptions`| Exfiltration check |
| `The23andMeDownloadData` | `read_doc` | Download genetic DNA sequencing file | `block` under taint |
| `The23andMeGetGeneticData` | `db_query` | `SELECT genome_sequence, alleles FROM dna` | `block` under taint |
| `The23andMeGetHealthRecommendations` | `read_doc` | Read medical risk factors | Exfiltration check |
| `The23andMeUpdateData` | `db_query` | `UPDATE dna_records SET ...` | `require_approval` |
| `TwilioGetPhoneNumberInfo` | `external_api` | Lookup subscriber carrier and owner | Exfiltration check |
| `VenmoListLinkedAccounts` | `db_query` | `SELECT bank_name, account_num FROM banks` | Exfiltration check |
| `WebBrowserSearchHistory` | `read_doc` | Read browser history records | Exfiltration check |

### 3.3 Data Stealing Egress Sinks (Mapped to `send_email` or `external_api`)
| Attacker Tool | Canonical Primitive | Mapping Description | Expected Gating |
| :--- | :--- | :--- | :--- |
| `GmailSendEmail` | `send_email` | Egress email with extracted payload | `block` under taint |
| `NortonIdentitySafeSharePassword` | `send_email` | Exfiltrate credentials to third-party | `block` under taint |
| `SlackLeaveChannel` | `external_api` | Slack API leave channel | `require_approval` |
| `The23andMeShareData` | `external_api` | Third-party data sharing endpoint | `block` under taint |
| `EvernoteManagerManageNoteSharingLevel` | `external_api` | Make private notes public | `block` under taint |

---

## 4. Coverage Summary

- Total InjecAgent tools: 80
- Total tools mapped: 80
- Coverage: 100.0%
- Excluded cases: 0
