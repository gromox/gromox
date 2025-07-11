#pragma once
/*
 * “COM specifies which values in a HRESULT are treated as errors, and which
 * aren't. […] there is a HRESULT_FROM_WIN32 function […] to convert a Win32
 * error code to a HRESULT.” –https://stackoverflow.com/a/28318589
 *
 * 8003xxxx: FACILITY_STORAGE
 * 8004xxxx: FACILITY_ITF (interface-specific)
 * 8007xxxx: FACILITY_WIN32
 * 8019xxxx: FACILITY_HTTP
 *
 * Needless to say MSMAPI messed this up, with some MAPI_E_* defined as
 * in-facility codes (< 0xffff) and some as COM HRESULTs (0x8xxxxxxx).
 *
 * -- Changes here should be reflected in lib/errno.cpp.
 */
#ifdef COMPILE_DIAG
enum ec_error_t_ll
#else
enum ec_error_t
#endif
{
	ecSuccess = 0, // ecNone
	MAPI_E_UNBINDSUCCESS = 1, /* NSPI */
	// MAPI_E_USER_ABORT = 0x1,
	// MAPI_E_FAILURE = 0x2,
	// MAPI_E_LOGON_FAILURE = 0x3,
	// MAPI_E_DISK_FULL = 0x4,
	// MAPI_E_INSUFFICIENT_MEMORY = 0x5,
	// MAPI_E_ACCESS_DENIED = 0x6,
	// MAPI_E_TOO_MANY_SESSIONS = 0x8,
	// MAPI_E_TOO_MANY_FILES = 0x9,
	// MAPI_E_TOO_MANY_RECIPIENTS = 0xA,
	// MAPI_E_ATTACHMENT_NOT_FOUND = 0xB,
	// MAPI_E_ATTACHMENT_OPEN_FAILURE = 0xC,
	// MAPI_E_ATTACHMENT_WRITE_FAILURE = 0xD,
	// MAPI_E_UNKNOWN_RECIPIENT = 0xE,
	// MAPI_E_BAD_RECIPTYPE = 0xF,
	// MAPI_E_NO_MESSAGES = 0x10,
	// MAPI_E_INVALID_MESSAGE = 0x11,
	// MAPI_E_TEXT_TOO_LARGE = 0x12,
	// MAPI_E_INVALID_SESSION = 0x13,
	// MAPI_E_TYPE_NOT_SUPPORTED = 0x14,
	// MAPI_E_AMBIGUOUS_RECIPIENT = 0x15,
	// MAPI_E_MESSAGE_IN_USE = 0x16,
	// MAPI_E_NETWORK_FAILURE = 0x17,
	// MAPI_E_INVALID_EDITFIELDS = 0x18,
	// MAPI_E_INVALID_RECIPS = 0x19,
	// MAPI_E_NOT_SUPPORTED = 0x1A,
	// StoreTestFailure = 0x000003e8,
	ecJetError = 0x000003EA,
	ecUnknownUser = 0x000003EB,
	// ecExiting = 0x000003ED,
	// ecBadConfig = 0x000003EE,
	// ecUnknownCodePage = 0x000003EF,
	ecServerOOM = 0x000003F0,
	ecLoginPerm = 0x000003F2,
	// ecDatabaseRolledBack = 0x000003F3,
	// ecDatabaseCopiedError = 0x000003F4,
	// ecAuditNotAllowed = 0x000003F5,
	// ecZombieUser = 0x000003F6,
	// ecUnconvertableACL = 0x000003F7,
	// ecNoFreeJses = 0x0000044C,
	// ecDifferentJses = 0x0000044D,
	// ecFileRemove = 0x0000044F,
	ecParameterOverflow = 0x00000450,
	// ecBadVersion = 0x00000451,
	// ecTooManyCols = 0x00000452,
	// ecHaveMore = 0x00000453,
	// ecDatabaseError = 0x00000454,
	// ecIndexNameTooBig = 0x00000455,
	// ecUnsupportedProp = 0x00000456,
	// ecMsgNotSaved = 0x00000457,
	// ecUnpubNotif = 0x00000459,
	// ecDifferentRoot = 0x0000045B,
	// ecBadFolderName = 0x0000045C,
	// ecAttachOpen = 0x0000045D,
	// ecInvClpsState = 0x0000045E,
	// ecSkipMyChildren = 0x0000045F,
	// ecSearchFolder = 0x00000460,
	ecNotSearchFolder = 0x00000461,
	// ecFolderSetReceive = 0x00000462,
	ecNoReceiveFolder = 0x00000463,
	// ecNoDelSubmitMsg = 0x00000465,
	ecInvalidRecips = 0x00000467,
	// ecNoReplicaHere = 0x00000468,
	// ecNoReplicaAvailable = 0x00000469,
	// ecPublicMDB = 0x0000046A,
	// ecNotPublicMDB = 0x0000046B,
	// ecRecordNotFound = 0x0000046C,
	// ecReplConflict = 0x0000046D,
	// ecFxBufferOverrun = 0x00000470,
	// ecFxBufferEmpty = 0x00000471,
	// ecFxPartialValue = 0x00000472,
	// ecFxNoRoom = 0x00000473,
	// ecMaxTimeExpired = 0x00000474,
	// ecDstError = 0x00000475,
	// ecMDBNotInit = 0x00000476,
	ecWrongServer = 0x00000478,
	// WrongTenant = 0x00000479,
	// MissingMessageTenantHint = 0x0000047a,
	// WriteOperationOnReadOnlyDatabase = 0x0000047b,
	// CrossMailboxAccess = 0x0000047c,
	ecBufferTooSmall = 0x0000047D,
	// ecRequiresRefResolve = 0x0000047E,
	// ecServerPaused = 0x0000047F,
	// ecServerBusy = 0x00000480,
	// MissingMessageMailboxGuid = 0x00000480,
	// ecNoSuchLogon = 0x00000481,
	// ecLoadLibFailed = 0x00000482,
	// ecObjAlreadyConfig = 0x00000483,
	// ecObjNotConfig = 0x00000484,
	// ecDataLoss = 0x00000485,
	// ecMaxSendThreadExceeded = 0x00000488,
	// ecFxErrorMarker = 0x00000489,
	// ecNoFreeJtabs = 0x0000048A,
	// ecNotPrivateMDB = 0x0000048B,
	// ecIsintegMDB = 0x0000048C,
	// ecRecoveryMDBMismatch = 0x0000048D,
	// ecTableMayNotBeDeleted = 0x0000048E,
	// SearchFolderNotEmpty = 0x0000048f,
	ecSearchFolderScopeViolation = 0x00000490,
	// CannotDeriveMsgViewFromBase = 0x00000491,
	// MsgHeaderIndexMismatch = 0x00000492,
	// MsgHeaderViewTableMismatch = 0x00000493,
	// CategViewTableMismatch = 0x00000494,
	// CorruptConversation = 0x00000495,
	// ConversationNotFound = 0x00000496,
	// ConversationMemberNotFound = 0x00000497,
	// VersionStoreBusy = 0x00000498,
	// SearchEvaluationInProgress = 0x00000499,
	// RecursiveSearchChainTooDeep = 0x0000049d,
	// EmbeddedMessagePropertyCopyFailed = 0x0000049e,
	// GlobalCounterRangeExceeded = 0x000004a1,
	// CorruptMidsetDeleted = 0x000004a2,
	// AssertionFailedError = 0x000004af,
	// ecRpcRegisterIf = 0x000004B1,
	// ecRpcListen = 0x000004B2,
	ecRpcFormat = 0x000004B6,
	// ecNoCopyTo = 0x000004B7,
	ecNullObject = 0x000004B9,
	// ecRpcAuthentication = 0x000004BC,
	// ecRpcBadAuthenticationLevel = 0x000004BD,
	// ecNullCommentRestriction = 0x000004BE,
	// ecRulesLoadError = 0x000004CC,
	// ecRulesDelivErr = 0x000004CD,
	// ecRulesParsingErr = 0x000004CE,
	// ecRulesCreateDaeErr = 0x000004CF,
	// ecRulesCreateDamErr = 0x000004D0,
	// ecRulesNoMoveCopyFolder = 0x000004D1,
	// ecRulesNoFolderRights = 0x000004D2,
	// InvalidRTF = 0x000004d3,
	// ecMessageTooBig = 0x000004D4,
	// ecFormNotValid = 0x000004D5,
	// ecNotAuthorized = 0x000004D6,
	// ecDeleteMessage = 0x000004D7,
	// ecBounceMessage = 0x000004D8,
	ecQuotaExceeded = 0x000004D9,
	// ecMaxSubmissionExceeded = 0x000004DA,
	ecMaxAttachmentExceeded = 0x000004DB,
	ecSendAsDenied = 0x000004DC,
	// ecShutoffQuotaExceeded = 0x000004DD,
	// ecMaxObjsExceeded = 0x000004DE,
	// ecClientVerDisallowed = 0x000004DF,
	// ecRpcHttpDisallowed = 0x000004E0,
	// ecCachedModeRequired = 0x000004E1,
	// ecFolderNotCleanedUp = 0x000004E3,
	// MessagePerFolderCountReceiveQuotaExceeded = 0x000004e4,
	// FolderHierarchyChildrenCountReceiveQuotaExceeded = 0x000004e5,
	// FolderHierarchyDepthReceiveQuotaExceeded = 0x000004e6,
	// DynamicSearchFoldersPerScopeCountReceiveQuotaExceeded = 0x000004e7,
	// FolderHierarchySizeReceiveQuotaExceeded = 0x000004e8,
	// ecFmtError = 0x000004ED,
	ecNotExpanded = 0x000004F7,
	ecNotCollapsed = 0x000004F8,
	// ecLeaf = 0x000004F9,
	// ecUnregisteredNamedProp = 0x000004FA,
	// ecFolderDisabled = 0x000004FB,
	// ecDomainError = 0x000004FC,
	// ecNoCreateRight = 0x000004FF,
	// ecPublicRoot = 0x00000500,
	// ecNoReadRight = 0x00000501,
	// ecNoCreateSubfolderRight = 0x00000502,
	ecDstNullObject = 0x00000503,
	ecMsgCycle = 0x00000504,
	ecTooManyRecips = 0x00000505,
	// TooManyProps = 0x00000506,
	// ecVirusScanInProgress = 0x0000050A,
	// ecVirusDetected = 0x0000050B,
	// ecMailboxInTransit = 0x0000050C,
	// ecBackupInProgress = 0x0000050D,
	// ecVirusMessageDeleted = 0x0000050E,
	// ecInvalidBackupSequence = 0x0000050F,
	// ecInvalidBackupType = 0x00000510,
	// ecTooManyBackupsInProgress = 0x00000511,
	// ecRestoreInProgress = 0x00000512,
	// PropsDontMatch = 0x00000519,
	// ecDuplicateObject = 0x00000579,
	// ecObjectNotFound = 0x0000057A,
	// ecFixupReplyRule = 0x0000057B,
	// ecTemplateNotFound = 0x0000057C,
	// ecRuleException = 0x0000057D,
	// ecDSNoSuchObject = 0x0000057E,
	// ecMessageAlreadyTombstoned = 0x0000057F,
	// ecRequiresRWTransaction = 0x00000596,
	// JetWarningColumnMaxTruncated = 0x000005e8,
	// ecPaused = 0x0000060E,
	// ecNotPaused = 0x0000060F,
	// ecWrongMailbox = 0x00000648,
	// ecChgPassword = 0x0000064C,
	// ecPwdExpired = 0x0000064D,
	// ecInvWkstn = 0x0000064E,
	// ecInvLogonHrs = 0x0000064F,
	// ecAcctDisabled = 0x00000650,
	// ecRuleVersion = 0x000006A4,
	// ecRuleFormat = 0x000006A5,
	// ecRuleSendAsDenied = 0x000006A6,
	// ecNoServerSupport = 0x000006B9,
	// ecLockTimedOut = 0x000006BA,
	// ecObjectLocked = 0x000006BB,
	// ecInvalidLockNamespace = 0x000006BD,
	RPC_X_BAD_STUB_DATA = 0x000006F7,
	// ecMessageDeleted = 0x000007D6,
	// ecProtocolDisabled = 0x000007D8,
	// ecClearTextLogonDisabled = 0x000007D9,
	ecRejected = 0x000007EE,
	// CrossPostDenied = 0x000007f7,
	// NoMessages = 0x00000805,
	// NoRpcInterface = 0x00000824,
	// ecAmbiguousAlias = 0x0000089A,
	// ecUnknownMailbox = 0x0000089B,
	// ecExpReserved = 0x000008FC,
	// ecExpParseDepth = 0x000008FD,
	// ecExpFuncArgType = 0x000008FE,
	// ecExpSyntax = 0x000008FF,
	// ecExpBadStrToken = 0x00000900,
	// ecExpBadColToken = 0x00000901,
	// ecExpTypeMismatch = 0x00000902,
	// ecExpOpNotSupported = 0x00000903,
	// ecExpDivByZero = 0x00000904,
	// ecExpUnaryArgType = 0x00000905,
	// ecNotLocked = 0x00000960,
	// ecClientEvent = 0x00000961,
	// ecCorruptEvent = 0x00000965,
	// ecCorruptWatermark = 0x00000966,
	// ecEventError = 0x00000967,
	// ecWatermarkError = 0x00000968,
	// ecNonCanonicalACL = 0x00000969,
	// ecMailboxDisabled = 0x0000096C,
	// ecRulesFolderOverQuota = 0x0000096D,
	// ecADUnavailable = 0x0000096E,
	// ecADError = 0x0000096F,
	// ecNotEncrypted = 0x00000970,
	// ecADNotFound = 0x00000971,
	// ecADPropertyError = 0x00000972,
	// ecRpcServerTooBusy = 0x00000973,
	// ecRpcOutOfMemory = 0x00000974,
	// ecRpcServerOutOfMemory = 0x00000975,
	// ecRpcOutOfResources = 0x00000976,
	// ecRpcServerUnavailable = 0x00000977,
	// ADDuplicateEntry = 0x00000978,
	// ImailConversion = 0x00000979,
	// ecSecureSubmitError = 0x0000097A,
	// ImailConversionProhibited = 0x0000097b,
	// ecEventsDeleted = 0x0000097C,
	// ecSubsystemStopping = 0x0000097D,
	// ecSAUnavailable = 0x0000097E,
	// ecCIStopping = 0x00000A28,
	// ecFxInvalidState = 0x00000A29,
	// ecFxUnexpectedMarker = 0x00000A2A,
	// ecDuplicateDelivery = 0x00000A2B,
	// ecConditionViolation = 0x00000A2C,
	// ecMaxPoolExceeded = 0x00000A2D,
	ecRpcInvalidHandle = 0x00000A2E,
	// ecEventNotFound = 0x00000A2F,
	// ecPropNotPromoted = 0x00000A30,
	// ecLowMdbSpace = 0x00000A31,
	// LowDatabaseLogDiskSpace = 0x00000a32,
	// MailboxQuarantined = 0x00000a33,
	// MountInProgress = 0x00000a34,
	// DismountInProgress = 0x00000a35,
	// InvalidPool = 0x00000a39,
	// VirusScannerError = 0x00000a3a,
	// GranularReplInitFailed = 0x00000a3b,
	// CannotRegisterNewReplidGuidMapping = 0x00000a3c,
	// CannotRegisterNewNamedPropertyMapping = 0x00000a3d,
	// GranularReplInvalidParameter = 0x00000a41,
	// GranularReplStillInUse = 0x00000a42,
	// GranularReplCommunicationFailed = 0x00000a44,
	// CannotPreserveMailboxSignature = 0x00000a48,
	// UnexpectedState = 0x00000a4a,
	// MailboxSoftDeleted = 0x00000a4b,
	// DatabaseStateConflict = 0x00000a4c,
	// RpcInvalidSession = 0x00000a4d,
	// MaxThreadsPerMdbExceeded = 0x00000a8c,
	// MaxThreadsPerSCTExceeded = 0x00000a8d,
	// WrongProvisionedFid = 0x00000a8e,
	// ISIntegMdbTaskExceeded = 0x00000a8f,
	// ISIntegQueueFull = 0x00000a90,
	// InvalidMultiMailboxSearchRequest = 0x00000af0,
	// InvalidMultiMailboxKeywordStatsRequest = 0x00000af1,
	// MultiMailboxSearchFailed = 0x00000af2,
	// MaxMultiMailboxSearchExceeded = 0x00000af3,
	// MultiMailboxSearchOperationFailed = 0x00000af4,
	// MultiMailboxSearchNonFullTextSearch = 0x00000af5,
	// MultiMailboxSearchTimeOut = 0x00000af6,
	// MultiMailboxKeywordStatsTimeOut = 0x00000af7,
	// MultiMailboxSearchInvalidSortBy = 0x00000af8,
	// MultiMailboxSearchNonFullTextSortBy = 0x00000af9,
	// MultiMailboxSearchInvalidPagination = 0x00000afa,
	// MultiMailboxSearchNonFullTextPropertyInPagination = 0x00000afb,
	// MultiMailboxSearchMailboxNotFound = 0x00000afc,
	// MultiMailboxSearchInvalidRestriction = 0x00000afd,
	// UserInformationAlreadyExists = 0x00000b0e,
	// UserInformationLockTimeout = 0x00000b0f,
	// UserInformationNotFound = 0x00000b10,
	// UserInformationNoAccess = 0x00000b11,
	// EncryptionTransientError = 0x00000b15,
	// EncryptionPermanentError = 0x00000b16,
	// InvalidInternetMessageHeaderName = 0x00000b17,
	// SyncStateTooOld = 0x00000b19,
	MAPI_W_NO_SERVICE = 0x00040203,
	ecWarnWithErrors = 0x00040380, /* MAPI_W_ERRORS_RETURNED */
	// ecWarnPositionChanged = 0x00040481, /* MAPI_W_POSITION_CHANGED */
	// ecWarnApproxCount = 0x00040482, /* MAPI_W_APPROX_COUNT */
	MAPI_W_CANCEL_MESSAGE = 0x00040580,
	// ecPartialCompletion = 0x00040680, /* MAPI_W_PARTIAL_COMPLETION */
	// MapiSecurityRequiredLow = 0x00040681,
	// MapiSecuirtyRequiredMedium = 0x00040682,
	// MapiPartialItems = 0x00040687,
	// SYNC_W_PROGRESS = 0x00040820,
	SYNC_W_CLIENT_CHANGE_NEWER = 0x00040821,
	ecInterfaceNotSupported = 0x80004002, /* E_NOINTERFACE, MAPI_E_INTERFACE_NOT_SUPPORTED */
	ecError = 0x80004005, /* MAPI_E_CALL_FAILED, SYNC_E_ERROR */
	// STG_E_INVALIDFUNCTION = 0x80030001, /* STG := "storage" */
	STG_E_ACCESSDENIED = 0x80030005,
	// STG_E_INSUFFICIENTMEMORY = 0x80030008,
	// STG_E_INVALIDPOINTER = 0x80030009, /* like EFAULT */
	StreamSeekError = 0x80030019,
	// STG_E_READFAULT = 0x8003001E,
	// STG_E_LOCKVIOLATION = 0x80030021,
	STG_E_INVALIDPARAMETER = 0x80030057,
	ecStreamSizeError = 0x80030070, /* STG_E_MEDIUMFULL */
	// STG_E_INVALIDFLAG = 0x800300FF,
	// STG_E_CANTSAVE = 0x80030103,
	ecNotSupported = 0x80040102, /* MAPI_E_NO_SUPPORT */
	// ecBadCharwidth = 0x80040103, /* MAPI_E_BAD_CHARWIDTH */
	// ecStringTooLarge = 0x80040105, /* MAPI_E_STRING_TOO_LONG */
	// ecUnknownFlags = 0x80040106, /* MAPI_E_UNKNOWN_FLAGS, SYNC_E_UNKNOWN_FLAGS */
	ecInvalidEntryId = 0x80040107, /* MAPI_E_INVALID_ENTRYID */
	ecInvalidObject = 0x80040108, /* MAPI_E_INVALID_OBJECT */
	ecObjectModified = 0x80040109, /* MAPI_E_OBJECT_CHANGED */
	ecObjectDeleted = 0x8004010A, /* MAPI_E_OBJECT_DELETED */
	// ecBusy = 0x8004010B, /* MAPI_E_BUSY */
	// ecDiskFull = 0x8004010D, /* MAPI_E_NOT_ENOUGH_DISK */
	ecInsufficientResrc = 0x8004010E, /* MAPI_E_NOT_ENOUGH_RESOURCES */
	ecNotFound = 0x8004010F, /* MAPI_E_NOT_FOUND */
	// ecVersion = 0x80040110, /* MAPI_E_VERSION */
	ecLoginFailure = 0x80040111, /* MAPI_E_LOGON_FAILED */
	// ecTooManySessions = 0x80040112, /* MAPI_E_SESSION_LIMIT */
	// ecUserAbort = 0x80040113, /* MAPI_E_USER_CANCEL */
	ecUnableToAbort = 0x80040114, /* MAPI_E_UNABLE_TO_ABORT */
	ecRpcFailed = 0x80040115,
	ecNetwork = 0x80040115, /* MAPI_E_NETWORK_ERROR */
	// ecReadFault = 0x80040116, /* ecWriteFault, MAPI_E_DISK_ERROR */
	ecTooComplex = 0x80040117, /* MAPI_E_TOO_COMPLEX */
	// MAPI_E_BAD_COLUMN = 0x80040118,
	// MAPI_E_EXTENDED_ERROR = 0x80040119,
	ecComputed = 0x8004011A, /* MAPI_E_COMPUTED */
	ecCorruptData = 0x8004011B, /* MAPI_E_CORRUPT_DATA */
	MAPI_E_UNCONFIGURED = 0x8004011C,
	MAPI_E_FAILONEPROVIDER = 0x8004011D,
	MAPI_E_UNKNOWN_CPID = 0x8004011E,
	MAPI_E_UNKNOWN_LCID = 0x8004011F,
	MAPI_E_PASSWORD_CHANGE_REQUIRED = 0x80040120,
	MAPI_E_PASSWORD_EXPIRED = 0x80040121,
	MAPI_E_INVALID_WORKSTATION_ACCOUNT = 0x80040122,
	ecTimeSkew = 0x80040123, /* MAPI_E_INVALID_ACCESS_TIME */
	MAPI_E_ACCOUNT_DISABLED = 0x80040124,
	// MapiConflict = 0x80040125,
	MAPI_E_END_OF_SESSION = 0x80040200,
	MAPI_E_UNKNOWN_ENTRYID = 0x80040201,
	// MAPI_E_MISSING_REQUIRED_COLUMN = 0x80040202,
	// FailCallback = 0x80040219,
	// ecPropBadValue = 0x80040301, /* MAPI_E_BAD_VALUE */
	// ecInvalidType = 0x80040302, /* MAPI_E_INVALID_TYPE */
	// ecTypeNotSupported = 0x80040303, /* MAPI_E_TYPE_NO_SUPPORT */
	// ecPropType = 0x80040304, /* MAPI_E_UNEXPECTED_TYPE */
	ecTooBig = 0x80040305, /* MAPI_E_TOO_BIG */
	MAPI_E_DECLINE_COPY = 0x80040306,
	// MAPI_E_UNEXPECTED_ID = 0x80040307,
	// ecUnableToComplete = 0x80040400, /* MAPI_E_UNABLE_TO_COMPLETE */
	// ecTimeout = 0x80040401, /* MAPI_E_TIMEOUT */
	ecTableEmpty = 0x80040402, /* MAPI_E_TABLE_EMPTY */
	ecTableTooBig = 0x80040403, /* MAPI_E_TABLE_TOO_BIG */
	ecInvalidBookmark = 0x80040405, /* MAPI_E_INVALID_BOOKMARK */
	// MapiDataLoss = 0x80040485,
	// ecWait = 0x80040500, /* MAPI_E_WAIT */
	// ecCancel = 0x80040501, /* MAPI_E_CANCEL */
	// MAPI_E_NOT_ME = 0x80040502,
	// MAPI_E_CORRUPT_STORE = 0x80040600,
	ecNotInQueue = 0x80040601, /* MAPI_E_NOT_IN_QUEUE */
	// MAPI_E_NO_SUPPRESS = 0x80040602,
	ecDuplicateName = 0x80040604, /* MAPI_E_COLLISION */
	ecNotInitialized = 0x80040605, /* MAPI_E_NOT_INITIALIZED */
	// MAPI_E_NON_STANDARD = 0x80040606,
	MAPI_E_NO_RECIPIENTS = 0x80040607,
	// ecSubmitted = 0x80040608, /* MAPI_E_SUBMITTED */
	// ecFolderHasChildren = 0x80040609, /* MAPI_E_HAS_FOLDERS */
	// ecFolderHasContents = 0x8004060A, /* MAPI_E_HAS_MESSAGES */
	ecRootFolder = 0x8004060B, /* MAPI_E_FOLDER_CYCLE */
	MAPI_E_STORE_FULL = 0x8004060C, /* also: MapiRecursionLimit */
	// ecLockIdLimit = 0x8004060D, /* MAPI_E_LOCKID_LIMIT */
	// MapiTooManyMountedDatabases = 0x8004060e,
	EC_EXCEEDED_SIZE = 0x80040610,
	// MapiPartialItem = 0x80040686,
	ecAmbiguousRecip = 0x80040700, /* MAPI_E_AMBIGUOUS_RECIP */
	SYNC_E_OBJECT_DELETED = 0x80040800,
	SYNC_E_IGNORE = 0x80040801,
	SYNC_E_CONFLICT = 0x80040802,
	SYNC_E_NO_PARENT = 0x80040803,
	// SYNC_E_CYCLE_DETECTED = 0x80040804, /* SYNC_E_CYCLE, SYNC_E_INCEST */
	// SYNC_E_UNSYNCHRONIZED = 0x80040805,
	ecNPQuotaExceeded = 0x80040900, /* MAPI_E_NAMED_PROP_QUOTA_EXCEEDED */
	NotImplemented = 0x80040FFF, /* _not_ the same as ecNotSupported/ecNotImplemented/MAPI_E_NOT_IMPLEMENTED */
	// ErrorPathNotFound = 0x80070003,
	ecAccessDenied = 0x80070005, /* MAPI_E_NO_ACCESS */
	ecMAPIOOM = 0x8007000E, /* MAPI_E_NOT_ENOUGH_MEMORY */
	ecInvalidParam = 0x80070057, /* MAPI_E_INVALID_PARAMETER, SYNC_E_INVALID_PARAMETER */
	// Win32ErrorDiskFull = 0x80070070,
	// ErrorInsufficientBuffer = 0x8007007a,
	// ErrorCanNotComplete = 0x800703eb,
	// ErrorCanceled = 0x800704c7,
	ecZNullObject = 0xfffffc00,
	ecZOutOfHandles = 0xfffffc04,
};

#ifdef COMPILE_DIAG
struct GX_EXPORT ec_error_t {
	constexpr ec_error_t() = default;
	constexpr ec_error_t(uint32_t x) : m_value(static_cast<ec_error_t_ll>(x)) {}
	constexpr ec_error_t(ec_error_t_ll x) : m_value(x) {}
	constexpr ec_error_t(int) = delete;
	constexpr bool operator==(ec_error_t_ll x) const { return m_value == x; }
	constexpr operator bool() const = delete;
	constexpr void operator!() const = delete;
	constexpr operator uint32_t() const { return m_value; }
	private:
	ec_error_t_ll m_value = ecSuccess;
};
#endif
