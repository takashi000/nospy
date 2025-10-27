class Kinds:
    def __init__(self):
        super(Kinds, self).__init__()
        self.kindclassification = ['regular', 'replaceable', 'ephemeral', 'parameterized', 'unknown']
        self.Metadata = 0
        self.ShortTextNote = 1
        self.RecommendRelay = 2
        self.Contacts = 3
        self.EncryptedDirectMessage = 4
        self.EventDeletion = 5
        self.Repost = 6
        self.Reaction = 7
        self.BadgeAward = 8
        self.Seal = 13
        self.PrivateDirectMessage = 14
        self.GenericRepost = 16
        self.ChannelCreation = 40
        self.ChannelMetadata = 41
        self.ChannelMessage = 42
        self.ChannelHideMessage = 43
        self.ChannelMuteUser = 44
        self.OpenTimestamps = 1040
        self.GiftWrap = 1059
        self.FileMetadata = 1063
        self.LiveChatMessage = 1311
        self.ProblemTracker = 1971
        self.Report = 1984
        self.Reporting = 1984
        self.Label = 1985
        self.CommunityPostApproval = 4550
        self.JobRequest = 5999
        self.JobResult = 6999
        self.JobFeedback = 7000
        self.ZapGoal = 9041
        self.ZapRequest = 9734
        self.Zap = 9735
        self.Highlights = 9802
        self.Mutelist = 10000
        self.Pinlist = 10001
        self.RelayList = 10002
        self.BookmarkList = 10003
        self.CommunitiesList = 10004
        self.PublicChatsList = 10005
        self.BlockedRelaysList = 10006
        self.SearchRelaysList = 10007
        self.InterestsList = 10015
        self.UserEmojiList = 10030
        self.DirectMessageRelaysList = 10050
        self.FileServerPreference = 10096
        self.NWCWalletInfo = 13194
        self.LightningPubRPC = 21000
        self.ClientAuth = 22242
        self.NWCWalletRequest = 23194
        self.NWCWalletResponse = 23195
        self.NostrConnect = 24133
        self.HTTPAuth = 27235
        self.Followsets = 30000
        self.Genericlists = 30001
        self.Relaysets = 30002
        self.Bookmarksets = 30003
        self.Curationsets = 30004
        self.ProfileBadges = 30008
        self.BadgeDefinition = 30009
        self.Interestsets = 30015
        self.CreateOrUpdateStall = 30017
        self.CreateOrUpdateProduct = 30018
        self.LongFormArticle = 30023
        self.DraftLong = 30024
        self.Emojisets = 30030
        self.Application = 30078
        self.LiveEvent = 30311
        self.UserStatuses = 30315
        self.ClassifiedListing = 30402
        self.DraftClassifiedListing = 30403
        self.Date = 31922
        self.Time = 31923
        self.Calendar = 31924
        self.CalendarEventRSVP = 31925
        self.Handlerrecommendation = 31989
        self.Handlerinformation = 31990
        self.CommunityDefinition = 34550

    def isRegularKind(self, kind:int) -> bool:
        return (1000 <= kind and kind < 10000) or kind in [1, 2, 4, 5, 6, 7, 8, 16, 40, 41, 42, 43, 44]

    def isReplaceableKind(self, kind:int) -> bool:
        return kind in [0, 3] or (10000 <= kind and kind < 20000)

    def isEphemeralKind(self, kind:int) -> bool:
        return 20000 <= kind and kind < 30000
    
    def isAddressableKind(self, kind:int) -> bool:
        return 30000 <= kind and kind < 40000
    
    def classifyKind(self, kind:int) -> str:
        if (self.isRegularKind(kind)): return self.kindclassification[0]
        if (self.isReplaceableKind(kind)): return self.kindclassification[1]
        if (self.isEphemeralKind(kind)): return self.kindclassification[2]
        if (self.isAddressableKind(kind)): return self.kindclassification[3]
        return self.kindclassification[-1]