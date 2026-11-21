{-# LANGUAGE OverloadedStrings #-}

-- | The JSON that the Rust oracle reads and answers, and that the corpus is
-- kept in.
--
-- A request is a store, the pinned genesis, optionally a history to verify,
-- any number of transactions to decide, each against the state it names, and
-- any number of transfers to check. A response has only what the two sides
-- are compared on: which objects were given a verdict, which of them are
-- invalid, which are on a conflicting lineage, how each transaction was
-- decided, and whether each transfer was recorded and as what. An
-- implementation's own account of /why/ travels beside the response and is
-- never compared.
module LeVCS.Harness.Wire
  ( -- * Requests
    Request (..)
  , historyRequest
  , traceRequest
  , encodeRequest
  , parseRequest
  , unrepresentable

    -- * Responses
  , Response (..)
  , VerifyResponse (..)
  , AdmitResponse (..)
  , RefusalKind (..)
  , ReceiveResponse (..)
  , ServeResponse (..)
  , encodeResponse
  , parseResponse
  , parseRemarks
  , parseTransferDamage
  , parseServeDamage

    -- * What the model expects
  , expected

    -- * Corpus
  , CorpusEntry (..)
  , encodeCorpusEntry
  , parseCorpusEntry
  ) where

import Data.Aeson (Value (..), object, withObject, withText, (.:), (.:?), (.=))
import Data.Aeson qualified as Aeson
import Data.Aeson.Key qualified as Key
import Data.Aeson.Types (Parser)
import Data.ByteString qualified as BS
import Data.List (intercalate)
import Data.Text.Encoding (encodeUtf8)
import Data.Word (Word32)
import Data.List (stripPrefix)
import Data.Map.Strict qualified as Map
import Data.Maybe (fromMaybe)
import Data.Scientific (toBoundedInteger)
import Data.Set (Set)
import Data.Set qualified as Set
import Data.Text (Text)
import Data.Text qualified as Text

import LeVCS.Authority.Model
import LeVCS.Authority.Reading
import LeVCS.Authority.RuleH
import LeVCS.Authority.RuleP
import LeVCS.Authority.RuleR
import LeVCS.Harness.Script (History (..), Trace (..), Attempt (..), pinId)

-- * Requests

data Request = Request
  { rqStore :: Store
  , rqPin :: AuthId
  , rqVerify :: Maybe (Maybe AuthId, [Object])
  -- ^ The replica's @current@ and the roots to verify from.
  , rqAdmit :: [(State, Transaction)]
  , rqReceive :: [(AuthId, AuthId, [Object])]
  -- ^ Transfers a source has agreed to send: the genesis the receiver
  -- expects, the source's current authority, and the roots asked for. There
  -- is no requester. Whether to send is the source's decision (R.2), and
  -- this is the receiver's check of what was sent.
  , rqServe :: [(Maybe AuthId, Requester, [Object])]
  -- ^ Reads asked of an instance that holds the store as the repository the
  -- pin is the genesis of: the current authority it has for it, if any, who
  -- is asking, and the roots asked for. The source decides first, and this
  -- is that decision and then the receiver's.
  }
  deriving (Eq, Show)

-- | A history to verify. Where the replica has a current authority, the same
-- history is also put as a transfer from a source with that authority: once
-- whole, and once for its first root alone.
historyRequest :: History -> Request
historyRequest h = Request (hStore h) pinId (Just (hCurrent h, hRoots h)) [] transfers []
  where
    transfers = case hCurrent h of
      Nothing -> []
      Just current ->
        (pinId, current, hRoots h) : [(pinId, current, take 1 (hRoots h)) | length (hRoots h) > 1]

traceRequest :: Trace -> Request
traceRequest tr = Request (tStore tr) pinId Nothing [(atState at, atTx at) | at <- tAttempts tr] [] []

encodeRequest :: Request -> Value
encodeRequest rq =
  object $
    [ "store" .= encodeStore (rqStore rq)
    , "pin" .= authInt (rqPin rq)
    , "verify" .= fmap encodeVerify (rqVerify rq)
    , "admit" .= map encodeAdmit (rqAdmit rq)
    , "receive" .= map encodeReceive (rqReceive rq)
    ]
      -- Written only where there are any, so that a request with none
      -- reads as it did before reads were compared.
      ++ ["serve" .= map encodeServe (rqServe rq) | not (null (rqServe rq))]
  where
    encodeServe (current, who, roots) =
      object
        [ "current" .= fmap authInt current
        , "requester" .= (case who of Anonymous -> Nothing; Holding k -> Just (keyInt k))
        , "roots" .= map encodeObject roots
        ]
    encodeVerify (current, roots) =
      object ["current" .= fmap authInt current, "roots" .= map encodeObject roots]
    encodeAdmit (s, tx) = object ["state" .= encodeState s, "tx" .= encodeTx tx]
    encodeReceive (expects, current, roots) =
      object ["expected" .= authInt expects, "current" .= authInt current, "roots" .= map encodeObject roots]

parseRequest :: Value -> Parser Request
parseRequest = withObject "request" $ \o -> do
  st <- o .: "store" >>= parseStore
  pin <- AuthId <$> num o "pin"
  v <- o .:? "verify" >>= traverse parseVerify
  a <- o .: "admit" >>= mapM (parseAdmit pin)
  -- Absent from requests saved before transfers were compared.
  t <- o .:? "receive" >>= mapM parseReceive . fromMaybe []
  -- Absent from requests saved before reads were compared.
  s <- o .:? "serve" >>= mapM parseServe . fromMaybe []
  let rq = Request st pin v a t s
  case unrepresentable rq of
    [] -> pure rq
    why -> fail (unlines why)
  where
    parseVerify = withObject "verify" $ \o ->
      (,) <$> (fmap AuthId <$> optNum o "current") <*> (o .: "roots" >>= mapM parseObject)
    parseAdmit pin = withObject "admit" $ \o ->
      (,) <$> (o .: "state" >>= parseState pin) <*> (o .: "tx" >>= parseTx)
    parseReceive = withObject "receive" $ \o ->
      (,,) <$> (AuthId <$> num o "expected") <*> (AuthId <$> num o "current") <*> (o .: "roots" >>= mapM parseObject)
    parseServe = withObject "serve" $ \o ->
      (,,)
        <$> (fmap AuthId <$> optNum o "current")
        <*> (maybe Anonymous (Holding . Key) <$> optNum o "requester")
        <*> (o .: "roots" >>= mapM parseObject)

-- | What in a request the implementation's objects cannot hold, so that the
-- two sides would be answering different questions. A request with any of
-- it is refused here and by the Rust oracle, and the generators make none.
--
-- * __Protected patterns.__ The @protected_branches@ policy is one string,
--   the globs joined by commas, of at most 65535 bytes. A glob with a comma
--   in it would be read back as two, and an empty one as none.
-- * __Numbers.__ An object's number, a key and an authority's version are
--   each a @u32@, wherever they appear.
-- * __Counts.__ An authority carries at most 255 signatures and 65535
--   members, and a commit at most 255 parents.
-- * __References.__ Everything named exists, and nothing is behind itself.
--   An object's id is the hash of what it names, so an object naming one
--   that is missing, or one that names it back, cannot be made.
-- * __Reads.__ A read is asked of a repository by its id, and the id is
--   derived from a genesis. So where reads are asked the pin is a genesis.
-- * __States.__ A state is given, not judged: its refs are branches naming
--   commits and release refs naming releases, each with a name a ref can
--   have. A transaction is judged, so it may name any ref; the objects it
--   names still have to exist.
unrepresentable :: Request -> [String]
unrepresentable rq =
  [ "authority " ++ show i ++ ": the protected pattern " ++ show glob ++ " is empty or has a comma in it"
  | (AuthId i, a) <- authorities
  , glob <- Set.toList (aProtected a)
  , null glob || ',' `elem` glob
  ]
    ++ [ "authority " ++ show i ++ ": its protected patterns come to more than 65535 bytes"
       | (AuthId i, a) <- authorities
       , BS.length (encodeUtf8 (Text.pack (intercalate "," (Set.toList (aProtected a))))) > 65535
       ]
    ++ ["authority " ++ show i ++ " has more than 255 signatures" | (AuthId i, a) <- authorities, length (aSigs a) > 255]
    ++ ["authority " ++ show i ++ " has more than 65535 members" | (AuthId i, a) <- authorities, Map.size (aMembers a) > 65535]
    ++ ["commit " ++ show i ++ " has more than 255 parents" | (CommitId i, k) <- commits, length (cParents k) > 255]
    ++ [what ++ " " ++ show n ++ " is not a u32" | (what, n) <- numbers, n < 0 || toInteger n > 4294967295]
    ++ [what ++ " names something that is missing, or that is behind itself" | (what, False) <- named]
    ++ [ "reads are asked of the repository the pin is the genesis of, and the pin is not a genesis"
       | not (null (rqServe rq))
       , Just a <- [Map.lookup (rqPin rq) (sAuthorities st)]
       , aPrev a /= Nothing
       ]
    ++ [ "a state holds " ++ refText ref ++ ", which is not a ref a state can hold, or not at that kind of object"
       | (s, _) <- rqAdmit rq
       , (ref, o) <- Map.toList (sRefs s)
       , not (wellNamed ref && holdable ref o)
       ]
  where
    st = rqStore rq
    authorities = Map.toList (sAuthorities st)
    commits = Map.toList (sCommits st)
    releases = Map.toList (sReleases st)
    holdable (Branch _) (OCommit _) = True
    holdable (ReleaseRef _) (ORelease _) = True
    holdable _ _ = False

    -- What can be made, each kind after what it names: an object whose
    -- every reference is already made, repeated until nothing more is.
    madeA = grow (\made a -> all (`Set.member` made) (aPrev a)) (sAuthorities st)
    madeC =
      grow
        (\made k -> all (`Set.member` made) (cParents k) && all (`Set.member` madeA) (cCites k : [a | Just a <- [cInstalls k]]))
        (sCommits st)
    madeR =
      grow
        ( \made r ->
            all (`Set.member` made) (rParent r) && rPredecessor r `Set.member` madeC && rCites r `Set.member` madeA
        )
        (sReleases st)
    grow :: Ord k => (Set k -> v -> Bool) -> Map.Map k v -> Set k
    grow ready m = go Set.empty
      where
        go made =
          let more = Map.keysSet (Map.filter (ready made) m)
           in if more == made then made else go more
    auth a = a `Set.member` madeA
    obj (OCommit k) = k `Set.member` madeC
    obj (ORelease r) = r `Set.member` madeR

    named =
      [("authority " ++ show i, auth a) | (a@(AuthId i), _) <- authorities]
        ++ [("commit " ++ show i, obj (OCommit k)) | (k@(CommitId i), _) <- commits]
        ++ [("release " ++ show i, obj (ORelease r)) | (r@(ReleaseId i), _) <- releases]
        ++ [("the pin", auth (rqPin rq))]
        ++ concat [("verify", all auth current) : [("a root to verify", obj o) | o <- roots] | Just (current, roots) <- [rqVerify rq]]
        ++ concat
          [ ("a state's current authority", all auth (sCurrent s))
              : ("a transaction's authority", all auth (txAuthority tx))
              : [("a state's ref", obj o) | o <- Map.elems (sRefs s)]
              ++ [("an update", obj o) | u <- txUpdates tx, Just o <- [uExpected u, uNew u]]
          | (s, tx) <- rqAdmit rq
          ]
        ++ concat
          [ ("a transfer", auth expects && auth current) : [("a root of a transfer", obj o) | o <- roots]
          | (expects, current, roots) <- rqReceive rq
          ]
        ++ concat
          [ ("a read", all auth current) : [("a root of a read", obj o) | o <- roots]
          | (current, _, roots) <- rqServe rq
          ]

    numbers =
      [("the pin", authInt (rqPin rq))]
        ++ concat
          [ ("authority", i)
              : ("the version of authority " ++ show i, aVersion a)
              : [("authority", p) | Just (AuthId p) <- [aPrev a]]
              ++ [("key", k) | Key k <- Map.keys (aMembers a) ++ map sigKey (aSigs a)]
          | (AuthId i, a) <- authorities
          ]
        ++ concat
          [ ("commit", i)
              : ("key", keyInt (sigKey (cSig k)))
              : ("authority", authInt (cCites k))
              : [("commit", p) | CommitId p <- cParents k]
              ++ [("authority", a) | Just (AuthId a) <- [cInstalls k]]
          | (CommitId i, k) <- commits
          ]
        ++ concat
          [ ("release", i)
              : ("key", keyInt (sigKey (rSig r)))
              : ("authority", authInt (rCites r))
              : ("commit", let CommitId p = rPredecessor r in p)
              : [("release", p) | Just (ReleaseId p) <- [rParent r]]
          | (ReleaseId i, r) <- releases
          ]
        ++ concat [[("authority", a) | Just (AuthId a) <- [current]] ++ map object' roots | Just (current, roots) <- [rqVerify rq]]
        ++ concat
          [ ("key", keyInt (txSigner tx))
              : [("authority", a) | Just (AuthId a) <- [sCurrent s, txAuthority tx]]
              ++ map object' (Map.elems (sRefs s))
              ++ [object' o | u <- txUpdates tx, Just o <- [uExpected u, uNew u]]
          | (s, tx) <- rqAdmit rq
          ]
        ++ concat
          [ ("authority", authInt expects) : ("authority", authInt current) : map object' roots
          | (expects, current, roots) <- rqReceive rq
          ]
        ++ concat
          [ [("authority", a) | Just (AuthId a) <- [current]]
              ++ [("key", k) | Holding (Key k) <- [who]]
              ++ map object' roots
          | (current, who, roots) <- rqServe rq
          ]
    object' (OCommit (CommitId i)) = ("commit", i)
    object' (ORelease (ReleaseId i)) = ("release", i)

-- | Every number on the wire is a @u32@: an object's number, a key, a
-- version. Checked as each is read, wherever it appears, so that a
-- reference is held to the same range as the thing it refers to.
--
-- It is the value that has to be a @u32@, not the way it is written: @0@,
-- @0.0@ and @0e0@ are the same number in JSON and are all read as 0. The
-- Rust reader does the same.
--
-- The value is taken exactly, from the digits. aeson's own reader of an
-- integer would not do: it refuses any exponent beyond 1024 either way
-- before it looks at the value, so it refuses @0e2000@, which is 0, and a
-- 1 with 1100 zeros after it written @e-1100@, which is 1.
u32 :: Value -> Parser Int
u32 (Number n) = case toBoundedInteger n :: Maybe Word32 of
  Just w -> pure (fromIntegral w)
  Nothing -> fail (show n ++ " is not a u32")
u32 v = fail ("not a number, so not a u32: " ++ show v)

num :: Aeson.Object -> Key.Key -> Parser Int
num o k = o .: k >>= u32

optNum :: Aeson.Object -> Key.Key -> Parser (Maybe Int)
optNum o k = o .:? k >>= traverse u32

-- | Entries that will be put in a map are checked first for one name used
-- twice. The map would keep one and forget there had been another.
unique :: (Ord a, Show a) => String -> [a] -> Parser ()
unique what names = case [i | (i, n) <- Map.toList (Map.fromListWith (+) [(i, 1 :: Int) | i <- names]), n > 1] of
  [] -> pure ()
  twice -> fail ("more than one " ++ what ++ " is given as " ++ show twice)

authInt :: AuthId -> Int
authInt (AuthId i) = i

keyInt :: Key -> Int
keyInt (Key i) = i

encodeObject :: Object -> Value
encodeObject (OCommit (CommitId i)) = object ["commit" .= i]
encodeObject (ORelease (ReleaseId i)) = object ["release" .= i]

parseObject :: Value -> Parser Object
parseObject = withObject "object" $ \o -> do
  c <- optNum o "commit"
  r <- optNum o "release"
  case (c, r) of
    (Just i, Nothing) -> pure (OCommit (CommitId i))
    (Nothing, Just i) -> pure (ORelease (ReleaseId i))
    _ -> fail "an object is {\"commit\": n} or {\"release\": n}"

roleText :: Role -> Text
roleText Reader = "reader"
roleText Contributor = "contributor"
roleText Maintainer = "maintainer"
roleText Owner = "owner"

parseRole :: Value -> Parser Role
parseRole = withText "role" $ \t ->
  maybe (fail ("unknown role " ++ Text.unpack t)) pure (lookup t [(roleText r, r) | r <- [minBound ..]])

encodeSig :: Sig -> Value
encodeSig (Sig k ok) = object ["key" .= keyInt k, "valid" .= ok]

parseSig :: Value -> Parser Sig
parseSig = withObject "signature" $ \o -> Sig <$> (Key <$> num o "key") <*> o .: "valid"

encodeStore :: Store -> Value
encodeStore st =
  object
    [ "authorities" .= [authority i a | (AuthId i, a) <- Map.toList (sAuthorities st)]
    , "commits" .= [commit i c | (CommitId i, c) <- Map.toList (sCommits st)]
    , "releases" .= [release i r | (ReleaseId i, r) <- Map.toList (sReleases st)]
    ]
  where
    authority :: Int -> Authority -> Value
    authority i a =
      object
        [ "id" .= i
        , "prev" .= fmap authInt (aPrev a)
        , "version" .= aVersion a
        , "members" .= [object ["key" .= keyInt k, "role" .= roleText r] | (k, r) <- Map.toList (aMembers a)]
        , "protected" .= Set.toList (aProtected a)
        , "public_read" .= aPublicRead a
        , "signatures" .= map encodeSig (aSigs a)
        ]
    commit :: Int -> Commit -> Value
    commit i c =
      object
        [ "id" .= i
        , "parents" .= [p | CommitId p <- cParents c]
        , "cites" .= authInt (cCites c)
        , "signature" .= encodeSig (cSig c)
        , "installs" .= fmap authInt (cInstalls c)
        ]
    release :: Int -> Release -> Value
    release i r =
      object
        [ "id" .= i
        , "predecessor" .= (let CommitId p = rPredecessor r in p)
        , "parent" .= fmap (\(ReleaseId p) -> p) (rParent r)
        , "cites" .= authInt (rCites r)
        , "signature" .= encodeSig (rSig r)
        ]

parseStore :: Value -> Parser Store
parseStore = withObject "store" $ \o -> do
  as <- o .: "authorities" >>= mapM authority
  cs <- o .: "commits" >>= mapM commit
  rs <- o .: "releases" >>= mapM release
  unique "authority" (map fst as)
  unique "commit" (map fst cs)
  unique "release" (map fst rs)
  pure (Store (Map.fromList as) (Map.fromList cs) (Map.fromList rs))
  where
    authority = withObject "authority" $ \o -> do
      i <- num o "id"
      members <- o .: "members" >>= mapM member
      unique "member" (map fst members)
      a <-
        Authority
          <$> (fmap AuthId <$> optNum o "prev")
          <*> num o "version"
          <*> pure (Map.fromList members)
          <*> (Set.fromList <$> o .: "protected")
          <*> o .: "public_read"
          <*> (o .: "signatures" >>= mapM parseSig)
      pure (AuthId i, a)
    member = withObject "member" $ \o -> (,) <$> (Key <$> num o "key") <*> (o .: "role" >>= parseRole)
    commit = withObject "commit" $ \o -> do
      i <- num o "id"
      c <-
        Commit
          <$> (map CommitId <$> (o .: "parents" >>= mapM u32))
          <*> (AuthId <$> num o "cites")
          <*> (o .: "signature" >>= parseSig)
          <*> (fmap AuthId <$> optNum o "installs")
      pure (CommitId i, c)
    release = withObject "release" $ \o -> do
      i <- num o "id"
      r <-
        Release
          <$> (CommitId <$> num o "predecessor")
          <*> (fmap ReleaseId <$> optNum o "parent")
          <*> (AuthId <$> num o "cites")
          <*> (o .: "signature" >>= parseSig)
      pure (ReleaseId i, r)

refText :: RefName -> String
refText (Branch n) = "refs/branches/" ++ n
refText (ReleaseRef n) = "refs/releases/" ++ n
refText (AuthorityRef n) = "refs/authority/" ++ n

parseRef :: String -> Parser RefName
parseRef s
  | Just n <- stripPrefix "refs/branches/" s = pure (Branch n)
  | Just n <- stripPrefix "refs/releases/" s = pure (ReleaseRef n)
  | Just n <- stripPrefix "refs/authority/" s = pure (AuthorityRef n)
  | otherwise = fail ("unknown ref " ++ s)

encodeState :: State -> Value
encodeState s =
  object
    [ "current" .= fmap authInt (sCurrent s)
    , "refs" .= [object ["ref" .= refText n, "target" .= encodeObject o] | (n, o) <- Map.toList (sRefs s)]
    ]

parseState :: AuthId -> Value -> Parser State
parseState pin = withObject "state" $ \o -> do
  current <- fmap AuthId <$> optNum o "current"
  refs <- o .: "refs" >>= mapM entry
  unique "ref of a state" (map (refText . fst) refs)
  pure (State pin current (Map.fromList refs))
  where
    entry = withObject "ref" $ \o -> (,) <$> (o .: "ref" >>= parseRef) <*> (o .: "target" >>= parseObject)

encodeTx :: Transaction -> Value
encodeTx tx =
  object
    [ "signer" .= keyInt (txSigner tx)
    , "updates" .= map update (txUpdates tx)
    , "authority" .= fmap authInt (txAuthority tx)
    ]
  where
    update u =
      object
        [ "ref" .= refText (uRef u)
        , "expected" .= fmap encodeObject (uExpected u)
        , "new" .= fmap encodeObject (uNew u)
        , "force" .= uForce u
        ]

parseTx :: Value -> Parser Transaction
parseTx = withObject "transaction" $ \o ->
  Transaction
    <$> (Key <$> num o "signer")
    <*> (o .: "updates" >>= mapM update)
    <*> (fmap AuthId <$> optNum o "authority")
  where
    update = withObject "update" $ \o ->
      Update
        <$> (o .: "ref" >>= parseRef)
        <*> (o .:? "expected" >>= traverse parseObject)
        <*> (o .:? "new" >>= traverse parseObject)
        <*> o .: "force"

-- * Responses

data Response = Response
  { rsVerify :: Maybe VerifyResponse
  , rsAdmit :: [AdmitResponse]
  , rsReceive :: [ReceiveResponse]
  , rsServe :: [ServeResponse]
  }
  deriving (Eq, Show)

data VerifyResponse = VerifyResponse
  { vrReached :: Set Object
  -- ^ Every commit and release given a verdict. Without it, an
  -- implementation that never looked at an object would be
  -- indistinguishable from one that looked and found it valid.
  , vrInvalid :: Set Object
  , vrConflicting :: Set Object
  , vrCurrentRejected :: Bool
  -- ^ The replica's current authority was reported as no authority of this
  -- repository, before any history was looked at.
  }
  deriving (Eq, Show)

data AdmitResponse
  = Admitted
      { arCommits :: Int
      -- ^ How many commits the transaction newly exposed.
      , arReleases :: Int
      , arCurrent :: Maybe AuthId
      -- ^ Where @current@ moves, if it does.
      }
  | Refused RefusalKind
  deriving (Eq, Show)

-- | Whether a transfer was kept, and as what. Why one was refused is not
-- compared.
data ReceiveResponse
  = ReceiveRecorded (Set Object)
  | ReceiveRefused
  deriving (Eq, Show)

-- | What a read asked of an instance comes to: kept, and as what; not
-- served at all; or served, and refused by the receiver for what was sent.
data ServeResponse
  = Served (Set Object)
  | ServeDenied
  | ServeRefused
  deriving (Eq, Show)

-- | @levcs-identity@'s kinds of refusal: what a caller can do about it.
data RefusalKind = Stale | NotFastForward | Unauthorized | NotAdmissible
  deriving (Eq, Show, Enum, Bounded)

kindText :: RefusalKind -> Text
kindText Stale = "stale"
kindText NotFastForward = "not_fast_forward"
kindText Unauthorized = "unauthorized"
kindText NotAdmissible = "invalid"

encodeResponse :: Response -> Value
encodeResponse rs =
  object $
    [ "verify" .= fmap verify' (rsVerify rs)
    , "admit" .= map admit' (rsAdmit rs)
    , "receive" .= map receive' (rsReceive rs)
    ]
      ++ ["serve" .= map serve' (rsServe rs) | not (null (rsServe rs))]
  where
    serve' (Served objects) = object ["recorded" .= map encodeObject (Set.toList objects)]
    serve' ServeDenied = object ["denied" .= True]
    serve' ServeRefused = object ["refused" .= True]
    receive' (ReceiveRecorded objects) = object ["recorded" .= map encodeObject (Set.toList objects)]
    receive' ReceiveRefused = object ["refused" .= True]
    verify' v =
      object
        [ "reached" .= map encodeObject (Set.toList (vrReached v))
        , "invalid" .= map encodeObject (Set.toList (vrInvalid v))
        , "conflicting" .= map encodeObject (Set.toList (vrConflicting v))
        , "current_rejected" .= vrCurrentRejected v
        ]
    admit' (Admitted c r cur) =
      object ["admitted" .= object ["commits" .= c, "releases" .= r, "new_current" .= fmap authInt cur]]
    admit' (Refused k) = object ["refused" .= kindText k]

parseResponse :: Value -> Parser Response
parseResponse = withObject "response" $ \o ->
  Response
    <$> (o .:? "verify" >>= traverse verify')
    <*> (o .: "admit" >>= mapM admit')
    <*> (o .:? "receive" >>= mapM receive' . fromMaybe [])
    -- Absent from responses saved before reads were compared, and from the
    -- answers of an oracle that has no instance to ask.
    <*> (o .:? "serve" >>= mapM serve' . fromMaybe [])
  where
    serve' = withObject "serve" $ \x -> do
      kept <- x .:? "recorded"
      denied <- x .:? "denied"
      refused <- x .:? "refused"
      case (kept, denied :: Maybe Bool, refused :: Maybe Bool) of
        (Just objects, Nothing, Nothing) -> Served . Set.fromList <$> mapM parseObject objects
        (Nothing, Just True, Nothing) -> pure ServeDenied
        (Nothing, Nothing, Just True) -> pure ServeRefused
        _ -> fail "a read is {\"recorded\": […]}, {\"denied\": true} or {\"refused\": true}"
    receive' = withObject "receive" $ \x -> do
      kept <- x .:? "recorded"
      refused <- x .:? "refused"
      case (kept, refused :: Maybe Bool) of
        (Just objects, Nothing) -> ReceiveRecorded . Set.fromList <$> mapM parseObject objects
        (Nothing, Just True) -> pure ReceiveRefused
        _ -> fail "a transfer is {\"recorded\": […]} or {\"refused\": true}"
    verify' = withObject "verify" $ \o ->
      VerifyResponse
        <$> (Set.fromList <$> (o .: "reached" >>= mapM parseObject))
        <*> (Set.fromList <$> (o .: "invalid" >>= mapM parseObject))
        <*> (Set.fromList <$> (o .: "conflicting" >>= mapM parseObject))
        -- Absent from responses saved before it was compared.
        <*> (fromMaybe False <$> o .:? "current_rejected")
    admit' = withObject "admit" $ \o -> do
      a <- o .:? "admitted"
      r <- o .:? "refused"
      case (a, r) of
        (Just adm, Nothing) -> flip (withObject "admitted") adm $ \x ->
          Admitted <$> num x "commits" <*> num x "releases" <*> (fmap AuthId <$> optNum x "new_current")
        (Nothing, Just k) -> Refused <$> withText "refusal" kind k
        _ -> fail "a decision is {\"admitted\": …} or {\"refused\": …}"
    kind t = maybe (fail ("unknown refusal " ++ Text.unpack t)) pure (lookup t [(kindText k, k) | k <- [minBound ..]])

-- | What an implementation said beside its response: damage it found, what
-- it thought of each authority, and its reasons for each refusal. Shown when
-- the two sides disagree, never compared. Damage is the exception: the
-- harness never sends a damaged store, so any at all is a fault in the
-- harness, and it is returned separately.
parseRemarks :: Value -> Parser ([String], [String])
parseRemarks = withObject "response" $ \o -> do
  v <- o .:? "verify"
  (damage, said) <- case v of
    Nothing -> pure ([], [])
    Just vo -> flip (withObject "verify") vo $ \x ->
      (,) <$> (maybe [] id <$> x .:? "damage") <*> (maybe [] id <$> x .:? "problems")
  decisions <- o .: "admit" >>= mapM (withObject "admit" (\x -> fromMaybe [] <$> x .:? "reasons"))
  let remarked name =
        o .:? name
          >>= mapM (withObject "remarked" (\x -> (,) <$> (fromMaybe [] <$> x .:? "damage") <*> (fromMaybe [] <$> x .:? "reasons")))
            . fromMaybe []
  transfers <- remarked "receive"
  asked <- remarked "serve"
  pure
    ( damage ++ concatMap fst transfers ++ concatMap fst asked
    , said
        ++ concat [("transaction " ++ show i ++ ": ") `prefix` rs | (i, rs) <- zip [0 :: Int ..] decisions]
        ++ concat [("transfer " ++ show i ++ ": ") `prefix` rs | (i, (_, rs)) <- zip [0 :: Int ..] transfers]
        ++ concat [("read " ++ show i ++ ": ") `prefix` rs | (i, (_, rs)) <- zip [0 :: Int ..] asked]
    )
  where
    prefix p = map (p ++)

-- | The damage reported of the reads alone.
parseServeDamage :: Value -> Parser [String]
parseServeDamage = withObject "response" $ \o ->
  o .:? "serve"
    >>= fmap concat . mapM (withObject "serve" (\x -> fromMaybe [] <$> x .:? "damage")) . fromMaybe []

-- | The damage reported of the transfers alone, for a run that is about
-- them and nothing else in the response.
parseTransferDamage :: Value -> Parser [String]
parseTransferDamage = withObject "response" $ \o ->
  o .:? "receive"
    >>= fmap concat . mapM (withObject "receive" (\x -> fromMaybe [] <$> x .:? "damage")) . fromMaybe []

-- * What the model expects

-- | The response the rules, under a reading, give to a request.
expected :: Reading -> Request -> Response
expected rd rq =
  Response
    { rsVerify = verified <$> rqVerify rq
    , rsAdmit = map decided (rqAdmit rq)
    , rsReceive = map transferred (rqReceive rq)
    , rsServe = map served (rqServe rq)
    }
  where
    st = rqStore rq
    served (current, who, roots) = case receive rd st current (Transfer (rqPin rq) roots who) of
      Recorded objects -> Served objects
      ReadDenied -> ServeDenied
      _ -> ServeRefused
    transferred (expects, current, roots) = case examine rd st expects current roots of
      Recorded objects -> ReceiveRecorded objects
      _ -> ReceiveRefused
    verified (current, roots) =
      let verdicts = verify rd st (rqPin rq) current roots
       in VerifyResponse
            { vrReached = Map.keysSet verdicts
            , vrInvalid = Map.keysSet (Map.filter isInvalid verdicts)
            , vrConflicting = Map.keysSet (Map.filter (== ConflictingLineage) verdicts)
            , vrCurrentRejected = maybe False (not . currentStands rd st (rqPin rq)) current
            }
    isInvalid (Invalid _) = True
    isInvalid _ = False
    decided (s, tx) = case admit rd st s tx of
      Left broken -> Refused (refusalKind broken)
      Right adm ->
        Admitted
          { arCommits = length [() | OCommit _ <- Set.toList (admExposed adm)]
          , arReleases = length [() | ORelease _ <- Set.toList (admExposed adm)]
          , arCurrent = txAuthority tx
          }

-- | Which kind of refusal @levcs-identity@ gives when a transaction breaks
-- several things at once.
--
-- This order is the implementation's and no part of the rules: the document
-- says what is refused, not which reason is given first. It is here so that
-- the kind can be compared exactly instead of loosely.
refusalKind :: Set Violation -> RefusalKind
refusalKind broken
  | has shape = NotAdmissible
  | has stale = Stale
  | NoCurrentAuthority `Set.member` broken = Unauthorized
  | CurrentNotOnPinnedChain `Set.member` broken = NotAdmissible
  | P1 `Set.member` broken = Unauthorized
  -- A target of the wrong kind is found when the history is read, which is
  -- before any ref's protection is looked at.
  | has illTyped = NotAdmissible
  | has unforced = NotFastForward
  | has denied = Unauthorized
  | otherwise = NotAdmissible
  where
    has p = any p (Set.toList broken)
    shape v = case v of
      P3AuthorityRef _ -> True
      BadRefName _ -> True
      NamedTwice _ -> True
      DeletesNothing _ -> True
      _ -> False
    illTyped v = case v of IllTyped _ -> True; _ -> False
    stale v = case v of StaleState _ -> True; _ -> False
    unforced v = case v of P4Unforced _ -> True; _ -> False
    denied v = case v of P4Protected _ -> True; P4Rewrite _ -> True; _ -> False

-- * Corpus

-- | A scenario kept with the response the rules give it, so that the Rust
-- test suite can replay it without a Haskell toolchain.
data CorpusEntry = CorpusEntry
  { ceName :: String
  , ceNote :: String
  , ceRequest :: Request
  , ceExpect :: Response
  -- ^ Under the 'implemented' reading.
  , ceRatified :: Response
  -- ^ Under the 'ratified' reading. It differs from 'ceExpect' exactly when
  -- the entry witnesses a recorded divergence.
  }
  deriving (Eq, Show)

encodeCorpusEntry :: CorpusEntry -> Value
encodeCorpusEntry e =
  object
    [ "name" .= ceName e
    , "note" .= ceNote e
    , "request" .= encodeRequest (ceRequest e)
    , "expect" .= encodeResponse (ceExpect e)
    , "ratified" .= encodeResponse (ceRatified e)
    ]

parseCorpusEntry :: Value -> Parser CorpusEntry
parseCorpusEntry = withObject "corpus entry" $ \o ->
  CorpusEntry
    <$> o .: "name"
    <*> o .: "note"
    <*> (o .: "request" >>= parseRequest)
    <*> (o .: "expect" >>= parseResponse)
    <*> (o .: "ratified" >>= parseResponse)
