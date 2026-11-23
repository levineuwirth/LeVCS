-- SPDX-FileCopyrightText: 2026 Levi Neuwirth
-- SPDX-License-Identifier: Apache-2.0

-- | Scripts that build histories and publish them.
--
-- A script is a list of operations whose references are small integers
-- resolved against whatever exists when the operation runs: \"the second
-- newest commit\", \"the first owner of the predecessor\". That makes every
-- script meaningful, and lets a failing one shrink by dropping operations
-- and lowering integers.
--
-- Operations come in an honest form, which picks what a well-behaved client
-- would pick, and an arbitrary form, which picks anything. The rules are
-- never consulted to decide what a script /means/, only (for publication
-- scripts) to decide what state the next transaction starts from. So a
-- script cannot agree with the model by construction.
module LeVCS.Harness.Script
  ( -- * Picking
    Pick (..)
  , keyCount
  , branchNames
  , releaseNames
  , protections
  , pinId

    -- * Building a store
  , Op (..)
  , From (..)
  , Edit (..)
  , Signer (..)
  , Cite (..)
  , Parent (..)
  , ParentRelease (..)
  , Ctx (..)
  , noCtx
  , genesisStore
  , applyOp

    -- * History scenarios
  , HScenario (..)
  , History (..)
  , buildHistory
  , heads

    -- * Publication scenarios
  , PScenario (..)
  , Step (..)
  , PushOp (..)
  , Upd (..)
  , RefPick (..)
  , AuthPick (..)
  , Attempt (..)
  , Trace (..)
  , runP
  ) where

import Data.List (nubBy, sortOn)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Maybe (isJust, listToMaybe, mapMaybe)
import Data.Ord (Down (..))
import Data.Set (Set)
import Data.Set qualified as Set

import LeVCS.Authority.Model
import LeVCS.Authority.Reading
import LeVCS.Authority.RuleH
import LeVCS.Authority.RuleP

-- * Picking

-- | 'Honest' picks among the candidates a well-behaved client would
-- consider, and falls back to 'Any' when there are none.
data Pick = Honest Int | Any Int
  deriving (Eq, Show)

-- | Keys are @k0@ to @k4@. @k0@ is an Owner of every genesis.
keyCount :: Int
keyCount = 5

branchNames, releaseNames :: [String]
branchNames = ["b0", "b1", "b2"]
releaseNames = ["r0", "r1"]

-- | The globs a policy's @protected_branches@ is drawn from: literal names,
-- every kind of wildcard, by short name and by full ref, and some that
-- match release refs or nothing at all.
protections :: [String]
protections =
  [ "b0"
  , "b*"
  , "refs/branches/b1"
  , "b?"
  , "[a-c]0"
  , "b[!0]"
  , "refs/branches/*"
  , "refs/*/b2"
  , "*"
  , "r*"
  , "refs/releases/*"
  , "B0"
  , "b"
  , "[b"
  ]

-- | The first authority made is the repository's genesis.
pinId :: AuthId
pinId = AuthId 0

-- | The @i@-th element, counting round the list; nothing from nothing.
nth :: [a] -> Int -> Maybe a
nth [] _ = Nothing
nth xs i = Just (xs !! (i `mod` length xs))

key :: Int -> Key
key i = Key (i `mod` keyCount)

newestFirst :: Map k v -> [k]
newestFirst = reverse . Map.keys

-- * Building a store

data From
  = -- | The @i@-th newest authority.
    FromRecent Int
  | -- | The replica's current authority, where there is one.
    FromCurrent
  deriving (Eq, Show)

data Edit
  = Grant Int Role
  | Revoke Int
  | Protect Int
  | Unprotect Int
  | Publicise Bool
  deriving (Eq, Show)

data Signer
  = -- | The @i@-th Owner of the predecessor, with a signature that verifies.
    OwnerSigns Int
  | -- | A given key, with a signature that verifies or does not.
    KeySigns Int Bool
  deriving (Eq, Show)

data Cite
  = -- | The replica's current authority, where there is one.
    CiteCurrent
  | -- | The @i@-th oldest authority that equals or descends from what is in
    -- effect after every parent. @CiteFloor 0@ is the tightest such.
    CiteFloor Int
  | -- | The @i@-th newest authority, whatever it is.
    CiteAny Int
  deriving (Eq, Show)

data Parent
  = -- | The @i@-th newest commit.
    Recent Int
  | -- | The published tip of the @i@-th branch. Where that branch does not
    -- exist yet, the tip of one that does: a new branch starts from published
    -- history. With nothing published at all, no parent.
    Tip Int
  deriving (Eq, Show)

data ParentRelease
  = RecentRelease Int
  | -- | What the @i@-th release ref holds, where it holds anything.
    HeldRelease Int
  deriving (Eq, Show)

data Op
  = -- | Another repository's genesis.
    OpGenesis [(Int, Role)]
  | OpSuccessor
      { osFrom :: From
      , osEdits :: [Edit]
      , osSigners :: [Signer]
      , osVersionSkew :: Int
      }
  | OpCommit
      { ocParents :: [Parent]
      , ocCites :: Cite
      , ocSigner :: Pick
      , ocSigValid :: Bool
      , ocInstalls :: Maybe Pick
      -- ^ 'Honest' picks among the authorities naming the cited one as
      -- previous, newest first, and installs nothing if there are none.
      }
  | OpRelease
      { orPredecessor :: Parent
      , orParent :: Maybe ParentRelease
      , orCites :: Cite
      , orSigner :: Pick
      , orSigValid :: Bool
      }
  deriving (Eq, Show)

-- | What an operation can see of the replica it is made on.
data Ctx = Ctx
  { ctxCurrent :: Maybe AuthId
  , ctxRefs :: Map RefName Object
  }

noCtx :: Ctx
noCtx = Ctx Nothing Map.empty

genesisOf :: [(Int, Role)] -> [Int] -> Authority
genesisOf members protected =
  Authority
    { aPrev = Nothing
    , aVersion = 1
    , aMembers = Map.insert (Key 0) Owner (Map.fromList [(key k, r) | (k, r) <- members])
    , aProtected = Set.fromList (mapMaybe (nth protections) protected)
    , aPublicRead = False
    , aSigs = [Sig (Key 0) True]
    }

-- | A store holding only a genesis, as 'pinId'.
genesisStore :: [(Int, Role)] -> [Int] -> Store
genesisStore members protected = addAuthority (genesisOf members protected) emptyStore

addAuthority :: Authority -> Store -> Store
addAuthority a st = st {sAuthorities = Map.insert (AuthId (Map.size (sAuthorities st))) a (sAuthorities st)}

addCommit :: Commit -> Store -> Store
addCommit c st = st {sCommits = Map.insert (CommitId (Map.size (sCommits st))) c (sCommits st)}

addRelease :: Release -> Store -> Store
addRelease r st = st {sReleases = Map.insert (ReleaseId (Map.size (sReleases st))) r (sReleases st)}

applyOp :: Ctx -> Op -> Store -> Store
applyOp _ (OpGenesis members) st = addAuthority (genesisOf members []) st
applyOp ctx (OpSuccessor from edits signers skew) st =
  case predecessor >>= \p -> (,) p <$> lookupAuthority st p of
    Nothing -> st
    Just (pid, p) ->
      addAuthority
        (foldl (flip edit) p edits)
          { aPrev = Just pid
          , aVersion = max 0 (aVersion p + 1 + skew)
          , aSigs = nubBy (\a b -> sigKey a == sigKey b) (map (sign p) signers)
          }
        st
  where
    predecessor = case from of
      FromCurrent | Just cur <- ctxCurrent ctx -> Just cur
      FromCurrent -> nth (newestFirst (sAuthorities st)) 0
      FromRecent i -> nth (newestFirst (sAuthorities st)) i
    edit (Grant k r) a = a {aMembers = Map.insert (key k) r (aMembers a)}
    edit (Revoke k) a
      -- An authority keeps at least one member, so that it can be encoded.
      | Map.size (aMembers a) > 1 = a {aMembers = Map.delete (key k) (aMembers a)}
      | otherwise = a
    edit (Protect p) a = a {aProtected = maybe id Set.insert (nth protections p) (aProtected a)}
    edit (Unprotect p) a = a {aProtected = maybe id Set.delete (nth protections p) (aProtected a)}
    edit (Publicise yes) a = a {aPublicRead = yes}
    sign p (OwnerSigns i) = case nth [k | (k, Owner) <- Map.toList (aMembers p)] i of
      Just k -> Sig k True
      Nothing -> Sig (key i) True
    sign _ (KeySigns k ok) = Sig (key k) ok
applyOp ctx (OpCommit parentPicks cite signer ok install) st =
  addCommit
    Commit
      { cParents = parents
      , cCites = citedId
      , cSig = Sig (signerFor st citedId required installs signer) ok
      , cInstalls = installs
      }
    st
  where
    parents = dedup (mapMaybe (resolveParent ctx st) parentPicks)
    floors = [effective c | p <- parents, Just c <- [lookupCommit st p]]
    citedId = resolveCite ctx st floors cite
    installs = case install of
      Nothing -> Nothing
      -- With no direct successor to install, an honest commit installs
      -- nothing.
      Just (Honest i) -> nth [a | a <- newestFirst (sAuthorities st), prevOf a == Just citedId] i
      Just (Any i) -> nth (newestFirst (sAuthorities st)) i
    prevOf a = lookupAuthority st a >>= aPrev
    required = if isJust installs then Owner else Contributor
applyOp ctx (OpRelease predPick parentPick cite signer ok) st =
  case resolveParent ctx st predPick of
    -- A release needs a commit to follow.
    Nothing -> st
    Just predecessor ->
      let floors = [effective c | Just c <- [lookupCommit st predecessor]]
          citedId = resolveCite ctx st floors cite
       in addRelease
            Release
              { rPredecessor = predecessor
              , rParent = parentPick >>= resolveParentRelease
              , rCites = citedId
              , rSig = Sig (signerFor st citedId Maintainer Nothing signer) ok
              }
            st
  where
    resolveParentRelease (RecentRelease i) = nth (newestFirst (sReleases st)) i
    resolveParentRelease (HeldRelease i) = do
      name <- nth releaseNames i
      ORelease r <- Map.lookup (ReleaseRef name) (ctxRefs ctx)
      pure r

dedup :: Eq a => [a] -> [a]
dedup = nubBy (==)

resolveParent :: Ctx -> Store -> Parent -> Maybe CommitId
resolveParent _ st (Recent i) = nth (newestFirst (sCommits st)) i
resolveParent ctx _ (Tip i) = listToMaybe (own ++ others)
  where
    own = [c | Just name <- [nth branchNames i], Just (OCommit c) <- [Map.lookup (Branch name) (ctxRefs ctx)]]
    others = [c | (Branch _, OCommit c) <- Map.toList (ctxRefs ctx)]

-- | The authority an object cites, given what is in effect after each of the
-- objects it follows.
resolveCite :: Ctx -> Store -> [AuthId] -> Cite -> AuthId
resolveCite ctx st floors cite = case cite of
  CiteCurrent | Just cur <- ctxCurrent ctx -> cur
  CiteCurrent -> floorPick 0
  CiteFloor i -> floorPick i
  CiteAny i -> anyPick i
  where
    anyPick i = maybe pinId id (nth (newestFirst (sAuthorities st)) i)
    floorPick i = maybe (anyPick i) id (nth candidates i)
    candidates
      | null floors = [pinId]
      | otherwise =
          sortOn
            (\a -> (maybe 0 aVersion (lookupAuthority st a), a))
            [a | a <- Map.keys (sAuthorities st), all (equalsOrDescendsFrom st a) floors]

-- | The key that signs. An honest signer holds the role the object needs in
-- the authority it cites and, for a commit that installs a successor, has
-- signed that successor where any such member has.
signerFor :: Store -> AuthId -> Role -> Maybe AuthId -> Pick -> Key
signerFor _ _ _ _ (Any i) = key i
signerFor st citedId required installs (Honest i) =
  maybe (key i) id (nth (sortOn (Down . signedSuccessor) holders) i)
  where
    holders = case lookupAuthority st citedId of
      Nothing -> []
      Just a -> [k | (k, r) <- Map.toList (aMembers a), r >= required]
    signedSuccessor k = case installs >>= lookupAuthority st of
      Nothing -> False
      Just new -> Sig k True `elem` aSigs new

-- * History scenarios

data HScenario = HScenario
  { hsGenesis :: [(Int, Role)]
  , hsOps :: [Op]
  , hsCurrent :: Maybe Int
  -- ^ The replica's current authority: the @i@-th newest authority whose
  -- chain is unbroken and ends at the genesis. 'Nothing' is a replica with
  -- none.
  }
  deriving (Eq, Show)

data History = History
  { hStore :: Store
  , hCurrent :: Maybe AuthId
  , hRoots :: [Object]
  }
  deriving (Eq, Show)

buildHistory :: HScenario -> History
buildHistory sc =
  History
    { hStore = st
    , hCurrent = hsCurrent sc >>= nth onChain
    , hRoots = heads st
    }
  where
    st = foldl (flip (applyOp noCtx)) (genesisStore (hsGenesis sc) []) (hsOps sc)
    -- Under the stricter reading, so that the pick is an authority both
    -- readings accept as this repository's.
    onChain = [a | a <- newestFirst (sAuthorities st), chainEndsAt amended st pinId a]

-- | The objects nothing else follows from. Every object is behind one.
heads :: Store -> [Object]
heads st = filter (`Set.notMember` followed) everything
  where
    everything = map OCommit (Map.keys (sCommits st)) ++ map ORelease (Map.keys (sReleases st))
    followed = Set.fromList (concatMap (links st) everything)

-- * Publication scenarios

data RefPick = RBranch Int | RRelease Int | RAuthority
  deriving (Eq, Show)

data Upd = Upd
  { upRef :: RefPick
  , upNew :: Maybe Int
  -- ^ The @i@-th newest commit, or release for a release ref; 'Nothing'
  -- deletes.
  , upExpected :: Maybe Int
  -- ^ 'Nothing' expects what the ref holds. Otherwise the @i@-th newest
  -- object of its kind, which may or may not be that.
  , upForce :: Bool
  }
  deriving (Eq, Show)

data AuthPick
  = -- | Move @current@ to what a commit being published installs, and
    -- leave it alone if none installs anything.
    AuthFollow
  | AuthNone
  | AuthAny Int
  deriving (Eq, Show)

data PushOp = PushOp
  { pSigner :: Pick
  -- ^ 'Honest' picks among the current authority's members, highest role
  -- first.
  , pUpdates :: [Upd]
  , pAuthority :: AuthPick
  }
  deriving (Eq, Show)

data Step = Make Op | Push PushOp
  deriving (Eq, Show)

data PScenario = PScenario
  { psGenesis :: [(Int, Role)]
  , psProtected :: [Int]
  , psSteps :: [Step]
  }
  deriving (Eq, Show)

-- | One transaction, the state it was put to, and what the model decided.
data Attempt = Attempt
  { atState :: State
  , atTx :: Transaction
  , atResult :: Either (Set Violation) Admission
  }
  deriving (Eq, Show)

data Trace = Trace
  { tStore :: Store
  -- ^ Every object the script made, published or not.
  , tAttempts :: [Attempt]
  , tFinal :: State
  }
  deriving (Eq, Show)

-- | Run a publication script from a repository that has published nothing.
-- The state moves only when the model, under the given reading, admits a
-- transaction.
runP :: Reading -> PScenario -> Trace
runP rd sc = finish (foldl step (store0, initialState pinId, []) (psSteps sc))
  where
    store0 = genesisStore (psGenesis sc) (psProtected sc)
    finish (st, s, attempts) = Trace st (reverse attempts) s
    step (st, s, attempts) (Make op) = (applyOp (Ctx (sCurrent s) (sRefs s)) op st, s, attempts)
    step (st, s, attempts) (Push p) =
      let tx = resolveTx st s p
          result = admit rd st s tx
          s' = either (const s) admState result
       in (st, s', Attempt s tx result : attempts)

resolveTx :: Store -> State -> PushOp -> Transaction
resolveTx st s (PushOp signer ups auth) =
  Transaction {txSigner = signerKey, txUpdates = updates, txAuthority = authority}
  where
    signerKey = case signer of
      Any i -> key i
      Honest i -> maybe (key i) id (nth members i)
    members = case sCurrent s >>= lookupAuthority st of
      Nothing -> []
      Just a -> map fst (sortOn (Down . snd) [m | m@(_, r) <- Map.toList (aMembers a), r >= Contributor])

    updates = nubBy (\a b -> uRef a == uRef b) (mapMaybe resolveUpd ups)

    resolveUpd (Upd ref new expected force) = do
      (name, objects) <- case ref of
        RBranch i -> (,) . Branch <$> nth branchNames i <*> Just (map OCommit (newestFirst (sCommits st)))
        RRelease i -> (,) . ReleaseRef <$> nth releaseNames i <*> Just (map ORelease (newestFirst (sReleases st)))
        RAuthority -> Just (AuthorityRef "current", map OCommit (newestFirst (sCommits st)))
      let held = Map.lookup name (sRefs s)
          expects = maybe held (nth objects) expected
      update <- case new of
        Nothing -> Just (Update name expects Nothing force)
        -- Asked to name an object where none exists yet: no update.
        Just i -> (\o -> Update name expects (Just o) force) <$> nth objects i
      -- A transaction never deletes a ref it expects to be absent.
      if uNew update == Nothing && uExpected update == Nothing then Nothing else Just update

    authority = case auth of
      AuthNone -> Nothing
      AuthAny i -> nth (newestFirst (sAuthorities st)) i
      -- What a client knows it is pushing: the commits its new values reach
      -- that the refs do not reach already.
      AuthFollow ->
        listToMaybe
          [ a
          | OCommit c <- Set.toList (closure st [o | Update {uNew = Just o} <- updates] `Set.difference` published st s)
          , Just k <- [lookupCommit st c]
          , Just a <- [cInstalls k]
          ]
