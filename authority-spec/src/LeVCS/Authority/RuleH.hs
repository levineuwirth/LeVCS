-- | Rule H, historical validity, and the terms it is stated in.
--
-- Every definition quotes the sentence of @doc/authority-semantics.md@ it
-- transcribes. Rule H \"depends only on the objects, never on a destination
-- ref or on the receiver's state\", so nothing here takes one: the only
-- inputs are the store and the pinned genesis. 'verify' adds the replica's
-- @current@ for the one thing that does depend on the replica, which is
-- telling a valid commit on its own lineage from a valid commit on a
-- conflicting one (D2).
module LeVCS.Authority.RuleH
  ( -- * Terms
    isGenesis
  , lineage
  , equalsOrDescendsFrom
  , comparable
  , holds
  , hasOwner
  , isSuccessorOf
  , chainEndsAt
  , currentStands
  , effective
  , cited

    -- * Rule H
  , Clause (..)
  , commitViolations
  , releaseViolations
  , violations

    -- * @verify@
  , Verdict (..)
  , verify
  ) where

import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Maybe (fromMaybe, isJust, isNothing)
import Data.Set (Set)
import Data.Set qualified as Set

import LeVCS.Authority.Model
import LeVCS.Authority.Reading

-- * Terms

-- | \"Genesis is the authority with a zero @previous_authority@ and
-- @version = 1@.\"
isGenesis :: Authority -> Bool
isGenesis a = isNothing (aPrev a) && aVersion a == 1

-- | The authorities reached by following @previous_authority@, starting with
-- the one given.
lineage :: Store -> AuthId -> [AuthId]
lineage st = go Set.empty
  where
    go seen a
      | a `Set.member` seen = []
      | otherwise = a : maybe [] (go (Set.insert a seen)) (lookupAuthority st a >>= aPrev)

-- | \"@B@ descends from @A@ when following @previous_authority@ from @B@
-- reaches @A@.\" This is the \"equals or descends from\" of H.3.
equalsOrDescendsFrom :: Store -> AuthId -> AuthId -> Bool
equalsOrDescendsFrom st b a = a `elem` lineage st b

-- | \"Two authorities are comparable when one descends from the other.\"
comparable :: Store -> AuthId -> AuthId -> Bool
comparable st a b = equalsOrDescendsFrom st a b || equalsOrDescendsFrom st b a

-- | The key is a member holding at least the role.
holds :: Authority -> Key -> Role -> Bool
holds a k r = maybe False (>= r) (Map.lookup k (aMembers a))

hasOwner :: Authority -> Bool
hasOwner a = Owner `elem` Map.elems (aMembers a)

-- | \"A successor of authority @A@ names @A@ as previous, has version
-- @A.version + 1@, and is signed by an @Owner@ of @A@.\"
--
-- @isSuccessorOf rd st b a@: @b@ is a successor of @a@.
isSuccessorOf :: Reading -> Store -> AuthId -> AuthId -> Bool
isSuccessorOf rd st bId aId = fromMaybe False $ do
  b <- lookupAuthority st bId
  a <- lookupAuthority st aId
  pure $
    aPrev b == Just aId
      && aVersion b == aVersion a + 1
      && any (\s -> sigValid s && holds a (sigKey s) Owner) (aSigs b)
      && (not (everyAuthoritySignatureVerifies rd) || all sigValid (aSigs b))
      && (not (ownerlessRejectedWhenCited rd) || hasOwner b)

-- | The authority's chain is unbroken and ends at the given genesis: every
-- step back is from a successor to the authority it succeeds, and the last
-- authority reached is that genesis.
--
-- This is the \"chain ends at the genesis pinned by @repo_id@\" of H.2. A
-- chain with a step that is not a successor step is the \"broken chain\" that
-- @verify@ reports as invalid, and one ending anywhere else is the \"foreign
-- chain\".
chainEndsAt :: Reading -> Store -> AuthId -> AuthId -> Bool
chainEndsAt rd st pin a =
  case reverse chain of
    [] -> False
    oldest : _ ->
      oldest == pin
        && maybe False genesisOk (lookupAuthority st oldest)
        && and (zipWith (isSuccessorOf rd st) chain (drop 1 chain))
  where
    chain = lineage st a
    genesisOk g =
      isGenesis g && (not (everyAuthoritySignatureVerifies rd) || all sigValid (aSigs g))

-- | Whether a replica's current authority can be used as one.
--
-- The text takes @current@ as given: \"the lineage ending at that replica's
-- accepted @current@ is canonical\" (D2), whatever that authority is. Rule P
-- only ever moves it along the pinned chain, but a state can come from
-- elsewhere. Under divergence (g) a current authority stands only if its
-- chain is unbroken and ends at the pinned genesis.
currentStands :: Reading -> Store -> AuthId -> AuthId -> Bool
currentStands rd st pin current =
  not (currentMustBeOnThePinnedChain rd) || chainEndsAt rd st pin current

-- | \"@E(C)@ is the authority in effect after @C@: if @C@ modifies authority,
-- the successor @C@ installs at @.levcs\/authority@; otherwise @A(C)@.\"
effective :: Commit -> AuthId
effective c = fromMaybe (cCites c) (cInstalls c)

-- | @A(C)@, or the authority a release cites.
cited :: Store -> Object -> Maybe AuthId
cited st (OCommit c) = cCites <$> lookupCommit st c
cited st (ORelease r) = rCites <$> lookupRelease st r

-- * Rule H

-- | The clauses an object can break. A commit answers to H.1 to H.5; a
-- release to the four parts of the release rule.
data Clause
  = -- | \"The signature is valid. The signer is a member of @A(C)@, holding
    -- @Owner@ if @C@ modifies authority and @Contributor@ otherwise.\"
    H1
  | -- | \"@A(C)@'s chain ends at the genesis pinned by @repo_id@.\"
    H2
  | -- | \"For every parent @Pi@, @A(C)@ equals or descends from @E(Pi)@.\"
    H3
  | -- | \"A commit with no parents cites the pinned genesis.\"
    H4
  | -- | \"If @C@ modifies authority, @E(C)@ is a valid direct successor of
    -- @A(C)@ with at least one @Owner@.\"
    H5
  | -- | A release's signature is valid.
    ReleaseSignature
  | -- | The chain of the authority a release cites ends at the pinned
    -- genesis.
    ReleaseChain
  | -- | \"Its declarer holds @Maintainer@ or above in @A(release)@.\"
    ReleaseDeclarer
  | -- | \"@A(release)@ equals or descends from @E(predecessor)@.\"
    ReleasePredecessor
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | The clauses of Rule H that a commit breaks, in the history whose genesis
-- is @pin@. The commit is historically valid if and only if there are none.
--
-- The verdict is the commit's own. A parent enters only through @E(Pi)@,
-- which is read off the parent whether or not the parent is itself valid.
commitViolations :: Reading -> Store -> AuthId -> Commit -> Set Clause
commitViolations rd st pin c =
  Set.fromList $
    [H1 | not h1] ++ [H2 | not h2] ++ [H3 | not h3] ++ [H4 | not h4] ++ [H5 | not h5]
  where
    signer = sigKey (cSig c)
    citedBody = lookupAuthority st (cCites c)
    required = if isJust (cInstalls c) then Owner else Contributor

    h1 = sigValid (cSig c) && maybe False (\a -> holds a signer required) citedBody

    h2 = chainEndsAt rd st pin (cCites c)

    h3 = all afterParent (cParents c)
    afterParent p = case lookupCommit st p of
      Nothing -> False
      Just parent -> equalsOrDescendsFrom st (cCites c) (effective parent)

    h4 = not (null (cParents c)) || cCites c == pin

    h5 = case cInstalls c of
      Nothing -> True
      Just new ->
        isSuccessorOf rd st new (cCites c)
          && maybe False hasOwner (lookupAuthority st new)
          && (not (successorSignedByBoundaryAuthor rd) || signedBy new)
    -- A signature that does not verify is not the author's signature, whatever
    -- key it names. This matters only where (b) is off: with it on, no
    -- signature on a successor fails.
    signedBy new =
      maybe False (any (\s -> sigKey s == signer && sigValid s) . aSigs) (lookupAuthority st new)

-- | \"A release is valid if its declarer holds @Maintainer@ or above in
-- @A(release)@, and @A(release)@ equals or descends from @E(predecessor)@.\"
--
-- The sentence takes two things as read, and they are clauses here: the
-- declarer's signature verifies, and @A(release)@ is an authority of this
-- repository. Without them the sentence would admit a release nobody signed,
-- under an authority of another repository.
releaseViolations :: Reading -> Store -> AuthId -> Release -> Set Clause
releaseViolations rd st pin r =
  Set.fromList $
    [ReleaseSignature | not (sigValid (rSig r))]
      ++ [ReleaseChain | not (chainEndsAt rd st pin (rCites r))]
      ++ [ReleaseDeclarer | not declarer]
      ++ [ReleasePredecessor | not predecessor]
  where
    declarer = maybe False (\a -> holds a (sigKey (rSig r)) Maintainer) (lookupAuthority st (rCites r))
    predecessor = case lookupCommit st (rPredecessor r) of
      Nothing -> False
      Just p -> equalsOrDescendsFrom st (rCites r) (effective p)

-- | Rule H for either kind of object. A name that no object answers to
-- satisfies nothing.
violations :: Reading -> Store -> AuthId -> Object -> Set Clause
violations rd st pin (OCommit c) =
  maybe (Set.fromList [H1 .. H5]) (commitViolations rd st pin) (lookupCommit st c)
violations rd st pin (ORelease r) =
  maybe (Set.fromList [ReleaseSignature ..]) (releaseViolations rd st pin) (lookupRelease st r)

-- * @verify@

-- | \"@verify@ reports one of three, and keeps them distinct.\"
data Verdict
  = Valid
  | -- | \"The commit is historically valid, but cites an authority that is
    -- incomparable with this replica's canonical lineage (D2).\"
    ConflictingLineage
  | Invalid (Set Clause)
  deriving (Eq, Show)

-- | A verdict for everything the roots reach, against the pinned genesis
-- and, when the replica has one, its @current@ authority.
--
-- \"Within a replica, the lineage ending at that replica's accepted @current@
-- is canonical\" (D2). With no @current@ there is no canonical lineage, and
-- nothing is reported as conflicting. The same goes, under divergence (g),
-- for a @current@ that does not stand.
verify :: Reading -> Store -> AuthId -> Maybe AuthId -> [Object] -> Map Object Verdict
verify rd st pin given roots = Map.fromSet verdict (closure st roots)
  where
    current = case given of
      Just cur | currentStands rd st pin cur -> Just cur
      _ -> Nothing

    verdict o
      | not (Set.null broken) = Invalid broken
      | conflicting o = ConflictingLineage
      | otherwise = Valid
      where
        broken = violations rd st pin o

    conflicting o = case current of
      Nothing -> False
      Just cur -> any (not . comparable st cur) (classified o)

    classified (OCommit c) = case lookupCommit st c of
      Nothing -> []
      Just k -> cCites k : [a | installedAuthorityCanConflict rd, Just a <- [cInstalls k]]
    classified (ORelease r) = maybe [] (pure . rCites) (lookupRelease st r)
