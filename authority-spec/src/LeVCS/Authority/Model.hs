-- | The objects that Rules H, R and P of @doc/authority-semantics.md@ speak
-- about, with everything the rules never read left out.
--
-- What is abstracted away:
--
-- * __Bytes and hashes.__ An object is named by a small integer. Two objects
--   with the same fields are still two objects.
-- * __Cryptography.__ A signature is the fact that a key signed, and whether
--   that signature verifies.
-- * __Trees.__ The only thing a tree tells the rules is which authority a
--   commit installs at @.levcs\/authority@, so a commit records that directly.
-- * __Time.__ Timestamps are self-asserted and the rules do not read them.
-- * __Damage.__ Every reference is taken to name an object of the right kind.
--   Missing, corrupt and mis-typed objects are a separate question from
--   whether intact history obeys the rules.
-- * __Forks.__ Fork commits keep their implemented rule and are not modelled.
module LeVCS.Authority.Model
  ( -- * Principals
    Key (..)
  , Role (..)
  , Sig (..)

    -- * Objects
  , AuthId (..)
  , CommitId (..)
  , ReleaseId (..)
  , Object (..)
  , Authority (..)
  , Commit (..)
  , Release (..)

    -- * The store
  , Store (..)
  , emptyStore
  , lookupAuthority
  , lookupCommit
  , lookupRelease
  , links
  , closure
  , reaches
  ) where

import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Set (Set)
import Data.Set qualified as Set

newtype Key = Key Int
  deriving (Eq, Ord, Show)

-- | Ordered: each role includes the ones before it.
data Role = Reader | Contributor | Maintainer | Owner
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | A signature by a key, and whether it verifies over the object it is on.
data Sig = Sig
  { sigKey :: Key
  , sigValid :: Bool
  }
  deriving (Eq, Ord, Show)

newtype AuthId = AuthId Int
  deriving (Eq, Ord, Show)

newtype CommitId = CommitId Int
  deriving (Eq, Ord, Show)

newtype ReleaseId = ReleaseId Int
  deriving (Eq, Ord, Show)

-- | The two kinds of object that Rule H gives a verdict on.
data Object = OCommit CommitId | ORelease ReleaseId
  deriving (Eq, Ord, Show)

-- | Terms: \"a signed membership object: @repo_id@, @previous_authority@,
-- @version@, members with roles, and policy.\"
--
-- @repo_id@ is not a field here. It pins one genesis, and the model names
-- that genesis directly wherever the rules need the pin.
data Authority = Authority
  { aPrev :: Maybe AuthId
  -- ^ @previous_authority@; 'Nothing' is the zero id.
  , aVersion :: Int
  , aMembers :: Map Key Role
  , aProtected :: Set String
  -- ^ Policy: @protected_branches@, a set of globs. What they protect is
  -- 'LeVCS.Authority.RuleP.protects'. The policy's value is the globs joined
  -- by commas, so a glob is never empty and never has a comma in it.
  , aPublicRead :: Bool
  -- ^ Policy: @public_read@.
  , aSigs :: [Sig]
  }
  deriving (Eq, Show)

data Commit = Commit
  { cParents :: [CommitId]
  , cCites :: AuthId
  -- ^ @A(C)@.
  , cSig :: Sig
  -- ^ The author's signature.
  , cInstalls :: Maybe AuthId
  -- ^ 'Just' when the commit modifies authority: what it installs at
  -- @.levcs\/authority@.
  }
  deriving (Eq, Show)

data Release = Release
  { rPredecessor :: CommitId
  , rParent :: Maybe ReleaseId
  , rCites :: AuthId
  , rSig :: Sig
  -- ^ The declarer's signature.
  }
  deriving (Eq, Show)

data Store = Store
  { sAuthorities :: Map AuthId Authority
  , sCommits :: Map CommitId Commit
  , sReleases :: Map ReleaseId Release
  }
  deriving (Eq, Show)

emptyStore :: Store
emptyStore = Store Map.empty Map.empty Map.empty

lookupAuthority :: Store -> AuthId -> Maybe Authority
lookupAuthority st a = Map.lookup a (sAuthorities st)

lookupCommit :: Store -> CommitId -> Maybe Commit
lookupCommit st c = Map.lookup c (sCommits st)

lookupRelease :: Store -> ReleaseId -> Maybe Release
lookupRelease st r = Map.lookup r (sReleases st)

-- | Where history continues from an object: a commit's parents; a release's
-- predecessor and its parent release.
links :: Store -> Object -> [Object]
links st (OCommit c) = maybe [] (map OCommit . cParents) (lookupCommit st c)
links st (ORelease r) = case lookupRelease st r of
  Nothing -> []
  Just rel -> OCommit (rPredecessor rel) : [ORelease p | Just p <- [rParent rel]]

-- | Everything the given objects reach, themselves included.
closure :: Store -> [Object] -> Set Object
closure st = go Set.empty
  where
    go seen [] = seen
    go seen (o : rest)
      | o `Set.member` seen = go seen rest
      | otherwise = go (Set.insert o seen) (links st o ++ rest)

-- | @reaches st from to@: @to@ is @from@ or history behind it.
reaches :: Store -> Object -> Object -> Bool
reaches st from to = to `Set.member` closure st [from]
