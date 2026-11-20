-- | Rule R, replication: \"receiving history that was already published
-- elsewhere\".
--
-- The rule is decided in two places, and so it is two functions here.
-- 'mayRead' is the source's decision: whether to send anything. 'examine' is
-- the receiver's: whether to keep what was sent. 'receive' is the two in
-- order.
module LeVCS.Authority.RuleR
  ( -- * At the source
    Requester (..)
  , mayRead

    -- * At the receiver
  , Received (..)
  , examine

    -- * A transfer
  , Transfer (..)
  , receive
  ) where

import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Set (Set)

import LeVCS.Authority.Model
import LeVCS.Authority.Reading
import LeVCS.Authority.RuleH

-- * At the source

-- | Who is asking the source for history.
data Requester = Anonymous | Holding Key
  deriving (Eq, Show)

-- | R.2: \"No membership is required of the receiver. The receiver needs only
-- the source's read permission: @public_read@, or a role of at least @Reader@
-- there.\"
mayRead :: Authority -> Requester -> Bool
mayRead source who = aPublicRead source || case who of
  Anonymous -> False
  Holding k -> holds source k Reader

-- * At the receiver

-- | What a transfer comes to.
data Received
  = -- | Recorded as the source's state. R.4: \"Replication admits nothing to
    -- the destination's authoritative state\", which is why this carries the
    -- received objects and no state: there is nothing here that Rule P could
    -- mistake for admission.
    Recorded (Set Object)
  | -- | R.2: the requester has no read permission at the source.
    ReadDenied
  | -- | R.1: \"If a chain ends at a different genesis, the transfer is
    -- refused\", as it is for any other failure of Rule H. Every object the
    -- transfer is refused for, with its verdict; none of them is 'Valid'.
    TransferRefused (Map Object Verdict)
  | -- | Divergence (g): the source's current authority is not an authority
    -- of the repository expected.
    NotThatRepository
  deriving (Eq, Show)

-- | What a receiver makes of the history behind the roots it asked for,
-- sent by a source whose current authority is the one given.
--
-- R.1: \"Every received commit and release passes Rule H against the
-- genesis pinned by the expected @repo_id@.\" The genesis is the receiver's
-- expectation and no part of what the source says: a source holding another
-- repository's history is refused, because none of it passes H.2 against
-- the genesis expected.
--
-- R.3, \"revoked authors are no obstacle\", is the absence of any other
-- check: the source's current authority is not consulted about what is
-- received. A commit by an author since removed is accepted exactly when
-- Rule H accepts it.
--
-- Read literally that holds for a conflicting lineage too. A commit on one
-- is historically valid, so it passes Rule H and is received; D2 detects
-- the disagreement and nothing in Rule R turns it into a refusal. Under
-- divergence (f) it is one: the history is classified against the source's
-- current authority, and anything on a conflicting lineage refuses the
-- whole transfer.
--
-- Only what the roots reach is recorded. A source's other refs, and what
-- only they reach, are no part of the transfer.
--
-- Read literally, that makes a transfer of nothing acceptable from any
-- source: no commit or release is received, so none fails. Under divergence
-- (g) the source is looked at before anything it sent. Its current authority
-- must have an unbroken chain ending at the genesis expected, or the
-- transfer is refused whatever was asked for.
examine :: Reading -> Store -> AuthId -> AuthId -> [Object] -> Received
examine rd st expected sourceCurrent roots
  | not (currentStands rd st expected sourceCurrent) = NotThatRepository
  | Map.null refused = Recorded (Map.keysSet verdicts)
  | otherwise = TransferRefused refused
  where
    canonical
      | conflictRefusesTransfer rd = Just sourceCurrent
      | otherwise = Nothing
    verdicts = verify rd st expected canonical roots
    refused = Map.filter (/= Valid) verdicts

-- * A transfer

-- | What a receiver asks of a source. None of it is the source's to say.
data Transfer = Transfer
  { tfExpected :: AuthId
  -- ^ The genesis pinned by the expected @repo_id@.
  , tfRoots :: [Object]
  -- ^ What is asked for: the targets of the refs wanted, which need not be
  -- every ref the source has.
  , tfRequester :: Requester
  }
  deriving (Eq, Show)

-- | A transfer from a source whose current authority is the one given.
--
-- R.2 is decided first, in the source's current authority. A source with no
-- current authority has no policy to permit anyone, so nobody reads it.
receive :: Reading -> Store -> Maybe AuthId -> Transfer -> Received
receive rd st sourceCurrent t = case sourceCurrent of
  Just current
    | Just there <- lookupAuthority st current
    , mayRead there (tfRequester t) ->
        examine rd st (tfExpected t) current (tfRoots t)
  _ -> ReadDenied
