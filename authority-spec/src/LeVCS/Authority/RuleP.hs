-- SPDX-FileCopyrightText: 2026 Levi Neuwirth
-- SPDX-License-Identifier: Apache-2.0

-- | Rule P, publication: \"changing a repository's authoritative state\",
-- \"evaluated against the single pre-transaction state @S0@\".
module LeVCS.Authority.RuleP
  ( -- * Authoritative state
    RefName (..)
  , State (..)
  , initialState
  , published

    -- * Transactions
  , Update (..)
  , Transaction (..)
  , newlyExposed
  , wellNamed

    -- * Protected branches
  , protects
  , globMatches

    -- * Admission
  , Violation (..)
  , Admission (..)
  , admit
  ) where

import Control.Applicative ((<|>))
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Maybe (isNothing)
import Data.Set (Set)
import Data.Set qualified as Set

import LeVCS.Authority.Model
import LeVCS.Authority.Reading
import LeVCS.Authority.RuleH

-- * Authoritative state

-- | A ref of the authoritative state. A branch names a commit and a release
-- ref names a release. @refs\/remote\/…@ has no constructor: \"it never
-- includes @refs\/remote\/…@\".
data RefName
  = Branch String
  | ReleaseRef String
  | -- | @refs\/authority\/…@. No transaction may name one (P.3), so a state
    -- never holds one either; it is here so that a transaction can try.
    AuthorityRef String
  deriving (Eq, Ord, Show)

-- | @S0@: \"the authoritative state before a transaction, with
-- @A0 = refs\/authority\/current@\".
--
-- A state's refs are branches naming commits and release refs naming
-- releases, under names a ref can have. 'admit' takes that as given.
data State = State
  { sPin :: AuthId
  -- ^ The genesis that @repo_id@ pins.
  , sCurrent :: Maybe AuthId
  -- ^ @A0@. A replica received under v1 has none (D6).
  , sRefs :: Map RefName Object
  }
  deriving (Eq, Show)

-- | A repository that has published nothing: its current authority is its
-- genesis.
initialState :: AuthId -> State
initialState pin = State {sPin = pin, sCurrent = Just pin, sRefs = Map.empty}

-- | @R0@: \"the commits admitted to the destination's authoritative state
-- before the transaction. Object presence, remote refs and workspace refs do
-- not establish admission.\" It is what the state's refs reach and nothing
-- else in the store.
published :: Store -> State -> Set Object
published st s = closure st (Map.elems (sRefs s))

-- * Transactions

data Update = Update
  { uRef :: RefName
  , uExpected :: Maybe Object
  -- ^ What the ref held when the transaction was made.
  , uNew :: Maybe Object
  -- ^ What it will hold; 'Nothing' deletes it.
  , uForce :: Bool
  }
  deriving (Eq, Show)

-- | Anything can be asked for. Whether it is a transaction at all is the
-- first thing 'admit' decides.
data Transaction = Transaction
  { txSigner :: Key
  , txUpdates :: [Update]
  , txAuthority :: Maybe AuthId
  -- ^ @A1@, when the transaction moves @current@.
  }
  deriving (Eq, Show)

-- | \"A commit is newly exposed by a transaction if the transaction makes the
-- authoritative state reach it and @R0@ does not contain it.\"
newlyExposed :: Store -> State -> Transaction -> Set Object
newlyExposed st s0 tx = closure st targets `Set.difference` published st s0
  where
    targets = [o | u <- txUpdates tx, publishable (uRef u), Just o <- [uNew u]]

publishable :: RefName -> Bool
publishable (AuthorityRef _) = False
publishable _ = True

-- | Whether a ref's name is one a ref can have: components separated by
-- @\/@, none of them empty, @.@ or @..@.
wellNamed :: RefName -> Bool
wellNamed ref = all component (pieces name)
  where
    name = case ref of
      Branch n -> n
      ReleaseRef n -> n
      AuthorityRef n -> n
    component part = not (null part) && part /= "." && part /= ".." && '\0' `notElem` part
    pieces s = case break (== '/') s of
      (part, []) -> [part]
      (part, _ : rest) -> part : pieces rest

-- * Protected branches

-- | Whether the authority's policy protects a ref.
--
-- The policy is @protected_branches@: \"globs that need a maintainer to
-- update\" (@README.md@). It protects branches and nothing else, so a
-- release ref is never protected, whatever the globs say. A branch is
-- protected when a glob matches either its name or its full ref,
-- @refs\/branches\/<name>@.
protects :: Authority -> RefName -> Bool
protects a (Branch name) =
  any (\glob -> globMatches glob name || globMatches glob ("refs/branches/" ++ name)) (aProtected a)
protects _ _ = False

-- | @globMatches glob text@. The whole text must match.
--
-- * @?@ matches any one character, and @*@ any run of characters, the
--   separator @\/@ included.
-- * @[abc]@ and @[a-c]@ match one character from the set, and @[!abc]@ one
--   character outside it. A @]@ directly after the opening is a member of
--   the set.
-- * Anything else matches itself.
--
-- A glob that is not well formed, with a @[@ that is never closed, matches
-- nothing. So does one containing @**@, which this model does not define.
globMatches :: String -> String -> Bool
globMatches glob text = maybe False (`go` text) (tokens glob)
  where
    go [] s = null s
    go (AnyRun : rest) s = go rest s || case s of
      [] -> False
      _ : more -> go (AnyRun : rest) more
    go (t : rest) (ch : more) = one t ch && go rest more
    go _ [] = False

    one AnyOne _ = True
    one (Literal l) ch = l == ch
    one (OneOf wanted members) ch = wanted == any (within ch) members
    one AnyRun _ = True

    within ch (lo, hi) = lo <= ch && ch <= hi

data GlobToken = Literal Char | AnyOne | AnyRun | OneOf Bool [(Char, Char)]

tokens :: String -> Maybe [GlobToken]
tokens [] = Just []
tokens ('*' : '*' : _) = Nothing
tokens ('*' : rest) = (AnyRun :) <$> tokens rest
tokens ('?' : rest) = (AnyOne :) <$> tokens rest
tokens ('[' : rest) = do
  let (wanted, body) = case rest of
        '!' : more -> (False, more)
        _ -> (True, rest)
  (members, after) <- classBody body
  (OneOf wanted members :) <$> tokens after
tokens (ch : rest) = (Literal ch :) <$> tokens rest

-- | The members of a set, up to its closing bracket, and what follows.
classBody :: String -> Maybe ([(Char, Char)], String)
classBody (first : rest) | first == ']' = do
  (members, after) <- classRest rest
  pure ((first, first) : members, after)
classBody s = classRest s

classRest :: String -> Maybe ([(Char, Char)], String)
classRest [] = Nothing
classRest (']' : after) = Just ([], after)
classRest (lo : '-' : hi : rest) | hi /= ']' = do
  (members, after) <- classRest rest
  pure ((lo, hi) : members, after)
classRest (ch : rest) = do
  (members, after) <- classRest rest
  pure ((ch, ch) : members, after)

-- * Admission

data Violation
  = -- | The update names a ref no ref could be.
    BadRefName RefName
  | -- | The transaction names a ref more than once, so there is no one thing
    -- it asks of that ref.
    NamedTwice RefName
  | -- | An update that deletes a ref it expects to be absent.
    DeletesNothing RefName
  | -- | Divergence (g): the state's current authority does not stand.
    CurrentNotOnPinnedChain
  | -- | D6: with no current authority \"the replica can read it but cannot
    -- publish from it\".
    NoCurrentAuthority
  | -- | The transaction was made against a state other than @S0@: a ref
    -- does not hold what the transaction expects.
    StaleState RefName
  | -- | P.1: \"The transaction's signer holds at least @Contributor@ in
    -- @A0@.\"
    P1
  | -- | P.2: \"Newly exposed commits must all pass Rule H.\"
    P2RuleH Object (Set Clause)
  | -- | P.2: \"Each must cite, and be authorized by, @A0@ exactly\"; \"no
    -- newly exposed commit may cite @A1@\"; \"releases follow the same
    -- rule\". Work under any other authority needs adoption (D1), and
    -- \"without an adoption record such work is refused\".
    P2NotCurrent Object
  | -- | P.2: \"The one exception is a single authority-transition boundary
    -- commit.\"
    P2SeveralBoundaries
  | -- | P.3: \"@current@ moves only with that boundary.\" The transaction
    -- would move it and exposes no commit that installs an authority.
    P3MoveWithoutBoundary
  | -- | P.3, from the other side: a boundary commit is exposed, and the
    -- transaction does not move @current@ to what it installs.
    P3BoundaryWithoutMove
  | -- | P.3: \"Any other change to @refs\/authority\/*@ is refused.\"
    P3AuthorityRef RefName
  | -- | P.4: \"Updating a protected ref requires the transaction's signer to
    -- hold @Maintainer@ in @A0@.\"
    P4Protected RefName
  | -- | P.4: \"A non-fast-forward update also requires @Maintainer@ in
    -- @A0@.\"
    P4Rewrite RefName
  | -- | Reading (d): a non-fast-forward update that is not marked as forced.
    P4Unforced RefName
  | -- | A branch asked to name a release, or a release ref a commit.
    IllTyped RefName
  deriving (Eq, Ord, Show)

data Admission = Admission
  { admState :: State
  -- ^ The authoritative state once the transaction is applied.
  , admExposed :: Set Object
  -- ^ What it newly exposed.
  }
  deriving (Eq, Show)

-- | Decide a transaction against @S0@. It is admitted if and only if it
-- breaks nothing.
--
-- __Precondition.__ @S0@ is an input and is not judged. Its refs are
-- branches naming commits and release refs naming releases, each under a
-- name a ref can have ('wellNamed'), and every object they name is in the
-- store. For any other state this function's answer means nothing. Two
-- things about a state are in scope all the same: it may have no current
-- authority (D6), and the one it has may be any authority in the store,
-- another repository's or one that succeeds nothing included, which is
-- divergence (g).
--
-- The transaction is what is judged, so it may be anything: a ref no ref
-- could be, the same ref twice, a target of the wrong kind.
--
-- P.5, \"nothing self-authorizes\", is how this is written and not a clause
-- of its own: every role is looked up in @A0@, every \"already published\"
-- in 'published', and both are fixed by @s0@ before the transaction is
-- read. Nothing the transaction carries, @A1@ included, is consulted for
-- either.
admit :: Reading -> Store -> State -> Transaction -> Either (Set Violation) Admission
admit rd st s0 tx
  | Set.null found = Right Admission {admState = s1, admExposed = exposed}
  | otherwise = Left found
  where
    found = Set.fromList (shape ++ stale ++ authorityRefs ++ illTyped ++ underA0)

    -- Whether it is a transaction at all. The text does not say what one
    -- is; these are what it would take for the rest to have a meaning.
    shape =
      [BadRefName (uRef u) | u <- txUpdates tx, publishable (uRef u), not (wellNamed (uRef u))]
        ++ [NamedTwice ref | (ref, n) <- Map.toList named, n > (1 :: Int)]
        ++ [DeletesNothing (uRef u) | u <- txUpdates tx, isNothing (uExpected u), isNothing (uNew u)]
    named = Map.fromListWith (+) [(uRef u, 1) | u <- txUpdates tx]

    stale =
      [ StaleState (uRef u)
      | u <- txUpdates tx
      , publishable (uRef u)
      , Map.lookup (uRef u) (sRefs s0) /= uExpected u
      ]

    authorityRefs = [P3AuthorityRef (uRef u) | u <- txUpdates tx, not (publishable (uRef u))]

    illTyped =
      [ IllTyped (uRef u)
      | u <- txUpdates tx
      , o <- [o | Just o <- [uExpected u, uNew u]]
      , not (wellTyped (uRef u) o)
      ]
    wellTyped (Branch _) (OCommit _) = True
    wellTyped (ReleaseRef _) (ORelease _) = True
    wellTyped (AuthorityRef _) _ = True
    wellTyped _ _ = False

    underA0 = case sCurrent s0 >>= \a -> (,) a <$> lookupAuthority st a of
      Nothing -> [NoCurrentAuthority]
      Just (a0, body0) ->
        [CurrentNotOnPinnedChain | not (currentStands rd st (sPin s0) a0)]
          ++ p1 body0
          ++ p2 a0
          ++ p3
          ++ p4 body0

    exposed = newlyExposed st s0 tx

    p1 body0 = [P1 | not (holds body0 (txSigner tx) Contributor)]

    p2 a0 =
      concat
        [ [P2RuleH o broken | let broken = violations rd st (sPin s0) o, not (Set.null broken)]
          ++ [P2NotCurrent o | cited st o /= Just a0]
        | o <- Set.toList exposed
        ]
        ++ [P2SeveralBoundaries | length boundaries > 1]

    -- The newly exposed commits that modify authority, with what each
    -- installs.
    boundaries =
      [ a1
      | OCommit c <- Set.toList exposed
      , Just k <- [lookupCommit st c]
      , Just a1 <- [cInstalls k]
      ]

    p3 = case (txAuthority tx, boundaries) of
      (Nothing, []) -> []
      (Just _, []) -> [P3MoveWithoutBoundary]
      (Nothing, _) -> [P3BoundaryWithoutMove]
      (Just a1, [installed]) -> [P3BoundaryWithoutMove | installed /= a1]
      (Just _, _) -> []

    p4 body0 = concatMap check (filter (publishable . uRef) (txUpdates tx))
      where
        maintainer = holds body0 (txSigner tx) Maintainer
        check u =
          [P4Protected (uRef u) | protects body0 (uRef u), not maintainer]
            ++ (if rewrites u then unforced u ++ [P4Rewrite (uRef u) | not maintainer] else [])
        unforced u = [P4Unforced (uRef u) | rewriteMustBeForced rd, not (uForce u)]

    -- An update that is not a fast-forward of what S0 holds: the new value
    -- does not have the old one behind it.
    rewrites u = case (Map.lookup (uRef u) (sRefs s0), uNew u) of
      (Just old, Just new) -> old /= new && not (reaches st new old)
      (Just old, Nothing) ->
        deletionCanUnpublish rd && not (any (\kept -> reaches st kept old) (Map.elems (sRefs s1)))
      (Nothing, _) -> False

    s1 =
      s0
        { sCurrent = txAuthority tx <|> sCurrent s0
        , sRefs = foldl apply (sRefs s0) (filter (publishable . uRef) (txUpdates tx))
        }
    apply refs u = Map.alter (const (uNew u)) (uRef u) refs
