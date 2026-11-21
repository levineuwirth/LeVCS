-- | Generators for the scripts of "LeVCS.Harness.Script".
--
-- Most of what they emit is what a well-behaved client would do, because a
-- history broken in five places says little about any one rule. The rest is
-- one departure at a time: a stale citation, a signer without the role, a
-- successor nobody with the right to sign has signed.
module LeVCS.Harness.Gen
  ( -- * History scenarios
    genHScenario
  , genHonestHScenario
  , genHistory
  , genKey

    -- * Publication scenarios
  , genPScenario
  , genHonestPScenario
  ) where

import Hedgehog (Gen)
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range

import Data.Map.Strict qualified as Map

import LeVCS.Authority.Model (Role (..), Store (..))
import LeVCS.Harness.Script

-- | A history whose replica may have any authority in the store as its
-- current one. 'buildHistory' picks only from the pinned chain, which is
-- where Rule P keeps it; a third of the time this picks from everything, so
-- that another repository's genesis and an authority that succeeds nothing
-- are among the things a replica is found holding.
genHistory :: Gen History
genHistory = do
  h <- buildHistory <$> genHScenario
  current <-
    Gen.frequency
      [ (2, pure (hCurrent h))
      , (1, Just <$> Gen.element (Map.keys (sAuthorities (hStore h))))
      ]
  pure h {hCurrent = current}

-- | A small index, most often the first.
small :: Gen Int
small = Gen.frequency [(6, pure 0), (3, pure 1), (2, Gen.int (Range.linear 0 6))]

genKey :: Gen Int
genKey = Gen.int (Range.linear 0 (keyCount - 1))

genRole :: Gen Role
genRole = Gen.enumBounded

-- | Mostly true.
usually :: Gen Bool
usually = Gen.frequency [(19, pure True), (1, pure False)]

-- | An index into 'protections', with the plain names and the simplest
-- wildcard most often.
genProtection :: Gen Int
genProtection = Gen.frequency [(3, small), (4, Gen.int (Range.linear 0 (length protections - 1)))]

genGenesis :: Gen [(Int, Role)]
genGenesis = Gen.list (Range.linear 0 4) ((,) <$> genKey <*> genRole)

-- * Operations

genEdit :: Gen Edit
genEdit =
  Gen.frequency
    [ (4, Grant <$> genKey <*> genRole)
    , (3, Revoke <$> genKey)
    , (1, Protect <$> genProtection)
    , (1, Unprotect <$> genProtection)
    , (2, Publicise <$> Gen.bool)
    ]

-- | An edit that leaves @k0@ an Owner, so that the authority can always be
-- succeeded and always has someone able to do anything.
genHonestEdit :: Gen Edit
genHonestEdit =
  Gen.frequency
    [ (4, Grant <$> Gen.int (Range.linear 1 (keyCount - 1)) <*> genRole)
    , (3, Revoke <$> Gen.int (Range.linear 1 (keyCount - 1)))
    , (1, Protect <$> genProtection)
    , (1, Unprotect <$> genProtection)
    ]

genSigners :: Gen [Signer]
genSigners =
  Gen.frequency
    [ (10, pure [OwnerSigns 0])
    , (2, (\i -> [OwnerSigns i]) <$> small)
    , (2, (\i j -> [OwnerSigns i, OwnerSigns j]) <$> small <*> small)
    , (1, (\k -> [OwnerSigns 0, KeySigns k False]) <$> genKey)
    , (1, (\k ok -> [KeySigns k ok]) <$> genKey <*> Gen.bool)
    , (1, pure [])
    ]

genSuccessor :: Gen From -> Gen Op
genSuccessor from =
  OpSuccessor
    <$> from
    <*> Gen.list (Range.linear 0 2) genEdit
    <*> genSigners
    <*> Gen.frequency [(12, pure 0), (1, pure 1), (1, pure (-1))]

genHonestSuccessor :: From -> Gen Op
genHonestSuccessor from =
  OpSuccessor from
    <$> Gen.list (Range.linear 0 2) genHonestEdit
    <*> pure [OwnerSigns 0]
    <*> pure 0

genCite :: Gen Cite -> Gen Cite
genCite honest =
  Gen.frequency [(10, honest), (2, CiteFloor <$> small), (2, CiteAny <$> small)]

genPick :: Gen Pick
genPick = Gen.frequency [(8, Honest <$> small), (2, Any <$> genKey)]

genCommit :: Gen [Parent] -> Gen Cite -> Gen Op
genCommit parents honestCite =
  OpCommit
    <$> parents
    <*> genCite honestCite
    <*> genPick
    <*> usually
    <*> Gen.frequency [(8, pure Nothing), (4, Just . Honest <$> small), (1, Just . Any <$> small)]

genRelease :: Gen Parent -> Gen Cite -> Gen Op
genRelease predecessor honestCite =
  OpRelease
    <$> predecessor
    <*> Gen.frequency [(3, pure Nothing), (1, Just . RecentRelease <$> small)]
    <*> genCite honestCite
    <*> genPick
    <*> usually

-- * History scenarios

genRecentParents :: Gen [Parent]
genRecentParents =
  Gen.frequency
    [ (1, pure [])
    , (9, (\i -> [Recent i]) <$> small)
    , (3, (\i j -> [Recent i, Recent j]) <$> small <*> small)
    ]

genHOp :: Gen Op
genHOp =
  Gen.frequency
    [ (20, genCommit genRecentParents (pure (CiteFloor 0)))
    , (6, genSuccessor (FromRecent <$> Gen.frequency [(4, pure 0), (3, pure 1), (2, small)]))
    , (4, genRelease (Recent <$> small) (pure (CiteFloor 0)))
    , (1, OpGenesis <$> genGenesis)
    ]

-- | A successor of the newest authority and, on the newest commit, the
-- commit that installs it. In a history with one line of authorities this is
-- an honest membership change.
changeOnTip :: Gen Edit -> Gen [Op]
changeOnTip edit = do
  edits <- Gen.list (Range.linear 0 2) edit
  pure
    [ OpSuccessor (FromRecent 0) edits [OwnerSigns 0] 0
    , OpCommit [Recent 0] (CiteFloor 0) (Honest 0) True (Just (Honest 0))
    ]

-- | A history, and a replica looking at it.
genHScenario :: Gen HScenario
genHScenario =
  HScenario
    <$> genGenesis
    <*> (concat <$> Gen.list (Range.linear 0 24) (Gen.frequency [(9, pure <$> genHOp), (1, changeOnTip genEdit)]))
    <*> Gen.frequency [(1, pure Nothing), (6, Just <$> small)]

-- | A history every step of which is what a well-behaved client would make:
-- one line of authorities, each signed by an Owner of the last; every commit
-- and release citing the oldest authority its parents allow, signed by a
-- member with the role it needs.
genHonestHScenario :: Gen HScenario
genHonestHScenario =
  HScenario
    <$> genGenesis
    <*> (concat <$> Gen.list (Range.linear 0 24) op)
    <*> Gen.frequency [(1, pure Nothing), (6, pure (Just 0))]
  where
    op =
      Gen.frequency
        [ (12, pure <$> (OpCommit <$> genRecentParents <*> pure (CiteFloor 0) <*> honest <*> pure True <*> pure Nothing))
        , (2, pure <$> genHonestSuccessor (FromRecent 0))
        , (2, pure <$> (OpCommit <$> genRecentParents <*> pure (CiteFloor 0) <*> pure (Honest 0) <*> pure True <*> pure (Just (Honest 0))))
        , (2, changeOnTip genHonestEdit)
        , (3, pure <$> (OpRelease <$> (Recent <$> small) <*> pure Nothing <*> pure (CiteFloor 0) <*> honest <*> pure True))
        ]
    honest = Honest <$> small

-- * Publication scenarios

-- | An honest commit on a branch, then its publication.
honestWork :: Gen [Step]
honestWork = do
  b <- small
  signer <- Honest <$> small
  pure
    [ Make (OpCommit [Tip b] CiteCurrent signer True Nothing)
    , Push (PushOp (Honest 0) [Upd (RBranch b) (Just 0) Nothing False] AuthFollow)
    ]

-- | An honest membership change: a successor of the current authority, the
-- boundary commit that installs it, and one transaction publishing that
-- commit and moving @current@.
honestChange :: Gen Edit -> Gen [Step]
honestChange edit = do
  b <- small
  successor <- OpSuccessor FromCurrent <$> Gen.list (Range.linear 0 2) edit <*> pure [OwnerSigns 0] <*> pure 0
  pure
    [ Make successor
    , Make (OpCommit [Tip b] CiteCurrent (Honest 0) True (Just (Honest 0)))
    , Push (PushOp (Honest 0) [Upd (RBranch b) (Just 0) Nothing False] AuthFollow)
    ]

-- | An honest release of a published branch tip, following whatever the
-- release ref already holds.
honestRelease :: Gen [Step]
honestRelease = do
  b <- small
  r <- small
  pure
    [ Make (OpRelease (Tip b) (Just (HeldRelease r)) CiteCurrent (Honest 0) True)
    , Push (PushOp (Honest 0) [Upd (RRelease r) (Just 0) Nothing False] AuthFollow)
    ]

-- | What P.2 forbids: a membership change published together with work made
-- under the authority it installs.
changeWithWorkOnTop :: Gen [Step]
changeWithWorkOnTop = do
  b <- small
  signer <- Honest <$> small
  pure
    [ Make (OpSuccessor FromCurrent [] [OwnerSigns 0] 0)
    , Make (OpCommit [Tip b] CiteCurrent (Honest 0) True (Just (Honest 0)))
    , Make (OpCommit [Recent 0] (CiteFloor 0) signer True Nothing)
    , Push (PushOp (Honest 0) [Upd (RBranch b) (Just 0) Nothing False] AuthFollow)
    ]

-- | What P.3 forbids: a boundary commit published while @current@ is moved
-- somewhere of the transaction's own choosing.
changeMovedElsewhere :: Gen [Step]
changeMovedElsewhere = do
  b <- small
  other <- genSuccessor (Gen.frequency [(2, pure FromCurrent), (1, FromRecent <$> small)])
  install <- small
  move <- small
  pure
    [ Make (OpSuccessor FromCurrent [] [OwnerSigns 0] 0)
    , Make other
    , Make (OpCommit [Tip b] CiteCurrent (Honest 0) True (Just (Honest install)))
    , Push (PushOp (Honest 0) [Upd (RBranch b) (Just 0) Nothing False] (AuthAny move))
    ]

genPOp :: Gen Op
genPOp =
  Gen.frequency
    [ (10, genCommit parents (pure CiteCurrent))
    , (4, genSuccessor (Gen.frequency [(3, pure FromCurrent), (1, FromRecent <$> small)]))
    , (3, genRelease (Gen.choice [Tip <$> small, Recent <$> small]) (pure CiteCurrent))
    , (1, OpGenesis <$> genGenesis)
    ]
  where
    parents =
      Gen.frequency
        [ (6, (\i -> [Tip i]) <$> small)
        , (3, (\i -> [Recent i]) <$> small)
        , (2, (\i j -> [Tip i, Recent j]) <$> small <*> small)
        , (1, pure [])
        ]

genPush :: Gen PushOp
genPush =
  PushOp
    <$> Gen.frequency [(6, pure (Honest 0)), (2, Honest <$> small), (2, Any <$> genKey)]
    <*> Gen.list (Range.linear 1 3) upd
    <*> Gen.frequency [(8, pure AuthFollow), (1, pure AuthNone), (1, AuthAny <$> small)]
  where
    upd =
      Upd
        <$> Gen.frequency [(10, RBranch <$> small), (3, RRelease <$> small), (1, pure RAuthority)]
        <*> Gen.frequency [(8, Just <$> small), (1, pure Nothing)]
        <*> Gen.frequency [(12, pure Nothing), (1, Just <$> small)]
        <*> Gen.frequency [(3, pure False), (1, pure True)]

genPScenario :: Gen PScenario
genPScenario =
  PScenario
    <$> genGenesis
    <*> Gen.list (Range.linear 0 2) genProtection
    <*> (concat <$> Gen.list (Range.linear 0 14) round')
  where
    round' =
      Gen.frequency
        [ (6, honestWork)
        , (2, honestChange genEdit)
        , (2, honestRelease)
        , (1, changeWithWorkOnTop)
        , (1, changeMovedElsewhere)
        , (6, pure . Make <$> genPOp)
        , (7, pure . Push <$> genPush)
        ]

-- | Only honest rounds. Every transaction in one should be admitted.
genHonestPScenario :: Gen PScenario
genHonestPScenario =
  PScenario
    <$> genGenesis
    <*> Gen.list (Range.linear 0 2) genProtection
    <*> (concat <$> Gen.list (Range.linear 0 14) round')
  where
    round' = Gen.frequency [(6, honestWork), (2, honestChange genHonestEdit), (2, honestRelease)]
