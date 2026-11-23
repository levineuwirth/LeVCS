-- SPDX-FileCopyrightText: 2026 Levi Neuwirth
-- SPDX-License-Identifier: Apache-2.0

{-# LANGUAGE OverloadedStrings #-}

-- | The rules checked against themselves. Nothing here runs the Rust.
--
-- These are consequences the document claims, or that it would be a defect
-- for the rules not to have. They are checked under both readings, the text
-- as first ratified and the text as amended, because a consequence that
-- held only with what the amendment added would not have been a consequence
-- of the text that first claimed it.
module Main (main) where

import Control.Monad (forM, forM_, unless, when)
import Data.Aeson (Value (..), eitherDecodeFileStrict, eitherDecodeStrict, encode, toJSON)
import Data.ByteString.Char8 qualified as BS
import Data.ByteString.Lazy qualified as BL
import Data.Text qualified as Text
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Foldable (toList)
import GHC.Exts (fromList)
import Data.Aeson.Types (parseEither)
import Data.List (isPrefixOf, isSuffixOf, sort)
import Data.Map.Strict qualified as Map
import Data.Maybe (fromMaybe, isJust)
import Data.Set qualified as Set
import Data.String (fromString)
import System.Directory (listDirectory)
import System.Exit (exitFailure)
import System.FilePath ((<.>), (</>))

import Hedgehog hiding (Update)
import Hedgehog.Gen qualified as Gen

import LeVCS.Authority.Model
import LeVCS.Authority.Reading
import LeVCS.Authority.RuleH
import LeVCS.Authority.RuleP
import LeVCS.Authority.RuleR
import LeVCS.Harness.Cases
import LeVCS.Harness.Gen
import LeVCS.Harness.Script
import LeVCS.Harness.Wire

main :: IO ()
main = do
  ok <-
    mapM
      checkParallel
      [ Group "generators" generators
      , Group "Rule H" (bothReadings ruleH ++ [("the amended reading only ever refuses more", amendedIsStricter)])
      , Group
          "Rule R"
          ( bothReadings ruleR
              ++ [("the amended reading only ever refuses more", amendedReceivesLess)]
          )
      , Group
          "Rule P"
          ( bothReadings ruleP
              ++ [("the amended reading only ever refuses more", amendedAdmitsLess)]
          )
      , Group "named cases" namedCases
      ]
  unless (and ok) exitFailure

bothReadings :: [(String, Reading -> Property)] -> [(PropertyName, Property)]
bothReadings props =
  [ (fromString (name ++ " [" ++ reading ++ "]"), prop rd)
  | (name, prop) <- props
  , (reading, rd) <- [("unamended", unamended), ("amended", amended)]
  ]

tests :: TestLimit
tests = 2000

-- * The generators say something

-- | A generator that produced only valid histories, or only invalid ones,
-- would make every property below hold for no reason.
generators :: [(PropertyName, Property)]
generators =
  [
    ( "histories are a mix of verdicts"
    , withTests tests . property $ do
        sc <- forAll genHScenario
        let History st current roots = buildHistory sc
            verdicts = Map.elems (verify amended st pinId current roots)
            literal = Map.elems (verify unamended st pinId current roots)
        cover 40 "some object valid" (Valid `elem` verdicts)
        cover 40 "some object invalid" (any invalid verdicts)
        cover 1 "some object on a conflicting lineage" (ConflictingLineage `elem` verdicts)
        cover 3 "the readings disagree" (verdictClasses verdicts /= verdictClasses literal)
    )
  ,
    ( "publications are a mix of outcomes"
    , withTests tests . property $ do
        sc <- forAll genPScenario
        let tr = runP amended sc
            results = map atResult (tAttempts tr)
            literal = map atResult (tAttempts (runP unamended sc))
        cover 60 "a transaction admitted" (any isRight results)
        cover 20 "a transaction refused" (any isLeft results)
        cover 10 "current moved" (sCurrent (tFinal tr) /= Just pinId)
        cover 1 "the readings disagree" (map isRight results /= map isRight literal)
    )
  ,
    ( "every protected pattern generated can be put on the wire"
    , withTests 1 . property $ do
        -- The policy is one comma-separated string, so a pattern with a
        -- comma in it, or an empty one, would be a different policy to the
        -- implementation. The generators draw none, and one is not parsed.
        forM_ protections $ \glob -> do
          annotateShow glob
          unrepresentable (protecting glob) === []
        forM_ ["b0,b1", ""] $ \glob -> do
          annotateShow glob
          assert (not (null (unrepresentable (protecting glob))))
          assert (isLeft (parseEither parseRequest (encodeRequest (protecting glob))))
    )
  ,
    ( "a request the implementation's objects cannot hold is not parsed"
    , withTests 1 . property $ do
        -- One valid commit, published on b0, verified, and transferred.
        let st = applyOp noCtx (OpCommit [] (CiteFloor 0) (Any 0) True Nothing) (genesisStore [(1, Contributor)] [])
            c0 = OCommit (CommitId 0)
            s0 = State pinId (Just pinId) (Map.fromList [(Branch "b0", c0)])
            base = Request st pinId (Just (Just pinId, [c0])) [(s0, Transaction (Key 0) [] Nothing)] [(pinId, pinId, [c0])] [(Just pinId, Holding (Key 0), [c0])]
            authority f rq = rq {rqStore = (rqStore rq) {sAuthorities = Map.map f (sAuthorities (rqStore rq))}}
            commit f rq = rq {rqStore = (rqStore rq) {sCommits = Map.map f (sCommits (rqStore rq))}}
            holding ref o = base {rqAdmit = [(s0 {sRefs = Map.fromList [(ref, o)]}, Transaction (Key 0) [] Nothing)]}
            asking ref = base {rqAdmit = [(s0, Transaction (Key 0) [Update ref Nothing (Just c0) False] Nothing)]}
            refused rq = do
              annotateShow rq
              assert (not (null (unrepresentable rq)))
              assert (isLeft (parseEither parseRequest (encodeRequest rq)))
            parsed rq = do
              annotateShow rq
              unrepresentable rq === []
              parseEither parseRequest (encodeRequest rq) === Right rq
            -- For what a request cannot say once it is a value: a number
            -- out of range, or one name given twice.
            unread path f = do
              annotateShow path
              assert (isLeft (parseEither parseRequest (tamper path f (encodeRequest base))))
            twice v = case v of Array as -> Array (as <> as); _ -> v
            set = const
        parsed base
        -- Numbers, where they are defined and where they are referred to.
        mapM_ refused [authority (\a -> a {aVersion = 4294967298}) base, authority (\a -> a {aVersion = -1}) base]
        parsed (authority (\a -> a {aVersion = 4294967295}) base)
        refused base {rqAdmit = [(s0, Transaction (Key (-1)) [] Nothing)]}
        unread [K "pin"] (set (Number 4294967296))
        unread [K "verify", K "roots", I 0, K "commit"] (set (Number (-1)))
        unread [K "verify", K "current"] (set (Number 4294967296))
        unread [K "receive", I 0, K "expected"] (set (Number 1.5))
        unread [K "store", K "commits", I 0, K "cites"] (set (Number 4294967296))
        -- Signatures.
        refused (authority (\a -> a {aSigs = replicate 256 (Sig (Key 0) True)}) base)
        parsed (authority (\a -> a {aSigs = replicate 255 (Sig (Key 0) True)}) base)
        -- References: to something missing, and to itself.
        refused base {rqVerify = Just (Just pinId, [OCommit (CommitId 9)])}
        refused base {rqVerify = Just (Just (AuthId 9), [c0])}
        refused base {rqPin = AuthId 9}
        refused base {rqReceive = [(pinId, AuthId 9, [c0])]}
        refused (commit (\k -> k {cCites = AuthId 9}) base)
        refused (commit (\k -> k {cParents = [CommitId 0]}) base)
        refused (authority (\a -> a {aPrev = Just pinId}) base)
        refused base {rqAdmit = [(s0, Transaction (Key 0) [Update (Branch "b1") Nothing (Just (OCommit (CommitId 9))) False] Nothing)]}
        -- States. A transaction may name any ref: that is for the rules.
        mapM_ refused
          [ holding (Branch "") c0
          , holding (Branch "a//b") c0
          , holding (ReleaseRef "r0") c0
          , holding (AuthorityRef "current") c0
          ]
        mapM_ parsed [holding (Branch "a/b") c0, asking (Branch ""), asking (AuthorityRef "current")]
        -- Counts: the parents of a commit and the members of an authority.
        let roots n = Map.fromList [(CommitId i, sCommits st Map.! CommitId 0) | i <- [0 .. n - 1]]
            merging n =
              base
                { rqStore = st {sCommits = Map.insert (CommitId n) ((sCommits st Map.! CommitId 0) {cParents = map CommitId [0 .. n - 1]}) (roots n)}
                , rqVerify = Just (Just pinId, [OCommit (CommitId n)])
                }
            crowd n = authority (\a -> a {aMembers = Map.fromList [(Key k, Reader) | k <- [1 .. n - 1]] <> Map.singleton (Key 0) Owner}) base
        parsed (merging 255)
        refused (merging 256)
        parsed (crowd 65535)
        refused (crowd 65536)
        -- The protected patterns are a set, and measured as one: the same
        -- pattern any number of times is that pattern once.
        let long i = Text.justifyRight 255 '0' (Text.pack (show (i :: Int)))
            patterns ps = tamper [K "store", K "authorities", I 0, K "protected"] (set (toJSON ps)) (encodeRequest base)
        parseEither parseRequest (patterns (replicate 257 (long 0)))
          === Right (authority (\a -> a {aProtected = Set.singleton (Text.unpack (long 0))}) base)
        assert (isLeft (parseEither parseRequest (patterns (map long [0 .. 256]))))
        -- A number is its value, however it is written.
        let written text = do
              let (before, after) = BS.breakSubstring "\"pin\":0" (BL.toStrict (encode (encodeRequest base)))
              annotate text
              assert (not (BS.null after))
              pure (eitherDecodeStrict (before <> "\"pin\":" <> BS.pack text <> BS.drop 7 after) >>= parseEither parseRequest)
        forM_ ["0", "0.0", "0e0", "-0.0"] $ \text -> written text >>= (=== Right base)
        forM_ ["0.5", "-1", "4294967296.0", "1e10"] $ \text -> written text >>= assert . isLeft
        -- Exactly its value: zero at any exponent is zero, and what is not
        -- quite a whole number is not one, however near.
        forM_ ["0e2000", "-0e5000", "0e-5000", "0.000e+00"] $ \text -> written text >>= (=== Right base)
        forM_ ["1.0000000000000000001", "0.99999999999999999", "1e-400", "1e-2000"] $ \text ->
          written text >>= assert . isLeft
        -- The same of a number that is not zero: the one version here is 1.
        let versioned text = do
              let (before, after) = BS.breakSubstring "\"version\":1" (BL.toStrict (encode (encodeRequest base)))
              annotate text
              assert (not (BS.null after))
              assert (BS.null (snd (BS.breakSubstring "\"version\":" (BS.drop 11 after))))
              pure (eitherDecodeStrict (before <> "\"version\":" <> BS.pack text <> BS.drop 11 after) >>= parseEither parseRequest)
        forM_ ["1.0", "0.01E+2", "1000000000000000000000000000000e-30", '1' : replicate 1100 '0' ++ "e-1100"] $ \text ->
          versioned text >>= (=== Right base)
        forM_ ["1.0000000000000000001", "0.99999999999999999", "1e-400"] $ \text ->
          versioned text >>= assert . isLeft
        -- Reads are asked of a repository by the id its genesis derives.
        forM_ [c | c <- cases, caseName c == "r-read-permission-is-decided-in-the-current-authority"] $ \c -> do
          unrepresentable (caseRequest c) === []
          refused (caseRequest c) {rqPin = AuthId 1}
        -- One name given twice, which a map would have kept one of.
        unread [K "store", K "authorities"] twice
        unread [K "store", K "commits"] twice
        unread [K "store", K "authorities", I 0, K "members"] twice
        unread [K "admit", I 0, K "state", K "refs"] twice
    )
  ]
  where
    invalid (Invalid _) = True
    invalid _ = False
    verdictClasses = map (\v -> (v == Valid, v == ConflictingLineage))
    protecting glob =
      Request (genesisStore [] []) {sAuthorities = protect glob} pinId Nothing [] [] []
    protect glob = Map.map (\a -> a {aProtected = Set.singleton glob}) (sAuthorities (genesisStore [] []))

isRight, isLeft :: Either a b -> Bool
isRight = either (const False) (const True)
isLeft = not . isRight

-- | One step into a JSON value: a field, or a place in a list.
data Into = K Key.Key | I Int
  deriving (Show)

-- | Change what is at the end of a path, which must be there.
tamper :: [Into] -> (Value -> Value) -> Value -> Value
tamper [] f v = f v
tamper (K key : rest) f (Object o)
  | KeyMap.member key o = Object (KeyMap.mapWithKey (\k v -> if k == key then tamper rest f v else v) o)
tamper (I n : rest) f (Array as)
  | n < length as = Array (fromList [if i == n then tamper rest f v else v | (i, v) <- zip [0 ..] (toList as)])
tamper path _ v = error ("tamper: nothing at " ++ show path ++ " in " ++ show v)

-- * Rule H

ruleH :: [(String, Reading -> Property)]
ruleH =
  [ ("honest history is valid", honestHistoryIsValid)
  , ("a change of authority binds everything after it", changeBindsDescendants)
  , ("a valid merge has comparable parents", mergeHasComparableParents)
  , ("validity does not depend on the replica", validityIsIntrinsic)
  , ("validity does not depend on what is made later", validityIsStable)
  ]

-- | The rules are not vacuous: what a well-behaved client makes passes.
honestHistoryIsValid :: Reading -> Property
honestHistoryIsValid rd = withTests tests . property $ do
  sc <- forAll genHonestHScenario
  let History st current roots = buildHistory sc
      verdicts = verify rd st pinId current roots
  cover 20 "an authority change" (any (isJust . cInstalls) (Map.elems (sCommits st)))
  cover 30 "a release" (not (Map.null (sReleases st)))
  annotateShow (Map.filter (/= Valid) verdicts)
  assert (all (== Valid) (Map.elems verdicts))

-- | \"H.3 is the revocation rule. Every descendant of a commit that installs
-- @v2@ cites @v2@ or later.\"
--
-- H.3 only relates a commit to its parents. The claim about every descendant
-- needs the history in between to be valid, and then follows: a commit, all
-- of whose ancestors are valid, cites an authority that equals or descends
-- from what is in effect after each of them. Its signer is a member of that
-- authority (H.1), so a key removed by an ancestor can sign only under a
-- later authority that took it back.
changeBindsDescendants :: Reading -> Property
changeBindsDescendants rd = withTests tests . property $ do
  sc <- forAll genHScenario
  let st = hStore (buildHistory sc)
      valid c = Set.null (violations rd st pinId (OCommit c))
      behind c = [a | OCommit a <- Set.toList (closure st [OCommit c]), a /= c]
      sound = [(cid, c) | (cid, c) <- Map.toList (sCommits st), valid cid, all valid (behind cid)]
      installers cid = [a | a <- behind cid, Just k <- [lookupCommit st a], isJust (cInstalls k)]
  cover 10 "a valid commit after an authority change" (any (not . null . installers . fst) sound)
  forM_ sound $ \(cid, c) ->
    forM_ (behind cid) $ \a -> do
      ancestor <- evalMaybe (lookupCommit st a)
      annotateShow (cid, a)
      assert (equalsOrDescendsFrom st (cCites c) (effective ancestor))

-- | \"When they are incomparable, no authority satisfies H.3, and the
-- situation is a hard conflict.\" So a commit that is valid never merges
-- incomparable lineages, and the separate check for it in @history.rs@ can
-- only ever fire together with H.3.
mergeHasComparableParents :: Reading -> Property
mergeHasComparableParents rd = withTests tests . property $ do
  sc <- forAll genHScenario
  let st = hStore (buildHistory sc)
      merges = [(cid, c) | (cid, c) <- Map.toList (sCommits st), length (cParents c) > 1]
  cover 12 "a merge" (not (null merges))
  forM_ merges $ \(cid, c) ->
    when (H3 `Set.notMember` commitViolations rd st pinId c) $ do
      effects <- mapM (fmap effective . evalMaybe . lookupCommit st) (cParents c)
      annotateShow (cid, effects)
      assert (and [comparable st a b | a <- effects, b <- effects])

-- | \"Rule H is intrinsic to the history: it depends only on the objects,
-- never on a destination ref or on the receiver's state.\" Which clauses an
-- object breaks is the same for every replica; only whether a valid object
-- is on a conflicting lineage depends on @current@, and with no @current@
-- nothing is.
validityIsIntrinsic :: Reading -> Property
validityIsIntrinsic rd = withTests tests . property $ do
  sc <- forAll genHScenario
  let History st current roots = buildHistory sc
      here = verify rd st pinId current roots
      nowhere = verify rd st pinId Nothing roots
      broken v = case v of Invalid cs -> Just cs; _ -> Nothing
  Map.map broken here === Map.map broken nowhere
  assert (ConflictingLineage `notElem` Map.elems nowhere)

-- | An object's verdict is settled when it is made. Nothing made afterwards,
-- no later authority and no later commit, changes which clauses it breaks.
validityIsStable :: Reading -> Property
validityIsStable rd = withTests tests . property $ do
  sc <- forAll genHScenario
  let whole = hStore (buildHistory sc)
  forM_ [0 .. length (hsOps sc)] $ \n -> do
    let part = hStore (buildHistory sc {hsOps = take n (hsOps sc)})
        objects = map OCommit (Map.keys (sCommits part)) ++ map ORelease (Map.keys (sReleases part))
    forM_ objects $ \o -> do
      annotateShow (n, o)
      violations rd part pinId o === violations rd whole pinId o

-- | Every recorded divergence is the amended text being stricter. If one
-- were ever looser, an object the unamended text refuses would be accepted,
-- and that would be a hole and not a divergence.
--
-- That is about what an object breaks, and it holds whatever the replica's
-- current authority is: no clause broken under the literal text is unbroken
-- under the amended reading. A conflicting lineage is not something an
-- object breaks. It is a report about the replica, and (g) changes whose
-- report it is:
--
-- * where the current authority stands under both readings, a commit the
--   literal text puts on a conflicting lineage is not plainly valid under
--   the amended reading;
-- * where it does not stand under (g), the amended reading reports the
--   authority and classifies nothing against it, which is what the witness
--   @div-g-verify-with-another-repository-as-current@ shows.
amendedIsStricter :: Property
amendedIsStricter = withTests tests . property $ do
  h@(History st current roots) <- forAll genHistory
  let literal = verify unamended st pinId current roots
      strict = verify amended st pinId current roots
      stands = maybe True (currentStands amended st pinId) current
      reported rd = fmap vrCurrentRejected (rsVerify (expected rd (historyRequest h)))
  cover 3 "a current authority that does not stand" (not stands)
  cover 30 "a current authority that stands" (isJust current && stands)
  forM_ (Map.toList literal) $ \(o, v) -> do
    annotateShow (o, v, Map.lookup o strict)
    case (v, Map.lookup o strict) of
      (Invalid a, Just (Invalid b)) -> assert (a `Set.isSubsetOf` b)
      (Invalid _, _) -> failure
      (ConflictingLineage, Just Valid) -> assert (not stands)
      _ -> success
  -- The literal text has no notion of a current authority that does not
  -- stand, so it never reports one.
  reported unamended === Just False
  reported amended === Just (not stands)
  unless stands $ assert (ConflictingLineage `notElem` Map.elems strict)

-- * Rule P

ruleP :: [(String, Reading -> Property)]
ruleP =
  [ ("honest work is admitted", honestWorkIsAdmitted)
  , ("everything published is valid history", publishedIsValid)
  , ("current moves one successor at a time", currentIsLinear)
  , ("nothing is published on top of the boundary it arrives with", boundaryIsATip)
  , ("only members of the current authority publish", onlyCurrentMembersPublish)
  , ("an object's presence admits nothing", presenceIsNotAdmission)
  , ("a new root is published only under the genesis", rootsOnlyUnderGenesis)
  , ("an emptied repository cannot be restarted once current has moved", emptiedCannotRestart)
  , ("a published change of authority is in force", publishedChangeIsInForce)
  ]

admissions :: Trace -> [(Attempt, Admission)]
admissions tr = [(at, adm) | at <- tAttempts tr, Right adm <- [atResult at]]

-- | The rules are not vacuous: honest commits, honest membership changes and
-- honest releases, each published by an Owner, are all admitted.
honestWorkIsAdmitted :: Reading -> Property
honestWorkIsAdmitted rd = withTests tests . property $ do
  sc <- forAll genHonestPScenario
  let tr = runP rd sc
  cover 30 "current moved" (sCurrent (tFinal tr) /= Just pinId)
  cover 20 "a release published" (or [True | (ReleaseRef _, _) <- Map.toList (sRefs (tFinal tr))])
  forM_ (tAttempts tr) $ \at -> do
    annotateShow at
    assert (isRight (atResult at))

-- | P.2 holds every newly exposed object to Rule H, and @R0@ is only ever
-- what earlier transactions admitted. So from a repository that has
-- published nothing, the authoritative state only ever reaches valid
-- history: valid, on the replica's own lineage, and therefore something a
-- fresh replica can receive under Rule R.
publishedIsValid :: Reading -> Property
publishedIsValid rd = withTests tests . property $ do
  sc <- forAll genPScenario
  let tr = runP rd sc
      st = tStore tr
  forM_ (admissions tr) $ \(_, adm) -> do
    let s1 = admState adm
        tips = Map.elems (sRefs s1)
        verdicts = verify rd st pinId (sCurrent s1) tips
    annotateShow (Map.filter (/= Valid) verdicts)
    assert (all (== Valid) (Map.elems verdicts))
    member <- evalMaybe (sCurrent s1 >>= lookupAuthority st >>= fmap fst . Map.lookupMin . aMembers)
    everything rd st s1 (Holding member) === Recorded (Map.keysSet verdicts)

-- | P.3: \"@current@ moves only with that boundary, by compare-and-swap from
-- @A0@ to @A1@.\" It never moves anywhere but to a successor of where it
-- was, so it stays on one unbroken chain from the genesis.
currentIsLinear :: Reading -> Property
currentIsLinear rd = withTests tests . property $ do
  sc <- forAll genPScenario
  let tr = runP rd sc
      st = tStore tr
  cover 10 "current moved" (sCurrent (tFinal tr) /= Just pinId)
  forM_ (admissions tr) $ \(at, adm) -> do
    before <- evalMaybe (sCurrent (atState at))
    after <- evalMaybe (sCurrent (admState adm))
    annotateShow (before, after)
    assert (after == before || isSuccessorOf rd st after before)
    assert (chainEndsAt rd st pinId after)

-- | P.2: \"No newly exposed commit may cite @A1@. Commits that do are
-- accepted in a later transaction, whose @A0@ is @A1@.\" Anything built on
-- the boundary must cite @A1@ or later (H.3), so nothing newly exposed in
-- the boundary's own transaction has the boundary behind it.
boundaryIsATip :: Reading -> Property
boundaryIsATip rd = withTests tests . property $ do
  sc <- forAll genPScenario
  let tr = runP rd sc
      st = tStore tr
  forM_ (admissions tr) $ \(_, adm) -> do
    let exposed = Set.toList (admExposed adm)
        boundaries = [o | o@(OCommit c) <- exposed, Just k <- [lookupCommit st c], isJust (cInstalls k)]
    assert (length boundaries <= 1)
    forM_ boundaries $ \b ->
      forM_ exposed $ \o -> do
        annotateShow (b, o)
        assert (o == b || not (reaches st o b))

-- | Revocation, for publication. Whatever a transaction newly exposes was
-- signed by a member of the authority current when it is published, holding
-- at least @Contributor@ there. A key that authority has removed publishes
-- nothing: not as the transaction's signer (P.1), and not as the author of
-- anything a current member publishes for it (P.2).
onlyCurrentMembersPublish :: Reading -> Property
onlyCurrentMembersPublish rd = withTests tests . property $ do
  sc <- forAll genPScenario
  let tr = runP rd sc
      st = tStore tr
  forM_ (admissions tr) $ \(at, adm) -> do
    a0 <- evalMaybe (sCurrent (atState at) >>= lookupAuthority st)
    assert (holds a0 (txSigner (atTx at)) Contributor)
    forM_ (Set.toList (admExposed adm)) $ \o -> do
      sig <- evalMaybe (signature st o)
      annotateShow (o, sig)
      assert (sigValid sig && holds a0 (sigKey sig) Contributor)
  where
    signature st (OCommit c) = cSig <$> lookupCommit st c
    signature st (ORelease r) = rSig <$> lookupRelease st r

-- | \"Object presence, remote refs and workspace refs do not establish
-- admission.\" A transaction is decided the same way however much else the
-- store has come to hold, so nothing can be made eligible by being
-- received, or made, first (R.4, P.5).
presenceIsNotAdmission :: Reading -> Property
presenceIsNotAdmission rd = withTests tests . property $ do
  sc <- forAll genPScenario
  let tr = runP rd sc
  forM_ (tAttempts tr) $ \at ->
    admit rd (tStore tr) (atState at) (atTx at) === atResult at

-- | H.4 has a root commit cite the genesis, and P.2 has every newly exposed
-- commit cite @A0@. Together: once @current@ has moved off the genesis, no
-- commit without parents can be published again. A branch unrelated to
-- existing history cannot be started after the first membership change.
--
-- The document does not say this, and it may not be intended.
rootsOnlyUnderGenesis :: Reading -> Property
rootsOnlyUnderGenesis rd = withTests tests . property $ do
  sc <- forAll genPScenario
  let tr = runP rd sc
      st = tStore tr
      roots adm = [c | OCommit c <- Set.toList (admExposed adm), Just k <- [lookupCommit st c], null (cParents k)]
  cover 30 "a root published" (any (not . null . roots . snd) (admissions tr))
  forM_ (admissions tr) $ \(at, adm) ->
    unless (null (roots adm)) $ sCurrent (atState at) === Just pinId

-- | P.3, from the side that matters for revocation: a membership change
-- that has been published has taken effect. @current@ equals or descends
-- from what is in effect after every published commit, so there is never a
-- published removal that the replica is not yet enforcing.
publishedChangeIsInForce :: Reading -> Property
publishedChangeIsInForce rd = withTests tests . property $ do
  sc <- forAll genPScenario
  let tr = runP rd sc
      st = tStore tr
  forM_ (admissions tr) $ \(_, adm) -> do
    current <- evalMaybe (sCurrent (admState adm))
    forM_ [c | OCommit c <- Set.toList (published st (admState adm))] $ \c -> do
      k <- evalMaybe (lookupCommit st c)
      annotateShow (c, current)
      assert (equalsOrDescendsFrom st current (effective k))

-- | The sharper form of the same consequence. If every authoritative ref
-- is gone after @current@ has moved, @R0@ is empty, so any history at all
-- is newly exposed down to a root. That root cites the genesis, which is no
-- longer the current authority (P.2), or it cites something else and breaks
-- H.4. No key, no ref and no accompanying move of @current@ gets anything
-- published again.
emptiedCannotRestart :: Reading -> Property
emptiedCannotRestart rd = withTests 500 . property $ do
  sc <- forAll genPScenario
  let tr = runP rd sc
      st = tStore tr
      emptied = (tFinal tr) {sRefs = Map.empty}
      moved = sCurrent emptied /= Just pinId
      targets =
        [(Branch "b0", OCommit c) | c <- Map.keys (sCommits st)]
          ++ [(ReleaseRef "r0", ORelease r) | r <- Map.keys (sReleases st)]
      moves = Nothing : map Just (Map.keys (sAuthorities st))
  cover 10 "current moved" moved
  when moved $
    forM_ targets $ \(ref, o) ->
      forM_ [Key k | k <- [0 .. keyCount - 1]] $ \signer ->
        forM_ moves $ \move -> do
          let attempt = Transaction signer [Update ref Nothing (Just o) False] move
          annotateShow attempt
          assert (isLeft (admit rd st emptied attempt))

-- | The publication side of \"only ever refuses more\". Every transaction,
-- put to the same @S0@ under both readings, breaks at least as much under
-- 'amended' as under 'unamended'; and where both admit it, they admit
-- the same thing. The states come from running the script under each
-- reading in turn, so both readings' reachable states are covered, but the
-- two decisions compared are always about one transaction and one state.
amendedAdmitsLess :: Property
amendedAdmitsLess = withTests tests . property $ do
  sc <- forAll genPScenario
  let attempts = [(tStore tr, at) | rd <- [unamended, amended], let tr = runP rd sc, at <- tAttempts tr]
      decide rd (st, at) = admit rd st (atState at) (atTx at)
      broken = either flat (const Set.empty)
      -- One entry per clause, so that breaking a further clause of Rule H on
      -- the same object counts as more and not as different.
      flat = Set.fromList . concatMap each . Set.toList
      each (P2RuleH o cs) = [P2RuleH o (Set.singleton cl) | cl <- Set.toList cs]
      each v = [v]
  cover 1 "amended refuses what unamended admits" $
    or [isRight (decide unamended a) && isLeft (decide amended a) | a <- attempts]
  forM_ attempts $ \a -> do
    let literal = decide unamended a
        strict = decide amended a
    annotateShow (snd a, literal, strict)
    assert (broken literal `Set.isSubsetOf` broken strict)
    case (literal, strict) of
      (Right x, Right y) -> x === y
      _ -> success

-- * Rule R

ruleR :: [(String, Reading -> Property)]
ruleR =
  [ ("a reader of a public repository replicates it", publicIsReadByAnyone)
  , ("a private repository is read by its members only", privateIsReadByMembers)
  , ("history by a since-revoked author is received", revokedAuthorIsNoObstacle)
  , ("reading needs the source's permission and nothing else", readingNeedsOnlyPermission)
  , ("only what was asked for is received", onlyWhatWasAskedFor)
  , ("another repository's history is refused", anotherRepositoryIsRefused)
  ]

-- | A transfer of everything a source's refs hold, by a receiver expecting
-- the repository the source is.
everything :: Reading -> Store -> State -> Requester -> Received
everything rd st source who =
  receive rd st (sCurrent source) (Transfer (sPin source) (Map.elems (sRefs source)) who)

-- | A source with one published commit: @k0@ an Owner, @k1@ a Reader, @k2@
-- a Contributor who made the commit; @k3@ and @k4@ are not members.
sourceWith :: Bool -> (Store, State)
sourceWith public = (st, (initialState pinId) {sRefs = Map.fromList [(Branch "b0", OCommit (CommitId 0))]})
  where
    made = applyOp noCtx (OpCommit [] (CiteFloor 0) (Any 2) True Nothing) (genesisStore [(1, Reader), (2, Contributor)] [])
    st = made {sAuthorities = Map.map (\a -> a {aPublicRead = public}) (sAuthorities made)}

everyone :: [Requester]
everyone = Anonymous : [Holding (Key k) | k <- [0 .. keyCount - 1]]

-- | R.2: \"No membership is required of the receiver.\" The document's test:
-- \"a reader replicating a public repository (accepted)\".
publicIsReadByAnyone :: Reading -> Property
publicIsReadByAnyone rd = withTests 1 . property $ do
  let (st, source) = sourceWith True
  forM_ everyone $ \who -> do
    annotateShow who
    everything rd st source who === Recorded (Set.singleton (OCommit (CommitId 0)))

-- | R.2: without @public_read@, \"a role of at least @Reader@ there\". The
-- Reader, the Contributor and the Owner read it. A key with no role does
-- not, and neither does a request nobody signed.
privateIsReadByMembers :: Reading -> Property
privateIsReadByMembers rd = withTests 1 . property $ do
  let (st, source) = sourceWith False
      recorded = Recorded (Set.singleton (OCommit (CommitId 0)))
  forM_ [0, 1, 2] $ \k -> everything rd st source (Holding (Key k)) === recorded
  forM_ [3, 4] $ \k -> everything rd st source (Holding (Key k)) === ReadDenied
  everything rd st source Anonymous === ReadDenied

-- | R.3, and the document's test: \"a fresh replica receiving history with a
-- since-revoked author (accepted)\". The source's current authority has
-- removed @k1@, and @k1@'s commits are received all the same. Permission is
-- the other way about: the source being private, the removed @k1@ may no
-- longer read it.
revokedAuthorIsNoObstacle :: Reading -> Property
revokedAuthorIsNoObstacle rd = withTests 1 . property $ do
  c <- evalMaybe (lookup "h-branch-that-never-saw-the-revocation" [(caseName k, k) | k <- cases])
  let st = rqStore (caseRequest c)
      byRevoked = OCommit (CommitId 2)
      source =
        State pinId (Just (AuthId 1)) $
          Map.fromList [(Branch "b0", OCommit (CommitId 1)), (Branch "b1", byRevoked)]
  case everything rd st source (Holding (Key 0)) of
    Recorded objects -> assert (byRevoked `Set.member` objects)
    other -> annotateShow other >> failure
  everything rd st source (Holding (Key 1)) === ReadDenied

-- | Over generated sources, valid and not: whether a transfer is denied
-- depends on the requester and the source's current authority alone, and
-- everyone permitted is given the same answer, which is the receiver's check
-- of the history. Being an Owner gets a requester nothing that being a
-- Reader, or a stranger to a public repository, does not.
readingNeedsOnlyPermission :: Reading -> Property
readingNeedsOnlyPermission rd = withTests tests . property $ do
  sc <- forAll genHScenario
  -- Generated authorities are seldom public, and whether one is has no
  -- bearing on Rule H, so a quarter of the sources are opened here.
  open <- forAll (Gen.frequency [(3, pure False), (1, pure True)])
  let History built current roots = buildHistory sc
      st
        | open = built {sAuthorities = Map.map (\a -> a {aPublicRead = True}) (sAuthorities built)}
        | otherwise = built
      there = current >>= lookupAuthority st
      public = maybe False aPublicRead there
      -- Every role is at least Reader, so a member is anyone with a role.
      permitted who = public || case who of
        Anonymous -> False
        Holding k -> maybe False (Map.member k . aMembers) there
      history = maybe ReadDenied (\cur -> examine rd st pinId cur roots) current
  cover 15 "a public source" public
  cover 30 "a private source that denies someone" (isJust there && not public && not (all permitted everyone))
  cover 20 "a transfer refused for its history" (isJust there && not (kept history))
  forM_ everyone $ \who -> do
    annotateShow who
    receive rd st current (Transfer pinId roots who) === (if permitted who then history else ReadDenied)

kept :: Received -> Bool
kept (Recorded _) = True
kept _ = False

-- | A transfer is of the roots asked for. Whatever the source has published,
-- asking for some of its refs records what those reach, all of it and
-- nothing else: pulling one branch does not bring the others.
onlyWhatWasAskedFor :: Reading -> Property
onlyWhatWasAskedFor rd = withTests tests . property $ do
  sc <- forAll genPScenario
  let tr = runP rd sc
      st = tStore tr
      source = tFinal tr
  wanted <- forAll (Gen.subsequence (Map.toList (sRefs source)))
  current <- evalMaybe (sCurrent source)
  let roots = map snd wanted
      asked = closure st roots
  cover 20 "something published is left behind" (not (published st source `Set.isSubsetOf` asked))
  cover 20 "something is received" (not (Set.null asked))
  examine rd st pinId current roots === Recorded asked

-- | R.1: \"If a chain ends at a different genesis, the transfer is refused:
-- that is a different repository.\" The genesis is the receiver's to expect.
-- Honest history, which a receiver expecting this repository records whole,
-- is refused whole by one expecting any other.
anotherRepositoryIsRefused :: Reading -> Property
anotherRepositoryIsRefused rd = withTests tests . property $ do
  -- With nothing asked for there is nothing to refuse, read literally; that
  -- is the case div-g-a-source-that-is-not-the-repository-expected.
  sc <- forAll (Gen.filter (not . null . hRoots . buildHistory) genHonestHScenario)
  let History built current roots = buildHistory sc
      other = AuthId (-1)
      st = built {sAuthorities = Map.insert other (genesisOf built) (sAuthorities built)}
      source = fromMaybe pinId current
      reached = closure st roots
  examine rd st pinId source roots === Recorded reached
  case examine rd st other source roots of
    -- Refused for everything in it,
    TransferRefused refused -> Map.keysSet refused === reached
    -- or, under (g), before any of it is looked at.
    NotThatRepository -> assert (currentMustBeOnThePinnedChain rd)
    answer -> annotateShow answer >> failure
  where
    genesisOf st = (sAuthorities st Map.! pinId) {aSigs = [Sig (Key 0) True]}

-- | The replication side of \"only ever refuses more\": whatever the
-- amended reading records, the literal text records, and as the same
-- objects.
amendedReceivesLess :: Property
amendedReceivesLess = withTests tests . property $ do
  sc <- forAll genHScenario
  let History st current roots = buildHistory sc
      source = fromMaybe pinId current
      literal = examine unamended st pinId source roots
      strict = examine amended st pinId source roots
  cover 0.3 "amended refuses what unamended records" (kept literal && not (kept strict))
  cover 5 "both record it" (kept strict)
  annotateShow (literal, strict)
  when (kept strict) $ literal === strict

-- * Named cases

-- | The answers written by hand in "LeVCS.Harness.Cases" are the answers the
-- rules give, under each reading, and the corpus on disk is those cases.
namedCases :: [(PropertyName, Property)]
namedCases =
  [ (fromString (caseName c), once (caseIsAnswered c))
  | c <- cases
  ]
    ++ [ ("received work is recorded and still refused", once receivedIsNotPublishable)
       , ("every named case is in the corpus", once corpusIsCurrent)
       , ("every corpus entry is what the rules say", once corpusAgreesWithRules)
       ]
  where
    once = withTests 1 . property

caseIsAnswered :: Case -> PropertyT IO ()
caseIsAnswered c = do
  expected unamended (caseRequest c) === caseUnamended c
  expected amended (caseRequest c) === caseAmended c
  forM_ (caseUnder c) $ \(name, answer) -> do
    annotate name
    rd <- evalMaybe (readingNamed name)
    expected rd (caseRequest c) === answer
  -- A case witnesses a divergence exactly when it is named as one.
  ("div-" `isPrefixOf` caseName c) === (caseUnamended c /= caseAmended c)

-- | R.4: \"A historically valid commit citing a stale authority can be
-- received under @refs\/remote\/…@, but it is still newly exposed when
-- promoted, so it still needs adoption.\" Replication of the stale commit
-- succeeds, and every attempt to publish it is refused.
receivedIsNotPublishable :: PropertyT IO ()
receivedIsNotPublishable = do
  c <- evalMaybe (lookup "p-work-made-under-an-older-authority" [(caseName k, k) | k <- cases])
  let rq = caseRequest c
      stale = OCommit (CommitId 2)
      -- A source that holds the stale commit on a branch, read by a member.
      source = State (rqPin rq) (Just (AuthId 1)) (Map.fromList [(Branch "b1", stale)])
  forM_ [unamended, amended] $ \rd -> do
    received <- case everything rd (rqStore rq) source (Holding (Key 1)) of
      Recorded objects -> pure objects
      other -> annotateShow other >> failure
    assert (stale `Set.member` received)
    forM_ (rqAdmit rq) $ \(s, t) -> assert (isLeft (admit rd (rqStore rq) s t))

readCorpus :: FilePath -> PropertyT IO CorpusEntry
readCorpus path = do
  value <- evalEither =<< evalIO (eitherDecodeFileStrict path)
  evalEither (parseEither parseCorpusEntry value)

corpusFiles :: PropertyT IO [FilePath]
corpusFiles = sort . filter (".json" `isSuffixOf`) <$> evalIO (listDirectory "corpus")

-- | Run @cabal run write-corpus@ after changing the cases.
corpusIsCurrent :: PropertyT IO ()
corpusIsCurrent =
  forM_ cases $ \c -> do
    entry <- readCorpus ("corpus" </> caseName c <.> "json")
    entry === corpusEntry c

-- | Holds for entries that are not named cases too, such as a counterexample
-- saved from a differential run.
corpusAgreesWithRules :: PropertyT IO ()
corpusAgreesWithRules = do
  files <- corpusFiles
  entries <- forM files (readCorpus . ("corpus" </>))
  forM_ entries $ \e -> do
    annotate (ceName e)
    expected amended (ceRequest e) === ceExpect e
    expected unamended (ceRequest e) === ceUnamended e
