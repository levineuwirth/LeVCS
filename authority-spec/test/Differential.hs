{-# LANGUAGE OverloadedStrings #-}

-- | The rules checked against @levcs-identity@, and Rule R's receiver
-- against @receive@ in @levcs-cli@.
--
-- Every generated scenario is put to the model and, as real signed objects,
-- to the Rust. The two must agree on every verdict: which commits and
-- releases are invalid, which are on a conflicting lineage, whether the
-- replica's current authority was rejected, how every
-- transaction is decided, down to the kind of refusal and the number of
-- objects newly exposed, and whether every transfer is recorded and as what.
--
-- There are two oracles ("Oracle"). The first calls 'verify_history' and
-- 'admit' directly. The second answers the same requests with every
-- transfer made by the function the CLI receives with, against a source
-- that sends everything it has whatever was asked for, and with every read
-- asked of a real instance, which decides for itself whom to answer.
--
-- The model is run under the 'amended' reading, which is the document as it
-- stands. So agreement means that the Rust implements the rules as first
-- ratified, amended by exactly the divergences recorded in @DIVERGENCES.md@.
module Main (main) where

import Control.Monad (forM_, unless, when)
import Data.Aeson (encode)
import Data.ByteString.Lazy.Char8 qualified as BL
import Data.Maybe (fromMaybe)
import Data.String (fromString)
import System.Environment (lookupEnv)
import System.Exit (die, exitFailure)
import Text.Read (readMaybe)

import Data.Map.Strict qualified as Map
import Hedgehog hiding (Update)
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range

import LeVCS.Authority.Model
import LeVCS.Authority.RuleP
import LeVCS.Authority.RuleR (Requester (..))

import LeVCS.Authority.Reading
import LeVCS.Harness.Cases
import LeVCS.Harness.Gen
import LeVCS.Harness.Script
import LeVCS.Harness.Wire
import Oracle

-- | @LEVCS_SPEC_TESTS@ sets how many scenarios each property runs.
--
-- @LEVCS_SPEC_READING@ holds the Rust to another reading instead:
-- @unamended@ for the text as first ratified, read literally, or
-- @without:a@ (and so on, by the letters of @DIVERGENCES.md@) for everything
-- but one recorded divergence. Each of those runs is expected to fail, and
-- what it shrinks to is a smallest scenario on which the implementation and
-- that reading part ways.
main :: IO ()
main = do
  n <- maybe 2000 (fromMaybe 2000 . readMaybe) <$> lookupEnv "LEVCS_SPEC_TESTS"
  asked <- lookupEnv "LEVCS_SPEC_READING"
  let name = fromMaybe "amended" asked
  rd <- maybe (die ("LEVCS_SPEC_READING: unknown reading " ++ name)) pure (readingNamed name)
  rules <- withOracle Rules $ \o ->
    checkSequential $
      Group
        (fromString ("the oracle against the " ++ name ++ " reading"))
        [ ("Rule H: verify_history", withTests (fromIntegral (n :: Int)) (agrees rd o genHistoryRequest))
        , ("Rule P: admit", withTests (fromIntegral n) (agrees rd o (genTraceRequest rd)))
        , ("named cases", withTests 1 (named rd o))
        ]
  -- The same again where it bears on Rule R, with every transfer made by
  -- the function the CLI receives with.
  receiver <- withOracle Receiver $ \o ->
    checkSequential $
      Group
        (fromString ("receive in levcs-cli against the " ++ name ++ " reading"))
        [ ("Rule R: receive", withTests (fromIntegral n) (receives rd o genTransfersRequest))
        , ("Rule R: read permission at an instance", withTests (fromIntegral n) (serves' rd o genReadsRequest))
        , ("named cases", withTests 1 (namedTransfers rd o))
        ]
  unless (and rules && and receiver) exitFailure

-- | A history to verify, with the transfers 'historyRequest' makes of it and
-- one more that a well-behaved receiver and source would not make: any
-- authority in the store as the source's current one, any of the roots or
-- none, and now and then some other authority as the genesis expected.
genHistoryRequest :: Gen Request
genHistoryRequest = do
  h <- genHistory
  extra <- genTransfer h
  let rq = historyRequest h
  pure rq {rqReceive = rqReceive rq ++ [extra]}

-- | A transfer of some of a history's roots that a well-behaved receiver
-- and source might not make.
genTransfer :: History -> Gen (AuthId, AuthId, [Object])
genTransfer h = do
  let authorities = Map.keys (sAuthorities (hStore h))
  expects <- Gen.frequency [(3, pure pinId), (1, Gen.element authorities)]
  source <- Gen.element authorities
  roots <- Gen.subsequence (hRoots h)
  pure (expects, source, roots)

-- | A history and several transfers of it, for the oracle that makes them.
genTransfersRequest :: Gen Request
genTransfersRequest = do
  h <- genHistory
  extra <- Gen.list (Range.linear 1 4) (genTransfer h)
  let rq = historyRequest h
  pure rq {rqReceive = rqReceive rq ++ extra}

-- | A publication trace, and one of its transactions put again in a way the
-- trace never would: over a state whose current authority is any authority
-- in the store, or bent out of the shape of a transaction.
genTraceRequest :: Reading -> Gen Request
genTraceRequest rd = do
  tr <- runP rd <$> genPScenario
  let rq = traceRequest tr
      st = tStore tr
      commits = map OCommit (Map.keys (sCommits st))
      releases = map ORelease (Map.keys (sReleases st))
      -- The other kind of object from the one the ref is for.
      wrong (Branch _) = releases
      wrong _ = commits
      retarget u o = u {uNew = Just o}
      first f tx = case txUpdates tx of
        u : rest -> tx {txUpdates = f u ++ rest}
        [] -> tx
  case rqAdmit rq of
    [] -> pure rq
    attempts -> do
      (s, tx) <- Gen.element attempts
      bent <-
        Gen.choice $
          [ do a <- Gen.element (Map.keys (sAuthorities st)); pure (s {sCurrent = Just a}, tx)
          , pure (s, first (\u -> [u, u]) tx)
          , do
              name <- Gen.element ["", ".", "a//b", "a/../b", "a/b"]
              pure (s, first (\u -> [u {uRef = Branch name}]) tx)
          , pure (s, tx {txUpdates = txUpdates tx ++ [Update (Branch "gone") Nothing Nothing False]})
          ]
            ++ [ do o <- Gen.element (wrong (uRef u)); pure (s, first (\v -> [retarget v o]) tx)
               | u <- take 1 (txUpdates tx)
               , not (null (wrong (uRef u)))
               ]
      pure rq {rqAdmit = attempts ++ [bent]}

-- | The oracle gives each named case the answer the rules give it.
named :: Reading -> Oracle -> Property
named rd o = property $
  forM_ cases $ \c -> do
    annotate (caseName c)
    answer <- evalEither =<< evalIO (ask o (caseRequest c))
    annotate (unlines (anRemarks answer))
    anDamage answer === []
    -- Under whichever reading the oracle is held to, and for the two
    -- readings the cases have answers written out for, those answers too.
    -- The reads are left out: this oracle has no instance to ask, and the
    -- second one answers for them.
    let rules r = r {rsServe = []}
        given = rules (anResponse answer)
    given === rules (expected rd (caseRequest c))
    when (rd == unamended) $ given === rules (caseUnamended c)
    when (rd == amended) $ given === rules (caseAmended c)
    forM_ (caseUnder c) $ \(reading, written) ->
      when (readingNamed reading == Just rd) $ given === rules written

-- | A history held by an instance, and several reads asked of it: by no
-- one in particular, by each key the scenario could have made a member, and
-- by one it could not. The instance's current authority for the repository
-- is mostly the history's own, and now and then any authority in the store
-- or none. Some authorities are made public first, which changes no other
-- fact about the history.
genReadsRequest :: Gen Request
genReadsRequest = do
  h <- genHistory
  open <- Gen.subsequence (Map.keys (sAuthorities (hStore h)))
  let st = (hStore h) {sAuthorities = Map.mapWithKey (\a x -> if a `elem` open then x {aPublicRead = True} else x) (sAuthorities (hStore h))}
      authorities = Map.keys (sAuthorities st)
      stranger = Key keyCount
  asked <- Gen.list (Range.linear 1 5) $ do
    current <- Gen.frequency [(6, pure (hCurrent h)), (2, Just <$> Gen.element authorities), (1, pure Nothing)]
    who <- Gen.frequency [(2, pure Anonymous), (5, Holding . Key <$> genKey), (1, pure (Holding stranger))]
    roots <- Gen.subsequence (hRoots h)
    pure (current, who, roots)
  pure (Request st pinId Nothing [] [] asked)

-- | An instance answers every read as the rules do under the reading: sent
-- nothing, sent history that is kept, or sent history that is refused. Only
-- the reads are compared.
serves' :: Reading -> Oracle -> Gen Request -> Property
serves' rd o gen = property $ do
  rq <- forAllWith (BL.unpack . encode . encodeRequest) gen
  unrepresentable rq === []
  let st = rqStore rq
      specified = rsServe (expected rd rq)
      asked = zip (rqServe rq) specified
      private current = maybe False (not . aPublicRead) (current >>= lookupAuthority st)
      kept r = case r of Served _ -> True; _ -> False
  cover 1 "the readings disagree on a read" (rsServe (expected unamended rq) /= rsServe (expected amended rq))
  cover 20 "a read kept" (any (kept . snd) asked)
  cover 20 "a reader sent nothing" (ServeDenied `elem` specified)
  cover 5 "a reader sent history it refuses" (ServeRefused `elem` specified)
  cover 5 "a member reads what the public may not" (or [True | ((current, Holding _, _), r) <- asked, private current, r /= ServeDenied])
  cover 5 "a key that is no member's is sent nothing" (or [True | ((current, Holding _, _), ServeDenied) <- asked, private current])
  cover 5 "the public reads" (or [True | ((_, Anonymous, _), r) <- asked, r /= ServeDenied])
  cover 2 "no current authority" (or [True | (Nothing, _, _) <- rqServe rq])
  answer <- evalEither =<< evalIO (ask o rq)
  annotate (unlines (anRemarks answer))
  anReadDamage answer === []
  rsServe (anResponse answer) === specified

-- | @receive@ gives each transfer of each named case the answer the rules
-- give it, and an instance each read. Nothing else in a response is
-- compared here: a case with neither in it says nothing about replication,
-- whatever the reading.
namedTransfers :: Reading -> Oracle -> Property
namedTransfers rd o = property $
  forM_ cases $ \c -> do
    annotate (caseName c)
    answer <- evalEither =<< evalIO (ask o (caseRequest c))
    annotate (unlines (anRemarks answer))
    anTransferDamage answer === []
    anReadDamage answer === []
    let replicated r = (rsReceive r, rsServe r)
        made = replicated (anResponse answer)
    made === replicated (expected rd (caseRequest c))
    when (rd == unamended) $ made === replicated (caseUnamended c)
    when (rd == amended) $ made === replicated (caseAmended c)
    forM_ (caseUnder c) $ \(reading, written) ->
      when (readingNamed reading == Just rd) $ made === replicated written

-- | @receive@ keeps or refuses every transfer as the rules do under the
-- reading. Only the transfers are compared, so that a failure here is a
-- failure of @receive@: the verdicts on the same history are the first
-- oracle's to answer for.
receives :: Reading -> Oracle -> Gen Request -> Property
receives rd o gen = property $ do
  rq <- forAllWith (BL.unpack . encode . encodeRequest) gen
  unrepresentable rq === []
  let specified = rsReceive (expected rd rq)
  cover 1 "the readings disagree on a transfer" (rsReceive (expected unamended rq) /= rsReceive (expected amended rq))
  cover 20 "a transfer recorded" (or [True | ReceiveRecorded _ <- specified])
  cover 20 "a transfer refused" (ReceiveRefused `elem` specified)
  cover 5 "a transfer of several roots recorded" (or [True | ((_, _, _ : _ : _), ReceiveRecorded _) <- zip (rqReceive rq) specified])
  cover 5 "a transfer of branches alone recorded" (or [True | ((_, _, roots@(_ : _)), ReceiveRecorded _) <- zip (rqReceive rq) specified, all isCommit roots])
  cover 1 "a transfer of nothing recorded" (or [True | ((_, _, []), ReceiveRecorded _) <- zip (rqReceive rq) specified])
  answer <- evalEither =<< evalIO (ask o rq)
  annotate (unlines (anRemarks answer))
  anTransferDamage answer === []
  rsReceive (anResponse answer) === specified
  where
    isCommit (OCommit _) = True
    isCommit _ = False

-- | The Rust gives the response the rules give under the reading.
agrees :: Reading -> Oracle -> Gen Request -> Property
agrees rd o gen = property $ do
  rq <- forAllWith (BL.unpack . encode . encodeRequest) gen
  -- Both sides must be answering the same question.
  unrepresentable rq === []
  cover 1 "the readings disagree" (expected unamended rq /= expected amended rq)
  unless (null (rqReceive rq)) $ do
    cover 0 "a transfer recorded" (or [True | ReceiveRecorded _ <- rsReceive (expected rd rq)])
    cover 0 "a transfer refused" (ReceiveRefused `elem` rsReceive (expected rd rq))
  answer <- evalEither =<< evalIO (ask o rq)
  annotate (unlines (anRemarks answer))
  anDamage answer === []
  anResponse answer === expected rd rq
