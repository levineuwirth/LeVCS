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
-- that sends everything it has whatever was asked for.
--
-- The model is run under the 'implemented' reading, so agreement means that
-- the Rust implements the ratified rules amended by exactly the divergences
-- recorded in @DIVERGENCES.md@.
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

import LeVCS.Authority.Reading
import LeVCS.Harness.Cases
import LeVCS.Harness.Gen
import LeVCS.Harness.Script
import LeVCS.Harness.Wire
import Oracle

-- | @LEVCS_SPEC_TESTS@ sets how many scenarios each property runs.
--
-- @LEVCS_SPEC_READING@ holds the Rust to another reading instead:
-- @ratified@ for the literal text, or @without:a@ (and so on, by the letters
-- of @DIVERGENCES.md@) for everything but one recorded divergence. Each of
-- those runs is expected to fail, and what it shrinks to is a smallest
-- scenario on which the implementation and that reading part ways.
main :: IO ()
main = do
  n <- maybe 2000 (fromMaybe 2000 . readMaybe) <$> lookupEnv "LEVCS_SPEC_TESTS"
  asked <- lookupEnv "LEVCS_SPEC_READING"
  let name = fromMaybe "implemented" asked
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
    anResponse answer === expected rd (caseRequest c)
    when (rd == ratified) $ anResponse answer === caseRatified c
    when (rd == implemented) $ anResponse answer === caseImplemented c
    forM_ (caseUnder c) $ \(reading, written) ->
      when (readingNamed reading == Just rd) $ anResponse answer === written

-- | @receive@ gives each transfer of each named case the answer the rules
-- give it. Nothing else in a response is compared here: a case with no
-- transfer in it says nothing about @receive@, whatever the reading.
namedTransfers :: Reading -> Oracle -> Property
namedTransfers rd o = property $
  forM_ cases $ \c -> do
    annotate (caseName c)
    answer <- evalEither =<< evalIO (ask o (caseRequest c))
    annotate (unlines (anRemarks answer))
    anTransferDamage answer === []
    let made = rsReceive (anResponse answer)
    made === rsReceive (expected rd (caseRequest c))
    when (rd == ratified) $ made === rsReceive (caseRatified c)
    when (rd == implemented) $ made === rsReceive (caseImplemented c)
    forM_ (caseUnder c) $ \(reading, written) ->
      when (readingNamed reading == Just rd) $ made === rsReceive written

-- | @receive@ keeps or refuses every transfer as the rules do under the
-- reading. Only the transfers are compared, so that a failure here is a
-- failure of @receive@: the verdicts on the same history are the first
-- oracle's to answer for.
receives :: Reading -> Oracle -> Gen Request -> Property
receives rd o gen = property $ do
  rq <- forAllWith (BL.unpack . encode . encodeRequest) gen
  unrepresentable rq === []
  let specified = rsReceive (expected rd rq)
  cover 1 "the readings disagree on a transfer" (rsReceive (expected ratified rq) /= rsReceive (expected implemented rq))
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
  cover 1 "the readings disagree" (expected ratified rq /= expected implemented rq)
  unless (null (rqReceive rq)) $ do
    cover 0 "a transfer recorded" (or [True | ReceiveRecorded _ <- rsReceive (expected rd rq)])
    cover 0 "a transfer refused" (ReceiveRefused `elem` rsReceive (expected rd rq))
  answer <- evalEither =<< evalIO (ask o rq)
  annotate (unlines (anRemarks answer))
  anDamage answer === []
  anResponse answer === expected rd rq
