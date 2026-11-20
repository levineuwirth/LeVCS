{-# LANGUAGE OverloadedStrings #-}

-- | The rules checked against @levcs-identity@.
--
-- Every generated scenario is put to the model and, as real signed objects,
-- to the Rust. The two must agree on every verdict: which commits and
-- releases are invalid, which are on a conflicting lineage, whether the
-- replica's current authority was rejected, how every
-- transaction is decided, down to the kind of refusal and the number of
-- objects newly exposed, and whether every transfer is recorded and as what.
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
  ok <- withOracle $ \o ->
    checkSequential $
      Group
        (fromString ("the oracle against the " ++ name ++ " reading"))
        [ ("Rule H: verify_history", withTests (fromIntegral (n :: Int)) (agrees rd o genHistoryRequest))
        , ("Rule P: admit", withTests (fromIntegral n) (agrees rd o (genTraceRequest rd)))
        , ("named cases", withTests 1 (named rd o))
        ]
  unless ok exitFailure

-- | A history to verify, with the transfers 'historyRequest' makes of it and
-- one more that a well-behaved receiver and source would not make: any
-- authority in the store as the source's current one, any of the roots or
-- none, and now and then some other authority as the genesis expected.
genHistoryRequest :: Gen Request
genHistoryRequest = do
  h <- genHistory
  let rq = historyRequest h
      authorities = Map.keys (sAuthorities (hStore h))
  expects <- Gen.frequency [(3, pure pinId), (1, Gen.element authorities)]
  source <- Gen.element authorities
  roots <- Gen.subsequence (hRoots h)
  pure rq {rqReceive = rqReceive rq ++ [(expects, source, roots)]}

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
