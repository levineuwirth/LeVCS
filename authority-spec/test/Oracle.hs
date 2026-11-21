-- | A Rust oracle, as a process that is asked one scenario at a time.
module Oracle
  ( Oracle
  , Answer (..)
  , Which (..)
  , withOracle
  , ask
  ) where

import Control.Exception (bracket)
import Data.Aeson (eitherDecodeStrict, encode)
import Data.Aeson.Types (parseEither)
import Data.ByteString.Char8 qualified as BS
import Data.ByteString.Lazy.Char8 qualified as BL
import System.Environment (lookupEnv)
import System.IO (BufferMode (..), Handle, hClose, hFlush, hSetBuffering)
import System.Process

import LeVCS.Harness.Wire

data Oracle = Oracle
  { toOracle :: Handle
  , fromOracle :: Handle
  }

data Answer = Answer
  { anResponse :: Response
  , anDamage :: [String]
  -- ^ Damage the implementation found. The harness never sends any, so a
  -- non-empty list is a fault in the harness.
  , anTransferDamage :: [String]
  -- ^ The part of that damage found in making the transfers.
  , anReadDamage :: [String]
  -- ^ The part found in the reads asked of an instance.
  , anRemarks :: [String]
  -- ^ The implementation's own account of each problem and refusal.
  }

-- | The two oracles. Both answer a whole request, and they differ in one
-- thing: how a transfer is decided.
data Which
  = -- | @spec_oracle@ in @levcs-identity@: 'verify_history' and 'admit'
    -- called directly, and a transfer decided from the report of the walk.
    Rules
  | -- | @spec_receive_oracle@ in @levcs-cli@: the same, with every transfer
    -- made by the @receive@ that @clone@, @pull@ and @fork@ call, and every
    -- read asked of an instance of @levcs-instance@. The first oracle has no
    -- instance to ask, and says nothing of reads.
    Receiver

-- | Start an oracle, built and run through cargo from the repository root,
-- or the program an environment variable names in its place:
-- @LEVCS_SPEC_ORACLE@ for 'Rules', @LEVCS_SPEC_RECEIVE_ORACLE@ for
-- 'Receiver'.
--
-- With @LEVCS_SPEC_ORACLE@ set and the other not, there is no second oracle
-- and the answer is 'Nothing': the program named is some other
-- implementation, answering transfers its own way, and @levcs-cli@ has no
-- part in the run.
withOracle :: Which -> (Oracle -> IO a) -> IO (Maybe a)
withOracle which use = do
  rules <- named "LEVCS_SPEC_ORACLE"
  receiver <- named "LEVCS_SPEC_RECEIVE_ORACLE"
  let cargo package example =
        (proc "cargo" ["run", "--quiet", "--release", "-p", package, "--example", example])
          { cwd = Just ".."
          }
      command = case (which, rules, receiver) of
        (Rules, Just path, _) -> Just (proc path [])
        (Rules, Nothing, _) -> Just (cargo "levcs-identity" "spec_oracle")
        (Receiver, _, Just path) -> Just (proc path [])
        (Receiver, Just _, Nothing) -> Nothing
        (Receiver, Nothing, Nothing) -> Just (cargo "levcs-cli" "spec_receive_oracle")
  traverse (\c -> bracket (start c) stop (\(o, _) -> use o)) command
  where
    named variable = do
      value <- lookupEnv variable
      pure (case value of Just path | not (null path) -> Just path; _ -> Nothing)
    start command = do
      (Just hin, Just hout, _, ph) <-
        createProcess command {std_in = CreatePipe, std_out = CreatePipe}
      hSetBuffering hin (BlockBuffering Nothing)
      hSetBuffering hout (BlockBuffering Nothing)
      pure (Oracle hin hout, ph)
    stop (o, ph) = do
      hClose (toOracle o)
      _ <- waitForProcess ph
      pure ()

ask :: Oracle -> Request -> IO (Either String Answer)
ask o rq = do
  BL.hPutStrLn (toOracle o) (encode (encodeRequest rq))
  hFlush (toOracle o)
  line <- BS.hGetLine (fromOracle o)
  pure $ do
    value <- eitherDecodeStrict line
    case parseEither parseResponse value of
      Left e -> Left (e ++ " in " ++ BS.unpack line)
      Right response -> do
        (damage, remarks) <- parseEither parseRemarks value
        transfers <- parseEither parseTransferDamage value
        asked <- parseEither parseServeDamage value
        Right (Answer response damage transfers asked remarks)
