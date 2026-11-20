-- | The Rust oracle, as a process that is asked one scenario at a time.
module Oracle
  ( Oracle
  , Answer (..)
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
  , anRemarks :: [String]
  -- ^ The implementation's own account of each problem and refusal.
  }

-- | Start the oracle: the program named by @LEVCS_SPEC_ORACLE@ or, with that
-- unset, the @spec_oracle@ example built and run through cargo from the
-- repository root.
withOracle :: (Oracle -> IO a) -> IO a
withOracle use = do
  named <- lookupEnv "LEVCS_SPEC_ORACLE"
  let command = case named of
        Just path | not (null path) -> proc path []
        _ ->
          (proc "cargo" ["run", "--quiet", "--release", "-p", "levcs-identity", "--example", "spec_oracle"])
            { cwd = Just ".."
            }
  bracket (start command) stop (\(o, _) -> use o)
  where
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
        Right (Answer response damage remarks)
