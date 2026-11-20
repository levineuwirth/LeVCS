-- | The model itself, answering as an oracle.
--
-- Reads one request per line and writes the response the rules give it,
-- under the reading named by @LEVCS_SPEC_READING@ (@implemented@ if unset).
-- Put in place of the Rust oracle,
--
-- > LEVCS_SPEC_ORACLE=$(cabal list-bin model-oracle) cabal test differential
--
-- it must pass under every reading, since the harness holds it to the same
-- variable. That checks the harness: the wire format in both directions,
-- and that a conforming implementation of any reading passes its own run.
-- It is also a reference to compare another implementation's answers with.
module Main (main) where

import Data.Aeson (eitherDecodeStrict, encode, object, (.=))
import Data.Aeson.Key (fromString)
import Data.Aeson.Types (parseEither)
import Data.ByteString.Char8 qualified as BS
import Data.ByteString.Lazy.Char8 qualified as BL
import Data.Maybe (fromMaybe)
import System.Environment (lookupEnv)
import System.Exit (die)
import System.IO (hFlush, isEOF, stdout)

import LeVCS.Authority.Reading
import LeVCS.Harness.Wire

main :: IO ()
main = do
  name <- fromMaybe "implemented" <$> lookupEnv "LEVCS_SPEC_READING"
  rd <- maybe (die ("LEVCS_SPEC_READING: unknown reading " ++ name)) pure (readingNamed name)
  loop rd

loop :: Reading -> IO ()
loop rd = do
  done <- isEOF
  if done
    then pure ()
    else do
      line <- BS.getLine
      BL.putStrLn $ encode $ case eitherDecodeStrict line >>= parseEither parseRequest of
        Left e -> object [fromString "error" .= e]
        Right rq -> encodeResponse (expected rd rq)
      hFlush stdout
      loop rd
