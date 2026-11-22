-- | Write the corpus that the Rust test suite replays.
--
-- > cabal run write-corpus
--
-- writes every named case to @corpus\/<name>.json@. Run it after changing
-- "LeVCS.Harness.Cases"; the property suite fails while a case and its file
-- differ.
--
-- > cabal run write-corpus -- add <name> <note> < request.json
--
-- saves one more scenario, such as the request a failing differential run
-- printed, with the answers the rules give it under each reading.
module Main (main) where

import Control.Monad (forM_)
import Data.Aeson (eitherDecode)
import Data.Aeson.Encode.Pretty (Config (..), Indent (..), defConfig, encodePretty')
import Data.Aeson.Types (parseEither)
import Data.ByteString.Lazy.Char8 qualified as BL
import System.Directory (createDirectoryIfMissing)
import System.Environment (getArgs)
import System.Exit (die)
import System.FilePath ((<.>), (</>))

import LeVCS.Authority.Reading
import LeVCS.Harness.Cases
import LeVCS.Harness.Wire

main :: IO ()
main = do
  createDirectoryIfMissing True "corpus"
  args <- getArgs
  case args of
    [] -> forM_ cases (write . corpusEntry)
    ["add", name, note] -> do
      input <- BL.getContents
      request <- either die pure (eitherDecode input >>= parseEither parseRequest)
      write
        CorpusEntry
          { ceName = name
          , ceNote = note
          , ceRequest = request
          , ceExpect = expected amended request
          , ceUnamended = expected unamended request
          }
    _ -> die "usage: write-corpus [add <name> <note> < request.json]"

write :: CorpusEntry -> IO ()
write e = do
  let path = "corpus" </> ceName e <.> "json"
  BL.writeFile path (encodePretty' config (encodeCorpusEntry e) <> BL.pack "\n")
  putStrLn path
  where
    config = defConfig {confIndent = Spaces 2, confCompare = compare}
