-- | Where the implementation enforced something the text as first ratified
-- did not say, the rule is a named switch here instead of a silent part of
-- the model.
--
-- 'ratified' is the text of @doc/authority-semantics.md@ as first ratified,
-- on 2026-10-04, read literally. 'implemented' is that text plus every
-- switch, and is what the differential run holds @levcs-identity@ to. So the
-- claim the run makes is exact: the Rust implements the rules as first
-- ratified, amended by these switches and nothing else. @DIVERGENCES.md@ has
-- one entry per switch.
--
-- The document was amended on 2026-11-21 to say what every switch says, so
-- 'implemented' is the document as it stands. Where a comment in this model
-- sets "the text" against a switch, it means the text as first ratified.
module LeVCS.Authority.Reading
  ( Reading (..)
  , ratified
  , implemented
  , divergences
  , readingNamed
  ) where

import Data.List (stripPrefix)

data Reading = Reading
  { successorSignedByBoundaryAuthor :: Bool
  -- ^ (a) The author of a commit that installs a successor must have signed
  -- that successor, with a signature that verifies. The text asks only that
  -- the successor be signed by an Owner of its predecessor.
  , everyAuthoritySignatureVerifies :: Bool
  -- ^ (b) Every signature on every authority in a chain must verify. The
  -- text asks for one, by an Owner of the predecessor.
  , installedAuthorityCanConflict :: Bool
  -- ^ (c) A valid commit is on a conflicting lineage if the authority it
  -- installs is incomparable with @current@. The text speaks only of the
  -- authority it cites.
  , rewriteMustBeForced :: Bool
  -- ^ (d) A non-fast-forward update must be marked as forced, as well as
  -- being made by a Maintainer. P.4 asks only for the Maintainer.
  , deletionCanUnpublish :: Bool
  -- ^ (d) Deleting a ref whose target no remaining ref reaches counts as a
  -- non-fast-forward update. P.4 does not mention deletion.
  , ownerlessRejectedWhenCited :: Bool
  -- ^ (e) A successor with no Owner is invalid wherever it appears in a
  -- chain. H.5 rejects it where a commit installs it; D4 can be read either
  -- way.
  , conflictRefusesTransfer :: Bool
  -- ^ (f) A transfer is refused if anything in it is on a lineage that
  -- conflicts with the source's current authority. R.1 asks that everything
  -- received pass Rule H, which a commit on a conflicting lineage does.
  , currentMustBeOnThePinnedChain :: Bool
  -- ^ (g) A current authority counts for nothing unless its chain is
  -- unbroken and ends at the pinned genesis. A transfer from such a source
  -- is refused whatever was asked for, a transaction over such a state is
  -- refused whatever it does, and @verify@ reports the authority and
  -- classifies nothing against it. The text takes @current@ as given.
  }
  deriving (Eq, Show)

-- | The ratified text, read literally.
ratified :: Reading
ratified =
  Reading
    { successorSignedByBoundaryAuthor = False
    , everyAuthoritySignatureVerifies = False
    , installedAuthorityCanConflict = False
    , rewriteMustBeForced = False
    , deletionCanUnpublish = False
    , ownerlessRejectedWhenCited = False
    , conflictRefusesTransfer = False
    , currentMustBeOnThePinnedChain = False
    }

-- | The ratified text with every recorded divergence applied.
implemented :: Reading
implemented =
  Reading
    { successorSignedByBoundaryAuthor = True
    , everyAuthoritySignatureVerifies = True
    , installedAuthorityCanConflict = True
    , rewriteMustBeForced = True
    , deletionCanUnpublish = True
    , ownerlessRejectedWhenCited = True
    , conflictRefusesTransfer = True
    , currentMustBeOnThePinnedChain = True
    }

-- | Each recorded divergence under the letter @DIVERGENCES.md@ gives it,
-- with the 'implemented' reading less that one switch. Holding the Rust to
-- one of these must fail, or the switch is not needed and the entry is
-- wrong.
divergences :: [(String, Reading)]
divergences =
  [ ("a", implemented {successorSignedByBoundaryAuthor = False})
  , ("b", implemented {everyAuthoritySignatureVerifies = False})
  , ("c", implemented {installedAuthorityCanConflict = False})
  , ("d-force", implemented {rewriteMustBeForced = False})
  , ("d-delete", implemented {deletionCanUnpublish = False})
  , ("e", implemented {ownerlessRejectedWhenCited = False})
  , ("f", implemented {conflictRefusesTransfer = False})
  , ("g", implemented {currentMustBeOnThePinnedChain = False})
  ]

-- | A reading by name: @ratified@, @implemented@, or @without:@ and a
-- divergence's letter.
readingNamed :: String -> Maybe Reading
readingNamed "ratified" = Just ratified
readingNamed "implemented" = Just implemented
readingNamed name = stripPrefix "without:" name >>= (`lookup` divergences)
