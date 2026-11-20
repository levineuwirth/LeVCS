-- | Named scenarios with their answers written out by hand.
--
-- The generated runs say that the model and the Rust agree. These say what
-- they agree /on/, case by case, in terms a reader can check against the
-- document without running anything. Most are the document's own list of
-- tests (\"Implementation notes\"); the @div-@ cases are smallest witnesses
-- for the recorded divergences, where the two readings give different
-- answers.
--
-- Every answer here is checked three ways: against the model under each
-- reading (@test\/Properties.hs@), against the Rust (@test\/Differential.hs@
-- and, from the written corpus, @crates\/levcs-identity\/tests\/spec_corpus.rs@).
module LeVCS.Harness.Cases
  ( Case (..)
  , cases
  , corpusEntry
  ) where

import Data.Map.Strict qualified as Map
import Data.Set qualified as Set

import LeVCS.Authority.Model
import LeVCS.Authority.RuleP
import LeVCS.Harness.Wire

data Case = Case
  { caseName :: String
  , caseNote :: String
  , caseRequest :: Request
  , caseRatified :: Response
  , caseImplemented :: Response
  , caseUnder :: [(String, Response)]
  -- ^ Answers written out for other readings, by the name
  -- 'LeVCS.Authority.Reading.readingNamed' knows them by. For a case about
  -- how two divergences interact, where the two ends say nothing.
  }
  deriving (Eq, Show)

corpusEntry :: Case -> CorpusEntry
corpusEntry k =
  CorpusEntry
    { ceName = caseName k
    , ceNote = caseNote k
    , ceRequest = caseRequest k
    , ceExpect = caseImplemented k
    , ceRatified = caseRatified k
    }

-- * Building

-- | Objects are numbered in the order they are listed.
store :: [Authority] -> [Commit] -> [Release] -> Store
store as cs rs =
  Store
    (Map.fromList (zip (map AuthId [0 ..]) as))
    (Map.fromList (zip (map CommitId [0 ..]) cs))
    (Map.fromList (zip (map ReleaseId [0 ..]) rs))

-- | A genesis. @k0@ is an Owner and signs it.
genesis :: [(Int, Role)] -> Authority
genesis members =
  Authority
    { aPrev = Nothing
    , aVersion = 1
    , aMembers = Map.fromList ((Key 0, Owner) : [(Key k, role) | (k, role) <- members])
    , aProtected = Set.empty
    , aPublicRead = False
    , aSigs = [Sig (Key 0) True]
    }

-- | @successor prev version members signers@, with exactly those members.
successor :: Int -> Int -> [(Int, Role)] -> [Int] -> Authority
successor prev version members signers =
  Authority
    { aPrev = Just (AuthId prev)
    , aVersion = version
    , aMembers = Map.fromList [(Key k, role) | (k, role) <- members]
    , aProtected = Set.empty
    , aPublicRead = False
    , aSigs = [Sig (Key k) True | k <- signers]
    }

-- | @commit parents cites signer@.
commit :: [Int] -> Int -> Int -> Commit
commit parents cites signer =
  Commit
    { cParents = map CommitId parents
    , cCites = AuthId cites
    , cSig = Sig (Key signer) True
    , cInstalls = Nothing
    }

installing :: Int -> Commit -> Commit
installing a k = k {cInstalls = Just (AuthId a)}

-- | @release predecessor cites declarer@.
release :: Int -> Int -> Int -> Release
release predecessor cites declarer =
  Release
    { rPredecessor = CommitId predecessor
    , rParent = Nothing
    , rCites = AuthId cites
    , rSig = Sig (Key declarer) True
    }

c, r :: Int -> Object
c = OCommit . CommitId
r = ORelease . ReleaseId

-- | A history case: the replica's @current@, the roots, and under each
-- reading which objects are invalid and which on a conflicting lineage.
history
  :: String
  -> String
  -> Store
  -> Maybe Int
  -> [Object]
  -> ([Object], [Object])
  -> ([Object], [Object])
  -> Case
history name note st current roots literal strict =
  Case
    { caseName = name
    , caseNote = note
    , caseRequest = Request st (AuthId 0) (Just (AuthId <$> current, roots)) [] []
    , caseRatified = answer literal
    , caseImplemented = answer strict
    , caseUnder = []
    }
  where
    answer (invalid, conflicting) =
      Response (Just (VerifyResponse everything (Set.fromList invalid) (Set.fromList conflicting) False)) [] []
    -- In every case but the one built with 'reaching', the roots have every
    -- commit and release in the store behind them.
    everything =
      Set.fromList (map OCommit (Map.keys (sCommits st)) ++ map ORelease (Map.keys (sReleases st)))

-- | A history case whose roots reach only the objects listed.
reaching :: [Object] -> Case -> Case
reaching objects k =
  k {caseRatified = only (caseRatified k), caseImplemented = only (caseImplemented k)}
  where
    only rs = rs {rsVerify = (\v -> v {vrReached = Set.fromList objects}) <$> rsVerify rs}

-- | The answer to a history case under one more reading: which objects are
-- invalid and which on a conflicting lineage.
under :: String -> ([Object], [Object]) -> Case -> Case
under reading (invalid, conflicting) k = k {caseUnder = caseUnder k ++ [(reading, answer)]}
  where
    answer =
      (caseImplemented k)
        { rsVerify =
            (\v -> v {vrInvalid = Set.fromList invalid, vrConflicting = Set.fromList conflicting})
              <$> rsVerify (caseImplemented k)
        }

-- | A history case in which the implemented reading reports the replica's
-- current authority as no authority of this repository.
rejectingCurrent :: Case -> Case
rejectingCurrent k = k {caseImplemented = (caseImplemented k) {rsVerify = rejected <$> rsVerify (caseImplemented k)}}
  where
    rejected v = v {vrCurrentRejected = True}

-- | A history case the two readings agree on.
agreed :: String -> String -> Store -> Maybe Int -> [Object] -> [Object] -> [Object] -> Case
agreed name note st current roots invalid conflicting =
  history name note st current roots (invalid, conflicting) (invalid, conflicting)

-- | A publication case: transactions, each with the state it is put to and
-- the decision under each reading.
publication :: String -> String -> Store -> [(State, Transaction, AdmitResponse, AdmitResponse)] -> Case
publication name note st attempts =
  Case
    { caseName = name
    , caseNote = note
    , caseRequest = Request st (AuthId 0) Nothing [(s, t) | (s, t, _, _) <- attempts] []
    , caseRatified = Response Nothing [d | (_, _, d, _) <- attempts] []
    , caseImplemented = Response Nothing [d | (_, _, _, d) <- attempts] []
    , caseUnder = []
    }

-- | A replication case: transfers, each the genesis the receiver expects,
-- the source's current authority, the roots asked for, and what the
-- receiver makes of it under each reading.
replication :: String -> String -> Store -> [(Int, Int, [Object], ReceiveResponse, ReceiveResponse)] -> Case
replication name note st transfers =
  Case
    { caseName = name
    , caseNote = note
    , caseRequest = Request st (AuthId 0) Nothing [] [(AuthId e, AuthId cur, roots) | (e, cur, roots, _, _) <- transfers]
    , caseRatified = Response Nothing [] [d | (_, _, _, d, _) <- transfers]
    , caseImplemented = Response Nothing [] [d | (_, _, _, _, d) <- transfers]
    , caseUnder = []
    }

recorded :: [Object] -> ReceiveResponse
recorded = ReceiveRecorded . Set.fromList

-- | A transfer the two readings agree on.
alike :: Int -> Int -> [Object] -> ReceiveResponse -> (Int, Int, [Object], ReceiveResponse, ReceiveResponse)
alike e cur roots d = (e, cur, roots, d, d)

-- | A decision the two readings agree on.
both :: State -> Transaction -> AdmitResponse -> (State, Transaction, AdmitResponse, AdmitResponse)
both s t d = (s, t, d, d)

state :: Maybe Int -> [(RefName, Object)] -> State
state current refs = State (AuthId 0) (AuthId <$> current) (Map.fromList refs)

b :: Int -> RefName
b n = Branch ("b" ++ show n)

-- | @tx signer updates@, leaving @current@ alone.
tx :: Int -> [Update] -> Transaction
tx signer updates = Transaction (Key signer) updates Nothing

moving :: Int -> Transaction -> Transaction
moving a t = t {txAuthority = Just (AuthId a)}

-- | @move ref from to@, not forced.
move :: RefName -> Maybe Object -> Maybe Object -> Update
move ref from to = Update ref from to False

forced :: Update -> Update
forced u = u {uForce = True}

admitted :: Int -> AdmitResponse
admitted commits = Admitted commits 0 Nothing

-- * The cases

cases :: [Case]
cases =
  historyCases
    ++ divergentHistoryCases
    ++ publicationCases
    ++ divergentPublicationCases
    ++ replicationCases
    ++ divergentReplicationCases

-- | Two authorities used throughout: a genesis with @k1@ a Contributor, and
-- a successor that removes @k1@.
withK1, withoutK1 :: Authority
withK1 = genesis [(1, Contributor)]
withoutK1 = successor 0 2 [(0, Owner)] [0]

historyCases :: [Case]
historyCases =
  [ agreed
      "h-revoked-author-on-the-revoking-commit"
      "H.3, the revocation rule. c1 installs an authority without k1. On top of it, k1 can \
      \neither go on citing the old authority (c2) nor cite the new one, of which it is not a \
      \member (c4). The owner's commit under the new authority (c3) is valid."
      ( store
          [withK1, withoutK1]
          [ commit [] 0 1
          , installing 1 (commit [0] 0 0)
          , commit [1] 0 1
          , commit [1] 1 0
          , commit [1] 1 1
          ]
          []
      )
      (Just 1)
      [c 2, c 3, c 4]
      [c 2, c 4]
      []
  , agreed
      "h-branch-that-never-saw-the-revocation"
      "R.3: revoked authors are no obstacle. k1's commit c2 sits beside the revoking commit \
      \c1, not on top of it, so nothing behind c2 removed k1 and it stays valid."
      (store [withK1, withoutK1] [commit [] 0 1, installing 1 (commit [0] 0 0), commit [0] 0 1] [])
      (Just 1)
      [c 1, c 2]
      []
      []
  , agreed
      "h-merge-of-comparable-authorities-cites-the-newer"
      "H.3 as the merge rule. c1 puts authority 1 in effect and c2 is still under authority \
      \0. A merge of the two must cite authority 1 (c4); citing authority 0 (c3) is invalid."
      ( store
          [genesis [], successor 0 2 [(0, Owner)] [0]]
          [ commit [] 0 0
          , installing 1 (commit [0] 0 0)
          , commit [0] 0 0
          , commit [1, 2] 0 0
          , commit [1, 2] 1 0
          ]
          []
      )
      (Just 1)
      [c 3, c 4]
      [c 3]
      []
  , agreed
      "h-merge-of-incomparable-authorities"
      "H.3: when the parents' effective authorities are incomparable, no authority satisfies \
      \it. c1 and c2 install two different successors of the genesis; a merge is invalid \
      \whichever it cites."
      ( store
          [genesis [], successor 0 2 [(0, Owner)] [0], successor 0 2 [(0, Owner), (1, Contributor)] [0]]
          [ commit [] 0 0
          , installing 1 (commit [0] 0 0)
          , installing 2 (commit [0] 0 0)
          , commit [1, 2] 1 0
          , commit [1, 2] 2 0
          ]
          []
      )
      Nothing
      [c 3, c 4]
      [c 3, c 4]
      []
  , agreed
      "h-contributor-commit-under-a-protected-branch"
      "H.1 has no protected-ref requirement: a commit does not record the ref it was made \
      \for. A Contributor's commit is valid whatever the branch policy."
      (store [(genesis [(1, Contributor)]) {aProtected = Set.fromList ["b0"]}] [commit [] 0 1] [])
      (Just 0)
      [c 0]
      []
      []
  , agreed
      "h-release-declarer-needs-maintainer"
      "D5. Releases declared by a Reader (r0) and by a Contributor (r1) are invalid; by a \
      \Maintainer (r2) and by an Owner (r3), valid."
      ( store
          [genesis [(1, Reader), (2, Contributor), (3, Maintainer)]]
          [commit [] 0 0]
          [release 0 0 1, release 0 0 2, release 0 0 3, release 0 0 0]
      )
      (Just 0)
      [r 0, r 1, r 2, r 3]
      [r 0, r 1]
      []
  , agreed
      "h-ownerless-successor-installed"
      "H.5 and D4. The successor leaves k0 a Contributor and has no Owner, so the commit \
      \installing it is invalid."
      (store [genesis [], successor 0 2 [(0, Contributor)] [0]] [installing 1 (commit [] 0 0)] [])
      (Just 0)
      [c 0]
      [c 0]
      []
  , agreed
      "h-two-successors-when-replicas-meet"
      "D2. This replica's current authority is 1. c3 cites authority 2, another successor of \
      \the genesis: historically valid, and on a conflicting lineage, which is not the same \
      \as invalid."
      twoSuccessors
      (Just 1)
      [c 2, c 3]
      []
      [c 3]
  , agreed
      "h-history-under-a-foreign-genesis"
      "H.2. Authority 1 is the genesis of another repository. Nothing in this history may \
      \cite it, on top of this repository's commits (c1) or as a root (c2)."
      (store [genesis [], genesis [(1, Contributor)]] [commit [] 0 0, commit [0] 1 0, commit [] 1 0] [])
      (Just 0)
      [c 1, c 2]
      [c 1, c 2]
      []
  , agreed
      "h-root-commit-cites-the-genesis"
      "H.4. A commit with no parents must cite the genesis (c1), not a later authority, \
      \however valid that authority is (c0)."
      (store [genesis [], successor 0 2 [(0, Owner)] [0]] [commit [] 1 0, commit [] 0 0] [])
      (Just 1)
      [c 0, c 1]
      [c 0]
      []
  , agreed
      "h-broken-authority-chain"
      "H.2. Authority 1 is signed only by k1, who is not an Owner of the genesis. Authority \
      \2 is signed by the Owner and skips a version. Neither is a successor, so a commit \
      \citing either is invalid."
      ( store
          [genesis [(1, Contributor)], successor 0 2 [(0, Owner), (1, Owner)] [1], successor 0 3 [(0, Owner)] [0]]
          [commit [] 0 0, commit [0] 1 0, commit [0] 2 0]
          []
      )
      (Just 0)
      [c 1, c 2]
      [c 1, c 2]
      []
  , agreed
      "h-signatures-that-do-not-verify"
      "H.1, and the same for a release. c1 and r0 are signed by an Owner's key, with a \
      \signature that does not verify."
      ( store
          [genesis []]
          [commit [] 0 0, (commit [0] 0 0) {cSig = Sig (Key 0) False}]
          [(release 0 0 0) {rSig = Sig (Key 0) False}, release 0 0 0]
      )
      (Just 0)
      [c 1, r 0, r 1]
      [c 1, r 0]
      []
  , agreed
      "h-objects-numbered-out-of-order"
      "An object's number is a name and says nothing of order. Here everything refers to \
      \something with a higher number than its own: authority 3 succeeds authority 5, \
      \commit 1 is on commit 2, which is on the root commit 7, and release 4 follows \
      \release 9. It is honest history, two changes of authority and two releases, and \
      \all of it is valid."
      ( Store
          ( Map.fromList
              [ (AuthId 0, genesis [])
              , (AuthId 5, successor 0 2 [(0, Owner)] [0])
              , (AuthId 3, successor 5 3 [(0, Owner)] [0])
              ]
          )
          ( Map.fromList
              [ (CommitId 7, commit [] 0 0)
              , (CommitId 2, installing 5 (commit [7] 0 0))
              , (CommitId 1, installing 3 (commit [2] 5 0))
              ]
          )
          ( Map.fromList
              [ (ReleaseId 9, release 7 0 0)
              , (ReleaseId 4, (release 1 3 0) {rParent = Just (ReleaseId 9)})
              ]
          )
      )
      (Just 3)
      [c 1, r 4]
      []
      []
  , reaching [c 0, c 1] $
      agreed
        "h-objects-the-roots-do-not-reach"
        "A verdict is given to what the roots reach and to nothing else. c2 carries a \
        \signature that does not verify, and r0 is declared by a Contributor. Neither is \
        \behind the root c1, so neither is reported, as invalid or at all."
        ( store
            [genesis [(1, Contributor)]]
            [commit [] 0 0, commit [0] 0 0, (commit [0] 0 0) {cSig = Sig (Key 0) False}]
            [release 0 0 1]
        )
        (Just 0)
        [c 1]
        []
        []
  ]

divergentHistoryCases :: [Case]
divergentHistoryCases =
  [ history
      "div-a-successor-not-signed-by-the-boundary-author"
      "Divergence (a). k0 and k1 are both Owners. k0 signs the successor and k1 authors the \
      \commit that installs it. The text asks that the successor be signed by an Owner of \
      \its predecessor, which it is. The Rust also wants the commit's author among the \
      \successor's signers."
      ( store
          [genesis [(1, Owner)], successor 0 2 [(0, Owner), (1, Owner)] [0]]
          [installing 1 (commit [] 0 1)]
          []
      )
      Nothing
      [c 0]
      ([], [])
      ([c 0], [])
  , history
      "div-b-authority-with-a-signature-that-does-not-verify"
      "Divergence (b). Authority 1 carries the Owner's valid signature and a second one, by \
      \k1, that does not verify. The text asks for one Owner's signature. The Rust rejects \
      \an authority if any signature on it fails."
      ( store
          [genesis [], (successor 0 2 [(0, Owner)] [0]) {aSigs = [Sig (Key 0) True, Sig (Key 1) False]}]
          [commit [] 0 0, commit [0] 1 0]
          []
      )
      Nothing
      [c 1]
      ([], [])
      ([c 1], [])
  , under "without:a" ([c 0], []) . under "without:b" ([c 0], []) $
      history
        "div-ab-boundary-author-signature-does-not-verify"
        "Divergences (a) and (b) together. k0 and k1 are both Owners. The successor carries \
        \k0's valid signature and one bearing k1's key that does not verify, and k1 authors \
        \the commit that installs it. The text asks for one Owner's signature, which k0's is. \
        \Each divergence refuses it by itself: (b) because a signature on the successor fails, \
        \and (a) because the boundary author has not signed it, a signature that does not \
        \verify being no signature."
        ( store
            [ genesis [(1, Owner)]
            , (successor 0 2 [(0, Owner), (1, Owner)] [0]) {aSigs = [Sig (Key 0) True, Sig (Key 1) False]}
            ]
            [installing 1 (commit [] 0 1)]
            []
        )
        Nothing
        [c 0]
        ([], [])
        ([c 0], [])
  , history
      "div-c-installing-an-authority-on-a-conflicting-lineage"
      "Divergence (c). This replica's current authority is 1. c0 cites the genesis, which is \
      \on the replica's lineage, and installs authority 2, which is not. The text classifies \
      \a commit by the authority it cites. The Rust classifies what it installs as well."
      ( store
          [genesis [], successor 0 2 [(0, Owner)] [0], successor 0 2 [(0, Owner), (1, Contributor)] [0]]
          [installing 2 (commit [] 0 0)]
          []
      )
      (Just 1)
      [c 0]
      ([], [])
      ([], [c 0])
  , history
      "div-e-ownerless-successor-cited-and-never-installed"
      "Divergence (e). Authority 1 has no Owner. No commit installs it, so H.5 never looks at \
      \it; c1 only cites it, and k0 is a Contributor there. Read literally the commit is \
      \valid. The Rust rejects an ownerless successor wherever it appears in a chain."
      (store [genesis [], successor 0 2 [(0, Contributor)] [0]] [commit [] 0 0, commit [0] 1 0] [])
      Nothing
      [c 1]
      ([], [])
      ([c 1], [])
  , rejectingCurrent $
      history
        "div-g-verify-with-another-repository-as-current"
        "Divergence (g), for verify. The replica's current authority is 1, the genesis of \
        \another repository. c0 is valid and cites genesis 0. Read literally the canonical \
        \lineage is the one ending at current, whatever current is, so c0 is on a \
        \conflicting lineage. The Rust reports the current authority as not descending from \
        \the genesis and classifies nothing against it."
        notThisRepository
        (Just 1)
        [c 0]
        ([], [c 0])
        ([], [])
  , rejectingCurrent $
      history
        "div-g-verify-with-a-broken-current"
        "Divergence (g), for verify. The replica's current authority is 2, which names the \
        \genesis as previous and was signed only by k1, not an Owner there. c0 cites the \
        \genesis, which authority 2 claims to descend from, so nothing conflicts under \
        \either reading. The Rust reports the current authority; the text has nothing to \
        \report it as."
        notThisRepository
        (Just 2)
        [c 0]
        ([], [])
        ([], [])
  ]

-- | The pinned repository is genesis 0, with one valid commit. Authority 1
-- is another repository's genesis. Authority 2 names genesis 0 as previous
-- but only @k1@, a Contributor there, signed it, so it succeeds nothing.
-- @k0@ is an Owner in all three.
notThisRepository :: Store
notThisRepository =
  store
    [genesis [(1, Contributor)], genesis [], successor 0 2 [(0, Owner), (1, Owner)] [1]]
    [commit [] 0 0]
    []

-- | A repository whose authority changed: genesis with @k1@ a Contributor,
-- then a successor adding @k2@. c0 is the root, c1 the boundary commit.
changed :: [Commit] -> Store
changed more =
  store
    [withK1, successor 0 2 [(0, Owner), (1, Contributor), (2, Contributor)] [0]]
    ([commit [] 0 0, installing 1 (commit [0] 0 0)] ++ more)
    []

publicationCases :: [Case]
publicationCases =
  [ publication
      "p-ordinary-work"
      "P.1 and P.2 at their simplest. A Contributor publishes a root commit to a repository \
      \that has published nothing, then a commit on top of it."
      (store [withK1] [commit [] 0 1, commit [0] 0 1] [])
      [ both (state (Just 0) []) (tx 1 [move (b 0) Nothing (Just (c 0))]) (admitted 1)
      , both (state (Just 0) [(b 0, c 0)]) (tx 1 [move (b 0) (Just (c 0)) (Just (c 1))]) (admitted 1)
      ]
  , publication
      "p-work-made-under-an-older-authority"
      "D1 and P.5. current is authority 1. c2 was made by k1, still a member, under \
      \authority 0 and never published. It is refused on a branch of its own, refused when \
      \two refs name it at once, and refused when a valid merge under the current authority \
      \(c3) brings it in: all of it is newly exposed, and none of it cites the current \
      \authority."
      (changed [commit [0] 0 1, commit [1, 2] 1 1])
      [ both published1 (tx 1 [move (b 1) Nothing (Just (c 2))]) (Refused NotAdmissible)
      , both
          published1
          (tx 1 [move (b 1) Nothing (Just (c 2)), move (b 2) Nothing (Just (c 2))])
          (Refused NotAdmissible)
      , both published1 (tx 1 [move (b 0) (Just (c 1)) (Just (c 3))]) (Refused NotAdmissible)
      ]
  , publication
      "p-membership-change-and-work-under-it"
      "P.2 and P.3. c1 installs authority 1 and c2 is made under it. Published together they \
      \are refused. The boundary alone, moving current, is admitted, and c2 in a later \
      \transaction whose current authority is 1. A boundary that does not move current is \
      \refused, and so is moving current with no boundary."
      (changed [commit [1] 1 1])
      [ both published0 (moving 1 (tx 0 [move (b 0) (Just (c 0)) (Just (c 2))])) (Refused NotAdmissible)
      , both
          published0
          (moving 1 (tx 0 [move (b 0) (Just (c 0)) (Just (c 1))]))
          (Admitted 1 0 (Just (AuthId 1)))
      , both published1 (tx 1 [move (b 0) (Just (c 1)) (Just (c 2))]) (admitted 1)
      , both published0 (tx 0 [move (b 0) (Just (c 0)) (Just (c 1))]) (Refused NotAdmissible)
      , both published0 (moving 1 (tx 0 [])) (Refused NotAdmissible)
      ]
  , publication
      "p-rollback-of-current"
      "P.3. current is authority 1. An Owner cannot move it back to the genesis, and no \
      \transaction may name a ref under refs/authority."
      (changed [])
      [ both published1 (moving 0 (tx 0 [])) (Refused NotAdmissible)
      , both published1 (tx 0 [move (AuthorityRef "current") Nothing (Just (c 0))]) (Refused NotAdmissible)
      , both published1 (tx 0 [move (AuthorityRef "genesis") Nothing (Just (c 0))]) (Refused NotAdmissible)
      ]
  , publication
      "p-protected-branch-needs-maintainer"
      "P.4. b0 is protected. A Contributor's update of it is refused, a Maintainer's is \
      \admitted, and the Contributor may still publish the same commit to an unprotected \
      \branch."
      ( store
          [(genesis [(1, Contributor), (2, Maintainer)]) {aProtected = Set.fromList ["b0"]}]
          [commit [] 0 1]
          []
      )
      [ both (state (Just 0) []) (tx 1 [move (b 0) Nothing (Just (c 0))]) (Refused Unauthorized)
      , both (state (Just 0) []) (tx 2 [move (b 0) Nothing (Just (c 0))]) (admitted 1)
      , both (state (Just 0) []) (tx 1 [move (b 1) Nothing (Just (c 0))]) (admitted 1)
      ]
  , publication
      "p-protected-by-a-glob-on-the-branch-name"
      "P.4, with the policy a glob. b* protects b0 by its name: a Contributor's update is \
      \refused and a Maintainer's admitted. It does not protect main."
      (protectedBy "b*")
      [ both (state (Just 0) []) (tx 1 [move (b 0) Nothing (Just (c 0))]) (Refused Unauthorized)
      , both (state (Just 0) []) (tx 2 [move (b 0) Nothing (Just (c 0))]) (admitted 1)
      , both (state (Just 0) []) (tx 1 [move (Branch "main") Nothing (Just (c 0))]) (admitted 1)
      ]
  , publication
      "p-protected-by-a-glob-on-the-full-ref"
      "P.4. A glob is matched against the full ref as well as the branch name, so \
      \refs/branches/b* protects b0 and not main."
      (protectedBy "refs/branches/b*")
      [ both (state (Just 0) []) (tx 1 [move (b 0) Nothing (Just (c 0))]) (Refused Unauthorized)
      , both (state (Just 0) []) (tx 2 [move (b 0) Nothing (Just (c 0))]) (admitted 1)
      , both (state (Just 0) []) (tx 1 [move (Branch "main") Nothing (Just (c 0))]) (admitted 1)
      ]
  , publication
      "p-protection-covers-branches-only"
      "P.4. The policy is protected_branches. The glob * protects every branch, so a \
      \Contributor cannot create b1. It protects no release ref: the same Contributor \
      \publishes a release that a Maintainer declared."
      ( store
          [(genesis [(1, Contributor), (2, Maintainer)]) {aProtected = Set.fromList ["*"]}]
          [commit [] 0 0]
          [release 0 0 2]
      )
      [ both (state (Just 0) [(b 0, c 0)]) (tx 1 [move (b 1) Nothing (Just (c 0))]) (Refused Unauthorized)
      , both
          (state (Just 0) [(b 0, c 0)])
          (tx 1 [move (ReleaseRef "r0") Nothing (Just (r 0))])
          (Admitted 0 1 Nothing)
      ]
  , publication
      "p-emptied-repository-cannot-restart"
      "H.4 with P.2. current is authority 1 and every ref has been deleted, so nothing is \
      \published any more. The history that was published before (c1, on the root c0) is \
      \now newly exposed and cites the genesis, not the current authority. A fresh root \
      \citing the current authority (c2) breaks H.4. Nothing can be published again."
      (changed [commit [] 1 0])
      [ both (state (Just 1) []) (tx 0 [move (b 0) Nothing (Just (c 1))]) (Refused NotAdmissible)
      , both (state (Just 1) []) (tx 0 [move (b 0) Nothing (Just (c 2))]) (Refused NotAdmissible)
      ]
  , publication
      "p-removed-member-publishes-nothing"
      "Revocation, for publication. Authority 1 removes k1. k1 cannot sign a transaction \
      \(P.1), and the Owner cannot publish k1's commits for it: c2 cites the current \
      \authority, of which k1 is not a member (H.1), and c3 cites the old one on top of the \
      \commit that replaced it (H.3)."
      ( store
          [withK1, withoutK1]
          [commit [] 0 0, installing 1 (commit [0] 0 0), commit [1] 1 1, commit [1] 0 1]
          []
      )
      [ both published1 (tx 1 [move (b 0) (Just (c 1)) (Just (c 2))]) (Refused Unauthorized)
      , both published1 (tx 0 [move (b 0) (Just (c 1)) (Just (c 2))]) (Refused NotAdmissible)
      , both published1 (tx 0 [move (b 0) (Just (c 1)) (Just (c 3))]) (Refused NotAdmissible)
      ]
  , publication
      "p-no-current-authority"
      "D6. A replica with no current authority can publish nothing, even for an Owner of \
      \the genesis."
      (store [genesis []] [commit [] 0 0] [])
      [both (state Nothing []) (tx 0 [move (b 0) Nothing (Just (c 0))]) (Refused Unauthorized)]
  , publication
      "p-transaction-made-against-another-state"
      "Rule P is evaluated against the single pre-transaction state. b0 holds c1, and the \
      \transaction was made when it held c0."
      (store [genesis []] [commit [] 0 0, commit [0] 0 0, commit [0] 0 0] [])
      [both (state (Just 0) [(b 0, c 1)]) (tx 0 [move (b 0) (Just (c 0)) (Just (c 2))]) (Refused Stale)]
  , publication
      "p-rewriting-a-branch-needs-maintainer"
      "P.4. c2 does not descend from c1. Moving b0 from one to the other is refused for a \
      \Contributor and admitted for a Maintainer. Both transactions are marked as forced, so \
      \the readings agree."
      rewrite
      [ both onC1 (tx 1 [forced (move (b 0) (Just (c 1)) (Just (c 2)))]) (Refused Unauthorized)
      , both onC1 (tx 2 [forced (move (b 0) (Just (c 1)) (Just (c 2)))]) (admitted 1)
      ]
  , publication
      "p-transaction-that-is-not-well-formed"
      "What is not a transaction is refused as one, before anything else about it is \
      \looked at. A branch with no name, a name with an empty or a dot component, a ref \
      \named twice, and a deletion of a ref expected to be absent are all refused as \
      \invalid: for a Contributor, for a stranger (k3) who would otherwise be refused as \
      \unauthorized, and alongside an update that would otherwise be stale. A name with \
      \several components is a name."
      (store [withK1] [commit [] 0 1] [])
      [ both empty (tx 1 [move (Branch "") Nothing (Just (c 0))]) (Refused NotAdmissible)
      , both empty (tx 1 [move (Branch "a//b") Nothing (Just (c 0))]) (Refused NotAdmissible)
      , both empty (tx 1 [move (Branch "a/../b") Nothing (Just (c 0))]) (Refused NotAdmissible)
      , both empty (tx 1 [move (ReleaseRef ".") Nothing (Just (c 0))]) (Refused NotAdmissible)
      , both
          empty
          (tx 1 [move (b 0) Nothing (Just (c 0)), move (b 0) Nothing (Just (c 0))])
          (Refused NotAdmissible)
      , both empty (tx 1 [move (b 0) Nothing Nothing]) (Refused NotAdmissible)
      , both empty (tx 3 [move (Branch "") Nothing (Just (c 0))]) (Refused NotAdmissible)
      , both
          (state (Just 0) [(b 0, c 0)])
          (tx 1 [move (b 0) Nothing (Just (c 0)), move (Branch "") Nothing (Just (c 0))])
          (Refused NotAdmissible)
      , both empty (tx 1 [move (Branch "a/b") Nothing (Just (c 0))]) (admitted 1)
      ]
  , publication
      "p-target-of-the-wrong-kind"
      "A branch names a commit and a release ref a release. b0 is protected. Pointing it \
      \at the valid release r0 is refused as invalid, for the Contributor k1 as for the \
      \Maintainer k2: what the ref would hold is wrong whoever asks, and that is found \
      \before the branch's protection is looked at. So is a release ref pointed at a \
      \commit. The stranger k3 is refused as unauthorized first (P.1)."
      ( store
          [(genesis [(1, Contributor), (2, Maintainer)]) {aProtected = Set.fromList ["b0"]}]
          [commit [] 0 0]
          [release 0 0 2]
      )
      [ both onB1 (tx 1 [move (b 0) Nothing (Just (r 0))]) (Refused NotAdmissible)
      , both onB1 (tx 2 [move (b 0) Nothing (Just (r 0))]) (Refused NotAdmissible)
      , both onB1 (tx 2 [move (ReleaseRef "r0") Nothing (Just (c 0))]) (Refused NotAdmissible)
      , both onB1 (tx 3 [move (b 0) Nothing (Just (r 0))]) (Refused Unauthorized)
      , both onB1 (tx 2 [move (ReleaseRef "r0") Nothing (Just (r 0))]) (Admitted 0 1 Nothing)
      ]
  ]
  where
    published0 = state (Just 0) [(b 0, c 0)]
    published1 = state (Just 1) [(b 0, c 1)]
    empty = state (Just 0) []
    onB1 = state (Just 0) [(b 1, c 0)]

-- | One root commit by the Contributor @k1@, under a policy protecting one
-- glob. @k2@ is a Maintainer.
protectedBy :: String -> Store
protectedBy glob =
  store
    [(genesis [(1, Contributor), (2, Maintainer)]) {aProtected = Set.fromList [glob]}]
    [commit [] 0 1]
    []

-- | c1 and c2 are both children of c0. @k1@ is a Contributor and @k2@ a
-- Maintainer.
rewrite :: Store
rewrite =
  store
    [genesis [(1, Contributor), (2, Maintainer)]]
    [commit [] 0 0, commit [0] 0 0, commit [0] 0 0]
    []

onC1 :: State
onC1 = state (Just 0) [(b 0, c 1)]

divergentPublicationCases :: [Case]
divergentPublicationCases =
  [ publication
      "div-g-publishing-over-a-current-that-does-not-stand"
      "Divergence (g), for publication. c0 is published on b0, and the transaction puts a \
      \second branch on it, which newly exposes nothing. Rule P reads the signer's role in \
      \the current authority and takes that authority as given: with current at another \
      \repository's genesis (1), or at an authority that succeeds nothing (2), the Owner k0 \
      \is admitted, and the stranger k3 refused as no member. The Rust checks that current \
      \descends from the pinned genesis before it reads any role, and refuses all of it as \
      \invalid. With current at the pinned genesis the readings agree."
      notThisRepository
      [ (state (Just 1) [(b 0, c 0)], tx 0 [move (b 1) Nothing (Just (c 0))], admitted 0, Refused NotAdmissible)
      , (state (Just 2) [(b 0, c 0)], tx 0 [move (b 1) Nothing (Just (c 0))], admitted 0, Refused NotAdmissible)
      , (state (Just 1) [(b 0, c 0)], tx 3 [move (b 1) Nothing (Just (c 0))], Refused Unauthorized, Refused NotAdmissible)
      , both (state (Just 0) [(b 0, c 0)]) (tx 0 [move (b 1) Nothing (Just (c 0))]) (admitted 0)
      ]
  , publication
      "div-a-publishing-a-successor-its-author-did-not-sign"
      "Divergence (a), for publication. The boundary commit of \
      \div-a-successor-not-signed-by-the-boundary-author, published with the move of current \
      \it calls for. Read literally it is a valid boundary by an Owner and is admitted. The \
      \Rust finds the commit invalid and refuses the transaction."
      ( store
          [genesis [(1, Owner)], successor 0 2 [(0, Owner), (1, Owner)] [0]]
          [installing 1 (commit [] 0 1)]
          []
      )
      [
        ( state (Just 0) []
        , moving 1 (tx 1 [move (b 0) Nothing (Just (c 0))])
        , Admitted 1 0 (Just (AuthId 1))
        , Refused NotAdmissible
        )
      ]
  , publication
      "div-d-rewrite-that-is-not-forced"
      "Divergence (d). A Maintainer moves b0 from c1 to c2, which does not descend from it, \
      \without marking the update as forced. P.4 asks for a Maintainer and says nothing of \
      \forcing. The Rust refuses an unforced rewrite from anyone."
      rewrite
      [(onC1, tx 2 [move (b 0) (Just (c 1)) (Just (c 2))], admitted 1, Refused NotFastForward)]
  , publication
      "div-d-deleting-a-ref-that-unpublishes"
      "Divergence (d). b0 is the only ref reaching c1. P.4 does not mention deletion, so \
      \read literally any Contributor may delete an unprotected branch. The Rust treats a \
      \deletion that leaves history unreachable as a rewrite: it must be forced, and by a \
      \Maintainer. With another ref still reaching c1 (the last transaction) the readings \
      \agree."
      rewrite
      [ (onC1, tx 2 [move (b 0) (Just (c 1)) Nothing], admitted 0, Refused NotFastForward)
      , (onC1, tx 1 [forced (move (b 0) (Just (c 1)) Nothing)], admitted 0, Refused Unauthorized)
      , both onC1 (tx 2 [forced (move (b 0) (Just (c 1)) Nothing)]) (admitted 0)
      , both
          (state (Just 0) [(b 0, c 1), (b 1, c 1)])
          (tx 1 [move (b 1) (Just (c 1)) Nothing])
          (admitted 0)
      ]
  ]

-- | Two successors of the genesis, as in @h-two-successors-when-replicas-meet@:
-- c1 installs authority 1 and c2 is made under it; c3 cites authority 2.
twoSuccessors :: Store
twoSuccessors =
  store
    [genesis [], successor 0 2 [(0, Owner)] [0], successor 0 2 [(0, Owner), (1, Contributor)] [0]]
    [commit [] 0 0, installing 1 (commit [0] 0 0), commit [1] 1 0, commit [0] 2 0]
    []

replicationCases :: [Case]
replicationCases =
  [ replication
      "r-history-by-a-since-revoked-author"
      "R.3, and the document's test. The source's current authority, 1, has removed k1. \
      \k1's commit c2, made beside the revoking commit c1, is received all the same."
      (store [withK1, withoutK1] [commit [] 0 1, installing 1 (commit [0] 0 0), commit [0] 0 1] [])
      [alike 0 1 [c 1, c 2] (recorded [c 0, c 1, c 2])]
  , replication
      "r-only-what-was-asked-for"
      "A transfer is of the roots asked for, not of everything the source has. c0 and c1 \
      \are two unrelated roots, each with a commit on it. Asking for the branch at c2 \
      \records c0 and c2 and nothing of the other; asking for both records all four."
      (store [genesis []] [commit [] 0 0, commit [] 0 0, commit [0] 0 0, commit [1] 0 0] [])
      [ alike 0 0 [c 2] (recorded [c 0, c 2])
      , alike 0 0 [c 2, c 3] (recorded [c 0, c 1, c 2, c 3])
      ]
  , replication
      "r-expecting-another-repository"
      "R.1: a chain that ends at a different genesis is a different repository. Authority 1 \
      \is another repository's genesis, and c1 is valid history of it. A receiver expecting \
      \this repository refuses it; a receiver expecting that one records it. The genesis \
      \is what the receiver expects, whatever the source holds."
      (store [genesis [], genesis []] [commit [] 0 0, commit [] 1 0] [])
      [ alike 0 1 [c 1] ReceiveRefused
      , alike 1 1 [c 1] (recorded [c 1])
      , alike 0 0 [c 0] (recorded [c 0])
      ]
  , replication
      "r-invalid-history-refuses-the-whole-transfer"
      "R.1. c1 carries a signature that does not verify. A transfer that reaches it is \
      \refused whole, the valid c0 included; a transfer of c2, which does not reach it, is \
      \recorded."
      (store [genesis []] [commit [] 0 0, (commit [0] 0 0) {cSig = Sig (Key 0) False}, commit [0] 0 0] [])
      [ alike 0 0 [c 1, c 2] ReceiveRefused
      , alike 0 0 [c 2] (recorded [c 0, c 2])
      ]
  ]

divergentReplicationCases :: [Case]
divergentReplicationCases =
  [ replication
      "div-g-a-source-that-is-not-the-repository-expected"
      "Divergence (g). The receiver expects the repository of genesis 0. A source whose \
      \current authority is 1, another repository's genesis, is asked for nothing: no \
      \commit is received, so read literally none fails and nothing is recorded. A source \
      \whose current authority is 2, which only k1 signed and so succeeds nothing, is asked \
      \for the valid c0: read literally it is recorded. The Rust looks at the source's \
      \current authority before anything it sent and refuses both. Asked for nothing by a \
      \receiver expecting the repository it is, a source is recorded as nothing under \
      \either reading."
      notThisRepository
      [ (0, 1, [], recorded [], ReceiveRefused)
      , (0, 2, [c 0], recorded [c 0], ReceiveRefused)
      , alike 0 0 [] (recorded [])
      , alike 1 1 [] (recorded [])
      ]
  , replication
      "div-f-receiving-history-on-a-conflicting-lineage"
      "Divergence (f). The source's current authority is 1, and its branches hold c2, made \
      \under it, and c3, which cites authority 2, another successor of the genesis. Every \
      \commit passes Rule H, so read literally all four are received, and D2 has the \
      \disagreement reported, not refused. The Rust's receive refuses a transfer with \
      \anything on a conflicting lineage. Without c3 the readings agree."
      twoSuccessors
      [ (0, 1, [c 2, c 3], recorded [c 0, c 1, c 2, c 3], ReceiveRefused)
      , alike 0 1 [c 2] (recorded [c 0, c 1, c 2])
      ]
  ]
