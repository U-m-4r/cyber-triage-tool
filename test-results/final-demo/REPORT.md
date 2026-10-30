# Final system integration — local presentation environment

**PASS for isolated demonstration preparation, validated evaluation dashboard, API/database/reporting verification and the observed browser smoke workflow. No commits, pushes, PRs, tags, releases, merges, resets, stashes or cleans.**

## Start and reopen saved work

Frontend: http://127.0.0.1:5259 . Backend: http://127.0.0.1:5109 . Owned MongoDB on127.0.0.1:27018; database`cyber_triage_test_f81c246a5f5c413aa1c951c45cd24423`. Development sign-in accepts an investigator display label. No authentication bypass was added; existing test configuration remains loopback-only.
Two running terminals are enough after the dedicated MongoDB service is up:
```powershell
rtk proxy .venv/Scripts/python.exe -m scripts.serve_final_demo
# Second terminal:
$env:BACKEND_PROXY_TARGET='http://127.0.0.1:5109'
rtk proxy npm --prefix frontend run dev -- --host 127.0.0.1 --port 5259 --strictPort
```
Serving reads existing savedcases and never retrains/reprocesses them. Runtime prerequisites: existing native Pythonenvironment; downloaded frozen network/PE artifacts; pytsk3,yara,pefile,signify,libewf-python,python-evtx,python-registry,packetparser,pymongo,reportlab,pypdf/PyMuPDF; installed frontendnode modules and localMongoDB. Health/model checks and testlogs document actual availability. No furtherdataset/modeldownload is needed for the live demo.

## Cases and measured results

| Case | ID | Stored records | Scan status |
|---|---|---:|---|
| disk | CASE-E855F07F91D5 | 6 | COMPLETED |
| ntfs | CASE-56540E3BFE9B | 19 | COMPLETED |
| file-inventory | CASE-53730B2651F2 | 2 | COMPLETED |
| partial | CASE-0DAA7F525B35 | 1 | PARTIAL |
| unavailable | CASE-9E450E7C0284 | 2 | PARTIAL |
| standalone-pe | CASE-30E18A99BCF7 | 1 | COMPLETED |
| cicids2017-xgb | CASE-F0A7D56A1116 | 84 | COMPLETED |
| cicids2017-iforest | CASE-1F8449428D92 | 84 | COMPLETED |
| external-csv | CASE-6E87BD593EAA | 60 | COMPLETED |
| native-evtx | CASE-6EC4EC7FD19D | 1601 | COMPLETED |
| native-registry | CASE-F479FBF39DF4 | 2000 | PARTIAL |
| event-export | CASE-5E161F49F3C1 | 2 | COMPLETED |
| registry-export | CASE-E8634644A6D7 | 2 | COMPLETED |
| pcap | CASE-FC0E8BDD23D9 | 1 | COMPLETED |
| ntfs-final | CASE-E042AF39B2C3 | 19 | COMPLETED |
| local-ewf | CASE-639E1724B463 | 19 | COMPLETED |

Use **ntfs-final CASE-E042AF39B2C3** for the presentation. The initial NTFS case used the FAT12marker ruleset; its harmlessPEheader rule still matched, but its differently worded text marker did not. That truthful initial execution is preserved; a newcase with the exact reviewed NTFS marker rule supplies the intended positive-file demonstration. The metadata stream/$MFT also matches resident marker bytes and is separately labeled. Allmarker/header rules are test-only indicators, not malwaregroundtruth.
All14initialHTTPcases, plus localEWF and finalNTFS, contain genuine analysis. NativeEVTX1601records and nativeRegistry2000storedrecords are actual execution counts; nativeRegistry coverage is partial under its cap. EWFcase uses complete existingsegmentset with genuine analyzer→scorer→persist_intake, not browserupload. EWFsegment andlogicalhash verification remains in Issue8. Original cases in other databases are untouched.
Unsupported bytes returned HTTP400/INVALID_INPUT; no fabricated findings or successful evidence case is created for rejected input. The response is preserved in the case manifest. File-inventory and negative NTFS files show no YARA match; partial/unavailable cases preserve scanner absence/limits rather than saying clean. PCAP contains one valid offline Ethernet/IPv4/UDP packet never transmitted; nativeparser ran. Its MLmodule is NOT_APPLICABLE because the CICIDSflow contract is unverified.

## Labeled live network subsets (not full evaluation)

Fullgroundtruth was joined by source row only, never modelscore.2017fixed84row subset:12benign72attacks. XGBoostTP55,TN12,FP0,FN17; IsolationForestTP10,TN6,FP6,FN62. External60row subset:20benign40attacks; XGBoostTP2,TN19,FP1,FN38. These small source-order/family-selected demos are not randompopulation or fullbenchmark estimates. live-labeled-network.json is authoritative. Initial IF summarymistakenly compared anomaly/normal prediction strings toATTACK; it is retained as initial-invalid evidence. Corrected summary uses the explicit binary_prediction field; no inference/modelchanged.

## Model Evaluation & Experimental Results

New `/evaluations`Reactpage and `/api/evaluations`read-onlyAPI load the actual versioned artifacts. FixedsourceIDs/paths, <=5MiB reads, SHA256pins, finiteJSON/metric checks and confusion/class-count arithmetic prevent arbitraryfilesystemaccess/defaultpercentages. Unknown IDs404; missing/corrupt source shows VERIFICATION DATA UNAVAILABLE. SourceJSON and provenance are inspectable through allowlisted endpoints. No rawmillionsofrows are sent to the browser.
Displayed evaluations: productionXGBoost andIFinternalCICIDS2017; frozenexternalCSE2018; Issue6Bincumbent/rejectedchallenger; EMBERordinaryuniqueidentities withWin32/64; positive-onlyevasivechallenge. Counts,thresholds,modelIDs,modelSHA,featureschema,script andsourcechecksum are retained. Dates without trustworthy savedtimestamp remain explicitly undocumented rather than inferred fromfilemtime. SourceJSON carries originalmetadata. Researchcandidateis NOTDEPLOYED. Groundtruthcounts remain separate fromlivefindings; modelscore/risk/accuracy remain distinct.
Actual ordinaryPEmetrics:479987unique files,239987benign240000malicious;accuracy98.1239%,precision98.7037%,recall97.5288%,F1.981127,FPR1.2809%. Challenge2730/4039recall67.591%; unsupportednegative-derivedmetrics omitted.2MiBinputlimit andfeaturebenchmark-vs-livecoverage caveats visible. InternalXGBoost99.7681%accuracy does not hide external0.0133%recall. No historicalmetricfilesor modelthresholds changed.
Presentationgraphs: internal-external-comparison.png; internal/external/research/pe-confusion.png; attack-familyfigures; backupcontains originalPEfigures including ordinary-vs-evasivecomparison. Labels identify populations/frozenconditions; crossdatasetcomparison is explicitly uncontrolled. Browsermetercharts and confusiontables are driven by the samevalidatedAPI.

## Genuine workflow verification

Allcases were reopened throughAPI; saved screening equals intake output and MongoDB ingestionhistory. Artifact/evidencehashes and storedcounts verified.16PDFs contain actualsavedresults;209pages rendered,zerooff-page-textblocks. OfflinePDFs and perreportSHA are listed in pdf-verification.json. Samplepages/browserdownload inspected; not every209page visually inspected. Caseworkflowstatus INGESTING is the existing investigator lifecycle, distinct frompersistedscancompletion.
Approvedbrowseraccessnowworks. Actualsign-in,case-list,evaluationpage,NTFSmarkerfilter,PEscore,refresh/reopen,networkmodeldisplay,partialcoverageexpansionand PDFgenerated/downloadedsuccess were observed. GenuinePNGfiles are in thisdirectory and backedup. No claimofbrowseruploadtesting foreveryevidencetype,allviewports,orsegmentedE01upload. browser-acceptance.md is the exactobserved/manualchecklist.

## Reproduction and execution evidence

Commands actually executed:
```powershell
rtk proxy .venv/Scripts/python.exe -m scripts.prepare_final_demo
rtk proxy .venv/Scripts/python.exe -m scripts.add_ewf_demo_case
rtk proxy .venv/Scripts/python.exe -m scripts.package_final_demo
rtk proxy .venv/Scripts/python.exe -m pytest -q --no-training --run-integration
rtk proxy npm --prefix frontend run check
rtk proxy .venv/Scripts/python.exe scripts/check.py
```
prepare_final_demo creates freshUUIDcases/database and updates onlyfinal-demo/latest.json; never seeding fabricatedfindings. Initialsetup hung duringScapyinterfaceinitialization beforeingestion; isolatedprocess stopped,partialfixtures/logpreserved. Retry uses a realvalidcontrolledofflinePCAP. PDF/API/fixturedata remainignored. FinaladditionalNTFS case and snapshot are preserved in ntfs-final.json; exactsourcehashes/scannerstatus/coverage/model/risk/timing/backupPDFpaths in case-manifest.json.

## Live sequence and backup

OpenCases→NTFSfinal→positive.txtYARA→launcher.binPE→negative.txt→2017XGBoostcase→externalcaseandlimitations→/evaluations→researchrejection→PEordinary/challenge→partialcase→generatePDF. E01canbeopened as savedlocalanalysis, with scopeexplained. Moststeps reuse MongoDBwithoutinference. Acomplete timed narratedrehearsal was notperformed; no invented duration estimate. RecordedHTTPprocessingtimes in casemanifest measure actual execution, not spokenpresentationduration.
Backup/ is ignored and explicitly labeled PREVIOUSLY CAPTURED GENUINE EXECUTION EVIDENCE, not aliveapp. It contains16PDFs,savedJSON,realbrowserPNGandPEgraphs. Nativefixtures/reportshave historicalhostrecords; inspectbeforepublishing. Originalprivate dfr-01-ntfs.dd/ remainsuntouched.

## Final tests, limitations and delivery

Finalbackend:423passed46skipped,zero failures/errors (regression-complete.txt). Frontend19passed andbuildPASS (frontend-complete.txt). ActualReactevaluationrenderpassed on savedAPIcounts. Static/config checksPASS. Training-onlyregressionfixturesremain skipped by --no-training; absentconfiguredprimaryimage skips do not negate separatelyexecutedNTFS/EWFtests.
Knownlimits: nosegmentedbrowserupload; nativeRegistryenumerationpartial; metadata-onlyinventorydoesnotreadsourcefilebytes; PCAPMLnotapplicable; PE2MiB/native-formatlimits; not allUIinteractions crossbrowserverified; nofulltimedrehearsal; localdevelopmentservernotproductionhosting. Historicalresearch retainsdocumentedfailures. No dependency/modeltraining/thresholdchanges performed duringfinalintegration.
All worklocal. FinalverificationJSONandFILE_MANIFEST.json recordcurrentGitstate,changedfiles,ignoredrequirements,sourcehashes and preservationchecks. NoIssue9orotherdevelopmentstarted.

Measured navigation smoke:2026-10-30 18:34:59–18:35:11UTC,12seconds across dashboard,NTFS,network,evaluations,partialcase and back. This is automated navigation with saveddata, not a narrated presentation-duration estimate. A full spoken rehearsal remains manual.


## Continued verification and provenance corrections

The final audit corrected two source references: the full internal evaluation was produced by scripts/verify_network_models.py (not the demo verifier); the external evaluator is scripts/evaluate_external_network.py. The initial presentation manifest is preserved as presentation-manifest-initial.json. All historical metric files are unchanged.

Supporting split, dataset, test-lock and evaluation-receipt documents are now independently checksum-verified before display. Their allowlisted endpoints use the normal API authentication. React source inspection uses the existing authenticated client rather than a new-tab URL that loses bearer headers. Actual evaluation start timestamps are displayed only where recorded in receipts, with the local-timestamp limitation. Missing dates remain explicit. Model SHA-256 and feature contracts are expandable. Source reads stop at 5MiB plus one byte before parsing or hashing; oversize/corrupt/missing supporting data marks only affected evaluations unavailable.

Current full tests: **426 passed,46skipped,zero failures/errors**; frontend **19passed**, production build PASS; static/configuration checks PASS. API checks opened every supporting source, verified token-required behavior in an isolated app, and reopened all16saved cases without inference. Actual React component rendering of current saved results passed. Models and all109checkpointed historical files remain unchanged.

Current browser continuation could not reconnect: `browser.user is unavailable`. One inventory/reconnection check confirmed the existing tab but failed access. No bypass or repeated attempts. Earlier screenshots and observed interactive acceptance remain genuine; new provenance controls have API/component verification, not fresh browser acceptance. A full timed narrated rehearsal remains manual. Serving remains available at localhost5259/5109; no Git mutation or remote publication occurred.
