# Historical benchmark qualification (Issue #3)

`benchmark_results.json` is preserved byte-for-byte as a historical artifact.
Its Isolation Forest row is invalid: the benchmark standardized the test vectors
with the supervised training scaler, then `infer_network` applied the saved
baseline scaler a second time. Reconstructing that path exactly reproduced the
historical 84.4726% accuracy and zero recall. Correct raw-input evaluation has
different measured results in `test-results/issue-3/evaluation.json`.

The supervised estimator benchmarks used their default 0.5 binary threshold.
The production XGBoost bundle uses the validation-selected 0.4343418846451664
threshold; its metrics must be reported separately. Experimental estimators were
saved without their scaler/provenance bundle. The reproduced comparison uses the
production scaler, independently verified against the same training population.

Do not call these results leakage-free or external validation. The raw float64
group split has no cross-partition exact-vector overlaps, but normalized/model
float32 vectors do have overlaps. The exploratory benchmark compared multiple
candidates on the final test partition, so test-informed model selection cannot
be excluded. Web Attack class performance must be reported alongside averages.
See the Issue #3 report, split audit and overlap sensitivity results.
