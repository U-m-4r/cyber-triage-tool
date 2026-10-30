"""Post-test explanatory audit; never changes selected model or operating point."""
import json
from pathlib import Path
import numpy as np
import pandas as pd
from ml.external_dataset_adapter import adapt_frame
from ml.network_experiment import fingerprints, validate_features, write_once, repo_path
from scripts.prepare_issue6 import external_chunks


def main():
    out=Path('test-results/issue-6');work=Path('.test-artifacts/issue6')
    final=np.load(work/'challenger-final.npz',allow_pickle=False)
    lock=json.loads((out/'locked-test.json').read_text())
    records=[];label_checks=[];rate_checks={};offset=0
    for day,source in enumerate(lock['sources']):
        aligned_rows=final['source_row'][final['day']==day]
        position=0;rates={'zero_duration':0}
        # Raw features only; labels come from the sealed final prediction archive.
        for chunk in external_chunks(repo_path(source['path']),labels=False):
            x,*_=adapt_frame(chunk);x=x.loc[(x.to_numpy()<=np.finfo(np.float32).max).all(axis=1)]
            n=len(x)
            np.testing.assert_array_equal(x.index.to_numpy(),aligned_rows[position:position+n])
            y=final['truth'][offset:offset+n]
            records.append(pd.DataFrame({'vector':fingerprints(validate_features(x)),'label':y}))
            position+=n;offset+=n
            rates['zero_duration']+=int((x['Flow Duration']==0).sum())
        rate_checks[source['filename']]=rates
        label_checks.append({'source':source['filename'],'exact_archive_row_alignment':True,'eligible_rows':position})
    combined=pd.concat(records,ignore_index=True);groups=combined.groupby('vector')['label'].agg(['size','sum'])
    conflict=(groups['sum']>0)&(groups['sum']<groups['size'])
    minority=np.minimum(groups['sum'],groups['size']-groups['sum'])
    result={'scope':'Post-test diagnostic; exact float32 candidate input vectors; not used to modify model, threshold or test population',
        'rows':len(combined),'unique_vectors':len(groups),'conflicting_binary_groups':int(conflict.sum()),
        'rows_in_conflicting_groups':int(groups.loc[conflict,'size'].sum()),
        'minimum_errors_for_any_deterministic_classifier_on_these_vectors':int(minority.sum()),
        'minimum_error_rate_from_observed_label_ambiguity':float(minority.sum()/len(combined)),
        'explanation':'Identical eleven-feature vectors carry both publisher labels. A deterministic classifier using only these inputs cannot classify every such record correctly. Could reflect information loss, label errors, or dataset construction; this audit does not establish which.',
        'source_alignment':label_checks,'zero_duration_counts':rate_checks,
        'no_post_test_tuning':True}
    write_once(out/'feature-ambiguity.json',result)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
