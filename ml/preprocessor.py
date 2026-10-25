import pandas as pd
import numpy as np
import csv
from sklearn.preprocessing import StandardScaler

# Versioned production schema. The older generic helpers below remain available
# for offline experiments; production inference never calls their fit methods.
NETWORK_FEATURES = (
    'Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Flow Bytes/s',
    'Flow Packets/s', 'Packet Length Mean',
)


class NetworkInputError(ValueError):
    def __init__(self, message, code='INVALID_NETWORK_DATA'):
        super().__init__(message)
        self.code = code


def read_network_csv(path, usecols=None, **read_options):
    """Reject ambiguous headers before pandas can rename duplicate columns."""
    try:
        with open(path, newline='', encoding='utf-8-sig') as handle:
            header = next(csv.reader(handle), [])
        stripped = [column.strip() for column in header]
        if not stripped or len(stripped) != len(set(stripped)):
            raise NetworkInputError('CSV requires a nonempty, unique column header.')
        frame = pd.read_csv(path, usecols=usecols, **read_options)
        frame.columns = frame.columns.str.strip()
        return frame
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeError) as exc:
        raise NetworkInputError(f'Cannot read network CSV: {exc}') from exc


def validate_network_frame(frame, features=NETWORK_FEATURES):
    """Report data quality without replacing values, dropping rows, or fitting.

    Missing cells are nulls or blank/whitespace-only values in any column.
    Numeric checks cover required features only. Explicit NaN tokens are counted
    separately from missing and nonnumeric cells; negative infinity is counted
    as infinity, not a finite negative measurement. Duplicate counts use all
    parsed columns before numeric conversion, counting copies beyond the first.
    Row categories can overlap; their union and pairwise overlaps are reported.
    """
    frame = frame.copy(deep=False)
    frame.columns = [str(column).strip() for column in frame.columns]
    if frame.columns.duplicated().any():
        raise NetworkInputError('Duplicate column names after whitespace removal.')
    missing_columns = [column for column in features if column not in frame.columns]
    if missing_columns:
        raise NetworkInputError('Missing required network features: ' + ', '.join(missing_columns),
                                'MISSING_FEATURES')

    names = ('missing_values', 'non_numeric_values', 'nan_values',
             'infinite_values', 'negative_measurements')
    rows = {name: np.zeros(len(frame), dtype=bool) for name in names}
    issues = {name: {'rows': 0, 'cells': 0, 'columns': {}} for name in names}

    def record(name, column, mask):
        mask = np.asarray(mask, dtype=bool)
        count = int(mask.sum())
        if count:
            issues[name]['columns'][column] = count
            issues[name]['cells'] += count
            rows[name] |= mask

    for column in frame.columns:
        original = frame[column]
        text = original.astype('string').str.strip()
        missing = original.isna() | text.eq('').fillna(False)
        record('missing_values', column, missing)
        if column not in features:
            continue
        nan = text.str.lower().isin(('nan', '+nan', '-nan')) & ~missing
        numeric = pd.to_numeric(original, errors='coerce').to_numpy(dtype=float, na_value=np.nan)
        record('nan_values', column, nan)
        record('non_numeric_values', column, np.isnan(numeric) & ~missing & ~nan)
        record('infinite_values', column, np.isinf(numeric))
        record('negative_measurements', column, np.isfinite(numeric) & (numeric < 0))

    for name in names:
        issues[name]['rows'] = int(rows[name].sum())
    rows['duplicate_rows'] = frame.duplicated().to_numpy()
    issues['duplicate_rows'] = {
        'rows': int(rows['duplicate_rows'].sum()),
        'rows_in_duplicate_groups': int(frame.duplicated(keep=False).sum()),
        'comparison': 'all parsed columns before numeric conversion; copies beyond first',
    }
    issue_count = np.stack(list(rows.values())).sum(axis=0)
    pairs = {}
    categories = list(rows)
    for index, left in enumerate(categories):
        for right in categories[index + 1:]:
            count = int((rows[left] & rows[right]).sum())
            if count:
                pairs[f'{left} & {right}'] = count
    affected = int((issue_count > 0).sum())
    return {
        'status': 'empty_dataset' if frame.empty else ('issues_found' if affected else 'valid'),
        'input_rows': len(frame), 'column_count': len(frame.columns),
        'required_feature_columns': list(features),
        'numeric_checks_scope': 'required feature columns; missing values checked in all columns',
        'rows_with_issues': affected, 'rows_without_detected_issues': len(frame) - affected,
        'issues': issues,
        'overlapping_issues': {'rows_with_multiple_issues': int((issue_count > 1).sum()),
                               'pairs': pairs},
        'rows_removed': 0, 'values_replaced': 0,
    }


def prepare_network_frame(frame, features=NETWORK_FEATURES):
    """Validate all required features, preserving row identity and duplicates.

    Drop only rows with invalid required numeric values; optional metadata and
    labels do not participate in inference cleaning. No scaler is fitted here.
    """
    frame = frame.copy()
    frame.columns = [str(column).strip() for column in frame.columns]
    if frame.columns.duplicated().any():
        raise NetworkInputError('Duplicate column names after whitespace removal.')
    missing = [column for column in features if column not in frame.columns]
    if missing:
        raise NetworkInputError('Missing required network features: ' + ', '.join(missing),
                                'MISSING_FEATURES')
    if 'artifact_type' in frame.columns:
        types = frame['artifact_type'].fillna('').astype(str).str.strip().str.lower()
        if not types.eq('network').all():
            raise NetworkInputError('Network inference accepts only network artifacts.',
                                    'WRONG_ARTIFACT_TYPE')
    numeric = frame.loc[:, list(features)].apply(pd.to_numeric, errors='coerce')
    valid = np.isfinite(numeric.to_numpy(dtype=float)).all(axis=1)
    clean = frame.loc[valid].copy()
    numeric = numeric.loc[valid].astype(float)
    if clean.empty:
        raise NetworkInputError('No valid network rows remain after numeric validation.',
                                'EMPTY_NETWORK_DATA')
    for column in features:
        clean[column] = numeric[column]
    report = {'input_rows': len(frame), 'valid_rows': len(clean),
              'dropped_invalid_rows': int((~valid).sum()),
              'duplicates_preserved': True}
    return clean, numeric, report


class ForensicPreprocessor:

    def __init__(self):
        # Z-score standardization: z = (x - mu) / sigma.
        # Chosen over min-max because forensic flow features are heavy-tailed and
        # contain extreme outliers (the very anomalies we want to preserve); z-score
        # keeps outlier separation instead of compressing it into [0, 1].
        # Ref: Han, Kamber & Pei, "Data Mining: Concepts and Techniques" (3rd ed.),
        #      §3.5 Data Transformation (z-score normalization); and
        #      sklearn.preprocessing.StandardScaler.
        self.scaler = StandardScaler()
    
    def load_data(self, filepath):
        print("[+] Loading data...")
        df = pd.read_csv(filepath)
        df.columns = df.columns.str.strip()
        print(f"[+] Loaded {len(df)} records, {len(df.columns)} columns")
        return df
    
    def clean_data(self, df):
        print("[+] Cleaning data...")
        before = len(df)
        # Rows with NaN or +/-inf (e.g. divide-by-zero packet-rate artifacts) are
        # dropped rather than imputed: for unsupervised anomaly detection we prefer
        # to discard corrupted records than to fabricate median values that could
        # mask or manufacture anomalies.
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.dropna()
        df = df.drop_duplicates()
        after = len(df)
        print(f"[+] Removed {before - after} bad rows")
        print(f"[+] Clean records: {after}")
        return df
    
    def extract_features(self, df):
        print("[+] Extracting features...")
        features = NETWORK_FEATURES
        available = [f for f in features if f in df.columns]
        missing = [f for f in features if f not in df.columns]
        if missing:
            print(f"[!] Missing features: {missing}")
        print(f"[+] Using {len(available)} features")
        return df[available]
    
    def scale_features(self, df):
        print("[+] Scaling features...")
        # StandardScaler applies z = (x - mu) / sigma per column (mean 0, unit variance).
        # See __init__ for rationale / references (Han, Kamber & Pei §3.5).
        scaled = self.scaler.fit_transform(df)
        df_scaled = pd.DataFrame(scaled, columns=df.columns)
        print("[+] Scaling complete")
        return df_scaled
    
    def run_pipeline(self, filepath):
        print("\n=== Starting Preprocessing Pipeline ===")
        df_raw = self.load_data(filepath)          # truly raw, unmodified
        df_clean = self.clean_data(df_raw)         # cleaned version
        df_features = self.extract_features(df_clean)
        df_scaled = self.scale_features(df_features)
        print(f"\n=== Pipeline Complete | Output shape: {df_scaled.shape} ===")
        return df_scaled, df_raw, df_clean         # return all three clearly
