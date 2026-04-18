import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

class ForensicPreprocessor:
    
    def __init__(self):
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
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.dropna()
        df = df.drop_duplicates()
        after = len(df)
        print(f"[+] Removed {before - after} bad rows")
        print(f"[+] Clean records: {after}")
        return df
    
    def extract_features(self, df):
        print("[+] Extracting features...")
        features = [
            'Flow Duration',
            'Total Fwd Packets',
            'Total Length of Fwd Packets',
            'Fwd Packet Length Max',
            'Fwd Packet Length Min',
            'Fwd Packet Length Mean',
            'Bwd Packet Length Max',
            'Bwd Packet Length Min',
            'Flow Bytes/s',
            'Flow Packets/s',
            'Packet Length Mean'
        ]
        available = [f for f in features if f in df.columns]
        missing = [f for f in features if f not in df.columns]
        if missing:
            print(f"[!] Missing features: {missing}")
        print(f"[+] Using {len(available)} features")
        return df[available]
    
    def scale_features(self, df):
        print("[+] Scaling features...")
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
