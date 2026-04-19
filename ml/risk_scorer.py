import numpy as np
import pandas as pd
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

RULES = {
    'network': {
        'high_packet_rate':    {'weight': 0.8, 'label': 'High Packet Rate'},
        'long_flow_duration':  {'weight': 0.6, 'label': 'Long Flow Duration'},
        'large_byte_transfer': {'weight': 0.7, 'label': 'Large Byte Transfer'},
        'low_packet_size':     {'weight': 0.4, 'label': 'Low Packet Size'},
    },
    'system_log': {
        'high_failed_logins':  {'weight': 0.9, 'label': 'High Failed Logins'},
        'odd_login_hour':      {'weight': 0.6, 'label': 'Odd Hour Login'},
        'privilege_escalation':{'weight': 1.0, 'label': 'Privilege Escalation'},
    },
    'file': {
        'executable_in_temp':  {'weight': 0.8, 'label': 'Executable in Temp'},
        'large_file_created':  {'weight': 0.5, 'label': 'Large File Created'},
        'hidden_file':         {'weight': 0.7, 'label': 'Hidden File Detected'},
    },
    'registry': {
        'autorun_entry':       {'weight': 0.9, 'label': 'Autorun Entry Added'},
        'suspicious_key':      {'weight': 0.8, 'label': 'Suspicious Registry Key'},
    }
}

class RiskScorer:

    def detect_artifact_type(self, row):
        def has_value(col):
            value = row.get(col)
            if isinstance(value, str):
                return value.strip() != ''
            return pd.notna(value) if value is not None else False

        explicit = row.get('artifact_type')
        if isinstance(explicit, str) and explicit.strip().lower() in RULES:
            return explicit.strip().lower()

        if any(has_value(c) for c in ('Flow Duration','Flow Packets/s','Flow Bytes/s','Packet Length Mean')):
            return 'network'
        elif any(has_value(c) for c in ('EventID','LogonType')):
            return 'system_log'
        elif any(has_value(c) for c in ('FileName','FileExtension')):
            return 'file'
        elif any(has_value(c) for c in ('RegistryKey','RegistryValue')):
            return 'registry'
        else:
            return 'network'

    def apply_rules(self, row, artifact_type='network'):
        rule_score = 0.0
        matched_rules = []

        try:
            if artifact_type == 'network':
                if row.get('Flow Packets/s', 0) > 10000:
                    rule_score += RULES['network']['high_packet_rate']['weight']
                    matched_rules.append(RULES['network']['high_packet_rate']['label'])
                if row.get('Flow Duration', 0) > 100000000:
                    rule_score += RULES['network']['long_flow_duration']['weight']
                    matched_rules.append(RULES['network']['long_flow_duration']['label'])
                if row.get('Flow Bytes/s', 0) > 1000000:
                    rule_score += RULES['network']['large_byte_transfer']['weight']
                    matched_rules.append(RULES['network']['large_byte_transfer']['label'])
                if row.get('Packet Length Mean', 0) < 10:
                    rule_score += RULES['network']['low_packet_size']['weight']
                    matched_rules.append(RULES['network']['low_packet_size']['label'])

            elif artifact_type == 'system_log':
                if row.get('FailedLogins', 0) > 5:
                    rule_score += RULES['system_log']['high_failed_logins']['weight']
                    matched_rules.append(RULES['system_log']['high_failed_logins']['label'])
                if row.get('LoginHour', 12) < 6 or row.get('LoginHour', 12) > 22:
                    rule_score += RULES['system_log']['odd_login_hour']['weight']
                    matched_rules.append(RULES['system_log']['odd_login_hour']['label'])
                if row.get('PrivilegeLevel', '') == 'SYSTEM':
                    rule_score += RULES['system_log']['privilege_escalation']['weight']
                    matched_rules.append(RULES['system_log']['privilege_escalation']['label'])

            elif artifact_type == 'file':
                path = str(row.get('FilePath', ''))
                if 'temp' in path.lower() and path.endswith('.exe'):
                    rule_score += RULES['file']['executable_in_temp']['weight']
                    matched_rules.append(RULES['file']['executable_in_temp']['label'])
                if row.get('FileSizeBytes', 0) > 100000000:
                    rule_score += RULES['file']['large_file_created']['weight']
                    matched_rules.append(RULES['file']['large_file_created']['label'])
                if str(row.get('FileName', '')).startswith('.'):
                    rule_score += RULES['file']['hidden_file']['weight']
                    matched_rules.append(RULES['file']['hidden_file']['label'])

            elif artifact_type == 'registry':
                key = str(row.get('RegistryKey', ''))
                if 'autorun' in key.lower() or 'run' in key.lower():
                    rule_score += RULES['registry']['autorun_entry']['weight']
                    matched_rules.append(RULES['registry']['autorun_entry']['label'])
                if any(s in key.lower() for s in ('cmd','powershell','wscript','temp')):
                    rule_score += RULES['registry']['suspicious_key']['weight']
                    matched_rules.append(RULES['registry']['suspicious_key']['label'])

        except (KeyError, TypeError) as e:
            logger.warning(f"Rule evaluation error at row: {e}")

        rule_score = min(rule_score, 1.0)
        return rule_score, matched_rules

    def get_anomaly_score_normalized(self, raw_score):
        normalized = 1 / (1 + np.exp(raw_score * 10))
        return normalized * 100

    def compute_risk_score(self, anomaly_score, rule_score):
        risk = (anomaly_score * 0.6) + (rule_score * 100 * 0.4)
        return round(min(risk, 100), 2)

    def assign_priority(self, risk_score):
        if risk_score >= 75:
            return 'CRITICAL'
        elif risk_score >= 50:
            return 'HIGH'
        elif risk_score >= 25:
            return 'MEDIUM'
        else:
            return 'LOW'

    def score_dataframe(self, df_clean, anomaly_scores):
        print("[+] Scoring artifacts...")
        total_records = len(df_clean)
        columns = list(df_clean.columns)

        record_ids = np.arange(total_records, dtype=np.int64)
        artifact_types = [None] * total_records
        anomaly_score_values = np.empty(total_records, dtype=np.float64)
        rule_score_values = np.empty(total_records, dtype=np.float64)
        risk_score_values = np.empty(total_records, dtype=np.float64)
        priorities = [None] * total_records
        matched_rules_list = [None] * total_records

        for i, row_values in enumerate(df_clean.itertuples(index=False, name=None)):
            row_dict = dict(zip(columns, row_values))
            artifact_type = self.detect_artifact_type(row_dict)
            a_score = self.get_anomaly_score_normalized(anomaly_scores[i])
            r_score, rules = self.apply_rules(row_dict, artifact_type)
            risk = self.compute_risk_score(a_score, r_score)

            artifact_types[i] = artifact_type
            anomaly_score_values[i] = round(a_score, 2)
            rule_score_values[i] = round(r_score * 100, 2)
            risk_score_values[i] = risk
            priorities[i] = self.assign_priority(risk)
            matched_rules_list[i] = ', '.join(rules) if rules else 'None'

            if i % 100000 == 0:
                print(f"[+] Processed {i}/{total_records} records...")

        df_results = pd.DataFrame({
            'record_id': record_ids,
            'artifact_type': artifact_types,
            'anomaly_score': anomaly_score_values,
            'rule_score': rule_score_values,
            'risk_score': risk_score_values,
            'priority': priorities,
            'matched_rules': matched_rules_list
        })

        df_results = df_results.sort_values('risk_score', ascending=False)
        print("[+] Scoring complete")
        return df_results