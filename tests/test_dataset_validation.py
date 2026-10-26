"""Report-only dataset checks; model fitting and publication are forbidden."""
import json
from pathlib import Path
import sys

import numpy as np
import pandas as pd
import pytest

from ml.preprocessor import NETWORK_FEATURES, NetworkInputError, validate_network_frame
from scripts import train_baseline as trainer


@pytest.fixture(autouse=True)
def forbid_training(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Validation attempted model fitting or publication')

    monkeypatch.setattr(trainer, 'train_baseline', forbidden)
    monkeypatch.setattr(trainer.IsolationForest, 'fit', forbidden)
    monkeypatch.setattr(trainer.StandardScaler, 'fit', forbidden)
    monkeypatch.setattr(trainer.StandardScaler, 'fit_transform', forbidden)
    monkeypatch.setattr(trainer.joblib, 'dump', forbidden)


def flow_frame(rows=3):
    return pd.DataFrame({column: [str(row + index + 1) for row in range(rows)]
                         for index, column in enumerate(NETWORK_FEATURES)})


def test_valid_csv_is_read_only(tiny_flow_csv):
    dataset = Path(tiny_flow_csv)
    before = dataset.read_bytes()
    report = trainer.validate_dataset(dataset)
    assert report['status'] == 'valid'
    assert report['input_rows'] == report['rows_without_detected_issues'] == 5
    assert report['rows_with_issues'] == report['rows_removed'] == report['values_replaced'] == 0
    assert all(issue['rows'] == 0 for issue in report['issues'].values())
    assert dataset.read_bytes() == before


def test_numeric_strings_and_frame_are_unchanged():
    frame = flow_frame()
    frame['Flow Bytes/s'] = ['1.5', ' 2e3 ', '0']
    before = frame.copy(deep=True)
    report = validate_network_frame(frame)
    assert report['status'] == 'valid'
    pd.testing.assert_frame_equal(frame, before)


@pytest.mark.parametrize('value,category', [
    ('', 'missing_values'), ('   ', 'missing_values'),
    (np.nan, 'missing_values'), ('invalid', 'non_numeric_values'),
    ('NaN', 'nan_values'), ('+nan', 'nan_values'), ('-NaN', 'nan_values'),
    ('inf', 'infinite_values'), ('-inf', 'infinite_values'),
    ('-0.5', 'negative_measurements'),
])
def test_invalid_values_are_reported_without_replacement(value, category):
    frame = flow_frame()
    frame.loc[1, 'Flow Duration'] = value
    before = frame.copy(deep=True)
    report = validate_network_frame(frame)
    assert report['status'] == 'issues_found'
    assert report['rows_with_issues'] == 1
    assert report['issues'][category] == {'rows': 1, 'cells': 1, 'columns': {'Flow Duration': 1}}
    assert all(issue['rows'] == 0 for name, issue in report['issues'].items() if name != category)
    pd.testing.assert_frame_equal(frame, before)


def test_csv_preserves_nan_missing_and_bad_tokens(tmp_path):
    frame = flow_frame(4)
    frame['Flow Duration'] = ['', 'NaN', 'bad', '-inf']
    dataset = tmp_path / 'issues.csv'
    frame.to_csv(dataset, index=False)
    before = dataset.read_bytes()
    report = trainer.validate_dataset(dataset)
    for category in ('missing_values', 'nan_values', 'non_numeric_values', 'infinite_values'):
        assert report['issues'][category]['rows'] == 1
    assert report['rows_with_issues'] == 4
    assert report['overlapping_issues']['rows_with_multiple_issues'] == 0
    assert dataset.read_bytes() == before


def test_missing_values_include_optional_columns():
    frame = flow_frame()
    frame['Label'] = ['BENIGN', '', 'BENIGN']
    report = validate_network_frame(frame)
    assert report['issues']['missing_values']['columns'] == {'Label': 1}


@pytest.mark.parametrize('dtype', ['string', 'Float64'])
def test_nullable_numeric_columns(dtype):
    frame = flow_frame()
    frame['Flow Duration'] = pd.Series([1, None, 3], dtype=dtype)
    report = validate_network_frame(frame)
    assert report['issues']['missing_values']['columns'] == {'Flow Duration': 1}
    assert report['issues']['non_numeric_values']['rows'] == 0


def test_missing_required_columns():
    frame = flow_frame().drop(columns=['Flow Duration', 'Total Fwd Packets'])
    with pytest.raises(NetworkInputError, match='Flow Duration, Total Fwd Packets') as error:
        validate_network_frame(frame)
    assert error.value.code == 'MISSING_FEATURES'


def test_duplicate_rows_compare_all_columns():
    frame = flow_frame(2)
    frame['Label'] = 'BENIGN'
    other_label = frame.iloc[[0]].copy()
    other_label['Label'] = 'DDoS'
    frame = pd.concat([frame, frame.iloc[[0]], other_label], ignore_index=True)
    before = frame.copy(deep=True)
    report = validate_network_frame(frame)
    assert report['issues']['duplicate_rows']['rows'] == 1
    assert report['issues']['duplicate_rows']['rows_in_duplicate_groups'] == 2
    assert report['rows_with_issues'] == 1
    pd.testing.assert_frame_equal(frame, before)


def test_negative_measurements_in_all_required_columns():
    frame = flow_frame()
    frame.loc[0, :] = '-1'
    report = validate_network_frame(frame)
    issue = report['issues']['negative_measurements']
    assert issue['rows'] == 1
    assert issue['cells'] == len(NETWORK_FEATURES)
    assert issue['columns'] == {column: 1 for column in NETWORK_FEATURES}
    assert report['overlapping_issues']['rows_with_multiple_issues'] == 0


def test_overlapping_issues_are_not_double_counted():
    frame = flow_frame()
    frame.loc[0, 'Flow Duration'] = '-1'
    frame.loc[0, 'Flow Bytes/s'] = ''
    frame.loc[1, 'Flow Duration'] = '-2'
    frame.loc[1, 'Flow Bytes/s'] = 'bad'
    frame = pd.concat([frame, frame.iloc[[0]]], ignore_index=True)
    report = validate_network_frame(frame)
    assert report['input_rows'] == 4
    assert report['rows_with_issues'] == 3
    assert report['rows_without_detected_issues'] == 1
    assert report['overlapping_issues'] == {
        'rows_with_multiple_issues': 3,
        'pairs': {'missing_values & negative_measurements': 2,
                  'missing_values & duplicate_rows': 1,
                  'non_numeric_values & negative_measurements': 1,
                  'negative_measurements & duplicate_rows': 1},
    }


def test_missing_file_has_clear_error(tmp_path):
    with pytest.raises(NetworkInputError, match='Dataset file not found') as error:
        trainer.validate_dataset(tmp_path / 'absent.csv')
    assert error.value.code == 'DATASET_MISSING'


def test_unreadable_csv_has_clear_error(tiny_flow_csv, monkeypatch):
    def unreadable(*args, **kwargs):
        raise PermissionError('permission denied')

    monkeypatch.setattr(trainer, 'read_network_csv', unreadable)
    with pytest.raises(NetworkInputError, match='Cannot read dataset CSV.*permission denied') as error:
        trainer.validate_dataset(tiny_flow_csv)
    assert error.value.code == 'DATASET_UNREADABLE'


@pytest.mark.parametrize('content', [b'column\n"unterminated\n', b'column\n\xff\n'])
def test_malformed_or_non_utf8_csv(tmp_path, content):
    dataset = tmp_path / 'unreadable.csv'
    dataset.write_bytes(content)
    with pytest.raises(NetworkInputError, match='Cannot read network CSV'):
        trainer.validate_dataset(dataset)


def test_duplicate_column_headers_rejected(tmp_path):
    dataset = tmp_path / 'ambiguous.csv'
    dataset.write_text('Flow Duration, Flow Duration\n1,2\n', encoding='utf-8')
    with pytest.raises(NetworkInputError, match='unique'):
        trainer.validate_dataset(dataset)


def test_csv_extra_fields_are_not_silently_truncated(tmp_path):
    dataset = tmp_path / 'extra_fields.csv'
    dataset.write_text(','.join(NETWORK_FEATURES) + '\n' +
                       ','.join(['1'] * (len(NETWORK_FEATURES) + 1)) + '\n', encoding='utf-8')
    with pytest.raises(NetworkInputError, match='Cannot read dataset CSV'):
        trainer.validate_dataset(dataset)


def test_empty_dataset_report():
    report = validate_network_frame(flow_frame(0))
    assert report['status'] == 'empty_dataset'
    assert report['input_rows'] == 0


def test_blank_csv_rows_are_counted(tmp_path):
    dataset = tmp_path / 'blank_row.csv'
    flow_frame(1).to_csv(dataset, index=False)
    with dataset.open('a', encoding='utf-8') as handle:
        handle.write('\n')
    report = trainer.validate_dataset(dataset)
    assert report['input_rows'] == 2
    assert report['issues']['missing_values']['rows'] == 1
    assert report['issues']['missing_values']['cells'] == len(NETWORK_FEATURES)


@pytest.mark.parametrize('use_default', [False, True])
def test_validation_only_never_trains_or_saves(tiny_flow_csv, tmp_path, monkeypatch, capsys, use_default):
    dataset = Path(tiny_flow_csv)
    before = dataset.read_bytes()
    contents = set(tmp_path.iterdir())
    monkeypatch.setattr(trainer, 'APPROVED_DATASET_PATH', dataset)
    argv = ['train_baseline.py', '--validate-only']
    if not use_default:
        argv += ['--data', str(dataset)]
    monkeypatch.setattr(sys, 'argv', argv)
    trainer.main()
    report = json.loads(capsys.readouterr().out)
    assert report['status'] == 'valid'
    assert report['dataset_path'] == str(dataset.resolve())
    assert dataset.read_bytes() == before
    assert set(tmp_path.iterdir()) == contents


def test_validation_only_issue_exit_code(tmp_path, monkeypatch, capsys):
    dataset = tmp_path / 'negative.csv'
    frame = flow_frame()
    frame.loc[0, 'Flow Duration'] = '-1'
    frame.to_csv(dataset, index=False)
    monkeypatch.setattr(sys, 'argv', ['train_baseline.py', '--validate-only', '--data', str(dataset)])
    with pytest.raises(SystemExit) as error:
        trainer.main()
    assert error.value.code == 2
    assert json.loads(capsys.readouterr().out)['issues']['negative_measurements']['rows'] == 1


@pytest.mark.parametrize('content,message', [(None, 'Dataset file not found'),
                                           ('other\n1\n', 'Missing required network features')])
def test_validation_only_file_and_schema_error_exit(tmp_path, monkeypatch, capsys, content, message):
    dataset = tmp_path / 'bad.csv'
    if content is not None:
        dataset.write_text(content, encoding='utf-8')
    monkeypatch.setattr(sys, 'argv', ['train_baseline.py', '--validate-only', '--data', str(dataset)])
    with pytest.raises(SystemExit) as error:
        trainer.main()
    assert error.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ''
    assert message in captured.err


def test_training_cli_still_requires_metadata(monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['train_baseline.py', '--data', 'any.csv'])
    with pytest.raises(SystemExit) as error:
        trainer.main()
    assert error.value.code == 2
    assert '--dataset-version, --expected-sha256' in capsys.readouterr().err


@pytest.mark.parametrize('use_default', [False, True])
def test_training_cli_preserves_arguments_without_fitting(monkeypatch, capsys, use_default):
    received = {}

    def simulated_training(**kwargs):
        received.update(kwargs)
        return {'provenance': {}}

    monkeypatch.setattr(trainer, 'train_baseline', simulated_training)
    argv = ['train_baseline.py', '--dataset-version', 'reviewed-test',
            '--expected-sha256', '0' * 64, '--contamination', '0.2', '--overwrite']
    if not use_default:
        argv += ['--data', 'data/custom folder/flows.csv']
    monkeypatch.setattr(sys, 'argv', argv)
    trainer.main()
    assert received == {
        'data': trainer.APPROVED_DATASET_PATH if use_default else Path('data/custom folder/flows.csv'),
        'dataset_version': 'reviewed-test', 'expected_sha256': '0' * 64,
        'contamination': 0.2, 'overwrite': True,
        'eligible': False, 'cleaning_record': None,
    }
    assert json.loads(capsys.readouterr().out)['provenance'] == {}
