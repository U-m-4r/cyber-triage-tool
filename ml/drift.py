"""Read-only population stability index (PSI) against fixed baseline bins."""
import numpy as np

EPSILON = 1e-6


def _proportions(values, cut_points):
    counts, _ = np.histogram(values, bins=[-np.inf, *cut_points, np.inf])
    proportions = counts.astype(float) / len(values)
    proportions = np.maximum(proportions, EPSILON)
    return proportions / proportions.sum()


def build_reference(features, bins=10, min_samples=100, threshold=0.2):
    """Called only by offline baseline training, never by upload handlers."""
    reference = {'method': 'psi', 'reference_rows': len(features),
                 'min_samples': min_samples, 'threshold': threshold, 'features': {}}
    for column in features.columns:
        values = features[column].to_numpy(dtype=float)
        cuts = np.unique(np.quantile(values, np.arange(1, bins) / bins)).tolist()
        if np.all(values == values[0]):
            # Isolate the constant value in its own bin, so a change in either
            # direction cannot hide in the same half-open histogram interval.
            adjacent = np.nextafter([values[0], values[0]], [-np.inf, np.inf])
            cuts = adjacent[np.isfinite(adjacent)].tolist()
        reference['features'][column] = {
            'cut_points': cuts, 'proportions': _proportions(values, cuts).tolist()}
    return reference


def monitor_drift(features, reference):
    """Compare a batch with frozen histograms; never update reference or model.

    PSI measures distribution change, not attack probability. Small batches are
    explicitly unassessed rather than interpreted as evidence of no drift.
    """
    report = {'method': 'psi', 'reference_rows': reference['reference_rows'],
              'batch_rows': len(features), 'min_samples': reference['min_samples'],
              'threshold': reference['threshold'], 'retraining_triggered': False,
              'drift_detected': None, 'features': {}}
    if reference['reference_rows'] < reference['min_samples']:
        report['status'] = 'insufficient_reference'
        return report
    if len(features) < reference['min_samples']:
        report['status'] = 'insufficient_data'
        return report
    for column, frozen in reference['features'].items():
        observed = _proportions(features[column].to_numpy(dtype=float), frozen['cut_points'])
        expected = np.asarray(frozen['proportions'])
        psi = float(np.sum((observed - expected) * np.log(observed / expected)))
        report['features'][column] = {'psi': psi, 'drift_detected': psi >= reference['threshold']}
    report['drift_detected'] = any(item['drift_detected'] for item in report['features'].values())
    report['status'] = 'drift_detected' if report['drift_detected'] else 'stable'
    return report
