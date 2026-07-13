//! Opt-in, deterministic-testable `iicp.selection.v1` candidate ordering.

pub fn weighted_v1_index(scores: &[f64], loads: &[f64], random_value: f64) -> usize {
    let weights: Vec<f64> = scores
        .iter()
        .zip(loads)
        .map(|(score, load)| score.max(0.01) / (1.0 + load.clamp(0.0, 1.0)))
        .collect();
    let mut remaining = random_value.clamp(0.0, 0.999_999_999) * weights.iter().sum::<f64>();
    for (index, weight) in weights.iter().enumerate() {
        remaining -= weight;
        if remaining <= 0.0 {
            return index;
        }
    }
    weights.len().saturating_sub(1)
}
