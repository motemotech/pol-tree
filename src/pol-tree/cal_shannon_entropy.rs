pub fn cal_shannon_entropy_from_probabilities(probabilities: &[f64]) -> f64 {
    if probabilities.is_empty() {
        return 0.0;
    }

    let sum: f64 = probabilities.iter().sum();
    if sum <= 0.0 {
        return 0.0;
    }

    probabilities
        .iter()
        .map(|&p| {
            let normalized_p = p / sum;
            if normalized_p > 0.0 {
                - normalized_p * normalized_p.log2()
            } else {
                0.0
            }
        })
        .sum()
}

pub fn information_gain(
    base_entropy: f64,
    subset_entropies: &[f64],
    subset_sizes: &[usize],
) -> f64 {
    if subset_entropies.len() != subset_sizes.len() {
        return 0.0;
    }

    let total: usize = subset_sizes.iter().sum();
    if total == 0 {
        return 0.0;
    }

    let total_f64 = total as f64;
    let weighted_entropy: f64 = subset_entropies
        .iter()
        .zip(subset_sizes.iter())
        .map(|(&entropy, &size)| {
            if size > 0 {
                (size as f64 / total_f64) * entropy
            } else {
                0.0
            }
        })
        .sum();

    base_entropy - weighted_entropy
}