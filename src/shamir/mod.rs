/// Threshold Secret Sharing scheme
/// See https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
/// Based on https://tools.ietf.org/id/draft-mcgrew-tss-03.html
use failure::Fail;

use crate::shamir::gf256::Gf256;
use std::convert::TryInto;

mod gf256;

#[derive(Debug, Fail)]
pub enum SecretShareError {
    #[fail(display = "Threshold must be positive")]
    ZeroThreshold,

    #[fail(
        display = "Not enough shares to reconstruct the secret (need {}, given {})",
        threshold, num_shares
    )]
    NotEnoughShares { num_shares: usize, threshold: usize },

    #[fail(
        display = "Too many shares requested ({}); current algorithm only supports up to {}",
        num_shares, max_shares
    )]
    TooManySharesRequested {
        num_shares: usize,
        max_shares: usize,
    },

    #[fail(display = "Shares of different length provided")]
    DifferentLengthShares,

    #[fail(display = "Share index {} is too large (max is {})", idx, max_idx)]
    ShareIndexTooLarge { idx: usize, max_idx: usize },

    #[fail(display = "Two or more shares given with the same index")]
    SharesWithSameIndices,
}

pub const MAX_SHARES: usize = 255;

/// Create `num_shares` secret shares, each represented as `Vec<u8>` with the same size as `secret`,
/// so that it's possible to reconstruct the `secret` using any `threshold` number of shares.
/// Requires a strong random generator.
pub fn create_secret_shares<R: rand::Rng + rand::CryptoRng>(
    secret: &[u8],
    num_shares: usize,
    threshold: usize,
    rng: &mut R,
) -> Result<Vec<Vec<u8>>, SecretShareError> {
    if threshold <= 0 {
        return Err(SecretShareError::ZeroThreshold);
    }
    if num_shares < threshold {
        return Err(SecretShareError::NotEnoughShares {
            num_shares,
            threshold,
        });
    }
    if num_shares > MAX_SHARES {
        return Err(SecretShareError::TooManySharesRequested {
            num_shares,
            max_shares: MAX_SHARES,
        });
    }
    let secret_len = secret.len();

    // Shares start being filled with secret bytes. Secret is not used after that.
    let mut shares = vec![secret.to_vec(); num_shares];

    // Create a view of the shares in Gf256 field, plus add shares' x and x^i values.
    let mut shares_gf256 = shares
        .iter_mut()
        .enumerate()
        .map(|(i, share)| {
            (
                Gf256((i + 1) as u8),       // Share 'x' value
                Gf256::one(),               // Share 'x^i' value, starting with i=0
                Gf256::as_slice_mut(share), // A view of the Share itself
            )
        })
        .collect::<Vec<_>>();

    let mut random = vec![Gf256::zero(); secret_len];
    for _ in 1..threshold {
        rng.fill(Gf256::to_bytes_mut(&mut random));

        for (x, xi, share) in shares_gf256.iter_mut() {
            *xi *= *x;
            // for all i: share[i] += random[i] * xi
            Gf256::add_mul_slice(share, &random, *xi);
        }
    }

    Ok(shares)
}

/// Recover the secret from the shares. For each share, its original index is required.
pub fn recover_secret(
    shares: &[(usize, impl AsRef<[u8]>)], // items are (share_idx, share)
    threshold: usize,
) -> Result<Vec<u8>, SecretShareError> {
    if threshold <= 0 {
        return Err(SecretShareError::ZeroThreshold);
    }

    // Check all shares have different indices
    let mut share_indices = shares.iter().map(|&(i, _)| i).collect::<Vec<_>>();
    share_indices.sort();
    share_indices.dedup();
    if share_indices.len() != shares.len() {
        return Err(SecretShareError::SharesWithSameIndices);
    }

    // Check we have enough shares to reconstruct the secret.
    let num_shares = shares.len();
    if num_shares < threshold {
        return Err(SecretShareError::NotEnoughShares {
            num_shares,
            threshold,
        });
    }

    // Create a view of shares and share indices in Gf256 field
    // Only take the first `threshold` number of shares.
    let shares: Vec<(Gf256, &[Gf256])> = shares[..threshold]
        .iter()
        .map(|(idx, share)| {
            let idx = (idx + 1)
                .try_into()
                .map_err(|_| SecretShareError::ShareIndexTooLarge {
                    idx: *idx,
                    max_idx: MAX_SHARES,
                })?;
            Ok((Gf256(idx), Gf256::as_slice(share.as_ref())))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Calculate the length of the secret and check the shares are the same length.
    let secret_len = shares[0].1.len();
    if shares.iter().any(|&(_, s)| s.len() != secret_len) {
        return Err(SecretShareError::DifferentLengthShares);
    }

    // Calculate the secret.
    let mut secret = vec![0u8; secret_len];
    let secret_gf256 = Gf256::as_slice_mut(&mut secret);
    for &(ui, share) in &shares {
        // Calculate Lagrange function evaluated at zero.
        let li = shares
            .iter()
            .filter_map(|&(uj, _)| if uj != ui { Some(uj) } else { None })
            .fold(Gf256::one(), |acc, uj| acc * uj / (uj - ui));

        // Use information from the share to reconstruct the secret.
        // for all i: secret_gf256[i] += share[i] * li
        Gf256::add_mul_slice(secret_gf256, share, li);
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use failure::Fallible;
    use rand::thread_rng;

    #[test]
    fn basic_test() -> Fallible<()> {
        let secret = b"secret-secret";
        let threshold = 3;
        let mut rng = thread_rng();

        let shares = create_secret_shares(secret, 5, threshold, &mut rng)?;

        // Check all permutations
        for (i, share1) in shares.iter().enumerate() {
            for (j, share2) in shares.iter().enumerate() {
                for (k, share3) in shares.iter().enumerate() {
                    if i != j && j != k && i != k {
                        let shares = &[(i, share1), (j, share2), (k, share3)];
                        assert_eq!(recover_secret(shares, threshold)?, secret);
                    }
                }
            }
        }

        let shares = create_secret_shares(secret, 1, 1, &mut rng)?;
        assert_eq!(&shares[0][..secret.len()], secret); // 1 share/1 threshold just keeps the secret in the open.
        assert_eq!(
            recover_secret(&shares.iter().enumerate().collect::<Vec<_>>(), 1)?,
            secret
        );

        let shares = create_secret_shares(secret, 3, 1, &mut rng)?;
        assert_eq!(&shares[0][..secret.len()], secret); // N shares/1 threshold also keeps the secret in the open.

        let shares = create_secret_shares(secret, 3, 3, &mut rng)?;
        assert_eq!(
            recover_secret(&shares.iter().enumerate().collect::<Vec<_>>(), 3)?,
            secret
        );

        Ok(())
    }
}
