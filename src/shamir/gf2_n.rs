/// Implementation of Gf(256) finite field arithmetic using tables-based multiplication and division
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Gf2N(pub u8);

impl Gf2N {
    #[inline]
    pub fn zero() -> Gf2N {
        Gf2N(0)
    }

    #[inline]
    pub fn one() -> Gf2N {
        Gf2N(1)
    }

    #[inline]
    pub fn as_slice(s: &[u8]) -> &[Gf2N] {
        // NOTE: This is safe because Gf2N is repr(transparent)
        unsafe { std::slice::from_raw_parts(s.as_ptr() as *const Gf2N, s.len()) }
    }

    #[inline]
    pub fn as_slice_mut(s: &mut [u8]) -> &mut [Gf2N] {
        // NOTE: This is safe because Gf2N is repr(transparent)
        unsafe { std::slice::from_raw_parts_mut(s.as_mut_ptr() as *mut Gf2N, s.len()) }
    }

    #[inline]
    pub fn to_bytes(s: &[Gf2N]) -> &[u8] {
        // NOTE: This is safe because Gf2N is repr(transparent)
        unsafe { std::slice::from_raw_parts(s.as_ptr() as *const u8, s.len()) }
    }

    #[inline]
    pub fn to_bytes_mut(s: &mut [Gf2N]) -> &mut [u8] {
        // NOTE: This is safe because Gf2N is repr(transparent)
        unsafe { std::slice::from_raw_parts_mut(s.as_mut_ptr() as *mut u8, s.len()) }
    }

    /// Batch apply operation res[i] += a[i] * b to a slice. Can be optimized in the future.
    pub fn add_mul_slice(res: &mut [Self], a: &[Self], b: Self) {
        assert_eq!(res.len(), a.len());
        for (res, &a) in res.iter_mut().zip(a) {
            *res += a * b;
        }
    }
    /*
    pub fn exp(power: usize) -> Gf2N {
        Gf2N(GF256_EXP[power % 255])
    }

    pub fn log(&self) -> Option<usize> {
        if self.0 != 0 {
            Some(GF256_LOG[self.0 as usize] as usize)
        } else {
            None
        }
    }
    */
}
/*
static GF256_EXP: [u8; 255] = [
    0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff, 0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
    0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
    0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
    0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc, 0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
    0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
    0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f, 0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
    0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
    0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec, 0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
    0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
    0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
    0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e, 0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
    0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf, 0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
    0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
    0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
    0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c, 0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
    0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6,
];

static GF256_LOG: [u8; 256] = [
    0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6, 0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03,
    0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef, 0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1,
    0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a, 0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78,
    0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24, 0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e,
    0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94, 0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38,
    0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62, 0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10,
    0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42, 0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba,
    0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca, 0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57,
    0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74, 0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8,
    0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5, 0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0,
    0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec, 0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7,
    0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86, 0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d,
    0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc, 0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1,
    0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47, 0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab,
    0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89, 0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5,
    0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18, 0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07,
];
*/
impl Add<Gf2N> for Gf2N {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Gf2N) -> Self::Output {
        Gf2N(self.0 ^ rhs.0)
    }
}

impl AddAssign<Gf2N> for Gf2N {
    #[inline]
    fn add_assign(&mut self, rhs: Gf2N) {
        *self = *self + rhs;
    }
}

impl Sub<Gf2N> for Gf2N {
    type Output = Gf2N;
    #[inline]
    fn sub(self, rhs: Gf2N) -> Self::Output {
        Gf2N(self.0 ^ rhs.0)
    }
}

impl SubAssign<Gf2N> for Gf2N {
    #[inline]
    fn sub_assign(&mut self, rhs: Gf2N) {
        *self = *self - rhs;
    }
}

impl Mul<Gf2N> for Gf2N {
    type Output = Gf2N;
    fn mul(self, rhs: Gf2N) -> Self::Output {
        Gf2N(mul(self.0, rhs.0))
    }
}

impl MulAssign<Gf2N> for Gf2N {
    fn mul_assign(&mut self, rhs: Gf2N) {
        *self = *self * rhs;
    }
}

impl Div<Gf2N> for Gf2N {
    type Output = Gf2N;
    fn div(self, rhs: Gf2N) -> Self::Output {
        Gf2N(div(self.0, rhs.0))
    }
}

impl DivAssign<Gf2N> for Gf2N {
    fn div_assign(&mut self, rhs: Gf2N) {
        *self = *self / rhs;
    }
}

//#[derive(Debug, Clone, Copy, PartialEq, Eq)]
//#[repr(transparent)]
//pub struct Poly(pub u8);

const POLY: u8 = 0x1B; // AES Gf(2^8) finite field; One of the alternatives is 0x63.

fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn mul(mut a: u8, mut b: u8) -> u8 {
    // Peasant's algorithm
    let mut p = 0u8;
    while a != 0 && b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        b >>= 1;
        a = a.rotate_left(1); // This is intentionally masked by the type size
        if a & 1 != 0 {
            a ^= POLY ^ 1;
        }
    }
    p
}

fn div_poly(mut a: u8, b: u8) -> (u8, u8) {
    assert_ne!(b, 0, "Division by zero");
    let mut q = 0u8; // quotient
    let blz = b.leading_zeros();
    while let Some(shift) = blz.checked_sub(a.leading_zeros()) {
        a ^= b << shift;
        q |= 1 << shift;
    }
    (q, a)
}

fn inverse(b: u8) -> u8 {
    assert_ne!(b, 0, "Inversion of zero");
    // Extended Euclidean Algorithm
    let mut r1 = POLY;
    let mut r2 = b;
    let mut a1 = 0u8;
    let mut a2 = 1u8;

    // Adjust initial values to keep us within the field size.
    // This whole block is intentionally masked by the type size
    if r2 != 1 {
        let blz = r2.leading_zeros();
        r1 ^= r2 << (blz + 1);
        a1 |= 1 << (blz + 1);
    }

    while r2 != 1 {
        assert_ne!(r2, 0, "Division by zero");
        let (q, r) = div_poly(r1, r2);
        r1 = r;
        a1 ^= mul(q as u8, a2);

        std::mem::swap(&mut r1, &mut r2);
        std::mem::swap(&mut a1, &mut a2);
    }
    a2
}

fn div(a: u8, b: u8) -> u8 {
    assert_ne!(b, 0, "Division by zero");
    mul(a, inverse(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir::gf256::Gf256;
    use quickcheck::*;

    #[test]
    fn test_mul() {
        for a in 0..255u8 {
            for b in 0..255u8 {
                let r1 = (Gf256(a) * Gf256(b)).0;
                let r2 = (Gf2N(a) * Gf2N(b)).0;
                assert_eq!(r1, r2);
            }
        }
    }

    #[test]
    fn test_div() {
        for a in 0..255u8 {
            for b in 1..255u8 {
                let r1 = (Gf256(a) / Gf256(b)).0;
                let r2 = (Gf2N(a) / Gf2N(b)).0;
                assert_eq!(r1, r2);
            }
        }
    }

    #[test]
    fn test_inv() {
        for a in 1..255u8 {
            let inv = inverse(a);
            assert_eq!((Gf2N(a) * Gf2N(inv)).0, 1);
        }
    }

    // NOTE: Tests are borrowed from https://github.com/SpinResearch/RustySecrets

    impl Arbitrary for Gf2N {
        fn arbitrary<G: Gen>(gen: &mut G) -> Gf2N {
            Gf2N(u8::arbitrary(gen))
        }
    }

    mod addition {
        use super::*;

        quickcheck! {
            fn law_associativity(a: Gf2N, b: Gf2N, c: Gf2N) -> bool {
                (a + b) + c == a + (b + c)
            }

            fn law_commutativity(a: Gf2N, b: Gf2N) -> bool {
                a + b == b + a
            }

            fn law_distributivity(a: Gf2N, b: Gf2N, c: Gf2N) -> bool {
                a * (b + c) == a * b + a * c
            }

            fn law_identity(a: Gf2N) -> bool {
                a + Gf2N::zero() == a && Gf2N::zero() + a == a
            }

            fn law_inverses(a: Gf2N) -> bool {
                a + (Gf2N::zero() - a) == Gf2N::zero() && (Gf2N::zero() - a) + a == Gf2N::zero()
            }
        }
    }

    mod multiplication {
        use super::*;

        quickcheck! {
            fn law_associativity(a: Gf2N, b: Gf2N, c: Gf2N) -> bool {
                (a * b) * c == a * (b * c)
            }

            fn law_commutativity(a: Gf2N, b: Gf2N) -> bool {
                a * b == b * a
            }

            fn law_distributivity(a: Gf2N, b: Gf2N, c: Gf2N) -> bool {
                (a + b) * c == a * c + b * c
            }

            fn law_identity(a: Gf2N) -> bool {
                a * Gf2N::one() == a && Gf2N::one() * a == a
            }

            fn law_inverses(a: Gf2N) -> TestResult {
                if a == Gf2N::zero() {
                    return TestResult::discard();
                }

                let left = a * (Gf2N::one() / a) == Gf2N::one();
                let right = (Gf2N::one() / a) * a == Gf2N::one();

                TestResult::from_bool(left && right)
            }
        }
    }
}
