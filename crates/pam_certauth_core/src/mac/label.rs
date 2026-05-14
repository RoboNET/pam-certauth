//! `IntegrityLabel` — Astra МКЦ integrity coordinate (linear level + categories).

/// Bound on Astra integrity.  Поля соответствуют официальной модели Astra:
/// линейный уровень целостности `linear_ilev` (int8, -128..=127) и
/// 64-битная маска категорий целостности (`PDP_CAT_T = uint64_t`,
/// `pdp_common.h`, fetch 2026-05-14).  Сериализуется в DER (§2.2 spec) и в
/// text-формат `libpdp` `"conf:integ:cat_hex:flags:linear"` (§C.4/C.10 spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegrityLabel {
    /// Линейный уровень целостности (`PDP_ILINEAR_T` = int8).
    /// Отрицательные — untrusted (sandbox); 0 — default.
    pub level: i8,
    /// Битовая маска категорий целостности (до 64 бит).
    pub categories: u64,
}

impl IntegrityLabel {
    /// Maximum allowed level (int8 upper bound).
    pub const MAX_LEVEL: i8 = i8::MAX;
    /// Minimum allowed level (int8 lower bound, untrusted/sandbox).
    pub const MIN_LEVEL: i8 = i8::MIN;

    /// Plain set-intersection (treats empty categories literally as "no cats").
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            level: self.level.min(other.level),
            categories: self.categories & other.categories,
        }
    }

    /// Intersection where `self` is the cert bound and `other` is the user
    /// МНКЦ.  `self.categories == 0` is interpreted as "cert imposes no
    /// category restriction" so `other.categories` survives unchanged.  This
    /// is the cert-vs-user-МНКЦ axis, not symmetric — do not call with
    /// arguments swapped.
    #[must_use]
    pub fn intersect_cert_with_user(&self, other: &Self) -> Self {
        let cats = if self.categories == 0 {
            other.categories
        } else {
            self.categories & other.categories
        };
        Self {
            level: self.level.min(other.level),
            categories: cats,
        }
    }

    /// Strict componentwise less-than (level lower OR fewer categories).
    #[must_use]
    pub fn strictly_below(&self, other: &Self) -> bool {
        let cats_subset = (self.categories & other.categories) == self.categories;
        (self.level < other.level && cats_subset)
            || (self.level <= other.level && self.categories != other.categories && cats_subset)
    }
}
