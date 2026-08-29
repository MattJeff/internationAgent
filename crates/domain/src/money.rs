//! Money as unsigned minor units plus an ISO-4217 currency.
//!
//! Three invariants are carried by the type system rather than by review:
//!
//! * **No negative amounts.** `minor` is `u64`. There is no constructor, no
//!   arithmetic operation and no deserialization path that produces one, so a
//!   negative spend limit is not a bug you can write.
//! * **No zero amounts.** A zero-value payment is always a bug in this system,
//!   so [`Money::new`] rejects it and every operation that would land on zero
//!   (`checked_sub` of equals, `checked_mul_int` by 0) is an error instead.
//! * **No implicit currency conversion.** Cross-currency arithmetic is an
//!   `Err`, never a panic and never a silent reinterpretation of minor units.
//!
//! LedgerDirection lives in [`LedgerDirection`] / [`SignedAmount`], not in the sign of an
//! integer, so a debit can never be silently spent as a credit.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// An ISO-4217 currency that knows its own minor-unit exponent.
///
/// The exponent is the whole point: `JPY` and `KRW` have no minor unit, so
/// `500` minor units is ¥500, not ¥5.00.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Currency {
    Usd,
    Eur,
    Gbp,
    Cny,
    Jpy,
    Krw,
    Chf,
    Cad,
    Aud,
    Inr,
}

impl Currency {
    /// Every currency this system understands. Iterate it in tests so a new
    /// variant cannot be added without being exercised.
    pub const ALL: [Currency; 10] = [
        Currency::Usd,
        Currency::Eur,
        Currency::Gbp,
        Currency::Cny,
        Currency::Jpy,
        Currency::Krw,
        Currency::Chf,
        Currency::Cad,
        Currency::Aud,
        Currency::Inr,
    ];

    /// The ISO-4217 alphabetic code.
    pub const fn code(self) -> &'static str {
        match self {
            Currency::Usd => "USD",
            Currency::Eur => "EUR",
            Currency::Gbp => "GBP",
            Currency::Cny => "CNY",
            Currency::Jpy => "JPY",
            Currency::Krw => "KRW",
            Currency::Chf => "CHF",
            Currency::Cad => "CAD",
            Currency::Aud => "AUD",
            Currency::Inr => "INR",
        }
    }

    /// Number of decimal places between the major and minor unit.
    ///
    /// Written out with no `_` arm, which is the whole point: ISO-4217 also has
    /// three-decimal currencies (BHD, KWD, TND, JOD) and a wildcard defaulting
    /// to `2` would price one of them at a hundredth of its value, silently, in
    /// every direction at once — [`Money::from_major`], [`Money::from_major_str`]
    /// and [`fmt::Display`] all read this one function, so nothing downstream
    /// would disagree with anything else and no test could see it. A new variant
    /// must stop the build here and be decided on.
    pub const fn exponent(self) -> u32 {
        match self {
            Currency::Jpy | Currency::Krw => 0,
            Currency::Usd
            | Currency::Eur
            | Currency::Gbp
            | Currency::Cny
            | Currency::Chf
            | Currency::Cad
            | Currency::Aud
            | Currency::Inr => 2,
        }
    }

    /// Minor units in one major unit: `10^exponent`.
    pub const fn minor_per_major(self) -> u64 {
        10u64.pow(self.exponent())
    }
}

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl FromStr for Currency {
    type Err = MoneyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let up = s.trim().to_ascii_uppercase();
        Currency::ALL
            .into_iter()
            .find(|c| c.code() == up)
            .ok_or_else(|| MoneyError::UnknownCurrency(s.to_owned()))
    }
}

/// Everything that can go wrong with money. No variant is recoverable by
/// guessing, which is why none of them is a panic.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MoneyError {
    #[error("amount must be greater than zero")]
    Zero,
    #[error("currency mismatch: {left} vs {right}")]
    CurrencyMismatch { left: Currency, right: Currency },
    #[error("amount overflowed u64 minor units")]
    Overflow,
    #[error("subtraction would produce a negative amount")]
    Underflow,
    #[error("unknown ISO-4217 currency code: {0:?}")]
    UnknownCurrency(String),
    #[error("not a valid major-unit amount: {0:?}")]
    InvalidAmount(String),
    #[error("{currency} has {expected} decimal place(s), got {got}")]
    WrongExponent {
        currency: Currency,
        expected: u32,
        got: usize,
    },
}

/// A strictly positive amount in a single currency, stored in minor units.
///
/// Serializes as `{"minor": 500, "currency": "JPY"}` — never as a float, which
/// would silently round real payments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "MoneyWire")]
pub struct Money {
    minor: u64,
    currency: Currency,
}

/// Deserialization funnel, so JSON cannot smuggle in a zero amount.
#[derive(Deserialize)]
struct MoneyWire {
    minor: u64,
    currency: Currency,
}

impl TryFrom<MoneyWire> for Money {
    type Error = MoneyError;

    fn try_from(w: MoneyWire) -> Result<Self, Self::Error> {
        Money::new(w.minor, w.currency)
    }
}

impl Money {
    /// The only way to build a `Money`. Rejects zero.
    pub const fn new(minor: u64, currency: Currency) -> Result<Self, MoneyError> {
        if minor == 0 {
            return Err(MoneyError::Zero);
        }
        Ok(Money { minor, currency })
    }

    /// Build from whole major units, respecting the currency's exponent:
    /// `from_major(5, USD)` is `500` minor, `from_major(5, JPY)` is `5`.
    pub fn from_major(major: u64, currency: Currency) -> Result<Self, MoneyError> {
        let minor = major
            .checked_mul(currency.minor_per_major())
            .ok_or(MoneyError::Overflow)?;
        Money::new(minor, currency)
    }

    /// Parse a decimal major-unit string: `"5.00"` for USD, `"500"` for JPY.
    ///
    /// More decimals than the currency has is an error, not a rounding
    /// opportunity: `"5.001"` USD and `"5.0"` JPY both fail. Fewer is fine
    /// (`"5.5"` USD is 550 minor units).
    pub fn from_major_str(s: &str, currency: Currency) -> Result<Self, MoneyError> {
        let s = s.trim();
        let invalid = || MoneyError::InvalidAmount(s.to_owned());
        let exp = currency.exponent() as usize;

        let (major, frac) = match s.split_once('.') {
            Some((major, frac)) => (major, frac),
            None => (s, ""),
        };
        if major.is_empty() || !major.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        // A trailing "." or a second "." leaves a non-digit or empty fraction.
        if s.contains('.') && (frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit())) {
            return Err(invalid());
        }
        if frac.len() > exp {
            return Err(MoneyError::WrongExponent {
                currency,
                expected: currency.exponent(),
                got: frac.len(),
            });
        }

        let major: u64 = major.parse().map_err(|_| MoneyError::Overflow)?;
        // frac is at most `exp` digits (<= 2), so this cannot overflow.
        let frac: u64 = if frac.is_empty() {
            0
        } else {
            frac.parse::<u64>().map_err(|_| invalid())? * 10u64.pow((exp - frac.len()) as u32)
        };

        let minor = major
            .checked_mul(currency.minor_per_major())
            .and_then(|m| m.checked_add(frac))
            .ok_or(MoneyError::Overflow)?;
        Money::new(minor, currency)
    }

    pub const fn minor(self) -> u64 {
        self.minor
    }

    pub const fn currency(self) -> Currency {
        self.currency
    }

    /// Add. Errors on currency mismatch and on `u64` overflow — never wraps.
    pub fn checked_add(self, rhs: Money) -> Result<Money, MoneyError> {
        self.same_currency(rhs)?;
        let minor = self
            .minor
            .checked_add(rhs.minor)
            .ok_or(MoneyError::Overflow)?;
        Money::new(minor, self.currency)
    }

    /// Subtract. Errors on currency mismatch, on going negative, and on
    /// landing exactly on zero (which `Money` cannot represent).
    pub fn checked_sub(self, rhs: Money) -> Result<Money, MoneyError> {
        self.same_currency(rhs)?;
        let minor = self
            .minor
            .checked_sub(rhs.minor)
            .ok_or(MoneyError::Underflow)?;
        Money::new(minor, self.currency)
    }

    /// Multiply by a count (line items, months of a subscription). A factor of
    /// zero is an error, not a zero-value payment.
    pub fn checked_mul_int(self, factor: u64) -> Result<Money, MoneyError> {
        let minor = self.minor.checked_mul(factor).ok_or(MoneyError::Overflow)?;
        Money::new(minor, self.currency)
    }

    fn same_currency(self, rhs: Money) -> Result<(), MoneyError> {
        if self.currency == rhs.currency {
            Ok(())
        } else {
            Err(MoneyError::CurrencyMismatch {
                left: self.currency,
                right: rhs.currency,
            })
        }
    }
}

impl fmt::Display for Money {
    /// `USD 5.00`, `JPY 500`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let exp = self.currency.exponent() as usize;
        if exp == 0 {
            write!(f, "{} {}", self.currency.code(), self.minor)
        } else {
            let d = self.currency.minor_per_major();
            write!(
                f,
                "{} {}.{:0exp$}",
                self.currency.code(),
                self.minor / d,
                self.minor % d,
            )
        }
    }
}

/// Which way money moves. Deliberately not a `bool` and not a sign bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerDirection {
    Debit,
    Credit,
}

/// A [`Money`] paired with a [`LedgerDirection`]. The only way to get one is to say
/// which direction you meant, so a debit cannot be summed as a credit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignedAmount {
    amount: Money,
    direction: LedgerDirection,
}

impl SignedAmount {
    pub const fn debit(amount: Money) -> Self {
        SignedAmount {
            amount,
            direction: LedgerDirection::Debit,
        }
    }

    pub const fn credit(amount: Money) -> Self {
        SignedAmount {
            amount,
            direction: LedgerDirection::Credit,
        }
    }

    pub const fn amount(self) -> Money {
        self.amount
    }

    pub const fn direction(self) -> LedgerDirection {
        self.direction
    }

    pub const fn is_debit(self) -> bool {
        matches!(self.direction, LedgerDirection::Debit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Currency::{Jpy, Usd};

    // A negative amount is unconstructible *by type*: `minor` is `u64` and no
    // constructor or operation below takes or returns a signed integer. There
    // is nothing to assert at runtime — the absence of a `-` is the test.
    #[test]
    fn zero_is_unconstructible() {
        assert_eq!(Money::new(0, Usd), Err(MoneyError::Zero));
        assert_eq!(Money::from_major(0, Usd), Err(MoneyError::Zero));
        assert_eq!(Money::from_major_str("0.00", Usd), Err(MoneyError::Zero));
        assert_eq!(Money::from_major_str("0", Jpy), Err(MoneyError::Zero));

        // Every path that could land on zero is an error too.
        let five = Money::new(5, Usd).unwrap();
        assert_eq!(five.checked_sub(five), Err(MoneyError::Zero));
        assert_eq!(five.checked_mul_int(0), Err(MoneyError::Zero));

        // Including the serde path.
        assert!(serde_json::from_str::<Money>(r#"{"minor":0,"currency":"USD"}"#).is_err());
    }

    #[test]
    fn jpy_and_usd_exponents_do_not_get_confused() {
        let usd = Money::from_major_str("5.00", Usd).unwrap();
        let jpy = Money::from_major_str("500", Jpy).unwrap();

        // Same minor units, different money. Equality must not conflate them.
        assert_eq!(usd.minor(), 500);
        assert_eq!(jpy.minor(), 500);
        assert_ne!(usd, jpy);

        // from_major respects the exponent.
        assert_eq!(Money::from_major(5, Usd).unwrap().minor(), 500);
        assert_eq!(Money::from_major(5, Jpy).unwrap().minor(), 5);

        // The naive-money bugs.
        assert_eq!(
            Money::from_major_str("5.001", Usd),
            Err(MoneyError::WrongExponent {
                currency: Usd,
                expected: 2,
                got: 3
            })
        );
        assert_eq!(
            Money::from_major_str("5.0", Jpy),
            Err(MoneyError::WrongExponent {
                currency: Jpy,
                expected: 0,
                got: 1
            })
        );

        // Fewer decimals than the exponent is fine; junk is not.
        assert_eq!(Money::from_major_str("5.5", Usd).unwrap().minor(), 550);
        for junk in ["", "-5.00", "+5.00", "5.", "5.0.0", "abc", "5 00", "1e3"] {
            assert!(
                Money::from_major_str(junk, Usd).is_err(),
                "accepted junk: {junk:?}"
            );
        }
    }

    #[test]
    fn overflow_is_reported_not_wrapped() {
        let max = Money::new(u64::MAX, Usd).unwrap();
        let one = Money::new(1, Usd).unwrap();

        assert_eq!(max.checked_add(one).ok(), None);
        assert_eq!(max.checked_add(one), Err(MoneyError::Overflow));
        assert_eq!(max.checked_mul_int(2), Err(MoneyError::Overflow));
        assert_eq!(one.checked_sub(max), Err(MoneyError::Underflow));
        assert_eq!(Money::from_major(u64::MAX, Usd), Err(MoneyError::Overflow));
        assert_eq!(
            Money::from_major_str("99999999999999999999", Usd),
            Err(MoneyError::Overflow)
        );
    }

    #[test]
    fn cross_currency_arithmetic_is_an_error() {
        let usd = Money::from_major(5, Usd).unwrap();
        let jpy = Money::from_major(5, Jpy).unwrap();

        assert_eq!(
            usd.checked_add(jpy),
            Err(MoneyError::CurrencyMismatch {
                left: Usd,
                right: Jpy
            })
        );
        assert_eq!(
            jpy.checked_sub(usd),
            Err(MoneyError::CurrencyMismatch {
                left: Jpy,
                right: Usd
            })
        );
    }

    #[test]
    fn display_round_trips_for_every_currency() {
        for currency in Currency::ALL {
            for minor in [1u64, 7, 500, 12_345, u64::MAX] {
                let m = Money::new(minor, currency).unwrap();
                let rendered = m.to_string();
                let (code, amount) = rendered.split_once(' ').unwrap();
                let back = Money::from_major_str(amount, code.parse().unwrap()).unwrap();
                assert_eq!(back, m, "{rendered} did not round-trip");
            }
        }
        assert_eq!(Money::from_major(5, Usd).unwrap().to_string(), "USD 5.00");
        assert_eq!(Money::from_major(500, Jpy).unwrap().to_string(), "JPY 500");
        assert_eq!(Money::new(5, Usd).unwrap().to_string(), "USD 0.05");
    }

    #[test]
    fn serde_shape_is_minor_units_and_a_code() {
        let m = Money::from_major_str("500", Jpy).unwrap();
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, r#"{"minor":500,"currency":"JPY"}"#);
        assert_eq!(serde_json::from_str::<Money>(&json).unwrap(), m);
        assert!(!json.contains('.'), "money must never serialize as a float");
        assert!(serde_json::from_str::<Money>(r#"{"minor":1,"currency":"XXX"}"#).is_err());
    }

    #[test]
    fn direction_is_carried_separately_from_the_amount() {
        let m = Money::from_major(5, Usd).unwrap();
        let d = SignedAmount::debit(m);
        let c = SignedAmount::credit(m);

        assert_ne!(d, c);
        assert_eq!(d.amount(), c.amount());
        assert!(d.is_debit());
        assert_eq!(c.direction(), LedgerDirection::Credit);
    }

    #[test]
    fn currency_codes_parse_and_round_trip() {
        for currency in Currency::ALL {
            assert_eq!(currency.code().parse::<Currency>().unwrap(), currency);
            assert_eq!(
                currency
                    .code()
                    .to_ascii_lowercase()
                    .parse::<Currency>()
                    .unwrap(),
                currency
            );
        }
        assert_eq!(
            "XYZ".parse::<Currency>(),
            Err(MoneyError::UnknownCurrency("XYZ".into()))
        );
    }

    proptest::proptest! {
        /// Addition of same-currency money is commutative and monotone.
        #[test]
        fn checked_add_is_commutative_and_never_shrinks(a in 1u64..=u64::MAX, b in 1u64..=u64::MAX) {
            let x = Money::new(a, Usd).unwrap();
            let y = Money::new(b, Usd).unwrap();

            proptest::prop_assert_eq!(x.checked_add(y), y.checked_add(x));

            if let Ok(sum) = x.checked_add(y) {
                proptest::prop_assert!(sum.minor() >= x.minor());
                proptest::prop_assert!(sum.minor() >= y.minor());
                proptest::prop_assert_eq!(sum.currency(), Usd);
                // And it round-trips back out.
                proptest::prop_assert_eq!(sum.checked_sub(y), Ok(x));
            } else {
                // The only reason to fail is overflow, never a wrap.
                proptest::prop_assert_eq!(x.checked_add(y), Err(MoneyError::Overflow));
            }
        }
    }
}
