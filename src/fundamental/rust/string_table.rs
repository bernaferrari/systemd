// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/string-table.h
//
// String table lookup declarations. In Rust, these become generic
// traits and macros for enum-to-string / string-to-enum conversions.

/// Trait for types that can be converted to a string representation.
pub trait ToStringTable {
    fn to_string_table(&self) -> Option<&'static str>;
}

/// Trait for types that can be parsed from a string.
pub trait FromStringTable: Sized {
    fn from_string_table(s: &str) -> Option<Self>;
}

/// Macro to generate string table lookup for an enum.
/// Usage:
///   define_string_table!(MyEnum {
///       VariantA => "variant_a",
///       VariantB => "variant_b",
///   });
#[macro_export]
macro_rules! define_string_table {
    ($enum:ident { $($variant:ident => $str:literal,)+ }) => {
        impl $crate::string_table::ToStringTable for $enum {
            fn to_string_table(&self) -> Option<&'static str> {
                match self {
                    $( <$enum>::$variant => Some($str), )+
                }
            }
        }

        impl $crate::string_table::FromStringTable for $enum {
            fn from_string_table(s: &str) -> Option<Self> {
                match s {
                    $( $str => Some(<$enum>::$variant), )+
                    _ => None,
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestEnum {
        Alpha,
        Beta,
        Gamma,
    }

    define_string_table!(TestEnum {
        Alpha => "alpha",
        Beta => "beta",
        Gamma => "gamma",
    });

    #[test]
    fn test_to_string_table() {
        use crate::string_table::ToStringTable;
        assert_eq!(TestEnum::Alpha.to_string_table(), Some("alpha"));
        assert_eq!(TestEnum::Beta.to_string_table(), Some("beta"));
    }

    #[test]
    fn test_from_string_table() {
        use crate::string_table::FromStringTable;
        assert_eq!(TestEnum::from_string_table("alpha"), Some(TestEnum::Alpha));
        assert_eq!(TestEnum::from_string_table("unknown"), None);
    }
}
