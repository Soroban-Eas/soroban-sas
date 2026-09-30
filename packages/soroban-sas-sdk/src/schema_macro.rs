use soroban_sdk::{Bytes, ConversionError, Env};

pub trait SchemaType: Sized {
    fn schema() -> &'static str;
    fn to_bytes(&self, env: &Env) -> Bytes;
    fn from_bytes(env: &Env, bytes: &Bytes) -> Result<Self, ConversionError>;
}

#[macro_export]
#[doc(hidden)]
macro_rules! __format_schema {
    () => {
        ""
    };
    ($f:ident : $t:ident) => {
        concat!(stringify!($f), " ", stringify!($t))
    };
    ($f:ident : $t:ident, $($rest_f:ident : $rest_t:ident),+ $(,)?) => {
        concat!(
            stringify!($f),
            " ",
            stringify!($t),
            ", ",
            $crate::__format_schema!($($rest_f : $rest_t),+)
        )
    };
}

#[macro_export]
macro_rules! schema_to_struct {
    // Explicit schema definition string
    (
        schema: $schema:expr,
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                $field_vis:vis $field:ident : $ty:ident
            ),* $(,)?
        }
    ) => {
        #[soroban_sdk::contracttype]
        #[derive(Clone, Debug, PartialEq, Eq)]
        $(#[$meta])*
        $vis struct $name {
            $(
                $(#[$field_meta])*
                $field_vis $field: $ty,
            )*
        }

        impl $crate::schema_macro::SchemaType for $name {
            fn schema() -> &'static str {
                $schema
            }

            fn to_bytes(&self, env: &soroban_sdk::Env) -> soroban_sdk::Bytes {
                use soroban_sdk::xdr::ToXdr;
                self.clone().to_xdr(env)
            }

            fn from_bytes(
                env: &soroban_sdk::Env,
                bytes: &soroban_sdk::Bytes,
            ) -> Result<Self, soroban_sdk::ConversionError> {
                use soroban_sdk::xdr::FromXdr;
                Self::from_xdr(env, bytes)
            }
        }

        impl $name {
            pub fn schema() -> &'static str {
                <Self as $crate::schema_macro::SchemaType>::schema()
            }

            pub fn to_bytes(&self, env: &soroban_sdk::Env) -> soroban_sdk::Bytes {
                <Self as $crate::schema_macro::SchemaType>::to_bytes(self, env)
            }

            pub fn from_bytes(
                env: &soroban_sdk::Env,
                bytes: &soroban_sdk::Bytes,
            ) -> Result<Self, soroban_sdk::ConversionError> {
                <Self as $crate::schema_macro::SchemaType>::from_bytes(env, bytes)
            }
        }
    };

    // Auto-derived schema definition string
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                $field_vis:vis $field:ident : $ty:ident
            ),* $(,)?
        }
    ) => {
        $crate::schema_to_struct!(
            schema: $crate::__format_schema!($($field : $ty),*),
            $(#[$meta])*
            $vis struct $name {
                $(
                    $(#[$field_meta])*
                    $field_vis $field: $ty,
                )*
            }
        );
    };
}

#[cfg(test)]
mod tests {
    use crate::attestation_builder::AttestationRequestBuilder;
    use crate::SchemaBuilder;
    use soroban_sdk::{Env, String};

    schema_to_struct! {
        pub struct KYCData {
            pub level: u32,
            pub verified: bool,
        }
    }

    schema_to_struct! {
        schema: "custom_id u64, name String",
        pub struct CustomRecord {
            pub custom_id: u64,
            pub name: String,
        }
    }

    #[test]
    fn test_schema_macro_generation_and_roundtrip() {
        let env = Env::default();
        let kyc = KYCData {
            level: 2,
            verified: true,
        };

        assert_eq!(KYCData::schema(), "level u32, verified bool");
        let bytes = kyc.to_bytes(&env);
        let recovered = KYCData::from_bytes(&env, &bytes).expect("deserialization should succeed");
        assert_eq!(kyc, recovered);
    }

    #[test]
    fn test_custom_schema_string() {
        let env = Env::default();
        let record = CustomRecord {
            custom_id: 12345,
            name: String::from_str(&env, "Alice"),
        };

        assert_eq!(CustomRecord::schema(), "custom_id u64, name String");
        let bytes = record.to_bytes(&env);
        let recovered = CustomRecord::from_bytes(&env, &bytes).expect("roundtrip should work");
        assert_eq!(record, recovered);
    }

    #[test]
    fn test_builders_integration_with_schema_type() {
        let env = Env::default();
        let resolver = stellar_strkey::Contract([9u8; 32]).to_string();
        let schema_builder = SchemaBuilder::new()
            .with_schema_type::<KYCData>()
            .with_resolver(&resolver);
        let schema_record = schema_builder
            .build(&env)
            .expect("schema record should build cleanly");
        assert_eq!(
            schema_record.schema,
            String::from_str(&env, "level u32, verified bool")
        );

        let kyc = KYCData {
            level: 3,
            verified: false,
        };
        let recipient = stellar_strkey::ed25519::PublicKey([1u8; 32]).to_string();
        let attester = stellar_strkey::ed25519::PublicKey([2u8; 32]).to_string();

        let att_req = AttestationRequestBuilder::new()
            .with_recipient(&recipient)
            .with_attester(&attester)
            .with_schema_uid([1u8; 32])
            .with_schema_data(&env, &kyc);

        let attestation = att_req
            .build(&env)
            .expect("attestation build should succeed");
        let recovered =
            KYCData::from_bytes(&env, &attestation.data).expect("payload bytes should decode");
        assert_eq!(recovered, kyc);
    }
}
