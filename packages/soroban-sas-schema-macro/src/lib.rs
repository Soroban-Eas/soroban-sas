//! Compile-time schema parser for typed SAS attestation payloads.

use proc_macro::TokenStream;
use quote::quote;
use std::collections::HashSet;
use syn::{parse_macro_input, Fields, Ident, ItemStruct, LitStr, Type};

/// Generate a Soroban-compatible struct from a schema string.
///
/// Apply this attribute to an empty named struct. Both `name Type` (registry
/// convention) and `Type name` (SDK convention) are accepted. Payloads use
/// the same `contracttype` ScVal-map XDR as `schema_to_struct!`.
#[proc_macro_attribute]
pub fn derive_schema(args: TokenStream, input: TokenStream) -> TokenStream {
    let schema = parse_macro_input!(args as LitStr);
    let item = parse_macro_input!(input as ItemStruct);
    match expand(&schema, &item) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

fn expand(schema: &LitStr, item: &ItemStruct) -> syn::Result<proc_macro2::TokenStream> {
    if !matches!(&item.fields, Fields::Named(fields) if fields.named.is_empty()) {
        return Err(syn::Error::new_spanned(
            &item.fields,
            "derive_schema requires an empty named struct, for example `struct Claim {}`",
        ));
    }
    let source = schema.value();
    if source.is_empty() || source.len() > 1024 || source.chars().any(|c| c.is_control()) {
        return Err(syn::Error::new_spanned(schema, "invalid SAS schema string"));
    }
    let mut names = HashSet::new();
    let mut fields = Vec::new();
    for field in source.split(',') {
        if fields.len() >= 64
            || field.is_empty()
            || field.ends_with(' ')
            || (fields.is_empty() && field.starts_with(' '))
            || field.starts_with("  ")
        {
            return Err(syn::Error::new_spanned(
                schema,
                "schema has too many fields or invalid spacing",
            ));
        }
        let field = field.strip_prefix(' ').unwrap_or(field);
        if field.len() > 64 {
            return Err(syn::Error::new_spanned(
                schema,
                "schema field exceeds 64 bytes",
            ));
        }
        let (first, second) = field.split_once(' ').ok_or_else(|| {
            syn::Error::new_spanned(schema, "expected `name Type` or `Type name`")
        })?;
        if first.is_empty() || second.is_empty() || second.contains(' ') {
            return Err(syn::Error::new_spanned(
                schema,
                "expected exactly one space between field name and type",
            ));
        }
        let (name, ty) = if rust_type(first).is_some() && valid_name(second) {
            (second, rust_type(first).unwrap())
        } else if valid_name(first) {
            (
                first,
                rust_type(second).ok_or_else(|| {
                    syn::Error::new_spanned(schema, format!("unsupported schema type `{second}`"))
                })?,
            )
        } else {
            return Err(syn::Error::new_spanned(
                schema,
                format!("invalid field name `{first}`"),
            ));
        };
        if !names.insert(name.to_owned()) {
            return Err(syn::Error::new_spanned(
                schema,
                format!("duplicate field `{name}`"),
            ));
        }
        let ident: Ident = syn::parse_str(name).map_err(|_| {
            syn::Error::new_spanned(schema, format!("`{name}` is not a Rust field identifier"))
        })?;
        fields.push((ident, ty));
    }
    let (names, types): (Vec<_>, Vec<_>) = fields.into_iter().unzip();
    let vis = &item.vis;
    let ident = &item.ident;
    let attrs = &item.attrs;
    let generics = &item.generics;
    if !generics.params.is_empty() || generics.where_clause.is_some() {
        return Err(syn::Error::new_spanned(
            generics,
            "derive_schema does not support generics",
        ));
    }
    Ok(quote! {
        #(#attrs)*
        #[soroban_sdk::contracttype]
        #[derive(Clone, Debug, PartialEq, Eq)]
        #vis struct #ident { #(pub #names: #types,)* }

        impl soroban_sas_sdk::schema_macro::SchemaType for #ident {
            fn schema() -> &'static str { #schema }
            fn to_bytes(&self, env: &soroban_sdk::Env) -> soroban_sdk::Bytes {
                soroban_sdk::xdr::ToXdr::to_xdr(self.clone(), env)
            }
            fn from_bytes(env: &soroban_sdk::Env, bytes: &soroban_sdk::Bytes)
                -> Result<Self, soroban_sdk::ConversionError> {
                soroban_sdk::xdr::FromXdr::from_xdr(env, bytes)
            }
        }

        impl #ident {
            pub fn schema() -> &'static str {
                <Self as soroban_sas_sdk::schema_macro::SchemaType>::schema()
            }
            pub fn to_bytes(&self, env: &soroban_sdk::Env) -> soroban_sdk::Bytes {
                <Self as soroban_sas_sdk::schema_macro::SchemaType>::to_bytes(self, env)
            }
            pub fn from_bytes(env: &soroban_sdk::Env, bytes: &soroban_sdk::Bytes)
                -> Result<Self, soroban_sdk::ConversionError> {
                <Self as soroban_sas_sdk::schema_macro::SchemaType>::from_bytes(env, bytes)
            }
        }
    })
}

fn valid_name(name: &str) -> bool {
    name.len() <= 32
        && name
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn rust_type(name: &str) -> Option<Type> {
    let ty = match name {
        "bool" => quote!(bool),
        "uint32" | "u32" => quote!(u32),
        "uint64" | "u64" => quote!(u64),
        "string" | "String" => quote!(soroban_sdk::String),
        "bytes" | "Bytes" => quote!(soroban_sdk::Bytes),
        "address" | "Address" => quote!(soroban_sdk::Address),
        _ => {
            let size = name
                .strip_prefix("BytesN<")?
                .strip_suffix('>')?
                .parse::<usize>()
                .ok()?;
            if size == 0 || size > 32 {
                return None;
            }
            return syn::parse2(quote!(soroban_sdk::BytesN<#size>)).ok();
        }
    };
    syn::parse2(ty).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_schemas_report_compile_errors() {
        let item: ItemStruct = syn::parse_quote!(
            pub struct Claim {}
        );
        for schema in [
            "",
            "bool",
            "bool  verified",
            "bool verified,",
            "bool verified, bool verified",
            "unknown value",
            "bool 1bad",
            "BytesN<0> digest",
        ] {
            let literal = LitStr::new(schema, proc_macro2::Span::call_site());
            assert!(expand(&literal, &item).is_err(), "accepted {schema:?}");
        }
        let nonempty: ItemStruct = syn::parse_quote!(
            struct Claim {
                value: bool,
            }
        );
        assert!(expand(&syn::parse_quote!("bool verified"), &nonempty).is_err());
    }
}
