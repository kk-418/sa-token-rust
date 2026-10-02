// Author: 金书记 | Author: Jin Shuji
//! HTTP Digest check macro | HTTP Digest 检查宏
//!
//! Forms | 形式:
//! - `#[sa_check_http_digest]`
//! - `#[sa_check_http_digest("user:pass")]`
//! - `#[sa_check_http_digest(username = "user", password = "pass", realm = "Sa-Token")]`

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Ident, ItemFn, LitStr, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

use crate::utils::expand_checked_fn;

struct DigestAttr {
    username: String,
    password: String,
    /// `None` → expand to `http_digest::DEFAULT_REALM`.
    realm: Option<String>,
    has_credentials: bool,
}

fn split_user_pass(account: &str) -> (String, String) {
    match account.split_once(':') {
        Some((user, pass)) => (user.to_string(), pass.to_string()),
        None => (account.to_string(), String::new()),
    }
}

impl Parse for DigestAttr {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(Self {
                username: String::new(),
                password: String::new(),
                realm: None,
                has_credentials: false,
            });
        }
        if input.peek(LitStr) {
            let lit = input.parse::<LitStr>()?;
            let (username, password) = split_user_pass(&lit.value());
            return Ok(Self {
                username,
                password,
                realm: None,
                has_credentials: true,
            });
        }
        let mut username = String::new();
        let mut password = String::new();
        let mut realm = None;
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let lit: LitStr = input.parse()?;
            if key == "username" {
                username = lit.value();
            } else if key == "password" {
                password = lit.value();
            } else if key == "realm" {
                realm = Some(lit.value());
            } else {
                return Err(syn::Error::new_spanned(
                    key,
                    "unknown field, use username / password / realm",
                ));
            }
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }
        let has_credentials = !username.is_empty();
        Ok(Self {
            username,
            password,
            realm,
            has_credentials,
        })
    }
}

pub(crate) fn sa_check_http_digest_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let digest = if attr.is_empty() {
        DigestAttr {
            username: String::new(),
            password: String::new(),
            realm: None,
            has_credentials: false,
        }
    } else {
        parse_macro_input!(attr as DigestAttr)
    };
    let input = parse_macro_input!(item as ItemFn);
    let check_code = if digest.has_credentials {
        let username = digest.username;
        let password = digest.password;
        let realm = match digest.realm {
            Some(r) => quote! { #r },
            None => quote! { sa_token_core::http_digest::DEFAULT_REALM },
        };
        quote! {
            sa_token_core::http_digest::check_user_realm(#username, #password, #realm)?;
        }
    } else {
        quote! {
            sa_token_core::http_digest::check(&sa_token_core::SaHttpDigestModel::default())?;
        }
    };
    expand_checked_fn(&input, check_code)
}
