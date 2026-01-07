use proc_macro::TokenStream;
use proc_macro2::Span as Span2;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream, Result as ParseResult};
use syn::{Expr, Ident, ItemFn, Lit, LitStr, ReturnType, Token, parse_macro_input};

/// Parser for attribute arguments of the form:
/// name = "literal", target = "literal", key = expr, ...
///
/// Examples:
/// #[wide_instrument]
/// #[wide_instrument(name = "api_get_report")]
/// #[wide_instrument(server_name = params.server_name, token_len = params.token.len())]
struct WideInstrumentArgs {
    // optional name literal
    pub name: Option<LitStr>,
    // optional target literal
    pub target: Option<LitStr>,
    // zero or more key = expr pairs to record on the span
    pub fields: Vec<(Ident, Expr)>,
}

impl Parse for WideInstrumentArgs {
    fn parse(input: ParseStream<'_>) -> ParseResult<Self> {
        let mut name: Option<LitStr> = None;
        let mut target: Option<LitStr> = None;
        let mut fields: Vec<(Ident, Expr)> = Vec::new();

        while !input.is_empty() {
            // parse identifier
            let ident: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            // If ident is "name" or "target", expect a string literal
            if ident == "name" {
                let lit: Lit = input.parse()?;
                match lit {
                    Lit::Str(s) => name = Some(s),
                    _ => {
                        return Err(syn::Error::new_spanned(
                            lit,
                            "expected string literal for `name`",
                        ));
                    }
                }
            } else if ident == "target" {
                let lit: Lit = input.parse()?;
                match lit {
                    Lit::Str(s) => target = Some(s),
                    _ => {
                        return Err(syn::Error::new_spanned(
                            lit,
                            "expected string literal for `target`",
                        ));
                    }
                }
            } else {
                // parse arbitrary expression for the field value
                let expr: Expr = input.parse()?;
                fields.push((ident, expr));
            }

            // consume optional comma
            if input.peek(Token![,]) {
                let _comma: Token![,] = input.parse()?;
            } else {
                break;
            }
        }

        Ok(WideInstrumentArgs {
            name,
            target,
            fields,
        })
    }
}

/// Attribute macro that instruments a function with a wide-event span.
///
/// Supported attribute args:
/// - name = "literal"       (optional) logical event name recorded as span attribute
/// - target = "literal"     (optional) tracing target string
/// - key = expr, ...        record the expression as attribute `key` on the span
///
/// Example:
/// #[wide_instrument(server_name = params.server_name)]
/// async fn handler(params: Params) -> impl IntoResponse { ... }
#[proc_macro_attribute]
pub fn wide_instrument(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the input function
    let input_fn = parse_macro_input!(item as ItemFn);

    // Parse attribute arguments
    let args = if attr.is_empty() {
        WideInstrumentArgs {
            name: None,
            target: None,
            fields: vec![],
        }
    } else {
        match syn::parse::<WideInstrumentArgs>(attr) {
            Ok(a) => a,
            Err(e) => return e.to_compile_error().into(),
        }
    };

    match expand_wide_instrument(input_fn, args) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_wide_instrument(
    func: ItemFn,
    args: WideInstrumentArgs,
) -> syn::Result<proc_macro2::TokenStream> {
    // Destructure the function
    let vis = &func.vis;
    let attrs = func
        .attrs
        .into_iter()
        // remove the attribute itself if present (avoid recursive attribute)
        .filter(|a| !a.path().is_ident("wide_instrument"))
        .collect::<Vec<_>>();
    let sig = func.sig;
    let block = func.block;
    let fn_name = &sig.ident;
    let inputs = &sig.inputs;
    let generics = &sig.generics;
    let where_clause = &sig.generics.where_clause;

    // Determine return type
    let output_ty = match &sig.output {
        ReturnType::Default => syn::parse_quote! { () },
        ReturnType::Type(_, ty) => (*ty).clone(),
    };

    // Build default name and target expressions
    let name_ts = if let Some(lit) = args.name {
        quote! { #lit }
    } else {
        // Default to function name as string literal
        let fn_name_str = fn_name.to_string();
        let lit = LitStr::new(&fn_name_str, Span2::call_site());
        quote! { #lit }
    };
    let target_ts = if let Some(lit) = args.target {
        quote! { #lit }
    } else {
        quote! { concat!(env!("CARGO_PKG_NAME"), "::", module_path!()) }
    };

    // Prepare field recording statements and ensure we bind temporaries to avoid lifetime issues.
    // We'll create for each field:
    //   let __wide_field_N = &$expr;
    //   __wide_span_N.record("key", ::tracing::field::display(__wide_field_N));
    let mut field_bind_stmts = Vec::new();
    // Build a fresh identifier for the generated span to avoid collisions.
    let span_ident = format_ident!("__wide_span_{}", unique_suffix());
    for (i, (ident, expr)) in args.fields.into_iter().enumerate() {
        let key_name = ident.to_string();
        let tmp_ident = format_ident!("__wide_field_{}", i);
        // bind by reference to avoid moving original variables (more conservative)
        field_bind_stmts.push(quote! {
            let #tmp_ident = &#expr;
            #span_ident.record(#key_name, ::tracing::field::display(#tmp_ident));
        });
    }

    // If the function is async, transform it into a non-async function returning an impl Future
    // and instrument the async block with tracing_futures::Instrument so the span lives across await points.
    let expanded = if sig.asyncness.is_some() {
        // Build argument list tokens (we need to keep the same arguments)
        // We'll reuse the original signature but remove the async token and change the return type to impl Future<Output = ...>
        let inputs_clone = inputs.clone();
        let where_clause_clone = where_clause.clone();
        let generics_clone = generics.clone();

        quote! {
            #(#attrs)*
            #vis fn #fn_name #generics_clone(#inputs_clone) -> impl std::future::Future<Output = #output_ty> #where_clause_clone {
                // Create the wide_event span
                let #span_ident = ::tracing::span!(::tracing::Level::INFO, "wide_event", target = #target_ts, event.name = %#name_ts);
                // Record provided fields onto the span
                #(#field_bind_stmts)*

                // Create the async block (the original function body) and instrument it with the span so it remains active across await points.
                let __wide_async_block = async move #block;
                ::tracing_futures::Instrument::instrument(__wide_async_block, #span_ident)
            }
        }
    } else {
        // Non-async function: enter the span for the scope of the function body.
        quote! {
            #(#attrs)*
            #vis #sig {
                let #span_ident = ::tracing::span!(::tracing::Level::INFO, "wide_event", target = #target_ts, event.name = %#name_ts);
                #(#field_bind_stmts)*
                // Enter span for the function body lifetime (non-async so Entered is not held across await)
                let _wide_evt_enter = #span_ident.enter();
                #block
            }
        }
    };

    Ok(expanded)
}

/// Create a short unique-ish suffix used for internal identifiers to reduce collision chances.
fn unique_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}", nanos)
}
