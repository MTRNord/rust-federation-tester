use crate::cache::{DnsCache, WellKnownCache};
use crate::federation::{lookup_server, lookup_server_well_known};
use crate::response::Root;
use hickory_resolver::{Resolver, name_server::ConnectionProvider};

pub async fn lookup_server_well_known_cached<P: ConnectionProvider>(
    data: &mut Root,
    server_name: &str,
    resolver: &Resolver<P>,
    cache: &WellKnownCache,
    use_cache: bool,
) -> Result<Option<String>, crate::error::WellKnownError> {
    if use_cache && let Some(cached_result) = cache.get_cached(&server_name.to_string(), use_cache)
    {
        data.well_known_result
            .insert(server_name.to_string(), cached_result.clone());
        return Ok(if !cached_result.m_server.is_empty() {
            Some(cached_result.m_server)
        } else {
            None
        });
    }
    let result = lookup_server_well_known(data, server_name, resolver).await;
    if use_cache && let Some(well_known) = data.well_known_result.get(server_name) {
        cache.insert(server_name.to_string(), well_known.clone());
    }
    result
}

pub async fn lookup_server_cached<P: ConnectionProvider>(
    data: &mut Root,
    server_name: &str,
    resolver: &Resolver<P>,
    cache: &DnsCache,
    use_cache: bool,
) -> color_eyre::eyre::Result<()> {
    if use_cache && let Some(cached_addrs) = cache.get_cached(&server_name.to_string(), use_cache) {
        data.dnsresult.addrs = cached_addrs;
        return Ok(());
    }
    lookup_server(data, server_name, resolver).await?;
    if use_cache && !data.dnsresult.addrs.is_empty() {
        cache.insert(server_name.to_string(), data.dnsresult.addrs.clone());
    }
    Ok(())
}
