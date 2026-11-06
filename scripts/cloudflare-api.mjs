export function cloudflareAPI(token, fetcher = fetch) {
  if (!token) throw Error('Set CLOUDFLARE_NETWORK_API_TOKEN');
  async function request(path, { method = 'GET', body, allow404 = false } = {}) {
    const response = await fetcher('https://api.cloudflare.com/client/v4' + path, {
      method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(30000),
    });
    if (allow404 && response.status === 404) return null;
    const data = await response.json();
    // Never echo response bodies: tunnel APIs can return credentials.
    if (!response.ok || data.success !== true) throw Error(`Cloudflare ${method} ${path.split('?')[0]} failed (HTTP ${response.status}; codes ${(data.errors || []).map(e => e.code).join(',')})`);
    return data;
  }
  async function list(path, query = {}, cursorMode = false) {
    const results = [], cursors = new Set(); let cursor;
    for (let page = 1; page <= 100; page++) {
      const params = new URLSearchParams({ ...query, per_page: cursorMode ? '50' : '100', ...(cursorMode ? cursor ? { cursor } : {} : { page: String(page) }) });
      const data = await request(`${path}?${params}`);
      if (!Array.isArray(data.result)) throw Error('Unexpected Cloudflare list response');
      results.push(...data.result);
      if (cursorMode) {
        cursor = data.result_info?.cursors?.after;
        if (!cursor) return results;
        if (typeof cursor !== 'string' || cursors.has(cursor)) throw Error('Repeated Cloudflare cursor');
        cursors.add(cursor);
      } else {
        const total = data.result_info?.total_pages;
        if (total !== undefined && (!Number.isInteger(total) || total < 0)) throw Error('Unexpected Cloudflare pagination');
        if (total !== undefined ? page >= total : data.result.length < 100) return results;
      }
    }
    throw Error('Cloudflare pagination exceeded supported size');
  }
  return { request, list };
}
