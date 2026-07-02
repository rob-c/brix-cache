#include "dashboard_http.h"
#include "compat/alloc_guard.h"

/*
 * dashboard/page.c - embedded dashboard UI.
 *
 * The page is self-contained and talks only to the /xrootd/api/v1 endpoints.
 * The legacy
 * /xrootd/transfers endpoint remains for compatibility with older callers.
 *
 * WHAT: a single static text/html asset (markup + inline CSS + inline JS),
 *       served verbatim by ngx_http_xrootd_dashboard_page_handler below.
 * WHY:  embedding the whole UI in one .rodata string keeps the dashboard a
 *       zero-dependency, zero-filesystem feature - no asset files to ship,
 *       package, or path-resolve at runtime, and no static-file disclosure
 *       surface. All dynamic state arrives over the JSON API at poll time.
 * HOW:  the literal is built from many adjacent string fragments that the C
 *       compiler concatenates; the comment lines interleaved below sit
 *       *between* fragments (legal, additive) and do not alter the bytes.
 *       Note: every backslash/quote here is C-escaped, so the on-wire HTML
 *       differs from the source text - count bytes via sizeof()-1, not by eye.
 */

/* static asset: document head, inline stylesheet (theme/layout only) */static const char ngx_xrootd_dashboard_html[] =
"<!DOCTYPE html>\n"
"<html lang=\"en\">\n"
"<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
"<title>nginx-xrootd Dashboard</title>\n"
"<style>\n"
"*{box-sizing:border-box}body{margin:0;background:#0f1419;color:#d8dee9;font:13px ui-monospace,SFMono-Regular,Consolas,monospace}\n"
"header{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.8rem 1rem;background:#151b23;border-bottom:1px solid #303842;position:sticky;top:0;z-index:2}\n"
"h1{font-size:1.1rem;margin:0;color:#8cc8ff}button,select,input{font:inherit;border:1px solid #394452;background:#111820;color:#e5edf5;border-radius:4px;padding:.45rem .55rem}\n"
"button{cursor:pointer}button:hover,select:focus,input:focus,button:focus{outline:2px solid #6aa9ff;outline-offset:1px}.status.live{color:#7ee787}.status.bad{color:#ff7b72}\n"
".toolbar,.cards,.panels{display:grid;gap:.65rem;padding:.75rem 1rem}.toolbar{grid-template-columns:repeat(5,minmax(0,1fr));background:#111820;border-bottom:1px solid #303842}\n"
"label{display:flex;flex-direction:column;gap:.25rem;color:#98a6b3;font-size:.78rem;text-transform:uppercase;letter-spacing:.03em}label>*{text-transform:none;letter-spacing:0;color:#d8dee9}\n"
".cards{grid-template-columns:repeat(4,minmax(0,1fr))}.card{border:1px solid #303842;background:#151b23;border-radius:6px;padding:.7rem}.card h2,.panel h2{font-size:.8rem;color:#98a6b3;margin:0 0 .45rem;text-transform:uppercase;letter-spacing:.04em}.metric{font-size:1.15rem;color:#fff}.sub{color:#98a6b3;font-size:.82rem;margin-top:.25rem}\n"
".table-wrap{padding:0 1rem 1rem}table{width:100%;border-collapse:collapse;font-size:12px}th,td{padding:.5rem .6rem;border-bottom:1px solid #252d36;text-align:left;vertical-align:top}th{position:sticky;top:50px;background:#151b23;color:#98a6b3;z-index:1}tbody tr{cursor:pointer}tbody tr:hover,tbody tr:focus{background:#17202a;outline:none}.path,.identity{max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.pill{display:inline-block;border-radius:999px;padding:.1rem .45rem;background:#263241}.state-active{color:#7ee787}.state-idle{color:#d29922}.state-throttled{color:#58a6ff}.state-stalled,.state-error{color:#ff7b72}.dir-read{color:#7ee787}.dir-write{color:#ffa657}.dir-tpc{color:#d2a8ff}\n"
".panels{grid-template-columns:2fr 1fr 1fr}.panel{border:1px solid #303842;background:#151b23;border-radius:6px;padding:.7rem;min-width:0}.events{max-height:220px;overflow:auto}.event{display:grid;grid-template-columns:5.5rem 5.5rem 1fr;gap:.5rem;border-top:1px solid #252d36;padding:.35rem 0}.event:first-child{border-top:0}.spark{width:100%;height:42px}.empty{padding:2rem;text-align:center;color:#6f7d8a}\n"
"#detail-panel{position:fixed;top:0;right:0;height:100vh;width:min(520px,100vw);background:#111820;border-left:1px solid #303842;box-shadow:-8px 0 24px rgba(0,0,0,.3);padding:1rem;overflow:auto;transform:translateX(105%);transition:transform .16s ease;z-index:4}#detail-panel.open{transform:translateX(0)}#detail-panel pre{white-space:pre-wrap;word-break:break-word;background:#0b1016;border:1px solid #303842;border-radius:6px;padding:.75rem}.detail-head{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin-bottom:.75rem}\n"
"@media(max-width:860px){.toolbar,.cards,.panels{grid-template-columns:1fr}.hide-sm{display:none}.path,.identity{max-width:180px}th{top:48px}}\n"
"@media(prefers-reduced-motion:reduce){#detail-panel{transition:none}}\n"
"</style></head>\n"
/* static asset: page chrome (header, toolbar, cards, table, panels) */"<body>\n"
"<header><h1>nginx-xrootd Dashboard</h1><div><button id=\"download-config\" type=\"button\" title=\"Download the running config (secrets redacted)\">Config</button> <button id=\"export-snapshot\" type=\"button\">Export</button> <span id=\"status\" class=\"status bad\" aria-live=\"polite\">connecting</span></div></header>\n"
"<div id=\"anon-banner\" role=\"status\" hidden style=\"padding:.5rem 1rem;background:#3a2d10;color:#ffd479;border-bottom:1px solid #5a4a1a;font-size:.85rem\">Anonymous read-only view \xe2\x80\x94 client identities, paths and other sensitive data are hidden. <a href=\"/xrootd/login\" style=\"color:#8cc8ff\">Sign in</a> for full details.</div>\n"
"<section class=\"toolbar\" aria-label=\"Transfer filters\">\n"
"<label for=\"protocol-filter\">Protocol<select id=\"protocol-filter\"><option value=\"\">All</option><option>root</option><option>webdav</option><option>s3</option></select></label>\n"
"<label for=\"direction-filter\">Direction<select id=\"direction-filter\"><option value=\"\">All</option><option>read</option><option>write</option><option>tpc</option></select></label>\n"
"<label for=\"state-filter\">State<select id=\"state-filter\"><option value=\"\">All</option><option>active</option><option>idle</option><option>throttled</option><option>stalled</option><option>closing</option><option>error</option></select></label>\n"
"<label for=\"sort-select\">Sort<select id=\"sort-select\"><option value=\"rate\">Rate</option><option value=\"bytes\">Bytes</option><option value=\"age\">Age</option><option value=\"idle\">Idle</option><option value=\"protocol\">Protocol</option><option value=\"client\">Client</option></select></label>\n"
"<label for=\"search-box\">Search<input id=\"search-box\" type=\"search\" autocomplete=\"off\"></label>\n"
"</section>\n"
"<section class=\"cards\" id=\"protocol-cards\" aria-label=\"Protocol summaries\"></section>\n"
"<div class=\"table-wrap\"><table aria-label=\"Active transfers\"><thead><tr><th>ID</th><th>Client</th><th>Identity</th><th>Path</th><th>Proto</th><th>Dir</th><th>State</th><th>Bytes</th><th>Rate</th><th class=\"hide-sm\">Idle</th></tr></thead><tbody id=\"tbody\"></tbody></table><div id=\"empty\" class=\"empty\" hidden>No active transfers</div></div>\n"
"<section class=\"panels\">\n"
"<div class=\"panel\"><h2>History</h2><svg id=\"history-spark\" class=\"spark\" role=\"img\" aria-label=\"Recent transfer activity\"></svg><div id=\"history-caption\" class=\"sub\"></div></div>\n"
"<div class=\"panel\"><h2>Cache</h2><div id=\"cache-panel\"></div></div>\n"
"<div class=\"panel\"><h2>Cluster</h2><div id=\"cluster-panel\"></div></div>\n"
"</section>\n"
"<section class=\"panels\" style=\"grid-template-columns:1fr\"><div class=\"panel events\" id=\"events-panel\"><h2>Recent Events</h2><div id=\"events-list\"></div></div></section>\n"
/* admin file browser (hidden unless xrootd_dashboard_browse_root set and
 *      the viewer is authenticated; populated by filesBrowse() in the script) ---- */
"<section class=\"panels\" style=\"grid-template-columns:1fr\" id=\"files-section\" hidden><div class=\"panel\"><h2>Files</h2><div id=\"files-bc\" class=\"sub\" style=\"margin-bottom:.5rem\"></div><div class=\"table-wrap\"><table aria-label=\"Files\"><thead><tr><th>Name</th><th>Owner</th><th>Size</th><th>Created</th><th class=\"hide-sm\">Modified</th><th></th></tr></thead><tbody id=\"files-tbody\"></tbody></table><div id=\"files-empty\" class=\"empty\" hidden>Empty directory</div></div></div></section>\n"
"<aside id=\"detail-panel\" aria-label=\"Transfer detail\" aria-hidden=\"true\"><div class=\"detail-head\"><h2>Transfer Detail</h2><button id=\"detail-close\" type=\"button\">Close</button></div><pre id=\"detail-body\"></pre></aside>\n"
/*
 * static asset: inline client logic (browser-side; not compiled C)
 *
 * WHAT: the client polls API+'/snapshot' every 2 s and re-renders from the
 *       latest snapshot; detail rows are fetched lazily from
 *       API+'/transfers/<id>'.
 * WHY:  reviewer note - this fragment encodes the dashboard's API contract.
 *       The field names referenced here (active_transfers, protocols, cache,
 *       cluster, events, history.buckets, server_ms, avg_bps, idle_ms, ...)
 *       must stay in lockstep with the JSON emitted by dashboard/api.c.
 * HOW:  caching/auth control flow that matters on review -
 *       - API base is hard-pinned to '/xrootd/api/v1' (see var API below).
 *       - every fetch uses {cache:'no-store'} so the browser never serves a
 *         stale snapshot; freshness is the poll loop's job, not the HTTP cache.
 *       - a 401 from the snapshot poll triggers a client-side redirect to
 *         '/xrootd/login' (session cookie expired) - mirrors the server-side
 *         redirect in the page handler below.
 *       - esc() HTML-escapes every server-supplied string before it reaches
 *         innerHTML; this is the XSS guard for untrusted path/identity/client
 *         values, so do not bypass it when adding columns.
 */
"<script>\n"
"'use strict';\n"
"var API='/xrootd/api/v1';var lastSnapshot=null;var selectedDetail=null;\n"
"var controls=['protocol-filter','direction-filter','state-filter','sort-select','search-box'];\n"
"function el(id){return document.getElementById(id)}\n"
"function fmt(n){n=Number(n)||0;if(n>=1e12)return(n/1e12).toFixed(2)+' TB';if(n>=1e9)return(n/1e9).toFixed(2)+' GB';if(n>=1e6)return(n/1e6).toFixed(2)+' MB';if(n>=1e3)return(n/1e3).toFixed(2)+' KB';return n+' B'}\n"
"function rate(n){return fmt(n)+'/s'}function age(ms){var s=Math.max(0,Math.floor((Date.now()-ms)/1000));if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m';return Math.floor(s/3600)+'h'}\n"
"function esc(s){return String(s==null?'':s).replace(/[&<>\"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]})}\n"
"function saveControls(){controls.forEach(function(id){localStorage.setItem('xrd_dash_'+id,el(id).value)})}\n"
"function loadControls(){controls.forEach(function(id){var v=localStorage.getItem('xrd_dash_'+id);if(v!==null)el(id).value=v;el(id).addEventListener('input',function(){saveControls();render()})})}\n"
"function filteredRows(){var rows=(lastSnapshot&&lastSnapshot.active_transfers)||[];var p=el('protocol-filter').value,d=el('direction-filter').value,s=el('state-filter').value,q=el('search-box').value.toLowerCase();rows=rows.filter(function(r){var blob=[r.id,r.path,r.identity,r.client].join(' ').toLowerCase();return(!p||r.protocol===p)&&(!d||r.direction===d)&&(!s||r.state===s)&&(!q||blob.indexOf(q)>=0)});var sort=el('sort-select').value;rows.sort(function(a,b){if(sort==='bytes')return b.bytes-a.bytes;if(sort==='age')return a.start_ms-b.start_ms;if(sort==='idle')return b.idle_ms-a.idle_ms;if(sort==='protocol')return String(a.protocol).localeCompare(String(b.protocol));if(sort==='client')return String(a.client).localeCompare(String(b.client));return (b.avg_bps||0)-(a.avg_bps||0)});return rows}\n"
"function renderCards(){var p=(lastSnapshot&&lastSnapshot.protocols)||{};var names=['root','webdav','s3','tpc'];el('protocol-cards').innerHTML=names.map(function(n){var x=p[n]||{};return '<div class=\"card\"><h2>'+n+'</h2><div class=\"metric\">'+(x.active||0)+' active</div><div class=\"sub\">in '+rate(x.ingress_bps||0)+' / out '+rate(x.egress_bps||0)+'</div></div>'}).join('')}\n"
"function renderRows(){var rows=filteredRows(),body='';rows.forEach(function(r){body+='<tr tabindex=\"0\" data-id=\"'+esc(r.id)+'\" class=\"state-'+esc(r.state)+'\"><td>'+esc(r.id)+'</td><td>'+esc(r.client)+'</td><td class=\"identity\" title=\"'+esc(r.identity)+'\">'+esc(r.identity)+'</td><td class=\"path\" title=\"'+esc(r.path)+'\">'+esc(r.path)+'</td><td><span class=\"pill\">'+esc(r.protocol)+'</span></td><td class=\"dir-'+esc(r.direction)+'\">'+esc(r.direction)+'</td><td class=\"state-'+esc(r.state)+'\">'+esc(r.state)+'</td><td>'+fmt(r.bytes)+'</td><td>'+rate(r.avg_bps||r.instant_bps||0)+'</td><td class=\"hide-sm\">'+(r.idle_ms||0)+' ms</td></tr>'});el('tbody').innerHTML=body;el('empty').hidden=rows.length!==0;Array.prototype.forEach.call(el('tbody').querySelectorAll('tr'),function(tr){tr.onclick=function(){openDetail(tr.getAttribute('data-id'))};tr.onkeydown=function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();openDetail(tr.getAttribute('data-id'))}}})}\n"
"function renderPanels(){var c=(lastSnapshot&&lastSnapshot.cache)||{};var listeners=c.listeners||[];el('cache-panel').innerHTML='<div class=\"metric\">'+(c.enabled?'enabled':'disabled')+'</div><div class=\"sub\">listeners '+listeners.length+'</div><div class=\"sub\">WT pending '+(((c.write_through||{}).flush_pending)||0)+'</div>';var cl=(lastSnapshot&&lastSnapshot.cluster)||{};var servers=cl.servers||[];el('cluster-panel').innerHTML='<div class=\"metric\">'+servers.length+' servers</div>'+servers.slice(0,4).map(function(s){return '<div class=\"sub\">'+esc(s.host)+':'+esc(s.port)+' '+(s.stale?'stale':'ok')+'</div>'}).join('');var events=(lastSnapshot&&lastSnapshot.events)||[];el('events-list').innerHTML=events.slice(-20).reverse().map(function(e){return '<div class=\"event\"><span>'+esc(e.class)+'</span><span>'+esc(e.protocol)+'</span><span>'+esc(e.message)+'</span></div>'}).join('')||'<div class=\"sub\">No recent events</div>';drawHistory()}\n"
"function drawHistory(){var h=(lastSnapshot&&lastSnapshot.history&&lastSnapshot.history.buckets)||[];var svg=el('history-spark');var max=1;var pts=h.map(function(b,i){var v=(b.active_root||0)+(b.active_webdav||0)+(b.active_s3||0)+(b.active_tpc||0);if(v>max)max=v;return v});var w=300,hgt=42,d=pts.map(function(v,i){var x=pts.length<2?0:i*(w/(pts.length-1));var y=hgt-(v/max)*(hgt-4)-2;return (i?'L':'M')+x.toFixed(1)+' '+y.toFixed(1)}).join(' ');svg.setAttribute('viewBox','0 0 '+w+' '+hgt);svg.innerHTML='<path d=\"'+d+'\" fill=\"none\" stroke=\"#8cc8ff\" stroke-width=\"2\"/><line x1=\"0\" y1=\"40\" x2=\"300\" y2=\"40\" stroke=\"#303842\"/>';el('history-caption').textContent=pts.length+' buckets, peak '+max+' active'}\n"
"function render(){renderCards();renderRows();renderPanels()}\n"
"function poll(){fetch(API+'/snapshot',{cache:'no-store'}).then(function(r){if(r.status===401){location.href='/xrootd/login';return null}if(!r.ok)throw new Error(r.status);return r.json()}).then(function(data){if(!data)return;lastSnapshot=data;applyAnon(!!data.anonymous);el('status').className='status live';el('status').textContent='live '+new Date(data.server_ms).toLocaleTimeString();render();if(selectedDetail)openDetail(selectedDetail,true);if(!data.anonymous&&!filesTried){filesTried=true;filesBrowse('/')}}).catch(function(){el('status').className='status bad';el('status').textContent='disconnected'})}\n"
"function openDetail(id,quiet){selectedDetail=id;fetch(API+'/transfers/'+encodeURIComponent(id),{cache:'no-store'}).then(function(r){return r.json().then(function(j){return{ok:r.ok,json:j}})}).then(function(x){var panel=el('detail-panel');panel.classList.add('open');panel.setAttribute('aria-hidden','false');el('detail-body').textContent=JSON.stringify(x.json.transfer||x.json,null,2);if(!quiet)el('detail-close').focus()})}\n"
"function closeDetail(){selectedDetail=null;el('detail-panel').classList.remove('open');el('detail-panel').setAttribute('aria-hidden','true')}\n"
"function exportSnapshot(){if(!lastSnapshot)return;var safe=JSON.parse(JSON.stringify(lastSnapshot));var blob=new Blob([JSON.stringify(safe,null,2)],{type:'application/json'});var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='xrootd-dashboard-snapshot.json';a.click();setTimeout(function(){URL.revokeObjectURL(a.href)},500)}\n"
/* Navigate to the auth-only config endpoint; the server replies with a
 * Content-Disposition attachment so the browser downloads it directly. */
"function downloadConfig(){window.location=API+'/config'}\n"
/* admin file browser (auth-only; 404 = feature disabled => stay hidden) */"var filesTried=false;\n"
"function fileDate(t){t=Number(t)||0;return t?new Date(t*1000).toLocaleString():''}\n"
"function filesRender(d){var base=(d.path||'/').replace(/\\/+$/,'');var rows=(d.entries||[]).slice();"
"rows.sort(function(a,b){if((a.type==='dir')!==(b.type==='dir'))return a.type==='dir'?-1:1;return String(a.name).localeCompare(String(b.name))});"
"var bc='<a href=\"#\" data-p=\"/\">root</a>';var acc='';base.split('/').filter(Boolean).forEach(function(seg){acc+='/'+seg;bc+=' / <a href=\"#\" data-p=\"'+esc(acc)+'\">'+esc(seg)+'</a>'});el('files-bc').innerHTML=bc;"
"var body='';rows.forEach(function(e){var full=(base==='/'?'':base)+'/'+e.name;if(e.type==='dir'){body+='<tr class=\"fdir\" data-p=\"'+esc(full)+'\" tabindex=\"0\" style=\"cursor:pointer\"><td>\xf0\x9f\x93\x81 '+esc(e.name)+'/</td><td>'+esc(e.owner)+'</td><td></td><td>'+esc(fileDate(e.btime||e.mtime))+'</td><td class=\"hide-sm\">'+esc(fileDate(e.mtime))+'</td><td></td></tr>'}else{var dl=API+'/download?path='+encodeURIComponent(full);body+='<tr><td>'+esc(e.name)+'</td><td>'+esc(e.owner)+'</td><td>'+fmt(e.size)+'</td><td>'+esc(fileDate(e.btime||e.mtime))+'</td><td class=\"hide-sm\">'+esc(fileDate(e.mtime))+'</td><td><a href=\"'+dl+'\">Download</a></td></tr>'}});"
"el('files-tbody').innerHTML=body+(d.truncated?'<tr><td colspan=\"6\" class=\"sub\">(listing truncated)</td></tr>':'');el('files-empty').hidden=rows.length!==0;"
"Array.prototype.forEach.call(el('files-tbody').querySelectorAll('tr.fdir'),function(tr){function go(){filesBrowse(tr.getAttribute('data-p'))}tr.onclick=go;tr.onkeydown=function(ev){if(ev.key==='Enter'){ev.preventDefault();go()}}});"
"Array.prototype.forEach.call(el('files-bc').querySelectorAll('a'),function(a){a.onclick=function(ev){ev.preventDefault();filesBrowse(a.getAttribute('data-p'))}})}\n"
"function filesBrowse(p){fetch(API+'/files?path='+encodeURIComponent(p||'/'),{cache:'no-store'}).then(function(r){if(r.status===404){el('files-section').hidden=true;return null}if(r.status===401){location.href='/xrootd/login';return null}if(!r.ok)throw new Error(r.status);return r.json()}).then(function(d){if(!d)return;el('files-section').hidden=false;filesRender(d)}).catch(function(){})}\n"
/* Toggle the anonymous banner and hide the auth-only buttons when the snapshot
 * arrives redacted (anonymous:true). */
"function applyAnon(a){var x=el('anon-banner');if(x)x.hidden=!a;var c=el('download-config');if(c)c.style.display=a?'none':'';var e=el('export-snapshot');if(e)e.style.display=a?'none':'';var f=el('files-section');if(f&&a)f.hidden=true}\n"
"loadControls();el('detail-close').onclick=closeDetail;el('export-snapshot').onclick=exportSnapshot;el('download-config').onclick=downloadConfig;document.addEventListener('keydown',function(e){if(e.key==='Escape')closeDetail()});poll();setInterval(poll,2000);\n"
"</script>\n"
"</body></html>\n";

/*
 * Content handler for the dashboard page route.
 *
 * WHAT: gate on the session cookie, then serve the embedded HTML asset above.
 * WHY:  the UI is behind the same cookie auth as the JSON API, so an
 *       unauthenticated GET must be bounced to the login page rather than
 *       leaking the dashboard shell.
 * HOW:  flow is (1) auth check -> on failure emit a 302 to
 *       <cookie_path>/login and return; (2) reject non-GET/HEAD; (3) hand
 *       back the static literal as a single memory-backed buffer.
 * Returns an NGX_HTTP_* status on error, or the output-filter result.
 */
ngx_int_t
ngx_http_xrootd_dashboard_page_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_dashboard_loc_conf_t *conf;
    ngx_buf_t                            *b;
    ngx_chain_t                           out;
    size_t                                html_len;
    ngx_int_t                             rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_dashboard_module);

    /*
     * SECURITY: cookie/session gate. Any non-NGX_OK (no/expired/invalid cookie)
     * means "not logged in". We then either (a) serve the page shell anyway when
     * xrootd_dashboard_anonymous is on - its JS will receive PII/secret-redacted
     * JSON and render the anonymous banner - or (b) redirect to login. The shell
     * itself contains no data, so serving it anonymously leaks nothing; all
     * redaction is enforced by the JSON API the JS fetches.
     */
    rc = ngx_http_xrootd_dashboard_check_auth(r, conf, conf->anonymous);
    if (rc != NGX_OK && !conf->anonymous) {
        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        r->headers_out.location->hash = 1;
        ngx_str_set(&r->headers_out.location->key, "Location");
        {
            /*
             * Build the redirect target "<cookie_path>/login" in the request
             * pool. Byte math: sizeof("/login") == 7 (includes the NUL), so
             * the alloc reserves room for cookie_path + "/login" + trailing
             * NUL. The memcpy of "/login" copies all 7 bytes including the
             * NUL terminator (defensive null-termination of the buffer).
             * The emitted ngx_str_t .len, however, is cookie_path.len + 7 - 1,
             * i.e. excludes that NUL - nginx header values are length-counted,
             * not C strings, so the NUL must not be on the wire.
             */
            u_char *loc = ngx_pnalloc(r->pool, conf->cookie_path.len
                                               + sizeof("/login"));
            if (loc == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_memcpy(loc, conf->cookie_path.data, conf->cookie_path.len);
            ngx_memcpy(loc + conf->cookie_path.len, "/login",
                       sizeof("/login"));
            r->headers_out.location->value.data = loc;
            r->headers_out.location->value.len = conf->cookie_path.len
                                                 + sizeof("/login") - 1;
        }
        return NGX_HTTP_MOVED_TEMPORARILY;
    }

    /* Read-only asset: only GET (full body) and HEAD (headers only). */
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* -1 drops the literal's terminating NUL: send the HTML, not the NUL. */
    html_len = sizeof(ngx_xrootd_dashboard_html) - 1;
    XROOTD_PCALLOC_OR_RETURN(b, r->pool, sizeof(*b), NGX_HTTP_INTERNAL_SERVER_ERROR);

    /*
     * Point the buffer straight at the const .rodata literal - no copy. Safe
     * because the literal outlives the request and is never mutated. b->memory
     * marks it read-only/in-memory (not file-backed, so no sendfile); b->last_buf
     * makes this the sole and final buf of the response.
     */
    b->pos = (u_char *) ngx_xrootd_dashboard_html;
    b->last = b->pos + html_len;
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) html_len;
    r->headers_out.content_type =
        (ngx_str_t) ngx_string("text/html; charset=utf-8");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    rc = ngx_http_send_header(r);
    /*
     * Bail before emitting a body when: send_header failed (NGX_ERROR),
     * returned a special/error code (rc > NGX_OK), or this is a HEAD request
     * (r->header_only) where the body must be suppressed. Otherwise fall
     * through and write the single-buffer chain.
     */
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    out.buf = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}
