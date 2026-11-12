const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const { webcrypto } = require('node:crypto');
const source = fs.readFileSync('web/public/ProviderHintRedirect.js', 'utf8');
async function redirect(userAgent, provider) {
 const start = new URL('https://iam.example/login/oauth/authorize?client_id=member&response_type=code&redirect_uri=https%3A%2F%2Fmember.example%2Fauth%2Fcallback&state=outer-state&nonce=nonce&code_challenge=challenge&code_challenge_method=S256&provider_hint=wechat');
 let target;
 const store = { getItem: () => null, setItem: () => {} };
 const location = { href: start.href, pathname: start.pathname, search: start.search, origin: start.origin, replace: url => { target = new URL(url, start); } };
 const sandbox = { URL, URLSearchParams, TextEncoder, Uint8Array, crypto: webcrypto, navigator: {userAgent, language:'en'}, localStorage: store, sessionStorage: store, btoa: value => Buffer.from(value).toString('base64'), document: {querySelector:()=>null}, fetch: async () => ({json:async()=>({status:'ok',data:{name:'member',providers:[{canSignIn:true,provider:{owner:'admin',name:'wechat',category:'OAuth',type:'WeChat',subType:'Web',clientId:'wx-open',clientId2:'wx-official',disableSsl:true,signName:'media',...provider}}]}})}) };
 sandbox.window = { location, crypto:webcrypto };
 vm.runInNewContext(source,sandbox);
 await sandbox.window.CasdoorProviderHintRedirect.run();
 return target;
}
test('desktop official-account hint hands off to the existing QR UI with the PKCE transaction intact', async () => {
 const url=await redirect('Mozilla/5.0 Chrome/130');
 assert.equal(url.pathname,'/login/oauth/authorize');
 assert.equal(url.searchParams.get('__casdoor_provider_hint_react'),'1');
 assert.equal(url.searchParams.get('provider_hint'),'wechat');
 for(const [key,value] of Object.entries({state:'outer-state',nonce:'nonce',code_challenge:'challenge',code_challenge_method:'S256',redirect_uri:'https://member.example/auth/callback'})) assert.equal(url.searchParams.get(key),value);
 assert.equal(url.searchParams.has('code'),false);
});
test('WeChat in-app authorization still opens official-account OAuth directly',async()=>{
 const url=await redirect('Mozilla/5.0 MicroMessenger/8.0');
 assert.equal(url.origin,'https://open.weixin.qq.com');
 assert.equal(url.pathname,'/connect/oauth2/authorize');
 assert.equal(url.searchParams.get('appid'),'wx-official');
});
test('desktop open-platform login without official-account QR keeps its normal redirect',async()=>{
 const url=await redirect('Mozilla/5.0 Chrome/130',{disableSsl:false});
 assert.equal(url.origin,'https://open.weixin.qq.com');
 assert.equal(url.pathname,'/connect/qrconnect');
});
