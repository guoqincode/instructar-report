'use strict';
// Public generic code; report content and file descriptors arrive only after decryption.
const sessions=new Map(),waiting=new Map(),MAX_CACHE=32*1024*1024;
const hex=b=>Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('');
const digest=async b=>hex(await crypto.subtle.digest('SHA-256',b));
self.addEventListener('install',e=>e.waitUntil(self.skipWaiting()));
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('message',e=>{
 if(e.data?.type!=='instructar-init-v2')return;
 const {session,key,manifest,base}=e.data;
 try{
  const u=new URL(base),origin=new URL(self.registration.scope).origin;
  if(u.origin!==origin||u.href!==self.registration.scope||!/^[a-f0-9]{32}$/.test(session)||manifest?.format!=='instructar-lazy-v2'||key?.type!=='secret'||key?.extractable!==false)throw Error('Invalid resource session');
  if(!sessions.has(session))sessions.set(session,{key,manifest,base,cache:new Map(),inflight:new Map(),bytes:0});
  if(waiting.has(session)){waiting.get(session).resolve(sessions.get(session));waiting.delete(session);}
  e.ports[0]?.postMessage({ok:true});
 }catch(error){e.ports[0]?.postMessage({ok:false,error:error.message});}
});
async function sessionFor(id){
 if(sessions.has(id))return sessions.get(id);
 if(waiting.has(id))return waiting.get(id).promise;
 let resolve,reject;
 const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});
 waiting.set(id,{promise,resolve,reject});
 const clients=await self.clients.matchAll({type:'window',includeUncontrolled:true});
 for(const client of clients)client.postMessage({type:'instructar-need-session-v2',session:id});
 const timer=setTimeout(()=>{waiting.delete(id);reject(Error('Encrypted session unavailable'));},10000);
 try{return await promise;}finally{clearTimeout(timer);}
}
async function decrypt(state,descriptor){
 const key=descriptor.encryptedSha256;
 if(state.cache.has(key)){const b=state.cache.get(key);state.cache.delete(key);state.cache.set(key,b);return b;}
 if(state.inflight.has(key))return state.inflight.get(key);
 const task=(async()=>{
  if(!/^sealed\/[a-f0-9]{64}\.bin$/.test(descriptor.url))throw Error('Invalid encrypted path');
  const response=await fetch(new URL(descriptor.url,state.base),{cache:'force-cache'});
  if(!response.ok)throw Error('Encrypted file unavailable');
  const sealed=await response.arrayBuffer(),buf=new Uint8Array(sealed);
  if(buf.length!==descriptor.encryptedBytes||await digest(sealed)!==descriptor.encryptedSha256||new TextDecoder().decode(buf.slice(0,8))!=='LRSEAL1\0'||hex(buf.slice(8,24))!==state.manifest.saltHex)throw Error('Ciphertext verification failed');
  const payload=await crypto.subtle.decrypt({name:'AES-GCM',iv:buf.slice(24,36),additionalData:buf.slice(0,8)},state.key,buf.slice(36));
  const plain=descriptor.encoding==='gzip'?await new Response(new Blob([payload]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer():payload;
  if(plain.byteLength!==descriptor.plainBytes||await digest(plain)!==descriptor.plainSha256)throw Error('Plaintext verification failed');
  while(state.bytes+plain.byteLength>MAX_CACHE&&state.cache.size){const oldest=state.cache.keys().next().value;state.bytes-=state.cache.get(oldest).byteLength;state.cache.delete(oldest);}
  if(plain.byteLength<=MAX_CACHE){state.cache.set(key,plain);state.bytes+=plain.byteLength;}
  return plain;
 })();state.inflight.set(key,task);
 try{return await task;}finally{state.inflight.delete(key);}
}
function rangeResponse(buffer,mime,range,head){
 const total=buffer.byteLength,headers={'Content-Type':mime,'Cache-Control':'no-store','Accept-Ranges':'bytes','X-Content-Type-Options':'nosniff'};
 if(!range){headers['Content-Length']=String(total);return new Response(head?null:buffer,{headers});}
 const m=/^bytes=(\d*)-(\d*)$/.exec(range);
 let start,end;
 if(m&&(m[1]||m[2])){if(!m[1]){start=Math.max(0,total-Number(m[2]));end=total-1;}else{start=Number(m[1]);end=m[2]?Math.min(total-1,Number(m[2])):total-1;}}
 if(!Number.isSafeInteger(start)||!Number.isSafeInteger(end)||start<0||start>=total||end<start){headers['Content-Range']='bytes */'+total;return new Response(null,{status:416,headers});}
 headers['Content-Range']='bytes '+start+'-'+end+'/'+total;headers['Content-Length']=String(end-start+1);
 return new Response(head?null:buffer.slice(start,end+1),{status:206,headers});
}
async function handle(request,path){
 const [id,kind,...rest]=path.split('/');
 try{
  if(!/^[a-f0-9]{32}$/.test(id)||!['GET','HEAD'].includes(request.method))throw Error('Invalid private route');
  const state=await sessionFor(id),name=decodeURIComponent(rest.join('/'));
  let descriptor;
  if(kind==='page')descriptor=state.manifest.pages[name];
  else if(kind==='asset')descriptor=state.manifest.resources[name];
  if(!descriptor)return new Response('Resource unavailable',{status:404,headers:{'Cache-Control':'no-store'}});
  let plain=await decrypt(state,descriptor);
  if(kind==='page'){
   const root=new URL('__private__/'+id+'/',state.base).href;
   let html=new TextDecoder().decode(plain);
   html=html.replace(/__IR_RESOURCE_([A-Za-z0-9_-]+)__/g,(_,key)=>{if(!Object.hasOwn(state.manifest.resources,key))throw Error('Missing asset');return root+'asset/'+key;});
   html=html.replace(/__IR_PAGE_([a-z0-9_]+\.html)__/g,(_,p)=>{if(!Object.hasOwn(state.manifest.pages,p))throw Error('Missing page');return root+'page/'+encodeURIComponent(p);});
   plain=new TextEncoder().encode(html).buffer;
  }
  return rangeResponse(plain,descriptor.mime,request.headers.get('range'),request.method==='HEAD');
 }catch(error){
  const clients=await self.clients.matchAll({type:'window'});
  for(const client of clients)client.postMessage({type:'instructar-asset-error-v2',session:id});
  return new Response('Unable to load encrypted resource. Refresh the original report link.',{status:503,headers:{'Cache-Control':'no-store'}});
 }
}
self.addEventListener('fetch',e=>{
 const url=new URL(e.request.url),prefix=new URL('__private__/',self.registration.scope);
 if(url.origin===prefix.origin&&url.pathname.startsWith(prefix.pathname))e.respondWith(handle(e.request,url.pathname.slice(prefix.pathname.length)));
});
