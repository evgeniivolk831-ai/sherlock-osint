import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json({limit:"8mb"}));
app.use(express.static(path.join(__dirname,"public")));

const asArray = v => v == null ? [] : Array.isArray(v) ? v : [v];
const fill = (v,u) => typeof v === "string" ? v.replaceAll("{}",u) :
  Array.isArray(v) ? v.map(x=>fill(x,u)) :
  v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k,x])=>[k,fill(x,u)])) : v;

function extractMeta(html) {
  const decode = s => s.replace(/&amp;/g,"&").replace(/&quot;/g,'"').replace(/&#39;|&apos;/g,"'")
    .replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/<[^>]*>/g,"").trim();
  const get = key => {
    const tags = html.match(/<meta\b[^>]*>/gi) || [];
    for (const tag of tags) {
      const name = (tag.match(/\b(?:property|name)\s*=\s*["']([^"']+)["']/i)||[])[1];
      if (name?.toLowerCase() === key.toLowerCase())
        return decode((tag.match(/\bcontent\s*=\s*["']([^"']*)["']/i)||[])[1]||"").slice(0,500);
    }
    return "";
  };
  const title = decode((html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)||[])[1]||"").slice(0,160);
  const displayName = get("og:title") || title;
  const bio = get("og:description") || get("description") || get("twitter:description");
  const avatarUrl = get("og:image") || get("twitter:image");
  return {displayName,bio,avatarUrl:avatarUrl.startsWith("https://")?avatarUrl:""};
}

async function checkSite(name, site, username) {
  const profileUrl = fill(site.url || "",username);
  const probeUrl = fill(site.urlProbe || site.url || "",username);
  const unknown = reason => ({site:name,url:profileUrl,status:"unknown",reason});
  if (!profileUrl.startsWith("https://") || !probeUrl.startsWith("https://")) return unknown("Небезопасный или отсутствующий HTTPS-шаблон");
  if (site.regexCheck) {
    try { if (!new RegExp(site.regexCheck).test(username)) return unknown("Username не соответствует regex сайта"); }
    catch { return unknown("Некорректное regex-правило сайта"); }
  }
  const types = asArray(site.errorType).filter(x=>typeof x==="string");
  const supported = ["message","status_code","response_url"];
  if (!types.length || types.some(x=>!supported.includes(x))) return unknown("Метод проверки не поддерживается");
  const method = String(site.request_method || (types.length===1 && types[0]==="status_code"?"HEAD":"GET")).toUpperCase();
  if (!["GET","HEAD","POST"].includes(method)) return unknown("HTTP-метод не поддерживается");
  const controller = new AbortController();
  const timer = setTimeout(()=>controller.abort(),10000);
  try {
    const headers = {"User-Agent":"SherlockCommunity/1.0 public-profile-checker","Accept":"text/html,application/xhtml+xml,*/*"};
    for (const [k,v] of Object.entries(site.headers||{})) {
      if (typeof v==="string" && !/^(host|content-length|connection)$/i.test(k)) headers[k]=v;
    }
    const payload = site.request_payload === undefined ? undefined : fill(site.request_payload,username);
    const response = await fetch(probeUrl,{
      method,headers,redirect:types.includes("response_url")?"manual":"follow",
      ...(payload!==undefined && method==="POST"?{body:typeof payload==="string"?payload:JSON.stringify(payload),headers:{...headers,"Content-Type":"application/json"}}:{}),
      signal:controller.signal
    });
    const code=response.status;
    if ([403,429,503].includes(code)) return {...unknown("Сайт ограничил запрос или включил anti-bot"),httpStatus:code};
    if (code>=500) return {...unknown("Ошибка на стороне сайта"),httpStatus:code};
    let html="";
    if(method!=="HEAD" && (types.includes("message")||types.includes("status_code"))) html=(await response.text()).slice(0,1200000);
    if (/captcha|verify you are human|challenge-platform|checking your browser/i.test(html))
      return {...unknown("CAPTCHA или anti-bot; результат не подтверждён"),httpStatus:code};
    let verdict=null;
    if(types.includes("message")) {
      const messages=asArray(site.errorMsg).filter(x=>typeof x==="string"&&x.length);
      if(!messages.length) return {...unknown("Для message отсутствует errorMsg"),httpStatus:code};
      verdict=messages.some(m=>html.includes(m))?"not_found":"found";
    }
    if(types.includes("status_code") && verdict!=="found") {
      const codes=asArray(site.errorCode).filter(x=>typeof x==="number");
      verdict=(codes.includes(code)||code<200||code>=300)?"not_found":"found";
    }
    if(types.includes("response_url") && verdict!=="found") verdict=(code>=200&&code<300)?"found":"not_found";
    if(!verdict) return {...unknown("Недостаточно данных для вывода"),httpStatus:code};
    return {site:name,url:profileUrl,status:verdict,httpStatus:code,...(verdict==="found"?extractMeta(html):{})};
  } catch(e) {
    return unknown(e.name==="AbortError"?"Тайм-аут":"Сетевая ошибка; сайт не подтвердил результат");
  } finally { clearTimeout(timer); }
}

app.post("/api/scan", async (req,res)=>{
  const username=String(req.body?.username||"").trim().replace(/^@/,"");
  const catalog=req.body?.catalog;
  const limit=Math.min(200,Math.max(1,Number(req.body?.limit)||150));
  if(!/^[a-zA-Z0-9_.-]{2,40}$/.test(username)) return res.status(400).json({error:"Username: 2–40 символов, латиница, цифры, точка, дефис или подчёркивание."});
  if(!catalog||typeof catalog!=="object"||Array.isArray(catalog)) return res.status(400).json({error:"Сначала установите корректный data.json."});
  const entries=Object.entries(catalog).filter(([name,s])=>name!=="$schema"&&s&&typeof s.url==="string"&&s.url.startsWith("https://")).slice(0,limit);
  let cursor=0;
  const results=new Array(entries.length);
  await Promise.all(Array.from({length:Math.min(8,entries.length)},async()=>{
    while(true){const i=cursor++;if(i>=entries.length)return;results[i]=await checkSite(entries[i][0],entries[i][1],username);}
  }));
  res.json({username,checked:results.length,found:results.filter(x=>x.status==="found").length,
    notFound:results.filter(x=>x.status==="not_found").length,unknown:results.filter(x=>x.status==="unknown").length,
    catalogCount:Object.keys(catalog).filter(x=>x!=="$schema").length,results});
});
app.get("/api/health",(_,res)=>res.json({ok:true}));
const port=process.env.PORT||3000;
app.listen(port,"0.0.0.0",()=>console.log(`Sherlock OSINT listening on ${port}`));