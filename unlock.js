"use strict";
const form=document.querySelector('#unlock'),button=document.querySelector('#open'),statusText=document.querySelector('#status'),input=document.querySelector('#password');
const bytes=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
form.addEventListener('submit',async e=>{e.preventDefault();button.disabled=true;statusText.textContent='A védett előnézet betöltése…';let password=input.value.trim();input.value='';
try{if(!window.isSecureContext||!crypto.subtle)throw new Error('UNSUPPORTED');
const [configResponse,payloadResponse]=await Promise.all([fetch('config.json',{cache:'no-store',credentials:'omit'}),fetch('payload.bin',{cache:'no-store',credentials:'omit'})]);
if(!configResponse.ok||!payloadResponse.ok)throw new Error('NETWORK');const config=await configResponse.json(),payload=await payloadResponse.arrayBuffer();
const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);password='';
const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:bytes(config.salt),iterations:config.iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(config.iv)},key,payload);const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',plain)),n=>n.toString(16).padStart(2,'0')).join('');if(digest!==config.sha256)throw new Error('INTEGRITY');
const frame=document.querySelector('#preview');frame.srcdoc=new TextDecoder().decode(plain);frame.style.display='block';document.querySelector('#gate').hidden=true;document.querySelector('#gate').style.display='none';document.body.style.overflow='hidden';frame.focus();
}catch(error){password='';statusText.textContent=error.message==='UNSUPPORTED'?'Nyisd meg a linket közvetlenül Safariban, HTTPS-címen.':error.message==='NETWORK'?'A betöltés nem sikerült. Ellenőrizd az internetkapcsolatot, és próbáld újra.':'Nem sikerült feloldani. Másold be újra pontosan a kapott jelszót.';button.disabled=false;input.focus();}
});
