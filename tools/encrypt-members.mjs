// 구독자 전용 글 암호화 스크립트
// 사용법: MEMBERS_PASSWORD='비밀번호' node tools/encrypt-members.mjs <원고 posts.json 경로>
// 원고(평문)는 저장소에 넣지 말 것. 결과물 members/posts.enc.js 만 올린다.
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const src = process.argv[2];
const password = process.env.MEMBERS_PASSWORD;
if (!src || !password) {
  console.error("MEMBERS_PASSWORD='비밀번호' node tools/encrypt-members.mjs posts.json");
  process.exit(1);
}
const plain = JSON.stringify(JSON.parse(readFileSync(src, 'utf8')));
const iter = 310000;
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plain)));
const b64 = u => Buffer.from(u).toString('base64');
const out = `// 자동 생성 파일 (tools/encrypt-members.mjs). 직접 고치지 말 것.\nwindow.MEMBERS_DATA = ${JSON.stringify({ v: 1, iter, salt: b64(salt), iv: b64(iv), ct: b64(ct) })};\n`;
const dest = new URL('../members/posts.enc.js', import.meta.url);
writeFileSync(dest, out);
console.log('암호화 완료:', dest.pathname);
