import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import Anthropic from '@anthropic-ai/sdk';
import Stripe from 'stripe';

const app = express();
const PORT = Number(process.env.PORT || 3000);
const API_KEY = process.env.ANTHROPIC_API_KEY;
const MODEL = process.env.CLAUDE_MODEL || 'claude-sonnet-5';
const SESSION_SECRET = process.env.SESSION_SECRET;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:5500';
const MAX_FILE_SIZE = 8 * 1024 * 1024;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const USERNAME_DB_FILE = process.env.USERNAME_DB_FILE || path.join(__dirname, 'usernames.json');
const LEADERBOARD_DB_FILE = process.env.LEADERBOARD_DB_FILE || path.join(__dirname, 'leaderboard.json');
const SOCIAL_DB_FILE = process.env.SOCIAL_DB_FILE || path.join(__dirname, 'social.json');
const SOCIAL_PREFS_DB_FILE = process.env.SOCIAL_PREFS_DB_FILE || path.join(__dirname, 'social-prefs.json');
const PUBLIC_APP_URL = process.env.PUBLIC_APP_URL || 'http://localhost:5500';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_PRICE_PRO = process.env.STRIPE_PRICE_PRO || '';
const STRIPE_MODE = process.env.STRIPE_MODE || 'subscription';
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

if (!API_KEY) throw new Error('ANTHROPIC_API_KEY غير موجود في ملف .env');
if (!SESSION_SECRET || SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET يجب أن يكون 32 حرفًا على الأقل');

const anthropic = new Anthropic({ apiKey: API_KEY });
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ok = file.mimetype === 'application/pdf' || /^image\/(jpeg|png|gif|webp)$/i.test(file.mimetype);
    cb(ok ? null : new Error('يسمح فقط بصورة أو PDF'), ok);
  }
});

const allowedOrigins = ALLOWED_ORIGIN.split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({ origin(origin, cb) {
  if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
  return cb(new Error('Origin غير مسموح'));
}}));
app.use(express.json({ limit: '1mb' }));

app.get('/api/health', (_req, res) => res.json({ ok: true, model: MODEL }));

function base64url(input) {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function unbase64url(input) {
  return Buffer.from(input.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}
function signSession(studentId) {
  const payload = base64url(JSON.stringify({ sub: studentId, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }));
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function verifySession(token) {
  try {
    const [payload, sig] = String(token || '').split('.');
    if (!payload || !sig) return null;
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const body = JSON.parse(unbase64url(payload));
    if (!body?.sub || !body?.exp || body.exp < Date.now()) return null;
    return body;
  } catch {
    return null;
  }
}
function getBearer(req) {
  const h = req.get('authorization') || '';
  return h.startsWith('Bearer ') ? h.slice(7) : '';
}
function cleanText(value, max = 5000) {
  return String(value ?? '').slice(0, max);
}

function readJsonFile(file, fallback) {
  try { if (!fs.existsSync(file)) return fallback; const raw = fs.readFileSync(file, 'utf8'); return JSON.parse(raw); } catch { return fallback; }
}
function writeJsonFile(file, value) {
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), 'utf8');
  fs.renameSync(tmp, file);
}
function normalizeUsername(value) { return cleanText(value, 30).normalize('NFKC').trim().toLowerCase(); }
function validUsername(value) { return /^[a-zA-Z0-9_.-]{2,30}$/.test(value); }
let usernameStore = readJsonFile(USERNAME_DB_FILE, {});
let leaderboardStore = readJsonFile(LEADERBOARD_DB_FILE, {});
let socialStore = readJsonFile(SOCIAL_DB_FILE, {});
let socialPrefsStore = readJsonFile(SOCIAL_PREFS_DB_FILE, {});
function saveStores() { writeJsonFile(USERNAME_DB_FILE, usernameStore); writeJsonFile(LEADERBOARD_DB_FILE, leaderboardStore); writeJsonFile(SOCIAL_DB_FILE, socialStore); writeJsonFile(SOCIAL_PREFS_DB_FILE, socialPrefsStore); }
function socialFor(studentId){ if(!socialStore[studentId]) socialStore[studentId]={friends:[],incomingFriendRequests:[],outgoingFriendRequests:[],followers:[],following:[]}; return socialStore[studentId]; }
function usernameForStudent(studentId){ const pair=Object.entries(usernameStore).find(([,id])=>id===studentId); return pair?.[0]||'مستخدم'; }
function prefsFor(studentId){ return socialPrefsStore[studentId] || {showInLeaderboard:true,allowFriendRequests:true,allowFollows:true,username:usernameForStudent(studentId)}; }


app.post('/api/session', (req, res) => {
  const studentId = cleanText(req.body?.studentId, 120);
  if (!/^[a-zA-Z0-9:_-]{8,120}$/.test(studentId)) return res.status(400).json({ error: 'studentId غير صالح' });
  return res.json({ token: signSession(studentId), expiresIn: 7 * 24 * 60 * 60 });
});


app.get('/api/usernames/check', (req, res) => {
  const username = normalizeUsername(req.query?.username);
  if (!validUsername(username)) return res.status(400).json({ available: false, error: 'اسم المستخدم غير صالح' });
  const owner = usernameStore[username];
  return res.json({ available: !owner });
});

app.post('/api/usernames/register', (req, res) => {
  const session = verifySession(getBearer(req));
  if (!session) return res.status(401).json({ error: 'الجلسة غير صالحة' });
  const username = normalizeUsername(req.body?.username);
  if (!validUsername(username)) return res.status(400).json({ error: 'اسم المستخدم يجب أن يكون من 2 إلى 30 رمزًا إنجليزيًا/رقميًا، ويمكن استخدام _ أو . أو - فقط.' });
  const owner = usernameStore[username];
  if (owner && owner !== session.sub) return res.status(409).json({ error: 'اسم المستخدم مستخدم بالفعل، اختر اسمًا آخر.' });
  // Release previous username owned by this student only.
  for (const [key, value] of Object.entries(usernameStore)) if (value === session.sub && key !== username) delete usernameStore[key];
  usernameStore[username] = session.sub;
  writeJsonFile(USERNAME_DB_FILE, usernameStore);
  return res.json({ ok: true, username });
});

app.post('/api/profile/preferences', (req, res) => {
  const session = verifySession(getBearer(req));
  if (!session) return res.status(401).json({ error: 'الجلسة غير صالحة' });
  const username = normalizeUsername(req.body?.username || usernameForStudent(session.sub));
  const showInLeaderboard = req.body?.showInLeaderboard !== false;
  socialPrefsStore[session.sub] = {
    username,
    displayName: cleanText(req.body?.displayName, 80) || username,
    showInLeaderboard,
    allowFriendRequests: req.body?.allowFriendRequests !== false,
    allowFollows: req.body?.allowFollows !== false,
    updatedAt: Date.now()
  };
  if (!showInLeaderboard) delete leaderboardStore[session.sub];
  writeJsonFile(SOCIAL_PREFS_DB_FILE, socialPrefsStore);
  writeJsonFile(LEADERBOARD_DB_FILE, leaderboardStore);
  return res.json({ ok: true, hidden: !showInLeaderboard });
});

app.get('/api/social/status', (req, res) => {
  const session = verifySession(getBearer(req));
  if (!session) return res.status(401).json({ error: 'الجلسة غير صالحة' });
  const me = socialFor(session.sub);
  return res.json({
    friendsCount: me.friends.length,
    followingCount: me.following.length,
    followersCount: me.followers.length,
    incomingFriendRequests: me.incomingFriendRequests.map(studentId => ({ studentId, username: usernameForStudent(studentId) })),
    outgoingFriendRequests: me.outgoingFriendRequests.map(studentId => ({ studentId, username: usernameForStudent(studentId) }))
  });
});

app.post('/api/social/friend/request', (req, res) => {
  const session = verifySession(getBearer(req));
  if (!session) return res.status(401).json({ error: 'الجلسة غير صالحة' });
  const targetUsername = normalizeUsername(req.body?.targetUsername);
  if (!validUsername(targetUsername)) return res.status(400).json({ error: 'اسم المستخدم غير صالح' });
  const targetId = usernameStore[targetUsername];
  if (!targetId) return res.status(404).json({ error: 'لم يتم العثور على هذا المستخدم' });
  if (targetId === session.sub) return res.status(400).json({ error: 'لا يمكنك إرسال طلب لنفسك' });
  if (!prefsFor(targetId).allowFriendRequests) return res.status(403).json({ error: 'هذا المستخدم لا يستقبل طلبات الصداقة حاليًا' });
  const me = socialFor(session.sub), target = socialFor(targetId);
  if (me.friends.includes(targetId)) return res.status(409).json({ error: 'أنتم أصدقاء بالفعل' });
  if (!me.outgoingFriendRequests.includes(targetId)) me.outgoingFriendRequests.push(targetId);
  if (!target.incomingFriendRequests.includes(session.sub)) target.incomingFriendRequests.push(session.sub);
  saveStores();
  return res.json({ ok:true, message:`تم إرسال طلب صداقة إلى ${targetUsername}.` });
});

app.post('/api/social/friend/respond', (req, res) => {
  const session = verifySession(getBearer(req));
  if (!session) return res.status(401).json({ error: 'الجلسة غير صالحة' });
  const senderId = cleanText(req.body?.senderStudentId, 120);
  const action = req.body?.action === 'accept' ? 'accept' : 'reject';
  const me = socialFor(session.sub), sender = socialFor(senderId);
  if (!me.incomingFriendRequests.includes(senderId)) return res.status(404).json({ error: 'الطلب غير موجود' });
  me.incomingFriendRequests = me.incomingFriendRequests.filter(x=>x!==senderId);
  sender.outgoingFriendRequests = sender.outgoingFriendRequests.filter(x=>x!==session.sub);
  if (action === 'accept') {
    if (!me.friends.includes(senderId)) me.friends.push(senderId);
    if (!sender.friends.includes(session.sub)) sender.friends.push(session.sub);
  }
  saveStores();
  return res.json({ ok:true, message: action==='accept' ? 'تم قبول طلب الصداقة.' : 'تم رفض طلب الصداقة.' });
});

app.post('/api/social/follow', (req, res) => {
  const session = verifySession(getBearer(req));
  if (!session) return res.status(401).json({ error: 'الجلسة غير صالحة' });
  const targetUsername = normalizeUsername(req.body?.targetUsername);
  if (!validUsername(targetUsername)) return res.status(400).json({ error: 'اسم المستخدم غير صالح' });
  const targetId = usernameStore[targetUsername];
  if (!targetId) return res.status(404).json({ error: 'لم يتم العثور على هذا المستخدم' });
  if (targetId === session.sub) return res.status(400).json({ error: 'لا يمكنك متابعة نفسك' });
  if (!prefsFor(targetId).allowFollows) return res.status(403).json({ error: 'هذا المستخدم لا يسمح بالمتابعة حاليًا' });
  const me = socialFor(session.sub), target = socialFor(targetId);
  if (!me.following.includes(targetId)) me.following.push(targetId);
  if (!target.followers.includes(session.sub)) target.followers.push(session.sub);
  saveStores();
  return res.json({ ok:true, message:`تمت متابعة ${targetUsername}.` });
});

app.get('/api/leaderboard', (req, res) => {
  const limit = Math.min(100, Math.max(1, Number(req.query?.limit) || 50));
  const rows = Object.values(leaderboardStore).sort((a,b)=>(Number(b.focusMinutes)||0)-(Number(a.focusMinutes)||0)).slice(0, limit);
  return res.json({ rows });
});

app.post('/api/leaderboard/report', (req, res) => {
  const session = verifySession(getBearer(req));
  if (!session) return res.status(401).json({ error: 'الجلسة غير صالحة' });
  const prefs = prefsFor(session.sub);
  if (prefs.showInLeaderboard === false) { delete leaderboardStore[session.sub]; writeJsonFile(LEADERBOARD_DB_FILE, leaderboardStore); return res.json({ ok:true, hidden:true }); }
  const username = normalizeUsername(req.body?.username || prefs.username || 'مستخدم');
  const focusMinutes = Math.max(0, Math.min(1000000, Number(req.body?.focusMinutes)||0));
  const stageLevel = Math.max(1, Math.min(7, Number(req.body?.stageLevel)||1));
  const buildingBadge = cleanText(req.body?.buildingBadge, 80) || '🏗️ قيد البناء';
  const displayName = cleanText(req.body?.displayName, 80) || username;
  leaderboardStore[session.sub] = { studentId: session.sub, username, name: displayName, focusMinutes, stageLevel, buildingBadge, updatedAt: Date.now() };
  writeJsonFile(LEADERBOARD_DB_FILE, leaderboardStore);
  return res.json({ ok: true });
});

app.get('/api/billing/config', (_req, res) => res.json({ enabled: !!stripe && !!STRIPE_PRICE_PRO, mode: STRIPE_MODE, wallets: { applePay: true, googlePay: true } }));

app.post('/api/billing/create-checkout-session', async (req, res) => {
  try {
    const session = verifySession(getBearer(req));
    if (!session) return res.status(401).json({ error: 'الجلسة غير صالحة' });
    if (!stripe || !STRIPE_PRICE_PRO) return res.status(503).json({ error: 'بوابة الدفع غير مفعلة على السيرفر بعد. أضف STRIPE_SECRET_KEY و STRIPE_PRICE_PRO إلى .env.' });
    const mode = STRIPE_MODE === 'payment' ? 'payment' : 'subscription';
    const checkout = await stripe.checkout.sessions.create({
      mode,
      line_items: [{ price: STRIPE_PRICE_PRO, quantity: 1 }],
      client_reference_id: session.sub,
      success_url: `${PUBLIC_APP_URL}/?billing=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${PUBLIC_APP_URL}/?billing=cancelled`,
      metadata: { studentId: session.sub, plan: cleanText(req.body?.plan || 'pro', 40) },
      allow_promotion_codes: true,
      billing_address_collection: 'auto'
    });
    return res.json({ url: checkout.url });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: error?.message || 'تعذر إنشاء جلسة الدفع' });
  }
});

const tools = [
  {
    name: 'add_task',
    description: 'أضف مهمة جديدة للمستخدم. استخدمها عندما يطلب بوضوح إنشاء مهمة.',
    input_schema: { type: 'object', additionalProperties: false, properties: {
      title: { type: 'string' }, date: { type: 'string', description: 'YYYY-MM-DD أو اتركها فارغة لليوم' }, time: { type: 'string', description: 'HH:MM أو فارغ' }, duration: { type: 'number' }
    }, required: ['title'] }
  },
  {
    name: 'complete_task',
    description: 'أكمل مهمة موجودة. فضّل id إن كان متاحًا، وإلا استخدم عنوانًا مطابقًا.',
    input_schema: { type: 'object', additionalProperties: false, properties: { id: { type: ['string','number'] }, title: { type: 'string' } } }
  },
  {
    name: 'add_note',
    description: 'أنشئ ملاحظة جديدة للمستخدم.',
    input_schema: { type: 'object', additionalProperties: false, properties: { title: { type: 'string' }, body: { type: 'string' } }, required: ['body'] }
  },
  {
    name: 'add_expense',
    description: 'سجل مصروفًا للمستخدم.',
    input_schema: { type: 'object', additionalProperties: false, properties: { name: { type: 'string' }, amount: { type: 'number' }, category: { type: 'string' } }, required: ['name','amount'] }
  },
  {
    name: 'delete_task',
    description: 'يطلب حذف مهمة. هذا الإجراء حساس ويجب أن يعود للتطبيق كطلب تأكيد ولا ينفذ مباشرة.',
    input_schema: { type: 'object', additionalProperties: false, properties: { id: { type: ['string','number'] }, title: { type: 'string' } } }
  },
  {
    name: 'delete_note',
    description: 'يطلب حذف ملاحظة. هذا الإجراء حساس ويجب أن يعود للتطبيق كطلب تأكيد ولا ينفذ مباشرة.',
    input_schema: { type: 'object', additionalProperties: false, properties: { id: { type: ['string','number'] }, title: { type: 'string' } } }
  }
];

function buildSystem(context) {
  return `أنت المساعد الذكي الرسمي والشامل داخل تطبيق «مهامي» للطلاب. مهمتك مساعدة المستخدم في احتياجاته الأكاديمية والمالية والشخصية المرتبطة بالتطبيق بدقة واحترافية، مع أسلوب إنساني وودود.\n\n`+
`أسلوب التفاعل:\n`+
`- تحدث بعربية سعودية بسيطة وطبيعية وودودة ومشجعة، وبشكل مباشر من غير حشو أو مبالغة.\n`+
`- نظّم الرد عند الحاجة باستخدام عناوين قصيرة، نقاط، خطوات، أو جداول نصية بسيطة لتكون القراءة سريعة وواضحة.\n`+
`- إذا احتاج المستخدم شرحًا، اشرح ثم أعطِ مثالًا عمليًا قصيرًا عند فائدته.\n`+
`- لا تدّعي تنفيذ شيء لم يتم تنفيذه فعليًا من خلال أداة أو من التطبيق.\n\n`+
`نطاق المعرفة والوصول:\n`+
`- اعتبر بيانات <student_data> هي بيانات المستخدم الحالية التي يزوّدك بها التطبيق، ويمكنك تحليلها والربط بينها والإجابة عن الأسئلة المتعلقة بها.\n`+
`- عند وجود صورة أو PDF مرفق في الطلب، اقرأ محتواه واستخرج منه النص والمعلومات والتمارين والنقاط المهمة قبل الإجابة.\n`+
`- لا تخترع بيانات غير موجودة في سياق الطالب، وإذا كانت معلومة أساسية ناقصة فاذكر ذلك بوضوح واسأل عند الحاجة.\n`+
`- لا تطلب مفاتيح API أو أسرار الخادم أو كلمات المرور.\n\n`+
`المهام الأكاديمية والتعليمية:\n`+
`- ساعد الطلاب من المرحلة المتوسطة والثانوية والجامعة والخريجين، وفي مختلف التخصصات والمواد.\n`+
`- لخّص الدروس والمحاضرات والملفات، واستخرج الأفكار الرئيسية، التعريفات، القوانين، المصطلحات، والأسئلة المتوقعة.\n`+
`- حوّل المحتوى عند الطلب إلى نقاط حفظ سريعة، خطوات، أسئلة وأجوبة، أو خريطة ذهنية نصية.\n`+
`- اشرح الواجبات والمسائل والقواعد والمصطلحات المعقدة بطريقة مبسطة ومتدرجة حسب مستوى الطالب.\n`+
`- عند وجود سؤال دراسي من صورة أو PDF: اقرأه أولًا، ثم حدّد المطلوب، ثم اشرح الحل أو الفكرة بوضوح.\n\n`+
`الإدارة المالية داخل التطبيق:\n`+
`- ساعد في تسجيل المصروفات اليومية وتصنيفها حسب نوعها مثل دراسة، مواصلات، شخصي وغيرها.\n`+
`- استخدم بيانات المصروفات الحالية لإعطاء مجموعات وتقارير وملخصات عند الطلب، مثل مصروف اليوم، حسب التصنيف، أو مقارنة الإنفاق بالميزانية الموجودة في السياق.\n`+
`- لا تغيّر أي مبلغ أو مصروف إلا من خلال أداة التطبيق المخصصة لذلك.\n\n`+
`إدارة بيانات التطبيق:\n`+
`- استخدم الأدوات عندما يريد المستخدم بوضوح إنشاء مهمة، إكمال مهمة، إضافة ملاحظة، أو تسجيل مصروف.\n`+
`- عند عرض مهام اليوم أو الإحصائيات أو المصروفات، اعتمد على البيانات الحالية داخل <student_data> ولا تتوقع أرقامًا من عندك.\n`+
`- عند وجود أكثر من عنصر متشابه، استخدم المعرّف إن كان متاحًا أو اطلب توضيحًا قبل التغيير.\n`+
`- حذف مهمة أو ملاحظة إجراء حساس: استخدم أداة الحذف فقط لإرجاع طلب تأكيد للتطبيق، ولا تنفذ الحذف مباشرة.\n`+
`- إذا كان الطلب غامضًا بطريقة قد تؤدي إلى تعديل خاطئ للبيانات، اسأل سؤالًا واحدًا واضحًا بدل التخمين.\n\n`+
`القاعدة الأساسية: كن مساعدًا عمليًا ودقيقًا، واستفد من كل البيانات الحالية التي أرسلها التطبيق وكل محتوى المرفق في الطلب، مع الحفاظ على حدود الأدوات والصلاحيات السابقة.\n\n`+
`<student_data>${JSON.stringify(context)}</student_data>`;
}

function fileBlock(file) {
  if (!file) return null;
  const data = file.buffer.toString('base64');
  if (file.mimetype === 'application/pdf') {
    return { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data } };
  }
  return { type: 'image', source: { type: 'base64', media_type: file.mimetype, data } };
}

app.post('/api/assistant', upload.single('file'), async (req, res) => {
  try {
    const session = verifySession(getBearer(req));
    if (!session) return res.status(401).json({ error: 'جلسة المساعد غير صالحة أو منتهية' });

    const message = cleanText(req.body?.message, 6000);
    const context = JSON.parse(req.body?.context || '{}');
    if (context.studentId !== session.sub) return res.status(403).json({ error: 'هوية الطالب لا تطابق الجلسة الحالية' });
    if (!message && !req.file) return res.status(400).json({ error: 'اكتب طلبك أو أرفق ملفًا' });

    const content = [];
    const attachment = fileBlock(req.file);
    if (attachment) content.push(attachment);
    content.push({ type: 'text', text: message || 'اشرح لي المرفق، لخّصه، واستخرج أهم النقاط والواجبات منه.' });

    const response = await anthropic.messages.create({
      model: MODEL,
      max_tokens: 1800,
      system: buildSystem(context),
      tools,
      tool_choice: { type: 'auto' },
      messages: [{ role: 'user', content }]
    });

    const textParts = response.content.filter(b => b.type === 'text').map(b => b.text).join('\n').trim();
    const toolUse = response.content.find(b => b.type === 'tool_use');

    if (toolUse) {
      if (toolUse.name === 'delete_task' || toolUse.name === 'delete_note') {
        return res.json({ reply: textParts || 'هذا الإجراء يحتاج تأكيدك قبل الحذف.', confirmation: { type: toolUse.name, ...toolUse.input } });
      }
      return res.json({ reply: textParts || 'تمام، بنفذها لك الآن.', action: { type: toolUse.name, ...toolUse.input } });
    }

    return res.json({ reply: textParts || 'أكيد 👍 قل لي وش تبغى أسوي.' });
  } catch (error) {
    console.error(error);
    const message = error?.message || 'تعذر تشغيل المساعد';
    return res.status(500).json({ error: message });
  }
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'الملف أكبر من 8MB' });
  if (err?.message) return res.status(400).json({ error: err.message });
  return res.status(500).json({ error: 'خطأ غير متوقع في السيرفر' });
});

app.listen(PORT, () => console.log(`Mahami Claude server running on http://localhost:${PORT} using ${MODEL}`));
