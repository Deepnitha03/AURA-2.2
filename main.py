from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl
import httpx, time, uuid
from urllib.parse import urljoin

app = FastAPI(title='AURA-2.2', version='2.0.0', description='Continuous API Authorization Security')
app.mount('/static', StaticFiles(directory='static'), name='static')

# ---------------- Controlled demo target API ----------------
DEMO_USERS = {
    'alice': {'id': 1, 'name': 'Alice', 'role': 'user', 'token': 'alice-token'},
    'bob': {'id': 2, 'name': 'Bob', 'role': 'user', 'token': 'bob-token'},
    'admin': {'id': 3, 'name': 'Admin', 'role': 'admin', 'token': 'admin-token'},
}
ORDERS = {
    101: {'id': 101, 'user_id': 1, 'product': 'Laptop', 'amount': 55000},
    201: {'id': 201, 'user_id': 2, 'product': 'Phone', 'amount': 30000},
}
demo_fixed = False


def demo_identity(request: Request):
    auth = request.headers.get('authorization', '')
    token = auth.replace('Bearer ', '').strip()
    for name, user in DEMO_USERS.items():
        if token == user['token']:
            return name, user
    return None, None

@app.get('/target/health', tags=['Demo Target'])
def target_health():
    return {'status': 'online', 'target': 'AURA Demo Target API'}

@app.post('/target/login', tags=['Demo Target'])
async def target_login(payload: dict):
    user = DEMO_USERS.get(payload.get('username'))
    if not user or payload.get('password') != f"{payload.get('username')}123":
        raise HTTPException(401, 'Invalid credentials')
    return {'access_token': user['token'], 'token_type': 'bearer', 'user': user['name'], 'role': user['role']}

@app.get('/target/orders/{order_id}', tags=['Demo Target'])
async def target_order(order_id: int, request: Request):
    name, user = demo_identity(request)
    if not user:
        raise HTTPException(401, 'Authentication required')
    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(404, 'Order not found')
    if demo_fixed and user['id'] != order['user_id'] and user['role'] != 'admin':
        raise HTTPException(403, 'Forbidden')
    return order  # intentionally vulnerable until Fix Demo API is used

@app.get('/target/secure/orders/{order_id}', tags=['Demo Target'])
async def target_secure_order(order_id: int, request: Request):
    name, user = demo_identity(request)
    if not user:
        raise HTTPException(401, 'Authentication required')
    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(404, 'Order not found')
    if user['id'] != order['user_id'] and user['role'] != 'admin':
        raise HTTPException(403, 'Forbidden')
    return order

@app.get('/target/admin/reports', tags=['Demo Target'])
async def target_admin_reports(request: Request):
    name, user = demo_identity(request)
    if not user:
        raise HTTPException(401, 'Authentication required')
    if demo_fixed and user['role'] != 'admin':
        raise HTTPException(403, 'Forbidden')
    return {'report': 'Confidential admin report', 'total_orders': len(ORDERS)}

@app.get('/target/profiles/{user_id}', tags=['Demo Target'])
async def target_profile(user_id: int, request: Request):
    name, user = demo_identity(request)
    if not user:
        raise HTTPException(401, 'Authentication required')
    for u in DEMO_USERS.values():
        if u['id'] == user_id:
            return {'id': u['id'], 'name': u['name'], 'role': u['role']}
    raise HTTPException(404, 'User not found')

@app.post('/target/fix', tags=['Demo Target'])
def fix_demo_target():
    global demo_fixed
    demo_fixed = True
    return {'status': 'fixed', 'message': 'Demo target authorization checks enabled'}

@app.post('/target/reset', tags=['Demo Target'])
def reset_demo_target():
    global demo_fixed
    demo_fixed = False
    return {'status': 'reset', 'message': 'Demo target returned to vulnerable demonstration mode'}

# ---------------- AURA scanner state ----------------
class TargetIn(BaseModel):
    name: str
    base_url: str
    openapi_url: str
    token_a: str
    token_b: str
    authorized: bool

state = {
    'target': None,
    'endpoints': [],
    'tests': [],
    'findings': [],
    'evidence': [],
    'last_run': None,
}

@app.get('/', response_class=HTMLResponse)
def home():
    return open('static/index.html', encoding='utf-8').read()

async def fetch_json(url: str):
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.json()

@app.post('/api/targets')
async def add_target(t: TargetIn):
    if not t.authorized:
        raise HTTPException(400, 'Confirm that you are authorized to test this API.')
    state['target'] = t.model_dump()
    state['endpoints'] = []
    state['tests'] = []
    state['findings'] = []
    state['evidence'] = []
    return {'status': 'connected', 'target': state['target']}

@app.get('/api/targets')
def targets():
    return {'target': state['target']}

@app.post('/api/targets/discover')
async def discover():
    if not state['target']:
        raise HTTPException(400, 'Connect a target first.')
    spec = await fetch_json(state['target']['openapi_url'])
    endpoints = []
    for path, methods in spec.get('paths', {}).items():
        for method, details in methods.items():
            if method.lower() not in {'get','post','put','patch','delete'}:
                continue
            endpoints.append({
                'method': method.upper(),
                'path': path,
                'summary': details.get('summary',''),
                'security': bool(details.get('security') or spec.get('security')),
                'parameters': [p.get('name') for p in details.get('parameters', [])],
            })
    state['endpoints'] = endpoints
    return {'status':'discovered', 'count':len(endpoints), 'endpoints':endpoints}

@app.get('/api/endpoints')
def endpoints():
    return {'endpoints': state['endpoints']}

@app.get('/api/authorization-graph')
def auth_graph():
    return {
        'nodes': [
            {'id':'alice','type':'USER','label':'Alice'},
            {'id':'bob','type':'USER','label':'Bob'},
            {'id':'user-role','type':'ROLE','label':'Customer'},
            {'id':'admin-role','type':'ROLE','label':'Admin'},
            {'id':'read','type':'PERMISSION','label':'READ'},
            {'id':'orders','type':'ENDPOINT','label':'/target/orders/{order_id}'},
            {'id':'admin-reports','type':'ENDPOINT','label':'/target/admin/reports'},
            {'id':'order101','type':'RESOURCE','label':'Order 101'},
            {'id':'order201','type':'RESOURCE','label':'Order 201'},
        ],
        'edges': [
            ['alice','user-role'],['bob','user-role'],['admin','admin-role'],['user-role','read'],
            ['read','orders'],['orders','order101'],['orders','order201'],
        ]
    }

@app.post('/api/tests/generate')
def generate_tests():
    if not state['target']:
        raise HTTPException(400, 'Connect a target first.')
    paths = {e['path'] for e in state['endpoints']}
    base = state['target']['base_url'].rstrip('/')
    tests=[]
    if '/target/orders/{order_id}' in paths or any('/orders/{order_id}' in p for p in paths):
        p = next((e['path'] for e in state['endpoints'] if 'orders/{order_id}' in e['path'] and 'secure' not in e['path']), '/target/orders/{order_id}')
        tests.append({'id':'BOLA-001','type':'BOLA','identity':'Alice','endpoint':p.replace('{order_id}','201').replace('/target/','/'),'expected':403,'description':"Alice must not access Bob's Order 201",'token':state['target']['token_a']})
    if '/target/admin/reports' in paths or any('/admin/reports' in p for p in paths):
        p = next((e['path'] for e in state['endpoints'] if '/admin/reports' in e['path']), '/target/admin/reports')
        tests.append({'id':'BFLA-001','type':'BFLA','identity':'Alice (normal user)','endpoint':p.replace('/target/','/'),'expected':403,'description':'Normal user must not access admin reports','token':state['target']['token_a']})
    state['tests']=tests
    return {'tests':tests,'count':len(tests)}

@app.get('/api/tests')
def get_tests():
    return {'tests':state['tests']}

@app.post('/api/tests/run')
async def run_tests():
    if not state['tests']:
        generate_tests()
    base = state['target']['base_url'].rstrip('/')
    findings=[]; evidence=[]
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
        for test in state['tests']:
            url = urljoin(base+'/', test['endpoint'].lstrip('/'))
            started=time.perf_counter()
            try:
                r=await client.get(url, headers={'Authorization':f"Bearer {test['token']}"})
                elapsed=round((time.perf_counter()-started)*1000,2)
                actual=r.status_code
                body=r.text[:1000]
                vulnerable = actual != test['expected'] and actual < 300
                item={**test,'actual':actual,'status':'VULNERABLE' if vulnerable else 'SECURE','response_time_ms':elapsed}
                ev={'id':str(uuid.uuid4())[:8],'test_id':test['id'],'timestamp':time.strftime('%Y-%m-%d %H:%M:%S'),'request':f"GET {test['endpoint']}",'expected':test['expected'],'actual':actual,'response_body':body,'response_time_ms':elapsed}
                evidence.append(ev)
                if vulnerable:
                    findings.append({**item,'severity':'HIGH','evidence_id':ev['id'],'evidence': 'Unauthorized resource/function returned by target API.'})
            except Exception as exc:
                evidence.append({'id':str(uuid.uuid4())[:8],'test_id':test['id'],'timestamp':time.strftime('%Y-%m-%d %H:%M:%S'),'request':f"GET {test['endpoint']}",'error':str(exc)})
    state['findings']=findings; state['evidence']=evidence; state['last_run']=time.strftime('%Y-%m-%d %H:%M:%S')
    return {'status':'completed','findings':findings,'evidence':evidence}

@app.get('/api/findings')
def findings(): return {'findings':state['findings']}

@app.get('/api/evidence')
def evidence(): return {'evidence':state['evidence']}

@app.post('/api/fix-and-retest')
async def fix_and_retest():
    # Only the built-in demo target can be switched by this button.
    base = (state['target'] or {}).get('base_url','')
    if not base.endswith('/target') and '/target' not in base:
        raise HTTPException(400, 'Fix demo is available only for the controlled AURA demo target.')
    fix_url = urljoin(base.rstrip('/')+'/', 'fix')
    async with httpx.AsyncClient(timeout=8.0) as client:
        await client.post(fix_url)
    result = await run_tests()
    return {'status':'retested','result':result,'verified':len(result['findings'])==0}

@app.get('/api/dashboard')
def dashboard():
    return {
        'api_connected': 1 if state['target'] else 0,
        'endpoints': len(state['endpoints']),
        'tests': len(state['tests']),
        'findings': len(state['findings']),
        'last_run': state['last_run'],
        'target': state['target'],
    }
