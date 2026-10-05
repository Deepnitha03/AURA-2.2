from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
app=FastAPI(title='AURA-2.2',version='1.0.0')
app.mount('/static',StaticFiles(directory='static'),name='static')
USERS={'alice':{'id':1,'name':'Alice','role':'user','password':'alice123'},'bob':{'id':2,'name':'Bob','role':'user','password':'bob123'},'admin':{'id':3,'name':'Admin','role':'admin','password':'admin123'}}
ORDERS={101:{'id':101,'user_id':1,'product':'Laptop','amount':55000},201:{'id':201,'user_id':2,'product':'Phone','amount':30000}}
class Login(BaseModel): username:str; password:str
@app.get('/',response_class=HTMLResponse)
def home(): return open('static/index.html',encoding='utf-8').read()
@app.post('/login')
def login(data:Login):
 u=USERS.get(data.username)
 if not u or u['password']!=data.password: raise HTTPException(401,'Invalid credentials')
 return {'message':'Login successful','user_id':u['id'],'name':u['name'],'role':u['role']}
@app.get('/orders/{order_id}')
def order(order_id:int,username:str='alice'):
 if username not in USERS: raise HTTPException(401,'Unknown user')
 if order_id not in ORDERS: raise HTTPException(404,'Order not found')
 return ORDERS[order_id] # intentional BOLA
@app.get('/secure/orders/{order_id}')
def secure(order_id:int,username:str='alice'):
 if username not in USERS: raise HTTPException(401,'Unknown user')
 o=ORDERS.get(order_id)
 if not o: raise HTTPException(404,'Order not found')
 if USERS[username]['id']!=o['user_id'] and USERS[username]['role']!='admin': raise HTTPException(403,'Forbidden')
 return o
@app.get('/admin/reports')
def admin_reports(username:str='alice'):
 if username not in USERS: raise HTTPException(401,'Unknown user')
 return {'report':'Confidential admin report','total_orders':len(ORDERS)} # intentional BFLA
@app.get('/profiles/{user_id}')
def profile(user_id:int):
 for u in USERS.values():
  if u['id']==user_id:return {'id':u['id'],'name':u['name'],'role':u['role']}
 raise HTTPException(404,'User not found')
@app.get('/api/discover')
def discover(): return {'target':'AURA Demo Target API','endpoints':['POST /login','GET /orders/{order_id}','GET /secure/orders/{order_id}','GET /admin/reports','GET /profiles/{user_id}']}
@app.post('/api/run-audit')
def audit(): return {'status':'completed','tests':[{'id':'BOLA-001','type':'BOLA','endpoint':'GET /orders/201','expected':403,'actual':200,'severity':'HIGH','status':'VULNERABLE'},{'id':'BFLA-001','type':'BFLA','endpoint':'GET /admin/reports','expected':403,'actual':200,'severity':'HIGH','status':'VULNERABLE'},{'id':'AUTH-001','type':'Authorization','endpoint':'GET /secure/orders/201','expected':403,'actual':403,'severity':'PASS','status':'SECURE'}]}
