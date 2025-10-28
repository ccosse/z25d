import asyncio, ssl, sys, websockets, json
import AppContext as appContext

USE_WSS=True
HOST="localhost"
PORT=7879

def log(msg):
	print(f"{msg}")

def plog(_x):#pretty log
	print(json.dumps(_x, indent=4, sort_keys=True))

class Z25WSSMgr:
	def __init__(self):
		print("Z25WSSMgr")
		self.connections={}
		self.queues={}
		self.ctx=None
		self.THE_M22 = {}
		self.messages_sent = 0

	def takeCtx(self,ctx):
		self.ctx=ctx

	async def receiver(self,websocket):
		log('receiver')
		while True:
			try:
				log('Waiting for msg ... ')
				json_msg=await websocket.recv()
				log('Received {}'.format(json_msg))
				msg=json.loads(json_msg)
				if 'type' in list(msg.keys()) and msg['type']=='associate':
					log(msg['type'])
					log('association success!')
				elif 'type' in list(msg.keys()) and msg['type']=='restartCBX':
					log(msg['type'])
					self.ctx.z25.restartCBX()
				elif 'type' in list(msg.keys()) and msg['type']=='refresh_orders':
					log(msg['type'])
					for wskey in self.ctx.wss.connections:
						orders=json.dumps({'type':'refresh_orders','orders':self.ctx.acct.refresh_orders()})
						log(orders)
						self.ctx.wss.queues[wskey].append(orders)
				elif 'type' in list(msg.keys()) and msg['type']=='L':#Limit
					log(msg)
					rval = self.ctx.acct.place_order(msg)
					log(rval)
				elif 'type' in list(msg.keys()) and msg['type']=='M':#Market
					log(msg)
					rval = self.ctx.acct.place_order(msg)
					log(rval)
				elif 'type' in list(msg.keys()) and msg['type']=='refresh_accounts':
					accts = self.ctx.acct.getCBX()#list of dicts
					rval=json.dumps({'type':'refresh_accounts','value':accts})
					plog(rval)
					for wskey in self.ctx.wss.connections:
						self.ctx.wss.queues[wskey].append(rval)
				elif 'type' in list(msg.keys()) and msg['type']=='clearLookAtMe':
					self.ctx.z25.clearLookAtMe()
				elif 'type' in list(msg.keys()) and msg['type']=='subscribe':
					self.ctx.z25.subscribe(msg['pid'])
				elif 'type' in list(msg.keys()) and msg['type']=='unsubscribe':
					self.ctx.z25.unsubscribe(msg['pid'])
				elif 'type' in list(msg.keys()) and msg['type']=='report':
					self.ctx.z25.report()
					self.report()
					self.ctx.wss.report()
					
			except:
				#log(sys.exc_info())
				self.connections={}
				self.queues={}
				log(f"Connection closed. {len(self.connections.keys())}")
				break

	async def sender(self,websocket):
		#log('sender')
		while True:
			try:
				if not websocket:
					#log('sender: no websocket!')
					raise Exception('no websocket exception')
				elif len(self.queues[websocket])>0:
					#log('sender preparing to send from queue ...')
					msg=self.queues[websocket].pop(0)
					self.messages_sent+=1
					#log(msg)
					await websocket.send(msg)
				else:
					#log('sender sleeping ...')
					await asyncio.sleep(1)

			except Exception as e:
				if type(e)==type(asyncio.CancelledError()):
					e.stopPropagation()
					log('No Biggie')
				else:
					return
				log('sender: continuing after exception')

	async def handler(self,websocket):
		#log('handler')
		if not websocket in list(self.queues):
			self.queues[websocket]=[]
			self.connections[websocket]={}
		
		self.ctx.z25.sendZ25D()
		self.ctx.z25.sendBlockUpdateNow()

		#log('handler for websocket');

		receiver = asyncio.ensure_future(
			self.receiver(websocket))
		#log('receiver: {}'.format(receiver))

		sender = asyncio.ensure_future(
			self.sender(websocket))
		#log('sender: {}'.format(sender))

		done, pending = await asyncio.wait(
			[sender],
			return_when=asyncio.FIRST_COMPLETED,
		)
		for task in pending:
			task.cancel()

	"""
	def listen(self):
		CERT, KEY = "localhost+2.pem", "localhost+2-key.pem"

		async def handler(ws):
			print("Received:", ws.remote_address, "Origin:", ws.request_headers.get("Origin"))
			try:
				async for msg in ws:
					print("Msg:", msg)

				if not ws in list(self.queues):
					self.queues[ws]=[]
					try:
						log('attempting to create NeedName for client @websocket ... ')
						#self.connections[ws]=self.THE_M22
					except:
						log(sys.exc_info())
					#self.sendZ23D()
					#self.sendBlockUpdateNow()

				log('handler for websocket')

				receiver = asyncio.ensure_future(
					self.receiver(ws))
				log('receiver: {}'.format(receiver))

				sender = asyncio.ensure_future(
					self.sender(ws))
				log('sender: {}'.format(sender))

				done, pending = await asyncio.wait(
					[sender],
					return_when=asyncio.FIRST_COMPLETED,
				)
				for task in pending:
					task.cancel()
			except:
				print(f"{sys.exc_info()}")
				print("Closed:", ws.remote_address)

		async def main():
			ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(CERT, KEY)
			async with websockets.serve(handler, "127.0.0.1", 7879, ssl=ctx):
				print("Listening on wss://localhost:7879"); await asyncio.Future()

		asyncio.run(main())
	"""
	async def xmain(self):

		CERT, KEY = "localhost+2.pem", "localhost+2-key.pem"
		ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(CERT, KEY)
		if USE_WSS:
			async with websockets.serve(self.handler, HOST, PORT, ssl=ctx):
				log('calling await ... ')
				await asyncio.Future()
		else:
			async with websockets.serve(self.handler, HOST, PORT):
				log('calling await ... ')
				await asyncio.Future()
	
	def report(self):
		print(f"z25WssMgr.report")
