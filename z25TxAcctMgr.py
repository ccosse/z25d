class Z25TxAcctMgr:
	def __init__(self):
		print("Z25TxAcctMgr")
		self.ctx=None
		
	def takeCtx(self,ctx):
		self.ctx=ctx
