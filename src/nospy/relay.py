import asyncio
import json
from aiohttp import ClientSession, ClientTimeout, ClientWebSocketResponse, ClientWSTimeout, WSMsgType
from aiohttp.client_exceptions import ClientConnectionResetError

from .filter import Filter
from .nips import Nips

class Relay(Filter, Nips):
    def __init__(self, url:str="", ping:bool=False, reconnect_on:bool=True, reconnect_max:int=3, timeout:float=1.5):
        super(Relay, self).__init__()

        self.session:ClientSession = None
        self.websocket:ClientWebSocketResponse = None
        self.connected:bool = False
        self.enableping:bool = ping
        self.url:str = url
        self.reconnect_on:bool = reconnect_on
        self.reconnect_max:int = reconnect_max
        self.reconnect_count:int = 0
        self.timeout_receive = timeout
        self.subscribe_ids:list[str] = []
        self.receive_data:list[list] = []

    async def connect(self, url:str="") -> None:
        ctimeout = ClientTimeout(
            total=None, 
            connect=20,
            sock_connect=20,
            sock_read=None
        )
        wstimeout = ClientWSTimeout(ws_receive=self.timeout_receive, ws_close=None)

        self.session =  ClientSession(timeout=ctimeout)
        self.websocket = await self.session.ws_connect(url=url, timeout=wstimeout)
        self.connected = True

        if self.enableping:
            await self.pingpong()

    async def reconnect(self, url:str="", error:ClientConnectionResetError=None) -> None:
        if self.reconnect_on:
            self.connected = False
            
            await self.websocket.close()
            await self.session.close()
            
            del self.session
            del self.websocket
            
            await asyncio.sleep(5)

            await self.connect(url=url)
            self.reconnect_count += 1
        else:
            raise ValueError(error)

    async def send(self, message:str="") -> None:
        if self.reconnect_count > self.reconnect_max:
            raise ValueError("Max try reconnect")
        try:
            await self.websocket.send_str(message)
            self.reconnect_count = 0
        except ClientConnectionResetError as e:
            await self.reconnect(self.url, e)
            await self.send(message)
        except Exception as e:
            raise ValueError(e)
    
    async def receive(self) -> list[dict]:
        if self.reconnect_count > self.reconnect_max:
            raise ValueError("Max try reconnect")
        try:
            async for data in self.websocket:
                match(data.type):
                    case WSMsgType.TEXT:
                        self.receive_data.append(json.loads(data.data))
                    case WSMsgType.ERROR:
                        print(f"error:{data.data}")
                    case _:
                        print(f"unknown:{data.data}")
                self.reconnect_count = 0
        except TimeoutError:
            pass
        except ClientConnectionResetError as e:
            await self.reconnect(self.url, e)
            await self.receive
        except Exception as e:
            print(e)
            pass

        return self.receive_data
     
    async def close(self, ids:list[str]=None) -> None:
        if ids:
            for id in ids:
                await self.send(self.closeMessage(id=id))
            self.subscribe_ids = list(filter(lambda x: x not in ids, self.subscribe_ids))
        else:
            for id in self.subscribe_ids:
                await self.send(self.closeMessage(id=id))
            self.subscribe_ids = []

        if self.subscribe_ids == []:
            self.connected = False
            await self.websocket.close()
            await self.session.close()
            del self.session
            del self.websocket

    async def auth(self):
        # NIP-42
        signevent = self.makeAuthEvent(self.url, self.ClientAuth)
        self.addEvent(
            kind=signevent['kind'],
            tags=signevent['tags'],
            content=signevent['content'],
            created_at=signevent['created_at'],
            verify=True, validate=True)
        event = {
            "kind": self.kind,
            "tags": self.tags,
            "content": self.content,
            "created_at": self.created_at,
            "pubkey": self.pubkey,
            "id": self.id,
            "sig": self.sig
        }
        await self.send(self.authMessage(event=event))
    
    async def count(self, id:str=""):
        await self.send(self.countMessage(id=id))

    async def fire(self, id:str="") -> None:
        await self.send(self.reqMessage(id=id))

    async def publish(self) -> None:
        event = {
            "kind": self.kind,
            "tags": self.tags,
            "content": self.content,
            "created_at": self.created_at,
            "pubkey": self.pubkey,
            "id": self.id,
            "sig": self.sig
        }
        await self.send(self.eventMessage(event=event))

    async def subscribe(self, id:str="") -> None:
        self.subscribe_ids.append(id)
        await self.fire(id=id)

    async def pingpong(self) -> None:
        await self.send("ping")
        async for msg in self.websocket:
            match(msg.type):
                case WSMsgType.TEXT:
                    print(f"from server text{msg.data}")
                    break
                case WSMsgType.PONG:
                    print(f"from server pong{msg.data}")
                    break
                case WSMsgType.CLOSED:
                    print(f"from server closed{msg.data}")
                    break
                case WSMsgType.ERROR:
                    print(f"from server error{msg.data}")
                    break
                case _:
                    print(f"from server unknown{msg.data}")
                    break

    def eventMessage(self, event:dict) -> str:
        return f'["EVENT",{json.dumps(event)}]'
    
    def requestMessage(self, id:str="") -> str:
        return f'["REQ","{id}",{json.dumps(self.subscribe_filters)}]'
    
    def closeMessage(self, id:str="") -> str:
        return f'["CLOSE","{id}"]'
    
    def authMessage(self, event:dict) -> str:
        return f'["AUTH",{json.dumps(event)}]'
    
    def countMessage(self, id:str="") -> str:
        subscribe_filters = self.strFilters()
        return f'["COUNT","{id}",{subscribe_filters}]' if subscribe_filters != "" else f'["COUNT","{id}",{{}}]'
    
    def reqMessage(self, id:str="") -> str:
        subscribe_filters = self.strFilters()
        return f'["REQ","{id}",{subscribe_filters}]' if subscribe_filters != "" else f'["REQ","{id}",{{}}]'

    def choice(self, subscribe_id:list[str]=None, msg_type:str="", num=-1):
        # subscribe_id: None すべてのIDを取得
        # msg_type: EVENT, EOSE, NOTICE, OK, COUNT, AUTH
        # num: -1 すべて, 0 空読み, 1以上 numの指定数だけ取得

        choiced_data = []
        if subscribe_id:
            choiced_data = list(filter(lambda x: x[0] == msg_type and x[1] in subscribe_id, self.receive_data))
        else:
            choiced_data = list(filter(lambda x: x[0] == msg_type, self.receive_data))
        
        return choiced_data[0:num] if num >= 0 else choiced_data[0:]
    