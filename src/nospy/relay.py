import asyncio
import json
import ssl
import uuid
from aiohttp import ClientSession, ClientTimeout, ClientWebSocketResponse, ClientWSTimeout, WSMsgType, web

from .filter import Filter
from .message import Message
from .nips import Nips

class Relay(Filter, Message, Nips):
    def __init__(
            self, url:str="",
            ping:bool=False,
            reconnect_on:bool=True,
            reconnect_max:int=3,
            timeout:float=1.5,
            server_host:str="0.0.0.0",
            server_port:int=8080,
            server_route:str="/",
            server_ssl_on:bool=False,
            ssl_certfile:str="",
            ssl_keyfile:str="",
            client_ssl_on:bool=True,
        ):
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
        self.client_ssl_on:bool = client_ssl_on

        self.server_app:web.Application = None
        self.server_runner:web.AppRunner = None
        self.server_host:str = server_host
        self.server_port:int = server_port
        self.server_route:str = server_route
        self.server_ssl_on:bool = server_ssl_on
        self.ssl_certfile:str = ssl_certfile
        self.ssl_keyfile:str = ssl_keyfile
        self.server_buffer:list[dict] = []

    async def server_start(self) -> None:
        ssl_context = None
        if self.server_ssl_on:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            if self.ssl_certfile != "" and self.ssl_keyfile != "":
                ssl_context.load_cert_chain(self.ssl_certfile, self.ssl_keyfile)

        self.server_app = web.Application()
        self.server_app.router.add_get(self.server_route, self.relay_handler)

        self.server_runner = web.AppRunner(self.server_app)
        await self.server_runner.setup()
        site = web.TCPSite(self.server_runner, host=self.server_host, port=self.server_port, ssl_context=ssl_context)
        await site.start()

    async def server_send(self, ws:web.WebSocketResponse, message:str="") -> None:
        try:
            await ws.send_str(message)
        except Exception as e:
            print(e)

    async def server_dequeue(self) -> dict|None:
        if len(self.server_buffer) > 0:
            return self.server_buffer.pop(0)
        return None

    async def relay_handler(self, request) -> web.WebSocketResponse:
        message:list = []
        uuid_id = str(uuid.uuid4())
        ws = web.WebSocketResponse()
        
        await ws.prepare(request)

        try:
            async for data in ws:
                # メッセージの受信
                try:
                    match(data.type):
                        case WSMsgType.TEXT:
                            message = json.loads(data.data)
                        case WSMsgType.CLOSE|WSMsgType.CLOSED|WSMsgType.ERROR:
                            break
                        case _:
                            print(f"from client unknown:{data.data}")
                except json.JSONDecodeError as e:
                    print(e)
                    continue
                # 受信したメッセージをバッファに追加
                self.server_buffer.append({
                    "uuid": uuid_id,
                    "ws": ws,
                    "message": message
                })
        except Exception as e:
            print(e)

        ws.close()
        print("websocket connection closed")

        return ws

    async def connect(self, url:str="") -> None:
        ctimeout = ClientTimeout(
            total=None, 
            connect=20,
            sock_connect=20,
            sock_read=None
        )
        wstimeout = ClientWSTimeout(ws_receive=self.timeout_receive, ws_close=None)

        self.session =  ClientSession(timeout=ctimeout)
        self.websocket = await self.session.ws_connect(url=url, timeout=wstimeout, ssl=self.client_ssl_on)
        self.connected = True

        if self.enableping:
            await self.pingpong()
            self.enableping = False

    async def reconnect(self, url:str="") -> None:
        if self.reconnect_on:
            self.connected = False
            
            await self.websocket.close()
            await self.session.close()
            
            del self.session
            del self.websocket
            
            await asyncio.sleep(5)

            self.enableping = True
            await self.connect(url)
            self.reconnect_count += 1
        else:
            raise ValueError("Not Connected")

    async def send(self, message:str="") -> None:
        try:
            if self.reconnect_count > self.reconnect_max:
                raise ValueError("Max try reconnect")
            async for msg in self.websocket:
                match(msg.type):
                    case WSMsgType.TEXT:
                        await self.websocket.send_str(message)
                    case WSMsgType.CLOSE:
                        print(f"close:{msg.data}")
                    case WSMsgType.CLOSED:
                        print(f"closed:{msg.data}")
                    case WSMsgType.ERROR:
                        print(f"error:{msg.data}")
                    case _:
                        print(f"unknown:{msg.data}")
                break
            self.reconnect_count = 0
        except TimeoutError:
            await self.reconnect(self.url)
            await self.send(message)
        except Exception as e:
            raise ValueError(e)

    async def receive(self) -> list[dict]:
        try:
            async for msg in self.websocket:
                match(msg.type):
                    case WSMsgType.TEXT:
                        self.receive_data.append(json.loads(msg.data))
                    case WSMsgType.CLOSE:
                        print(f"close:{msg.data}")
                    case WSMsgType.CLOSED:
                        print(f"closed:{msg.data}")
                    case WSMsgType.ERROR:
                        print(f"error:{msg.data}")
                    case _:
                        print(f"unknown:{msg.data}")
        except TimeoutError:
            await self.reconnect(self.url)
        except Exception as e:
            raise ValueError(e)

        return self.receive_data
     
    async def close(self, ids:list[str]=None) -> None:
        if ids:
            for id in ids:
                await self.send(self.closeMessage(id))
            self.subscribe_ids = list(filter(lambda x: x not in ids, self.subscribe_ids))
        else:
            for id in self.subscribe_ids:
                await self.send(self.closeMessage(id))
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
        await self.send(self.authMessage(event))
    
    async def count(self, id:str=""):
        await self.send(self.countMessage(id))

    async def fire(self, id:str="") -> None:
        await self.send(self.reqMessage(id))

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
        await self.send(self.eventMessage(event))

    async def subscribe(self, id:str="") -> None:
        self.subscribe_ids.append(id)
        await self.fire(id)

    async def pingpong(self) -> None:
        await self.websocket.send_str("PING")

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
    