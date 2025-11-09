import hashlib
import re
import json
import time

from .bip0340 import Bip0340

class Event(Bip0340):
    def __init__(self):
        super(Event, self).__init__()

        self.kind:int=1
        self.tags:list[list[str]]=[[""]]
        self.content:str=""
        self.created_at:int=0
        self.pubkey:str=""
        self.id:str=""
        self.sig:str=""

        self.verifiedSymbol:bool=False

        self.pubkey_match = re.compile(r'^[a-f0-9]{64}$')
        self.issigned:bool = False

    def VerifiedEvent(self):
        self.verifiedSymbol = True
    
    def validateEvent(self):
        if type(self.kind) is not int: return False
        if type(self.content) is not str: return False
        if type(self.created_at) is not int: return False
        if type(self.pubkey) is not str: return False
        if self.pubkey_match.match(self.pubkey) is False: return False
        if not isinstance(self.tags, list):
            return False
        for sublist in self.tags:
            if not isinstance(sublist, list):
                return False
            for item in sublist:
                if not isinstance(item, str):
                    return False
        return True

    def serializeEvent(self) -> str:
        if not self.validateEvent() : raise ValueError("can't serialize event with wrong or missing properties")
        event = self.unsignedEvent()
        return json.dumps(
            [0, 
             event['pubkey'], 
             event['created_at'], 
             event['kind'], 
             event['tags'], 
             event['content']
            ],
            ensure_ascii=False,
            separators=(',', ':')
        )

    def getEventHash(self) -> str:
        return hashlib.sha256(self.serializeEvent().encode('utf-8')).hexdigest()
    
    def finalizeEvent(self) -> dict:
        self.pubkey = self.generatePublicKey(self.skey) # defined nospy.py
        self.id = self.getEventHash()
        self.sig = self.signSchnorr(bytes.fromhex(self.getEventHash()), self.skey).hex()
        self.verifiedSymbol = True
        return self.eventTemplate()
    
    def verifyEvent(self) -> bool:
        if self.verifiedSymbol : self.verifiedSymbol
        hash = self.getEventHash()
        if hash != self.id:
            self.verifiedSymbol = False
            return False
        try:
            valid = self.verifySchnorr(bytes.fromhex(hash), bytes.fromhex(self.pubkey), bytes.fromhex(self.sig))
            self.verifiedSymbol = valid
            return valid
        except:
            self.verifiedSymbol = False
        return False

    def eventTemplate(self) -> dict:
        event = {
            "kind":self.kind,
            "tags":self.tags,
            "content":self.content,
            "created_at":self.created_at,
        }
        return event

    def unsignedEvent(self) -> dict:
        event = {
            "kind":self.kind,
            "tags":self.tags,
            "content":self.content,
            "created_at":self.created_at,
            "pubkey": self.pubkey,
        }
        return event
    
    def addEvent(
            self,
            kind:int=None,
            tags:list[list[str]]=None,
            content:str="",
            created_at:int=None,
            verify:bool=False,
            validate:bool=False,
        ) -> dict:
        self.kind = kind if kind else 1
        self.tags = tags if tags else [[""]]
        self.content = content if content else ""
        self.created_at = created_at if created_at else int(time.time())
        
        event = self.finalizeEvent()

        if verify:
            if not self.verifyEvent():
                raise ValueError("invalid Event: verifyEvent Error")
        
        if validate:
            if not self.validateEvent():
                raise ValueError("invalid Event: validateEvent Error")
        
        return event