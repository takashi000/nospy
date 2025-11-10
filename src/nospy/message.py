import json

from .filter import Filter

class Message(Filter):
    def __init__(self):
        super(Message, self).__init__()
    
    def eventMessage(self, event:dict) -> str:
        return f'["EVENT",{json.dumps(event)}]'
    
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

    def okMessage(self, id:str="", status:bool=True, message:str="") -> str:
        return f'["OK","{id}",{str(status).lower()},"{message}"]'
    
    def closedMessage(self, id:str="", message:str="") -> str:
        return f'["CLOSED","{id}","{message}"]'

    def noticeMessage(self, message:str="") -> str:
        return f'["NOTICE","{message}"]'
    
    def eoseMessage(self, id:str="") -> str:
        return f'["EOSE","{id}"]'