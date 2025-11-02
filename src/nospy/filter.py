import json
from .event import Event
from .kinds import Kinds

class Filter(Event, Kinds):
    def __init__(self):
        super(Filter, self).__init__()

        self.nostr_filter:dict = {
            "ids":[""],
            "kinds":[0],
            "authors":[""],
            "since":0,
            "until":0,
            "limit":0,
            "search":""
        }

        self.subscribe_filters:list[dict] = []

    def matchFilter(self, nostr_filter:dict) -> bool:
        self.nostr_filter = nostr_filter
        if self.nostr_filter.get("ids") and self.id not in self.nostr_filter.get("ids"):
            return False
            
        if self.nostr_filter.get("kinds") and self.kind not in self.nostr_filter.get("kinds"):
            return False
        
        if self.nostr_filter.get("authors") and self.pubkey not in self.nostr_filter.get("authors"):
            return False
        
        for key, values in self.nostr_filter.items():
            if type(values) is not list: continue
            if key[0] == '#':
                if values and not any(t == key[1:] and v in values for t, v in self.tags):
                    return False
        
        if self.nostr_filter.get("since") and self.created_at < self.nostr_filter.get("since"):
            return False
        
        if self.nostr_filter.get("until") and self.created_at > self.nostr_filter.get("until"):
            return False
        
        return True
    
    def getFilterLimit(self, nostr_filter:dict) -> int|float:
        self.nostr_filter = nostr_filter
        if self.nostr_filter.get("ids") and len(self.nostr_filter.get("ids")) == 0:
            return 0
        
        if self.nostr_filter.get("kinds") and len(self.nostr_filter.get("kinds")) == 0:
            return 0
        
        if self.nostr_filter.get("authors") and len(self.nostr_filter.get("authors")) == 0:
            return 0
        
        for key, value in self.nostr_filter.items():
            if key[0] == '#' and type(value) is list and len(value) == 0:
                return 0
        
        limit_num = self.nostr_filter.get('limit') if self.nostr_filter.get('limit') is not None else float('Inf')
        ids_num = len(self.nostr_filter.get('ids')) if self.nostr_filter.get('ids') is not None else float('inf')
        replace_num = len(self.nostr_filter.get('authors')) * len(self.nostr_filter.get('kinds')) \
            if self.nostr_filter.get('authors') is not None and all(self.isReplaceableKind(self.nostr_filter.get("kinds"))) else float('Inf')
        param_num = len(self.nostr_filter.get('authors')) * len(self.nostr_filter.get("kinds")) * len(self.nostr_filter.get("#d")) \
            if self.nostr_filter.get('authors') is not None and all(self.isReplaceableKind(self.nostr_filter.get("kinds"))) \
                  and self.nostr_filter.get("#d") else float('Inf')
        
        return min(
            max(0, limit_num),
            ids_num,
            replace_num,
            param_num
        )

    def addFilters(
            self,
            ids:list[str]=None,
            kinds:list[int]=None, 
            authors:list[str]=None,
            since:int=None,
            until:int=None,
            limit:int=None,
            search:str=None
        ) -> dict:
        filter_dict:dict = {}
        if isinstance(ids, list) and all(isinstance(item, str) for item in ids):
            filter_dict.update(ids=ids)
        if isinstance(kinds, list) and all(isinstance(item, int) for item in kinds):
            filter_dict.update(kinds=kinds)
        if isinstance(authors, list) and all(isinstance(item, str) for item in authors):
            filter_dict.update(authors=authors)
        if isinstance(since, int):
            filter_dict.update(since=since)
        if isinstance(until, int):
            filter_dict.update(until=until)
        if isinstance(limit, int):
            filter_dict.update(limit=limit)
        if isinstance(search, str):
            filter_dict.update(search=search)
        
        self.subscribe_filters.append(filter_dict)

        return filter_dict

    def pullFilters(self) -> list[dict]:
        return self.subscribe_filters

    def strFilters(self) -> str:
        return "".join([json.dumps(f)+',' for f in self.subscribe_filters]).rstrip(',')
    
    def deleteFilter(self, index:int):
        if index >= 0 and index < len(self.subscribe_filters):
            del self.subscribe_filters[index]

    def clearFilters(self):
        self.subscribe_filters.clear()