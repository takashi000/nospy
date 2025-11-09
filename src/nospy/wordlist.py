from .chinese_simplified import wordlist_chinese_simplified
from .chinese_traditional import wordlist_chinese_traditional
from .czech import wordlist_czech
from .english import wordlist_english
from .french import wordlist_french
from .italian import wordlist_italian
from .japanese import wordlist_japanese
from .korean import wordlist_korean
from .portuguese import wordlist_portuguese
from .spanish import wordlist_spanish

def get_wordlist(lang:str="english") -> tuple[str]:
    match lang.lower():
        case "chinese_simplified":
            return wordlist_chinese_simplified
        case "chinese_traditional":
            return wordlist_chinese_traditional
        case "czech":
            return wordlist_czech
        case "english":
            return wordlist_english
        case "french":
            return wordlist_french
        case "italian":
            return wordlist_italian
        case "japanese":
            return wordlist_japanese
        case "korean":
            return wordlist_korean
        case "portuguese":
            return wordlist_portuguese
        case "spanish":
            return wordlist_spanish
        case _:
            return wordlist_english

def get_wordlist_index_table(lang:str="english") -> dict[str, int]:
    wordlist = get_wordlist(lang)
    return {word: index for index, word in enumerate(wordlist)}

def get_supported_languages() -> tuple[str, ...]:
    return (
        "chinese_simplified",
        "chinese_traditional",
        "czech",
        "english",
        "french",
        "italian",
        "japanese",
        "korean",
        "portuguese",
        "spanish"
    )