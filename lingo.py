#come back to this later, need to consider implemention better
#kept this here to remind myself to get on with it.
#below will probably get deleted, but for the mo it reminds me
#of how not to do it.

en001 = "Welcome"
fr001 = "Bienvenue"


def GetLangString(which):
    match which:
        case "en001": return en001
        case "fr001": return fr001
        case _: return "Error"

def ReturnTrans(which, language):
    match language:
        case "en": 