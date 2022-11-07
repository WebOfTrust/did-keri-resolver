import re

from keri.core import coring

DID_RE = re.compile('\\Adid:keri:(?P<aid>[^:]+):(?P<oobi>.+)\\Z', re.IGNORECASE)


def parseDID(did):
    match = DID_RE.match(did)
    if match is None:
        raise ValueError(f"{did} is not a valid did:keri DID")

    aid = match.group("aid")

    try:
        _ = coring.Prefixer(qb64=aid)
    except Exception as e:
        raise ValueError(f"{aid} is an invalid AID")

    oobi = match.group("oobi")

    return aid, oobi
