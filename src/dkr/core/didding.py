import json
import re

from multibase import encode as mbencode

from keri.app import oobiing
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


def generateDIDDoc(hby, did, aid, oobi):
    obr = hby.db.roobi.get(keys=(oobi,))
    if obr.state == oobiing.Result.failed:
        msg = dict(msg=f"OOBI resolution for did {did} failed.")
        data = json.dumps(msg)
        return bytes(data)

    kever = hby.kevers[aid]
    keys = [mbencode('base58btc', verfer.raw) for verfer in kever.verfers]
    vms = []
    for idx, key in enumerate(keys):
        vms.append(dict(
            id=f"{did}#key-{idx}",
            type="Ed25519VerificationKey2020",
            controller=did,
            publicKeyMultibase=key.decode("utf-8")
        ))

    x = [(keys[1], loc.url) for keys, loc in
         hby.db.locs.getItemIter(keys=(aid,)) if loc.url]

    services = []
    for idx, eid in enumerate(kever.wits):
        keys = (eid,)
        for (aid, scheme), loc in hby.db.locs.getItemIter(keys):
            services.append(dict(
                id=f"{did}#witness-{idx}-{scheme}",
                type="keri-mailbox",
                serviceEndpoint=loc.url
            ))
    didResolutionMetadata = dict()
    didDocMetadata = dict()
    diddoc = dict(
        id=did,
        verificationMethod=vms,
        service=services
    )

    return didResolutionMetadata, diddoc, didDocMetadata
