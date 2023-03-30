import time, datetime
from sign import Sign
import json, requests

URL = "https://api.chainweb.com/chainweb/0.0/mainnet01/chain/CHAIN/pact/api/v1/"


class TX:
    def __init__(self) -> None:
        self.hash = None
        self.sigs = None
        self.url = URL
        self.temp_url = URL
        self.data = {"testdata": "arbitrary user data", "ks": [""]}

        self.signers = []
        self.sender = None
        self.meta = None
        self.nonce = None

    def buildCode(
        self, module: str, func: str, func_args: list = None, namespace: str = None
    ):
        code = "("
        if namespace is not None:
            code = code + namespace + "."
        code = f"{code}{module}.{func}"
        if func_args is not None:
            code = (
                code
                + " "
                + " ".join(
                    [
                        f'"{func_arg}"' if isinstance(func_arg, str) else str(func_arg)
                        for func_arg in func_args
                    ]
                )
            )
        code = code + ")"
        self.code = code

    def buildMeta(
        self,
        creationTime: float = None,
        ttl: int = 600,
        gasLimit: int = 300,
        chainId: str = "1",
        gasPrice: float = 1e-08,
        sender: str = None,
    ) -> None:
        self.temp_url = self.url.replace("CHAIN", chainId)
        self.meta = {
            "creationTime": creationTime or time.time(),
            "ttl": ttl,
            "gasLimit": gasLimit,
            "chainId": chainId,
            "gasPrice": gasPrice,
            "sender": False,
        }

    def buildCmd(self, signers: list = None, nonce: str = None, account: str = None):
        self.signers = signers or self.signers
        self.nonce = nonce or self.nonce or str(datetime.datetime.now())
        self.meta["sender"] = account or self.meta["sender"]
        self.payload = {"exec": {"data": self.data, "code": self.code}}
        self.cmd = {
            "address": account or self.meta["sender"],
            "signers": self.signers,
            "payload": self.payload,
            "meta": self.meta,
            "nonce": self.nonce,
        }

    def build(self):
        return {"sigs": self.sigs, "hash": self.hash, "cmd": json.dumps(self.cmd)}

    def sign(self, account, pub_key, priv_key=None, save=False, password=None):
        self.cmd["signers"] = [{"pubKey": pub_key}]
        if pub_key is not None and priv_key is not None:
            keys = [(pub_key, priv_key)]
            load = False
        else:
            assert password != None, "password required to decrypt keys"
            load = True
            keys = None

        signer = Sign(account, keys=keys, load=load, save=save, password=password)
        hashed_cmd = signer.code2HashedBytes(json.dumps(self.cmd))
        self.hash, signatures, pub_keys = signer.hashAndSign(hashed_cmd)
        sigs = list()
        signs = list()
        for sigNpub in list(zip(signatures, pub_keys)):
            sigs.append({"sig": sigNpub[0], "scheme": "ED25519", "pubKey": sigNpub[-1]})
            signs.append({"pubKey": sigNpub[-1]})

        self.sigs = sigs

        signer.finish()

    def send(self, url=None, endpoint="local"):
        self.temp_url = url or self.temp_url
        url = self.temp_url + endpoint
        r = requests.post(url, json=self.build())
        try:
            j = r.json()
            gas = j["gas"]
            result = j["result"]
            status = result["status"]

            if status == "success":
                try:

                    return {
                        "chain": self.meta["chainId"],
                        "balance": result["data"]["balance"],
                    }
                except:
                    return {
                        "chain": self.meta["chainId"],
                        "balance": result["data"],
                    }
            else:
                return {"chain": self.meta["chainId"], "balance": 0}
        except:
            print(r.__dict__)


KDA_Price = 0.9837
WIZA_Price = 0.023499
num_chains = 20


def getBalance(tx, addr):
    tx.buildCode("coin", "details", [addr])


def getWizaBalance(tx, addr):
    tx.buildCode("wiza", "get-user-balance", [addr], namespace="free")


def getWiza2KDA(tx):
    tx.buildCode(
        "kdswap-exchage", "get-pair", ["coin", "free.wiza"], namespace="kdlaunch"
    )


# testing testing
if __name__ == "__main__":
    address = "k:address"
    pub_key = ""
    priv_key = ""
    my_tx = TX()
    resp = dict()
    total_balance = 0
    for chain in range(num_chains):
        getBalance(my_tx, address)
        my_tx.buildMeta(sender=address, chainId=str(chain))
        my_tx.buildCmd(signers=[{"pubKey": pub_key}], account=address)
        my_tx.sign(
            account=address,
            pub_key=pub_key,
            priv_key=priv_key,
            save=True,
            password="password for saving and loading keys",
        )
        response = my_tx.send()
        balance = round(response["balance"], 4)
        resp[str(chain)] = balance
        if balance > 0:
            print(
                f"Chain:{str(chain).zfill(2)} KDA:{balance} USD:{round(balance*KDA_Price, 2)}"
            )
            total_balance += balance

    total_balance = round(total_balance, 4)
    s = f"Total:   KDA:{total_balance} USD:{round(total_balance*KDA_Price, 2)}"
    print(s)
    print("-" * len(s))
