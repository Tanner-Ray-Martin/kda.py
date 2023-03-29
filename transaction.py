import time

from sign import Sign

import json


class Hash:
    def __init__(self) -> None:
        self.name = "hash"
        self.hash: str = None

    def __call__(self, hash: str = None):
        self.hash = hash if hash is not None else self.hash
        return {self.name: self.hash}


class Sig:
    def __init__(self) -> None:
        self.name = "sig"
        self.sig: str = None
        self.scheme = "ED25519"
        self.pub_key: str = None

    def __call__(self, sig=None, pub_key=None) -> dict:
        self.sig = sig if sig is not None else self.sig
        self.pub_key = pub_key if pub_key is not None else self.pub_key
        return {self.name: self.sig, "scheme": self.scheme, "pubkey": self.pub_key}

    def __repr__(self) -> str:
        return "\n".join(
            [
                "{" + f"name: {self.name},",
                f"sig: {self.sig},",
                f"scheme: {self.scheme},",
                f"pub_key: {self.pub_key}" + "}",
            ]
        )


class Sigs:
    def __init__(self) -> None:
        self.name = "sigs"
        self.sigs: list = list()

    def __call__(self, sig: Sig = None) -> dict:
        if sig is not None:
            self.sigs.append(sig)
        return {self.name: self.sigs}


class Signer:
    def __init__(self) -> None:
        self.name = "pubKey"
        self.pub_key: str = None

    def __call__(self, pub_key: str = None) -> dict:
        self.pub_key = pub_key if pub_key is not None else self.pub_key
        return {self.name: self.pub_key}


class Signers:
    def __init__(self) -> None:
        self.name = "signers"
        self.signers: list = list()

    def __call__(self, signer: Signer = None) -> dict:
        if signer is not None:
            self.signers.append(signer)
        return {self.name: self.signers}


class Code:
    def __init__(self) -> None:
        self.name = "code"
        self.module: str = None
        self.module_func: str = None
        self.func_args: list = []

    def __call__(
        self, module: str = None, func: str = None, func_arg: str or float = None
    ) -> dict:
        self.module = module if module is not None else self.module
        self.module_func = func if func is not None else self.module_func
        if func_arg is not None:
            self.func_args.append(func_arg)
        func_args = " ".join(
            [
                '"' + func_arg + '"' if isinstance(func_arg, str) else str(func_arg)
                for func_arg in self.func_args
            ]
        )
        code = f'({self.module+"." if self.module is not None else ""}{self.module_func if self.module_func is not None else ""} {func_args}'
        return {self.name: code}


class Meta:
    def __init__(self) -> None:
        self.name = "meta"
        self.creationTime: float = round(time.time(), 0)
        self.ttl: int = (600,)
        self.gasLimit: int = (300,)
        self.chainId: int = (1,)
        self.gasPrice: float = (1e-08,)
        self.sender: str = None

    def __call__(
        self,
        ttl: int = None,
        gasLimit: int = None,
        chainId: int = None,
        gasPrice: float = None,
        sender: str = None,
        creationTime: float = None,
    ) -> dict:
        self.ttl = ttl if ttl is not None else self.ttl
        self.gasLimit = gasLimit if gasLimit is not None else self.gasLimit
        self.chainId = chainId if chainId is not None else self.chainId
        self.gasPrice = gasPrice if gasPrice is not None else self.gasPrice
        self.sender = sender if sender is not None else self.sender
        self.creationTime = (
            creationTime if creationTime is not None else round(time.time(), 0)
        )
        data = {
            "creationTime": self.creationTime,
            "ttl": self.ttl,
            "gasLimit": self.gasLimit,
            "chainId": f"{self.chainId}",
            "gasPrice": self.gasPrice,
            "sender": self.sender,
        }
        return {self.name: json.dumps(data)}


class Cmd:
    def __init__(self) -> None:
        self.name = "cmd"
        self.payload = dict()
        self.exec = dict()
        self.data = dict()
        self.code = Code()
        self.meta = Meta()


class Transaction:
    def __init__(self) -> None:
        self.hash = Hash()
        self.sigs = Sigs()
        self.cmd = Cmd()
        self.url = None
        self.request_key = None

    def sign(self):
        pass

    def send(self):
        pass

    def listen(self):
        pass

    def sendAndListen(self):
        pass

    def receive(self):
        pass


if __name__ == "__main__":
    hash = Hash()
    # write more testing
