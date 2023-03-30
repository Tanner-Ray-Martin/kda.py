from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder, URLSafeBase64Encoder, Base32Encoder, RawEncoder
from nacl.hash import blake2b
from nacl.secret import SecretBox
import json


class Sign:
    def __init__(
        self,
        account: str,
        keys: list = None,
        load: bool = False,
        save: bool = False,
        password: str = False,
    ):
        """
        account: str, | k:address

        keys: list = None | List of Tuples containing HexEncoded Verifykey and Signature Key Strings

        load: bool = False | load the keys from file. requires valid password

        save: bool = False | save the keys to file. requires password

        password: str = False | password used  as a seed to generate an Asymetric ED25519 Curve Encryption Key for public/secret key storage
        """
        self.account = account
        self.__keys = keys
        self.load = load
        self.save = save
        self.__password = self.__hashPassword(password)
        if self.__keys is None:
            if self.load:
                # try to load and construct the keys from the keys.json file
                self.__keys = self.__loadKeys()
                # convert the hex keys into Verify and Signing Key Objects
                self.__keys = self.__constructKeys()
            else:
                # generate new keys
                self.__keys = self.__genKeys()
        else:
            # convert the hex verify and signing keys to verify and signing key objects
            self.__keys = self.__constructKeys()

    def code2HashedBytes(self, pact_code) -> bytes:
        """
        convert the pact_code string to utf8 bytes and return the blake2b Hashed Bytes
        """
        # convert to utf8 bytes
        pact_code_bytes = bytes(pact_code, encoding="utf8")
        # convert the pact code bytes into blake2b hashed bytes
        hashed_blake2b = blake2b(pact_code_bytes, digest_size=32, encoder=RawEncoder)
        return hashed_blake2b

    def hash(self, hashed_bytes: bytes, num_bytes: int = 64) -> str:
        """
        convert and return the blake2b hashed bytes into base 64 url safe decoded string after removing any '=' sign that may appear on the far right of the string

        """
        encoder = URLSafeBase64Encoder if num_bytes == 64 else Base32Encoder
        return encoder.encode(hashed_bytes).decode().rstrip("=")

    def sign(self, hashed_bytes) -> list:
        """
        returns a list of HexEncoded signatures from each signing key in the self.__keys
        """
        return [__key[-1].sign(hashed_bytes).signature.hex() for __key in self.__keys]

    def hashAndSign(self, hashed_bytes) -> tuple:
        """
        return the ouput of both hash and sign functions
        """
        return (
            self.hash(hashed_bytes),
            self.sign(hashed_bytes),
            [__key[0].__bytes__().hex() for __key in self.__keys],
        )

    def __constructKeys(self) -> list:
        """
        converts the self.__keys from [(hex_public_key, hex_signing_key)] to [(VerifyKey, SigningKey)]
        _[0] = HexEncoded public key
        _[-1] = HexEncode signing key
        """
        return [
            (
                VerifyKey(__key[0], encoder=HexEncoder),
                SigningKey(__key[-1], encoder=HexEncoder),
            )
            for __key in self.__keys
        ]

    def __genKeys(self) -> list:
        """
        generate a SigningKey and return it along with its VerifyKey counterpart in a tuple within a list [(VerifyKey, SigningKey)]
        """
        return [(__sk.verify_key, __sk) for __sk in [SigningKey.generate()]]

    def __loadKeys(self) -> list:
        """
        open and read the keys.json file
        decrypt the signing key for the account and return [(VerifyKey, SigningKey)]
        """
        with open("keys.json", "r") as fp:
            account_dict = json.load(fp)
        encrypted_keys = account_dict[self.account]
        return [
            (
                self.__decrypt(bytes(__key[0], encoding="utf8")),
                self.__decrypt(bytes(__key[-1], encoding="utf8")),
            )
            for __key in encrypted_keys
        ]

    def __hashPassword(self, __password: str) -> bytes:
        return self.code2HashedBytes(__password)[32:]

    def __saveKeys(self) -> None:
        """
        WARNING!!!!
        A Different Password will overwrite the any encrypted keys with the new encryption
        save the hex representations of VerifyKey and Signing Key into the keys.json config
        {
            "k:address": [
                (
                    "verify_key_hex",
                    "public_key_hex:
                )
            ]
        }
        """
        with open("keys.json", "r") as fp:
            account_dict = json.load(fp)
        encrypted_keys = [
            (
                self.__encrypt(bytes(__key[0].__bytes__().hex(), encoding="utf8")),
                self.__encrypt(bytes(__key[-1].__bytes__().hex(), encoding="utf8")),
            )
            for __key in self.__keys
        ]
        account_dict[self.account] = encrypted_keys
        with open("keys.json", "w") as fp:
            json.dump(account_dict, fp, sort_keys=True, indent=4)

    def __encrypt(self, message: bytes) -> str:
        assert isinstance(self.__password, bytes), "encryption requires Password"
        return (
            SecretBox(self.__password.hex(), encoder=HexEncoder)
            .encrypt(message, encoder=HexEncoder)
            .hex()
        )

    def __decrypt(self, message: bytes) -> str:
        assert isinstance(self.__password, bytes), "decryption requires Password"
        return SecretBox(self.__password.hex(), encoder=HexEncoder).decrypt(
            message, encoder=HexEncoder
        )

    def finish(self) -> None:
        if self.save:
            self.__saveKeys()
