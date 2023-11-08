#!/usr/bin/env python3
import abc
import argparse
import asyncio
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from getpass import getpass
from pathlib import Path
from typing import AsyncGenerator, List, NoReturn, Optional, Tuple

import psycopg
import psycopg.connection_async as conn_async
import websockets
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from rich.highlighter import RegexHighlighter
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.messages import ExitApp
from textual.validation import Length
from textual.widgets import Header, Input, Log, TabbedContent, TabPane


class Crypto:
    @staticmethod
    def generate_public_private_keys(private_path: Path, public_path: Path) -> None:
        public_key_user_name = input("Enter user name for public key: ")
        private_key_password = getpass("Enter password for private key: ")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=(
                serialization.BestAvailableEncryption(private_key_password.encode())
                if private_key_password
                else serialization.NoEncryption()
            ),
        )
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        public_key_bytes += b" " + public_key_user_name.encode() + b"\n"
        with private_path.open("wb") as file:
            file.write(private_key_bytes)
        with public_path.open("wb") as file:
            file.write(public_key_bytes)

    @staticmethod
    def load_private_key(path: Path, password: bytes = None) -> rsa.RSAPrivateKey:
        with path.open("rb") as file:
            return serialization.load_ssh_private_key(
                file.read(),
                password=password,
            )

    @staticmethod
    def load_users_public_keys(path: Path) -> List[Tuple[str, rsa.RSAPublicKey]]:
        known_users = []
        with path.open("rb") as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith(b"#"):
                    continue
                user_name = line.split(b" ", maxsplit=2)[2].decode()
                public_key = serialization.load_ssh_public_key(line)
                known_users.append((user_name, public_key))
        return known_users

    @staticmethod
    def generate_signature(data, private_key: rsa.RSAPrivateKey) -> bytes:
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    @staticmethod
    def verify_signature(
        signature: bytes, data: bytes, public_key: rsa.RSAPublicKey
    ) -> None:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    @staticmethod
    def asymmetric_encrypt_data(data: bytes, public_key: rsa.RSAPublicKey) -> bytes:
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    @staticmethod
    def asymmetric_decrypt_data(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        return private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    @staticmethod
    def symmetric_encrypt_data(data: bytes, key: bytes, iv: bytes) -> bytes:
        padder = PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()

    @staticmethod
    def symmetric_decrypt_data(data: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(data) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()

    @staticmethod
    def sign_and_encrypt_message(
        message: bytes, private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey
    ) -> bytes:
        key, iv = os.urandom(32), os.urandom(16)
        message_signature = Crypto.generate_signature(message, private_key)
        encrypted_message = Crypto.symmetric_encrypt_data(
            message_signature + message, key, iv
        )
        encrypted_aes_key_iv = Crypto.asymmetric_encrypt_data(key + iv, public_key)
        return encrypted_aes_key_iv + encrypted_message

    @staticmethod
    def decrypt_message(
        message: bytes, private_key: rsa.RSAPrivateKey
    ) -> (bytes, bytes):
        encrypted_aes_key_iv = message[:256]
        encrypted_message = message[256:]
        aes_key_iv = Crypto.asymmetric_decrypt_data(encrypted_aes_key_iv, private_key)
        key, iv = aes_key_iv[:32], aes_key_iv[32:]
        message = Crypto.symmetric_decrypt_data(encrypted_message, key, iv)
        message_signature = message[:256]
        message = message[256:]
        return message_signature, message

    @staticmethod
    def discover_message_sender(
        message_signature: bytes,
        message: bytes,
        possible_senders: List[rsa.RSAPublicKey],
    ) -> int:
        for index, public_key in enumerate(possible_senders):
            try:
                Crypto.verify_signature(message_signature, message, public_key)
                return index
            except InvalidSignature:
                continue
        raise ValueError("Unknown sender or message tempered with.")


@dataclass
class KnownUser:
    name: str
    public_key: rsa.RSAPublicKey


class MyUser(KnownUser):
    def __init__(self, name: str, private_key: rsa.RSAPrivateKey):
        super().__init__(name, private_key.public_key())
        self.private_key = private_key


class Room:
    def __init__(self, members: List[KnownUser]):
        self.members = members
        keys = []
        for m in self.members:
            ns = m.public_key.public_numbers()
            keys.append(f"{ns.e}:{ns.n}".encode())
        keys.sort()
        diggest = hashes.Hash(hashes.SHA256())
        for key in keys:
            diggest.update(key)
        self.id = diggest.finalize()
        self._member_sequency_number = {}

    def get_sequency_number(self, member: KnownUser) -> int:
        return self._member_sequency_number.get(id(member), 0)

    def set_sequency_number(self, member: KnownUser, value: int) -> None:
        self._member_sequency_number[id(member)] = value


@dataclass
class Message:
    room_id: bytes
    sequency_number: int
    timestamp: datetime
    nickname: str
    content: str

    def serialize(self) -> bytes:
        return (
            b"\x00"  # version
            + self.room_id
            + self.sequency_number.to_bytes(2, byteorder="big")
            + int(self.timestamp.timestamp()).to_bytes(6, byteorder="big")
            + f"{self.nickname.strip()}:{self.content.strip()}".encode()
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "Message":
        if data[0] != 0:
            raise ValueError(f"Incompatible message version: {data[0]}")
        room_id = data[1:33]
        seq_number = int.from_bytes(data[33:35], byteorder="big")
        timestamp = datetime.fromtimestamp(
            int.from_bytes(data[35:41], byteorder="big"), tz=timezone.utc
        )
        nickname, content = (
            data[41:].decode("utf-8", errors="replace").split(":", maxsplit=1)
        )
        return cls(room_id, seq_number, timestamp, nickname.strip(), content.strip())


@dataclass
class RecievedMessage:
    timestamp: datetime
    sender: Optional[KnownUser]
    message: Message


class Network(abc.ABC):
    def __init__(
        self, connection_uri: str, my_user: MyUser, known_users: List[KnownUser]
    ):
        self.connection_uri = connection_uri
        self.my_user = my_user
        self.all_users = [my_user, *known_users]

    @abc.abstractmethod
    async def read_messages_forever(self) -> AsyncGenerator[RecievedMessage, NoReturn]:
        ...

    @abc.abstractmethod
    async def send_messages(self, messages: List[Tuple[Message, KnownUser]]) -> None:
        ...

    async def close(self):
        pass

    def decrypt_message(self, data) -> Optional[Tuple[Optional[KnownUser], Message]]:
        try:
            sign, raw_msg = Crypto.decrypt_message(data, self.my_user.private_key)
        except ValueError:
            return
        try:
            sender = self.all_users[
                Crypto.discover_message_sender(
                    sign, raw_msg, [u.public_key for u in self.all_users]
                )
            ]
        except ValueError:
            sender = None
        return sender, Message.from_bytes(raw_msg)


class PostgresNetwork(Network):
    def __init__(
        self, connection_uri: str, my_user: MyUser, known_users: List[KnownUser]
    ):
        super().__init__(connection_uri, my_user, known_users)
        self._read_connection = None
        self._write_connection = None

    async def _get_read_connection(self) -> psycopg.AsyncConnection:
        if self._read_connection is None:
            self._read_connection = await psycopg.AsyncConnection.connect(
                self.connection_uri, autocommit=True, connect_timeout=5
            )
            async with self._read_connection.cursor() as cursor:
                await cursor.execute("SELECT activate_listener()")
        return self._read_connection

    async def _get_write_connection(self) -> psycopg.AsyncConnection:
        if self._write_connection is None:
            self._write_connection = await psycopg.AsyncConnection.connect(
                self.connection_uri, autocommit=True, connect_timeout=5
            )
        return self._write_connection

    async def _read_messages(
        self,
        since_id: int,
    ) -> AsyncGenerator[RecievedMessage, None]:
        async with (await self._get_read_connection()).cursor() as cursor:
            await cursor.execute("""SELECT * FROM read_messages(%s)""", (since_id,))
            for line in await cursor.fetchall():
                if s_m := self.decrypt_message(line[2]):
                    yield line[0], RecievedMessage(line[1], s_m[0], s_m[1])

    async def read_messages_forever(
        self,
    ) -> AsyncGenerator[RecievedMessage, NoReturn]:
        conn = await self._get_read_connection()
        last_id = 0
        async for message_id, message in self._read_messages(last_id):
            last_id = message_id
            yield message
        while True:
            async with conn.lock:
                try:
                    await conn.wait(conn_async.notifies(conn.pgconn))
                except conn_async.e._NO_TRACEBACK as ex:
                    raise ex.with_traceback(None)
            async for message_id, message in self._read_messages(last_id):
                last_id = message_id
                yield message

    async def send_messages(self, messages: List[Tuple[Message, KnownUser]]) -> None:
        encrypted_messages = [
            Crypto.sign_and_encrypt_message(
                message.serialize(),
                self.my_user.private_key,
                user.public_key,
            )
            for message, user in messages
        ]
        async with (await self._get_write_connection()).cursor() as cursor:
            await cursor.execute("SELECT send_messages(%s)", [encrypted_messages])

    async def close(self):
        await asyncio.gather(
            *(c.close() for c in (self._read_connection, self._write_connection) if c)
        )


class WebSocketNetwork(Network):
    def __init__(
        self, connection_uri: str, my_user: MyUser, known_users: List[KnownUser]
    ):
        super().__init__(connection_uri, my_user, known_users)
        self._connection = None

    async def _get_connection(self) -> websockets.WebSocketClientProtocol:
        if self._connection is None:
            self._connection = await websockets.connect(self.connection_uri)
        return self._connection

    async def read_messages_forever(
        self,
    ) -> AsyncGenerator[RecievedMessage, NoReturn]:
        websocket = await self._get_connection()
        while True:
            data = await websocket.recv()
            timestamp = datetime.fromtimestamp(
                int.from_bytes(data[:6], byteorder="big"), tz=timezone.utc
            )
            if s_m := self.decrypt_message(data[6:]):
                yield RecievedMessage(timestamp, s_m[0], s_m[1])

    async def send_messages(self, messages: List[Tuple[Message, KnownUser]]) -> None:
        for message, user in messages:
            await (await self._get_connection()).send(
                Crypto.sign_and_encrypt_message(
                    message.serialize(),
                    self.my_user.private_key,
                    user.public_key,
                )
            )

    async def close(self):
        if self._connection:
            await self._connection.close()


class ChatHighlighter(RegexHighlighter):
    base_style = "progress."
    highlights = [
        r"^(?P<filesize>\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+(?P<remaining>\(.*\))? "
        r"(?P<percentage>.+) (?P<spinner>│) ",
        r"^(?P<elapsed>\[.*\])$",
    ]


class Chat(App):
    CSS = """
    #rooms-tabs TabPane { padding: 0; } .new-message { color: lightskyblue; }
    Log { border: solid ansi_bright_black; } #bottom { height: 3; dock: bottom; }
    .c1 { width: 15; } .c2 { width: 1fr; }
    """

    def __init__(
        self,
        network: Network,
        my_user: MyUser,
        known_users: List[KnownUser],
        rooms: List[Room],
    ):
        super().__init__()
        self.my_user = my_user
        self.known_users = known_users
        self.rooms = {r.id: r for r in rooms}
        self.network = network

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        self.tabs = TabbedContent(id="rooms-tabs")
        yield self.tabs
        with Horizontal(id="bottom"):
            with Vertical(classes="c1"):
                self.nickname_box = Input(
                    placeholder=self.my_user.name,
                    id="nickname-box",
                    validators=[Length(maximum=8)],
                )
                yield self.nickname_box
            with Vertical(classes="c2"):
                self.message_box = Input(
                    placeholder="Write your message here...",
                    id="message-box",
                    validators=[Length(minimum=1, maximum=461)],
                )
                yield self.message_box

    async def on_mount(self) -> None:
        self.title = "Vortex"
        self.sub_title = "Secure, Transport-Agnostic, E2EE Chat"
        self.message_box.focus()
        for room in self.rooms.values():
            log = Log(highlight=True)
            log.highlighter = ChatHighlighter()
            name = ", ".join(m.name for m in room.members if m != self.my_user) or "Me"
            tab_pane = TabPane(name, log, id=f"r-{room.id.hex()}")
            await self.tabs.add_pane(tab_pane)
        self.start_read_loop()

    @on(ExitApp)
    async def exit_app(self, event: ExitApp) -> None:
        await self.network.close()

    @on(Input.Submitted, "#nickname-box")
    def name_submitted(self, event: Input.Submitted) -> None:
        self.message_box.focus()

    @on(Input.Changed, "#nickname-box")
    def name_changed(self, event: Input.Changed) -> None:
        self.message_box.disabled = not event.validation_result.is_valid

    @on(Input.Submitted, "#message-box")
    def message_submitted(self, event: Input.Submitted) -> None:
        if event.validation_result.is_valid:
            active = self.tabs.active
            self.send_message(
                self.nickname_box.value or self.my_user.name,
                self.message_box.value,
                bytes.fromhex(active[2:]),
            )
            self.message_box.value = ""

    @on(TabbedContent.TabActivated, "#rooms-tabs")
    def tab_activated(self, event: TabbedContent.TabActivated) -> None:
        event.tab.remove_class("new-message")

    @work()
    async def start_read_loop(self):
        name_pad = max(len(u.name) for u in (self.my_user, *self.known_users))
        async for msg in self.network.read_messages_forever():
            room_id = msg.message.room_id
            if (
                room_id not in self.rooms
                or msg.sender not in self.rooms[room_id].members
            ):
                continue
            tab_id = f"r-{room_id.hex()}"
            if self.tabs.active != tab_id:
                self.tabs.query_one(f"ContentTab#{tab_id}").add_class("new-message")
            log = self.tabs.query_one(f"#{tab_id} Log", Log)
            if n_missing := (
                msg.message.sequency_number
                - self.rooms[room_id].get_sequency_number(msg.sender)
                - 1
            ):
                log.write_line(f"[Lost messages from {msg.sender.name}: {n_missing}]")
            self.rooms[room_id].set_sequency_number(
                msg.sender, msg.message.sequency_number
            )
            if abs(msg.message.timestamp - msg.timestamp) > timedelta(seconds=30):
                log.write_line(
                    msg.message.timestamp.strftime("[Network time: %d/%m %H:%M:%S]")
                )
            timestamp = msg.timestamp.strftime("%d/%m %H:%M:%S ")
            name, nickname = msg.sender.name, msg.message.nickname
            name = f"{'(' + name + ')' if nickname != name else '':>{name_pad + 2}s}"
            log.write_line(f"{timestamp} {name} {nickname:>8s} │ {msg.message.content}")
            if msg.sender != self.network.my_user:
                self.bell()

    @work()
    async def send_message(self, nickname, message, room_id):
        room = self.rooms[room_id]
        seq_number = room.get_sequency_number(self.my_user)
        timestamp = datetime.now(timezone.utc)
        network_message = Message(room_id, seq_number + 1, timestamp, nickname, message)
        messages = [(network_message, user) for user in room.members]
        await self.network.send_messages(messages)


def run_app(connection_uri):
    try:
        private_key = Crypto.load_private_key(Path("id_rsa"))
    except ValueError as e:
        if str(e) != "Key is password-protected.":
            raise
        try:
            private_key = Crypto.load_private_key(
                Path("id_rsa"), getpass("Enter password for private key: ").encode()
            )
        except ValueError as e:
            if str(e) != "Corrupt data: broken checksum":
                raise
            print("Corrupt data. Is the password correct?")
            return
    user_name, public_key = Crypto.load_users_public_keys(Path("id_rsa.pub"))[0]
    if private_key.public_key().public_numbers() != public_key.public_numbers():
        print("Public key does not match private key. Aborting.")
        return
    my_user = MyUser(user_name, private_key)
    known_users = [
        KnownUser(user_name, public_key)
        for user_name, public_key in Crypto.load_users_public_keys(Path("known_users"))
    ]
    name_user = {u.name: u for u in (my_user, *known_users)}
    if len(name_user) != len(known_users) + 1:
        print("User names must be unique. Aborting.")
        return
    rooms = [Room([my_user]), *(Room([my_user, u]) for u in known_users)]
    with Path("known_rooms").open("r") as file:
        for l in file:
            l = l.strip()
            if not l or l.startswith("#"):
                continue
            rooms.append(Room([my_user, *(name_user[n.strip()] for n in l.split(","))]))
    if connection_uri.startswith("postgres://"):
        network = PostgresNetwork(connection_uri, my_user, known_users)
    elif connection_uri.startswith("ws://") or connection_uri.startswith("wss://"):
        network = WebSocketNetwork(connection_uri, my_user, known_users)
    else:
        print("Invalid connection URI. Aborting.")
        return
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    app = Chat(network, my_user, known_users, rooms)
    app.run()


def generate_keys():
    if Path("id_rsa").exists() or Path("id_rsa.pub").exists():
        print("Keys already exist. Aborting.")
    else:
        Crypto.generate_public_private_keys(Path("id_rsa"), Path("id_rsa.pub"))
        Path("known_users").touch()
        Path("known_rooms").touch()


def main():
    parser = argparse.ArgumentParser(
        description="Vortex - Secure, Transport-Agnostic, E2EE Chat"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--generate-keys", action="store_true")
    group.add_argument("run", nargs="?", metavar="URI", help="(postgres|ws|wss)://...")
    args = parser.parse_args()
    if args.generate_keys:
        generate_keys()
    else:
        uri = args.run
        run_app(uri)


if __name__ == "__main__":
    main()
