# Vortex: Secure, Transport-Agnostic, E2EE Chat in Under 600 Lines

> [!WARNING]
This is a proof of concept, it was not audited!

Vortex is a lightweight, end-to-end encrypted chat application that ensures message
authenticity and confidentiality. It offers transport agnosticism, supporting both
PostgreSQL and WebSocket, all in less than 600 lines of Python code.

![screenshot](vortex.png)

## Setup and Usage

1. Clone the repository or download `requirements.txt` and  `vortex.py` to an empty directory.
2. Install python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Generate your public/private key pair:
   ```bash
   ./vortex.py --generate-keys
   ```
4. Share your public key (`id_rsa.pub`) with your contacts and ask them to share theirs
   with you.
5. Put your contacts' public keys in the `known_users` file. E.g.:
   ```
   # Work contacts:
   ssh-rsa <public key> John
   ssh-rsa <public key> Ofélia HR

   # Family:
   ssh-rsa <public key> Mother
   ssh-rsa <public key> Father
   ssh-rsa <public key> Joana
   ```
6. Optionally, add rooms to the `known_rooms` file. E.g.:
   ```
   # Work:
   Jonh, Ofélia HR

   # Family:
   Joana, Mother, Father
   ```
7. Run:
   ```bash
   ./vortex.py <connection-uri>
   ```
   Where `<connection-uri>` is either a PostgreSQL connection string or a WebSocket:
   `postgresql://user:password@localhost:5432/vortex`, `ws://localhost:8080`,
   `wss://localhost:8080`.

## Setup Server

Create a database like the specified on `postgres-setup.sql` if you want to use
PostgreSQL, or, to start a WebSocket server run:
```bash
./websocket-server.py
```
