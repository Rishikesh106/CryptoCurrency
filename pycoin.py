import hashlib
import json
import base64
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


# ============================================================
# SHA-256 HASHING FUNCTION
# ============================================================

def sha256(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# ============================================================
# CANONICAL JSON FUNCTION
# ============================================================

def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


# ============================================================
# WALLET CLASS
# ============================================================

class Wallet:

    def __init__(self):
        # Generate private and public keys
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        # Convert public key into bytes
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Encode public key using Base64
        self.public_key_text = base64.b64encode(
            public_bytes
        ).decode()

        # Generate wallet address using SHA-256
        self.address = sha256(public_bytes)[:40]

    def sign(self, transaction):
        # Sign transaction using private key
        message = canonical_json(transaction).encode()
        signature = self.private_key.sign(message)

        return base64.b64encode(signature).decode()


# ============================================================
# BLOCK CLASS
# ============================================================

class Block:

    def __init__(self, index, transactions, previous_hash):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
        }

        return sha256(canonical_json(block_data))


# ============================================================
# PYCOIN CRYPTOCURRENCY CLASS
# ============================================================

class PyCoin:

    def __init__(self, initial_balances):
        # Store initial balances
        self.initial_balances = dict(initial_balances)

        # Create the genesis block
        genesis = Block(0, [], "0")
        self.chain = [genesis]

    # --------------------------------------------------------
    # CALCULATE USER BALANCE
    # --------------------------------------------------------

    def balance(self, address):
        amount = self.initial_balances.get(address, 0)

        for block in self.chain[1:]:
            for tx in block.transactions:

                if tx["sender"] == address:
                    amount -= tx["amount"]

                if tx["recipient"] == address:
                    amount += tx["amount"]

        return amount

    # --------------------------------------------------------
    # VERIFY TRANSACTION
    # --------------------------------------------------------

    def verify_transaction(self, tx):
        try:
            amount = tx["amount"]

            # Check positive integer amount
            if type(amount) is not int or amount <= 0:
                return False

            # Validate recipient
            if not isinstance(tx["recipient"], str):
                return False

            # Decode sender public key
            public_bytes = base64.b64decode(
                tx["public_key"], validate=True
            )

            # Verify sender address
            if sha256(public_bytes)[:40] != tx["sender"]:
                return False

            # Reconstruct public key
            public_key = Ed25519PublicKey.from_public_bytes(
                public_bytes
            )

            # Reconstruct signed transaction data
            signed_data = {
                "id": tx["id"],
                "sender": tx["sender"],
                "recipient": tx["recipient"],
                "amount": amount,
            }

            # Decode digital signature
            signature = base64.b64decode(
                tx["signature"], validate=True
            )

            # Verify digital signature
            public_key.verify(
                signature,
                canonical_json(signed_data).encode(),
            )

            return True

        except Exception:
            return False

    # --------------------------------------------------------
    # TRANSFER CRYPTOCURRENCY
    # --------------------------------------------------------

    def transfer(self, sender_wallet, recipient, amount):

        # Validate transfer amount
        if type(amount) is not int or amount <= 0:
            print("Transfer rejected: amount must be positive.")
            return False

        # Check sender balance
        if self.balance(sender_wallet.address) < amount:
            print("Transfer rejected: insufficient balance.")
            return False

        # Create transaction
        tx = {
            "id": str(uuid.uuid4()),
            "sender": sender_wallet.address,
            "recipient": recipient,
            "amount": amount,
            "public_key": sender_wallet.public_key_text,
        }

        # Prepare transaction data for signing
        signed_data = {
            "id": tx["id"],
            "sender": tx["sender"],
            "recipient": tx["recipient"],
            "amount": tx["amount"],
        }

        # Sign transaction using sender's private key
        tx["signature"] = sender_wallet.sign(signed_data)

        # Verify transaction before recording
        if not self.verify_transaction(tx):
            print("Transfer rejected: invalid signature.")
            return False

        # Create a block linked to the previous block
        previous_hash = self.chain[-1].hash

        block = Block(
            len(self.chain),
            [tx],
            previous_hash,
        )

        # Add block to blockchain
        self.chain.append(block)

        print("\nTransfer successful!")
        print("Transaction ID:", tx["id"])
        print("Block hash:", block.hash)

        return True

    # --------------------------------------------------------
    # VERIFY BLOCKCHAIN INTEGRITY
    # --------------------------------------------------------

    def verify_chain(self):

        if not self.chain:
            return False

        # Verify genesis block
        genesis = self.chain[0]

        if (
            genesis.index != 0
            or genesis.previous_hash != "0"
            or genesis.transactions != []
            or genesis.hash != genesis.calculate_hash()
        ):
            return False

        # Start with initial balances
        balances = dict(self.initial_balances)

        # Verify remaining blocks
        for i, block in enumerate(self.chain[1:], start=1):

            # Verify block index
            if block.index != i:
                return False

            # Verify previous block hash
            if block.previous_hash != self.chain[i - 1].hash:
                return False

            # Verify current block hash
            if block.hash != block.calculate_hash():
                return False

            # Verify transactions
            for tx in block.transactions:

                if not self.verify_transaction(tx):
                    return False

                sender = tx["sender"]
                recipient = tx["recipient"]
                amount = tx["amount"]

                # Check available balance
                if balances.get(sender, 0) < amount:
                    return False

                # Update balances
                balances[sender] = (
                    balances.get(sender, 0) - amount
                )

                balances[recipient] = (
                    balances.get(recipient, 0) + amount
                )

        return True

    # --------------------------------------------------------
    # DISPLAY BLOCKCHAIN
    # --------------------------------------------------------

    def display_chain(self):

        for block in self.chain:

            print("\nBlock:", block.index)
            print("Previous hash:", block.previous_hash)
            print("Block hash:", block.hash)

            for tx in block.transactions:
                print(
                    tx["sender"],
                    "->",
                    tx["recipient"],
                    "| Amount:",
                    tx["amount"],
                    "PyCoin",
                )


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":

    # Create wallets for three users
    alice = Wallet()
    bob = Wallet()
    charlie = Wallet()

    # Initialize cryptocurrency with 100 PyCoin per user
    coin = PyCoin({
        alice.address: 100,
        bob.address: 100,
        charlie.address: 100,
    })

    # Display wallet addresses
    print("=" * 55)
    print("         PYCOIN CRYPTOCURRENCY SYSTEM")
    print("=" * 55)

    print("\nWallet Addresses:")
    print("Alice:", alice.address)
    print("Bob:", bob.address)
    print("Charlie:", charlie.address)

    # Display initial balances
    print("\nInitial Balances:")

    for name, wallet in [
        ("Alice", alice),
        ("Bob", bob),
        ("Charlie", charlie),
    ]:
        print(name, ":", coin.balance(wallet.address), "PyCoin")

    # Execute cryptocurrency transfers
    print("\n" + "=" * 55)
    print("             CRYPTOCURRENCY TRANSFERS")
    print("=" * 55)

    # Alice sends 25 PyCoin to Bob
    coin.transfer(alice, bob.address, 25)

    # Bob sends 10 PyCoin to Charlie
    coin.transfer(bob, charlie.address, 10)

    # Charlie sends 5 PyCoin to Alice
    coin.transfer(charlie, alice.address, 5)

    # Display final balances
    print("\n" + "=" * 55)
    print("                FINAL BALANCES")
    print("=" * 55)

    for name, wallet in [
        ("Alice", alice),
        ("Bob", bob),
        ("Charlie", charlie),
    ]:
        print(name, ":", coin.balance(wallet.address), "PyCoin")

    # Verify blockchain integrity
    print("\nBlockchain integrity:", coin.verify_chain())

    # Display all blocks
    print("\n" + "=" * 55)
    print("               BLOCKCHAIN DETAILS")
    print("=" * 55)

    coin.display_chain()

    # Demonstrate transaction tampering
    print("\n" + "=" * 55)
    print("                TAMPERING TEST")
    print("=" * 55)

    print("Original transaction amount: 25 PyCoin")

    # Change the first transaction amount from 25 to 90
    coin.chain[1].transactions[0]["amount"] = 90

    print("Modified transaction amount: 90 PyCoin")

    # Verify blockchain after modification
    print(
        "Blockchain integrity after tampering:",
        coin.verify_chain(),
    )

    print("\nExperiment completed successfully.")