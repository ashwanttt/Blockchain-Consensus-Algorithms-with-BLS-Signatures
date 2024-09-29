import hashlib
import time
import random
from typing import List, Optional, Dict
from dataclasses import dataclass, field

# Simulating py_ecc.bls for faster execution
class SimulatedBLS:
    @staticmethod
    def KeyGen(seed):
        return hashlib.sha256(seed).digest()

    @staticmethod
    def SkToPk(sk):
        return hashlib.sha256(sk).digest()

    @staticmethod
    def Sign(sk, message):
        return hashlib.sha256(sk + message).digest()

    @staticmethod
    def Aggregate(signatures):
        return hashlib.sha256(b''.join(signatures)).digest()

    @staticmethod
    def AggregateVerify(public_keys, messages, signature):
        return True  # Simplified for simulation

bls = SimulatedBLS()

@dataclass
class Block:
    index: int
    previous_hash: str
    timestamp: float
    data: str
    nonce: Optional[int] = None
    signatures: List[bytes] = field(default_factory=list)
    aggregate_signature: Optional[bytes] = None
    hash: str = field(init=False)

    def __post_init__(self):
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = f"{self.index}{self.previous_hash}{self.timestamp}{self.data}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def add_signature(self, signature: bytes):
        self.signatures.append(signature)
        self.aggregate_signature = bls.Aggregate(self.signatures)

    def verify_signatures(self, public_keys: List[bytes]) -> bool:
        if not self.aggregate_signature:
            print(f"Block {self.index} has no aggregated signature.")
            return False
        messages = [f"{self.index}{self.previous_hash}{self.timestamp}{self.data}{self.nonce}".encode()] * len(public_keys)
        return bls.AggregateVerify(public_keys, messages, self.aggregate_signature)

    def __repr__(self):
        sig_status = "Yes" if self.aggregate_signature else "No"
        return f"Block(Index: {self.index}, Hash: {self.hash[:10]}..., Nonce: {self.nonce}, Signatures Aggregated: {sig_status})"

class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, "0", time.time(), "Genesis Block")
        self.chain.append(genesis_block)

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, block: Block, public_keys: List[bytes]) -> bool:
        if self.is_valid_new_block(block, public_keys):
            self.chain.append(block)
            print(f"Block {block.index} added to the blockchain.")
            return True
        else:
            print(f"Block {block.index} is invalid and was not added.")
            return False

    def is_valid_new_block(self, block: Block, public_keys: List[bytes]) -> bool:
        if block.previous_hash != self.last_block.hash:
            print(f"Invalid previous hash for Block {block.index}.")
            return False
        if block.hash != block.compute_hash():
            print(f"Invalid hash for Block {block.index}.")
            return False
        if not block.verify_signatures(public_keys):
            print(f"Invalid signatures for Block {block.index}.")
            return False
        return True

    def is_chain_valid(self, validators: Dict[str, bytes]) -> bool:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.previous_hash != previous.hash:
                print(f"Invalid previous hash at block {current.index}")
                return False
            if current.hash != current.compute_hash():
                print(f"Invalid hash at block {current.index}")
                return False
            block_signers = list(validators.values())
            if not current.verify_signatures(block_signers):
                print(f"Invalid signatures at block {current.index}")
                return False
        return True

    def __repr__(self):
        return f"Blockchain(Length: {len(self.chain)})"

class Miner:
    def __init__(self, name: str, hash_rate: float):
        self.name = name
        self.hash_rate = hash_rate
        self.blocks_mined = 0
        self.private_key = bls.KeyGen(random.randint(1, 1 << 30).to_bytes(32, byteorder='big'))
        self.public_key = bls.SkToPk(self.private_key)

    def mine(self, blockchain: Blockchain, difficulty: int) -> Optional[Block]:
        previous_block = blockchain.last_block
        index = previous_block.index + 1
        timestamp = time.time()
        data = f"Block {index} mined by {self.name}"
        target = '0' * difficulty

        start_time = time.time()
        nonce = 0
        while True:
            new_block = Block(index, previous_block.hash, timestamp, data, nonce)
            if new_block.hash.startswith(target):
                end_time = time.time()
                self.blocks_mined += 1
                mining_time = end_time - start_time
                energy_consumed = self.hash_rate * mining_time * 1e-6
                
                signature = self.sign_block(new_block)
                new_block.add_signature(signature)

                print(f"[PoW] {self.name} mined Block {index} in {mining_time:.2f} seconds with nonce {nonce}. Energy consumed: {energy_consumed:.6f} J")
                return new_block

            nonce += 1
            if nonce % int(self.hash_rate) == 0:
                if time.time() - start_time > 5:  # Timeout after 5 seconds
                    break

        print(f"[PoW] {self.name} failed to mine Block {index}")
        return None

    def sign_block(self, block: Block) -> bytes:
        message = f"{block.index}{block.previous_hash}{block.timestamp}{block.data}{block.nonce}".encode()
        signature = bls.Sign(self.private_key, message)
        return signature

class ProofOfWorkBLS:
    def __init__(self, blockchain: Blockchain, miners: List[Miner], difficulty: int):
        self.blockchain = blockchain
        self.miners = miners
        self.difficulty = difficulty

    def run_consensus(self):
        print("\n[PoW] Starting consensus round...")
        for miner in self.miners:
            block = miner.mine(self.blockchain, self.difficulty)
            if block:
                public_keys = [miner.public_key]
                success = self.blockchain.add_block(block, public_keys)
                if success:
                    break
        else:
            print("[PoW] No miner could mine a block this round.")

def simulate_pow_bls():
    blockchain = Blockchain()
    miners = [
        Miner("Miner1", hash_rate=1e4),
        Miner("Miner2", hash_rate=1.5e4),
        Miner("Miner3", hash_rate=0.5e4)
    ]
    difficulty = 4

    pow_consensus = ProofOfWorkBLS(blockchain, miners, difficulty)

    for _ in range(10):
        pow_consensus.run_consensus()
        print(blockchain)

    print("\n[PoW] Final Blockchain:")
    for block in blockchain.chain:
        print(block)

    # Validate the blockchain
    validators = {miner.name: miner.public_key for miner in miners}
    is_valid = blockchain.is_chain_valid(validators)
    print(f"\nIs blockchain valid? {is_valid}")

    # Calculate and display statistics
    total_blocks = len(blockchain.chain)
    total_time = blockchain.chain[-1].timestamp - blockchain.chain[0].timestamp
    avg_block_time = total_time / (total_blocks - 1)
    total_energy = sum(miner.hash_rate * avg_block_time * 1e-6 for miner in miners)

    print(f"\nTotal blocks mined: {total_blocks}")
    print(f"Average block time: {avg_block_time:.2f} seconds")
    print(f"Estimated total energy consumed: {total_energy:.6f} J")
    
    # Display miner statistics
    print("\nMiner Statistics:")
    for miner in miners:
        print(f"{miner.name}: Blocks mined - {miner.blocks_mined}, Hash rate - {miner.hash_rate} H/s")

if __name__ == "__main__":
    print("=== Proof of Work with BLS Simulation ===")
    simulate_pow_bls()
