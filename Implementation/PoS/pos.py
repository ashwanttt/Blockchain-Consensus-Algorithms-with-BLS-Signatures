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
    signatures: List[bytes] = field(default_factory=list)
    aggregate_signature: Optional[bytes] = None
    hash: str = field(init=False)
    validator_public_keys: List[bytes] = field(default_factory=list)

    def __post_init__(self):
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = f"{self.index}{self.previous_hash}{self.timestamp}{self.data}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def add_signature(self, signature: bytes, public_key: bytes):
        self.signatures.append(signature)
        self.validator_public_keys.append(public_key)
        self.aggregate_signature = bls.Aggregate(self.signatures)

    def verify_signatures(self) -> bool:
        if not self.aggregate_signature:
            print(f"Block {self.index} has no aggregated signature.")
            return False
        message = self.get_message_for_signing()
        return bls.AggregateVerify(self.validator_public_keys, [message] * len(self.validator_public_keys), self.aggregate_signature)

    def get_message_for_signing(self) -> bytes:
        return f"{self.index}{self.previous_hash}{self.timestamp}{self.data}".encode()

    def __repr__(self):
        return f"Block(Index: {self.index}, Hash: {self.hash[:10]}..., Signatures: {len(self.signatures)})"

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

    def add_block(self, block: Block) -> bool:
        if self.is_valid_new_block(block):
            self.chain.append(block)
            print(f"Block {block.index} added to the blockchain.")
            return True
        else:
            print(f"Block {block.index} is invalid and was not added.")
            return False

    def is_valid_new_block(self, block: Block) -> bool:
        if block.previous_hash != self.last_block.hash:
            print(f"Invalid previous hash for Block {block.index}.")
            return False
        if block.hash != block.compute_hash():
            print(f"Invalid hash for Block {block.index}.")
            return False
        if not block.verify_signatures():
            print(f"Invalid signatures for Block {block.index}.")
            return False
        return True

    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.previous_hash != previous.hash:
                print(f"Invalid previous hash at block {current.index}")
                return False
            if current.hash != current.compute_hash():
                print(f"Invalid hash at block {current.index}")
                return False
            if not current.verify_signatures():
                print(f"Invalid signatures at block {current.index}")
                return False
        return True

    def __repr__(self):
        return f"Blockchain(Length: {len(self.chain)})"

class Validator:
    def __init__(self, name: str, stake: float):
        self.name = name
        self.stake = stake
        self.blocks_validated = 0
        self.private_key = bls.KeyGen(random.randint(1, 1 << 30).to_bytes(32, byteorder='big'))
        self.public_key = bls.SkToPk(self.private_key)

    def sign_block(self, block: Block) -> bytes:
        message = block.get_message_for_signing()
        signature = bls.Sign(self.private_key, message)
        return signature

    def __repr__(self):
        return f"Validator(Name: {self.name}, Stake: {self.stake})"

class ProofOfStakeBLS:
    def __init__(self, blockchain: Blockchain, validators: List[Validator], num_signatures_required: int = 2):
        self.blockchain = blockchain
        self.validators = validators
        self.total_stake = sum(v.stake for v in validators)
        self.num_signatures_required = num_signatures_required

    def select_validators(self) -> List[Validator]:
        selected = []
        for _ in range(self.num_signatures_required):
            selection_point = random.uniform(0, self.total_stake)
            current = 0
            for validator in self.validators:
                current += validator.stake
                if current >= selection_point:
                    if validator not in selected:
                        selected.append(validator)
                        break
            if len(selected) < _ + 1:
                remaining = [v for v in self.validators if v not in selected]
                if remaining:
                    selected.append(random.choice(remaining))
        return selected

    def run_consensus(self):
        print("\n[PoS] Starting consensus round...")
        start_time = time.time()

        selected_validators = self.select_validators()
        
        previous_block = self.blockchain.last_block
        new_block = Block(
            index=previous_block.index + 1,
            previous_hash=previous_block.hash,
            timestamp=time.time(),
            data=f"Block {previous_block.index + 1} proposed by validators {[v.name for v in selected_validators]}"
        )

        for validator in selected_validators:
            signature = validator.sign_block(new_block)
            new_block.add_signature(signature, validator.public_key)
            validator.blocks_validated += 1

        if self.blockchain.add_block(new_block):
            end_time = time.time()
            consensus_time = end_time - start_time
            print(f"[PoS] Block {new_block.index} validated and added. Time taken: {consensus_time:.2f} seconds.")
        else:
            print(f"[PoS] Failed to add Block {new_block.index} to the blockchain.")

    def simulate_pos(self, num_blocks: int):
        for _ in range(num_blocks):
            self.run_consensus()
            print(f"Current blockchain state: {self.blockchain}")
            time.sleep(0.1)  # Small delay to simulate network latency

        print("\n[PoS] Final Blockchain:")
        for block in self.blockchain.chain:
            print(block)

        is_valid = self.blockchain.is_chain_valid()
        print(f"\nIs the blockchain valid? {'Yes' if is_valid else 'No'}")

        # Calculate and display statistics
        total_blocks = len(self.blockchain.chain)
        total_time = self.blockchain.chain[-1].timestamp - self.blockchain.chain[0].timestamp
        avg_block_time = total_time / (total_blocks - 1)

        print(f"\nTotal blocks validated: {total_blocks}")
        print(f"Average block time: {avg_block_time:.2f} seconds")
        
        # Display validator statistics
        print("\nValidator Statistics:")
        for validator in self.validators:
            print(f"{validator.name}: Blocks validated - {validator.blocks_validated}, Stake - {validator.stake}")

        return is_valid

def main():
    blockchain = Blockchain()
    validators = [
        Validator("Validator1", stake=100),
        Validator("Validator2", stake=80),
        Validator("Validator3", stake=60),
        Validator("Validator4", stake=40)
    ]

    pos_consensus = ProofOfStakeBLS(blockchain, validators, num_signatures_required=2)
    is_valid = pos_consensus.simulate_pos(num_blocks=10)
    
    if not is_valid:
        print("Blockchain validation failed. Check the logs for details.")
    else:
        print("Blockchain validation successful.")

if __name__ == "__main__":
    print("=== Proof of Stake with BLS Simulation ===")
    main()
