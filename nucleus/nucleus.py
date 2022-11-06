# Copyright 2022 Cartesi Pte. Ltd.
#
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License. You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
import array
from collections import defaultdict
from eth_abi import decode_abi, encode_abi
from os import environ
import logging
import requests
import json
import numpy as np
import traceback

logging.basicConfig(level="INFO")
logger = logging.getLogger(__name__)

rollup_server = environ["ROLLUP_HTTP_SERVER_URL"]
logger.info(f"HTTP rollup_server url is {rollup_server}")

# Default header for ERC-20 transfers coming from the Portal, which corresponds
# to the Keccak256-encoded string "ERC20_Transfer", as defined at
# https://github.com/cartesi/rollups/blob/main/onchain/rollups/contracts/facets/ERC20PortalFacet.sol.
ERC20_TRANSFER_HEADER = b'Y\xda*\x98N\x16Z\xe4H|\x99\xe5\xd1\xdc\xa7\xe0L\x8a\x990\x1b\xe6\xbc\t)2\xcb]\x7f\x03Cx'
# Function selector to be called during the execution of a voucher that transfers funds,
# which corresponds to the first 4 bytes of the Keccak256-encoded result of "transfer(address,uint256)"
TRANSFER_FUNCTION_SELECTOR = b'\xa9\x05\x9c\xbb'


def reject_input(msg, payload):
    logger.error(msg)
    response = requests.post(rollup_server + "/report", json={"payload": payload})
    logger.info(f"Received report status {response.status_code} body {response.content}")
    return "reject"


def obj2hex(obj):
    return str2hex(json.dumps(obj))


def str2hex(text):
    """
    Encode a string as an hex string
    """
    return "0x" + text.encode("utf-8").hex()


class dotdict(dict):
    """dot.notation access to dictionary attributes"""

    def __getattr__(self, item):
        attr = self[item]
        if isinstance(attr, dict):
            return dotdict(attr)

        return attr

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class Stringer:
    def __str__(self):
        return str(vars(self))


class Stats(Stringer):
    std_semi_hourly = None
    std_hourly = None
    std_daily = None

    cv_semi_hourly = None
    cv_hourly = None
    cv_daily = None

    def update(self, new_sigma, new_mean):
        self.std_semi_hourly = new_sigma
        self.std_hourly = np.sqrt(2) * new_sigma
        self.std_daily = np.sqrt(48) * new_sigma

        self.cv_semi_hourly = self.std_semi_hourly / new_mean
        self.cv_hourly = self.std_hourly / new_mean
        self.cv_daily = self.std_daily / new_mean


class VolatilityIndex(Stringer):
    price_threshold = 1

    prices = defaultdict(lambda: [])
    price_stats = defaultdict(lambda: Stats())

    def update_price(self, msg):
        tickers = self.prices[msg.data.pair]
        tickers.append(msg.data.ticker)
        if len(tickers) > self.price_threshold:
            new_sigma = np.std(tickers)
            new_mean = np.mean(tickers)
            sigma = self.price_stats[msg.data.pair]
            sigma.update(new_sigma, new_mean)
            logger.info(f"updated price sigmas {sigma}")
            tickers.pop(0)

    def last_price(self, pair):
        if len(self.prices[pair]):
            return self.prices[pair][-1]

    def last_liquidity(self, pair):
        return 0

    def compute_risk_parameters(self, pair):
        cv_semi_hourly = self.price_stats[pair].cv_semi_hourly
        if not cv_semi_hourly:
            return

        liquidity = self.last_liquidity(pair)
        max_collateral = liquidity * (1 - cv_semi_hourly)
        return RiskParameters(pair, liquidity, max_collateral)


class RiskParameters(Stringer):
    pair = None
    max_collateral = None
    total_liquidity = None

    def __init__(self, pair, total_liquidity, max_collateral):
        self.pair = pair
        self.total_liquidity = total_liquidity
        self.max_collateral = max_collateral


class Deposit:
    depositor = None
    total = 0

    def __init__(self, depositor):
        self.depositor = depositor


class Loan:
    def __init__(self, borrower, total):
        self.borrower = borrower
        self.total = total


class Pool:
    erc20 = None
    # deposits per depositor
    deposits = defaultdict(lambda depositor: Deposit(depositor))
    # loans per borrower
    loans = defaultdict(lambda borrower: Loan(borrower))

    def __init__(self, erc20):
        self.erc20 = erc20


class Contract:
    rollup_address = '0xf119cc4ed90379e5e0cc2e5dd1c8f8750bafc812'
    collateral_factor = .5
    volatility = VolatilityIndex()
    pools = defaultdict(lambda erc20: Pool(erc20))

    def init(self, metadata):
        self.rollup_address = metadata["msg_sender"]
        logger.info(f"Captured rollup address: {self.rollup_address}")

    def handle_price(self, msg):
        self.volatility.update_price(msg)

        risk_parameters = msg.data.pair and self.volatility.compute_risk_parameters(msg.data.pair)
        if risk_parameters:
            report = {"payload": obj2hex({"risk_parameters": risk_parameters.__dict__})}
            response = requests.post(rollup_server + "/report", json=report)
            logger.info(f"sent risk parameters {response.status_code} -- {response.content}")

    def total_deposit(self, depositor):
        return sum([pool.deposits[depositor].total for pool in self.pools])

    def total_borrowed(self, borrower):
        return sum([pool.loans[borrower].total for pool in self.pools])

    def handle_withdrawal(self, metadata, msg):
        owner, erc20, amount = metadata["msg_sender"], msg.erc20, msg.amount
        pool = self.pools[erc20]
        deposit = pool.deposits[owner]
        if amount >= deposit.total:
            reject_input(f"{owner} has {deposit.total} to withdraw but asked {amount} in {erc20}")
            return

        total_deposit = self.total_deposit(owner)
        total_borrowed = self.total_borrowed(owner)
        locked = total_borrowed / self.collateral_factor
        withdrawable = total_deposit - locked
        if amount >= withdrawable:
            reject_input(f"{owner} has only {withdrawable} available to withdraw but asked {amount} in {erc20}")
            return

        # Encode a transfer function call that returns the amount back to the depositor
        transfer_payload = TRANSFER_FUNCTION_SELECTOR + encode_abi(['address', 'uint256'], [owner, amount])
        # Post voucher executing the transfer on the ERC-20 contract: "I don't want your money"!
        voucher = {"address": erc20, "payload": "0x" + transfer_payload.hex()}
        logger.info(f"Issuing voucher {voucher}")
        response = requests.post(rollup_server + "/voucher", json=voucher)
        logger.info(f"Received voucher status {response.status_code} body {response.content}")

        if response.status_code == 200:
            deposit.total -= amount

    def handle_borrow(self, metadata, msg):
        borrower, erc20, amount = metadata["msg_sender"], msg.erc20, msg.amount
        total_deposit = self.total_deposit(borrower)
        total_borrowed = self.total_borrowed(borrower)
        available = total_deposit - total_borrowed
        borrowable = available * self.collateral_factor
        if amount > borrowable:
            reject_input(f"{borrower} has only {borrowable} available to borrow but asked {amount} in {erc20}")
            return

        # Encode a transfer function call that returns the amount back to the depositor
        transfer_payload = TRANSFER_FUNCTION_SELECTOR + encode_abi(['address', 'uint256'], [borrower, amount])
        # Post voucher executing the transfer on the ERC-20 contract: "I don't want your money"!
        voucher = {"address": erc20, "payload": "0x" + transfer_payload.hex()}
        logger.info(f"Issuing voucher {voucher}")
        response = requests.post(rollup_server + "/voucher", json=voucher)
        logger.info(f"Received voucher status {response.status_code} body {response.content}")

        if response.status_code == 200:
            self.pools[erc20].loans[borrower].total += amount

    def handle_message(self, data):
        try:
            binary = bytes.fromhex(data["payload"][2:])
            msg = dotdict(json.loads(binary.decode('utf-8')))
        except Exception as e:
            return False

        logger.info(f"got new msg {msg}")
        if msg.kind == 'price':
            self.handle_price(msg)

        metadata = data["metadata"]
        if msg.kind == 'withdraw':
            self.handle_withdrawal(metadata, msg)

        if msg.kind == 'borrow':
            self.handle_borrow(metadata, msg)

        return 'accept'

    def handle_deposit(self, data):
        if data["metadata"]["msg_sender"] != self.rollup_address:
            return reject_input(f"Input does not come from the Portal", data["payload"])

        try:
            binary = bytes.fromhex(data["payload"][2:])
            decoded = decode_abi(['bytes32', 'address', 'address', 'uint256', 'bytes'], binary)
        except Exception as e:
            msg = "Payload does not conform to ERC20 deposit ABI"
            logger.error(f"{msg}\n{traceback.format_exc()}")
            return False

        # Check if the header matches the Keccak256-encoded string "ERC20_Transfer"
        input_header, depositor, erc20, amount = decoded
        if input_header != ERC20_TRANSFER_HEADER:
            return reject_input(f"Input header is not from an ERC20 transfer", data["payload"])

        pool = self.pools[erc20]
        returned = min(pool.loans[depositor].total, amount)
        surplus = amount - returned

        pool.loans[depositor].total -= returned
        pool.deposits[depositor].total += surplus

        return 'accept'

    def advance_state(self, data):
        for handler in [self.handle_message, self.handle_deposit]:
            result = handler(data)
            if result in ['reject', 'accept']:
                return result

        return reject_input('unsupported input', data["payload"])

    def inspect_state(self, data):
        # logger.info(f"Received inspect request data {data}")
        # logger.info("Adding report")
        report = {"payload": data["payload"]}
        response = requests.post(rollup_server + "/report", json=report)
        logger.info(f"Received report status {response.status_code}")
        return "accept"


contract = Contract()

finish = {"status": "accept"}

while True:
    # logger.info("Sending finish")
    response = requests.post(rollup_server + "/finish", json=finish)
    logger.info(f"Received finish status {response.status_code}")
    if response.status_code == 202:
        logger.info("No pending rollup request, trying again")
        continue

    rollup_request = response.json()
    data = rollup_request["data"]
    metadata = data["metadata"]
    # initialize the contract if it is the first time
    if metadata and metadata["epoch_index"] == 0 and metadata["input_index"] == 0:
        contract.init(metadata)
        continue

    req_type = rollup_request["request_type"]
    handler = getattr(contract, req_type)
    finish["status"] = handler(rollup_request["data"])
