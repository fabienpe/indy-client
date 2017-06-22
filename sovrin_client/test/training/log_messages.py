# !/usr/bin/python3
# -*- coding: utf-8 -*-
"""
A set of function to filter and reformat Sovrin log entries in order to make them more easily readable and
facilitate understanding of the communication protocol happening between various nodes and agents on the Sovrin network.
Given the relevant Sovrin logs come from various libraries (sovrin*, plenum, anoncreds, zstack, etc.), they are
not all consistent in their initial formatting, and the code below has many it/then test to cater for various cases.
It might not work for all but performs reasonably well with the test_getting_started_guide.py script.
"""
import ast
import inspect
import logging
import os
import re
import time
import traceback
from collections import OrderedDict, Counter
from enum import Enum, unique

from anoncreds.protocol.utils import shorten, serializeToStr
from base58 import alphabet
from plenum.client.client import Client
from plenum.common.constants import TXN_TIME, IDENTIFIER
from plenum.common.ledger_manager import LedgerManager
from plenum.common.member.steward import Steward
from plenum.common.types import f, OPERATION
from plenum.common.util import rawToFriendly
from plenum.server.node import Node
from plenum.server.propagator import Propagator
from sovrin_common.config_util import getConfig
from sovrin_common.constants import ROLE, ATTR_NAMES, TXN_TYPE, TARGET_NYM, VERKEY
from sovrin_common.roles import Roles as SovrinRoles
from sovrin_common.transactions import SovrinTransactions
from stp_zmq.zstack import ZStack, KITZStack
from zmq.utils.z85 import Z85CHARS

from sovrin_client.agent.agent import Agent
from sovrin_client.agent.walleted import Walleted, Wallet
from sovrin_client.agent.walleted_agent import WalletedAgent
from sovrin_node.pool.local_pool import LocalPool

Z85_CHARACTERS = re.escape(Z85CHARS.decode())
B58_CHARACTERS = re.escape(alphabet)

SPACE = " "
INDENT = SPACE * 4

LOGGING_LEVEL = logging.DEBUG

SHOW_RANDOM = True  # If False, replace random value with a comment, else add the comment before the random number.
USE_COLOURS = True  # If True, use colours to improve readability of output.

SHOW_UNFORMATTED_LOG = False  # Mostly for debugging purpose
SHOW_FIELD_TYPE = False  # Mostly for debugging purpose

# Default name of the logfile that is created
LOG_FILE_NAME = "sovrin_messages.log"

# Track number of times a particular role was used in order to properly increment friendly names
role_instances = Counter()

# Map between unique identifiers (NYM's, verkey's, Nonces) and friendly names
uid_names = OrderedDict()

# List of methods whose log record must be kept (exception to files_to_ignore)
functions_to_keep = [
    ZStack.setupOwnKeysIfNeeded
]

# Files to be filtered out from log recording
files_to_ignore = [
    "authenticator.py",
    "base.py",
    "batched.py",
    "eventually.py",
    "file_store.py",
    "has_action_queue.py",
    "has_file_storage.py",
    "idr_cache.py",
    "keep_in_touch.py",
    "ledger.py",
    "ledger_manager.py",
    "looper.py",
    "monitor.py",
    "motor.py",
    "network_interface.py",
    "node.py",
    "notifier_plugin_manager.py",
    "plugin_helper.py",
    "plugin_loader.py",
    "plugin_manager.py",
    "primary_elector.py",
    "propagator.py",
    "replica.py",
    "selector_events.py",
    "stacks.py",
    "upgrader.py",
    "zstack.py"
]

# List of methods to be ignored from log recording
functions_to_ignore = [
    Client.flushMsgsPendingConnection,
    Client.__init__
]

# List of messages explaining the meaning of some fields found in logs.
field_explanation = {
    "signature$": "Message signature",

    # anoncreds.protocol.types.PublicKey
    "primary_n$": "p*q",
    "primary_rms$": "Random number - S^random mod n",
    "primary_rctxt$": "Random number - S^random mod n",
    "primary_r_.+?$": "Random number",  # See anoncreds.protocol.primary.primary_claim_issuer.genKeys
    "primary_s$": "Random quadratic number",
    "primary_z$": "Random number - S^random mod n",
    # seqId

    # anoncreds.protocol.types.RevocationPublicKey
    "revocation_qr$": "Order of group",
    "revocation_g$": "Random element of group G1",
    "revocation_h$": "Random element of group G1",
    "revocation_h0$": "Random element of group G1",
    "revocation_h1$": "Random element of group G1",
    "revocation_h2$": "Random element of group G1",
    "revocation_htilde$": "Random element of group G1",
    "revocation_u$": "Random element of group G1",
    "revocation_pk$": "q^sk  (where sk is secret key)",
    "revocation_y$": "h^x",
    "revocation_x$": "Random element of group ZR",
    # seqId

    # anoncreds.protocol.types.ClaimRequest
    "claimReq_U$": "See section 5/6 of https://tinyurl.com/ydep46yx",
    "claimReq_Ur$": "See section 5/6 of https://tinyurl.com/ydep46yx",

    # anoncreds.protocol.types.PrimaryClaim
    # attrs
    "primaryClaim_encodedAttrs.+?$": "sha256(attribute value)",  # See anoncreds.protocol.utils.encodeAttr
    "primaryClaim_m2$": "Context attr for schema",  # See anoncreds.protocol.primary.primary_claim_issuer
    "primaryClaim_A$":
        "Signature(schemaId, encodedAttrs, v, U, e)",  # See anoncreds.protocol.primary.primary_claim_issuer
    "primaryClaim_e$": "Prime number",  # See anoncreds.protocol.primary.primary_claim_issuer
    "primaryClaim_v$": "Random number",  # See anoncreds.protocol.primary.primary_claim_issuer

    # anoncreds.protocol.types.PrimaryEqualProof
    "eqProof_e$": "See section 5/6 of https://tinyurl.com/ydep46yx",
    "eqProof_v$": "See section 5/6 of https://tinyurl.com/ydep46yx",
    "eqProof_m.+?$": "See section 5/6 of https://tinyurl.com/ydep46yx",
    "eqProof_m1$": "See section 5/6 of https://tinyurl.com/ydep46yx",
    "eqProof_Aprime$": "See section 5/6 of https://tinyurl.com/ydep46yx",
    # revealedAttrNames

    # anoncreds.protocol.types.FullProof
    "proof_cHash$": "See section 6.2 of https://tinyurl.com/ydep46yx",
    # schemaKeys
    # proofs
    "proof_CList$": "See section 6.1-1.1 of https://tinyurl.com/ydep46yx",
}


class Colours(Enum):
    """
    Definitions of some colours for terminal output. Using ANSI escape codes.
    See: https://en.wikipedia.org/wiki/ANSI_escape_code
    """
    GREY = "\033[90m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


@unique
class Roles(Enum):
    """
    Re-definition of main Sovrin roles, adding a generic "Client" role.
    """
    TRUSTEE = SovrinRoles.TRUSTEE.value
    STEWARD = SovrinRoles.STEWARD.value
    TGB = SovrinRoles.TGB.value
    TRUST_ANCHOR = SovrinRoles.TRUST_ANCHOR.value
    CLIENT = "999"

    def __str__(self):
        return self.name

    @classmethod
    def has_value(cls, value: str) -> bool:
        return any(value == item.value for item in cls)


def get_filename(obj: object) -> str:
    return os.path.split(inspect.getsourcefile(obj))[1]


def make_friendly_name(role: Roles = Roles.CLIENT) -> str:
    """
    Make a friendly name from a role by maintaining a usage counter for each available role name.
    :param role: A valid role.
    :return: A name made from the role and its usage counter (e.g. trustee_1).
    """
    role_instances[role] += 1
    return "{}{}".format(role.name.lower(), role_instances[role])


def add_uid_to_dictionary(nym: str, name: [str, Roles], update: bool = False) -> None:
    """
    Maintains a list of NYM's and verkey's with a friendly name.
    :param nym: NYM or verkey to be added to the dictionary.
    :param name: Friendly name or role of the NYM.
    :param update: If True and the nym already a key in the dictionary, then update the corresponding value.
    """
    if nym not in uid_names:
        if isinstance(name, Roles):
            name = make_friendly_name(name)
        logging.info("Adding NYM/verkey ({}) to database as {}".format(nym, apply_colour(name, Colours.BOLD)))
        uid_names[nym] = "{}".format(name)
    else:
        if update:
            if isinstance(name, Roles):
                name = make_friendly_name(name)
            logging.info("Updating NYM/verkey ({}) in database from {} to {}".format(nym, uid_names[nym],
                                                                                     apply_colour(name, Colours.BOLD)))
            uid_names[nym] = "{}".format(name)


def apply_colour(string: str, colour: Colours) -> str:
    return "{}{}{}".format(colour.value, string, Colours.ENDC.value) if USE_COLOURS else string


def format_random_value(name: str, value: str) -> str:
    """
    Take a string of random data and a name/explanation for it and format them together. For instance:
    'Faber College verkey (FuN98eH2eZybECWkofW6A9BKJxxnTatBCopfUiNxo6ZB)'
    :param name: Name of explanation related to the random string.
    :param value: String representation of some random-looking value.
    :return: A formatted string.
    """
    formatted_string = apply_colour(name, Colours.BOLD)
    if SHOW_RANDOM:
        formatted_string += " ({})".format(apply_colour(shorten(serializeToStr(value), 80), Colours.GREY))
    return formatted_string


def eval_string(data_string: str):
    """
    Tries to convert a character string back to initial data. Use of json.loads is not possible as most Sovrin log
    messages are created using the str.format() function.
    :param data_string:
    :return: Structured data if possible or the original string.
    """
    try:
        if "OrderedDict" in data_string:
            return eval(data_string, {'OrderedDict': OrderedDict})  # TODO: Unsafe. Build own parser.
        else:
            return ast.literal_eval(data_string)
    except (ValueError, SyntaxError):
        return data_string


def format_data(data, indent_level: int = 0, field_type: str = "") -> str:
    """
    Format recursively the content of a Sovrin transaction data. Formatting is based on the type of transaction
    and is specific to the data provided in that transaction.

    Some cases might be missing.
    :param field_type: Type of data field. See field_explanation.
    :param data: Dictionary structure containing the data.
    :param indent_level: Level of indentation at which should start the print-out of the data provided.
    :return: None
    """
    formatted_data_string = ""

    if data is None:
        return "None,\n"

    if type(data) == bytes:
        data = data.decode()

    if type(data) == str:
        data = eval_string(data)

    if type(data) in [str, int, float, tuple]:
        value = data
        if field_type != "":
            if field_type.endswith(OPERATION + "_" + TXN_TYPE) or \
                    field_type.endswith(OPERATION + "_" + f.RESULT.nm):
                value = (SovrinTransactions(str(data)).name if data else "")

            elif field_type.endswith(OPERATION + "_" + ROLE):
                value = (Roles(str(data)).name if data else "")

            elif field_type.endswith(ATTR_NAMES):
                value = (data.replace(",", ", "))

            elif field_type.endswith(TXN_TIME) or field_type.endswith(f.PP_TIME.nm):
                try:
                    value = time.ctime(float(data))
                except ValueError:
                    value = str(data)

            elif field_type.endswith(ROLE):
                if Roles.has_value(str(data)):
                    value = Roles(str(data)).name

            else:
                for field, explanation in field_explanation.items():
                    if re.search(field, field_type):
                        value = format_random_value(explanation, data)
                        break

            if type(value) is str:
                value = "'" + value.replace("\n", "") + "'"
            else:
                value = str(value)
        else:
            value = (INDENT * indent_level) + str(data)

        if SHOW_FIELD_TYPE:
            formatted_data_string += "{} ({}),\n".format(value, field_type)
        else:
            formatted_data_string += "{},\n".format(value)

    elif type(data) in [list, set, tuple]:
        formatted_data_string += "\n" + (INDENT * indent_level) + "[" + "\n"
        for element in data:
            formatted_data_string += INDENT * (indent_level + 1) + format_data(element, indent_level + 1, field_type)
        formatted_data_string += (INDENT * indent_level) + "]"
        if indent_level > 0:
            formatted_data_string += ",\n"

    elif isinstance(data, dict):
        formatted_data_string += "\n" + (INDENT * indent_level) + "{" + "\n"
        for key, value in data.items():
            formatted_data_string += INDENT * (indent_level + 1) + apply_colour("'{}': ".format(key), Colours.RED)
            formatted_data_string += format_data(value, indent_level + 2, field_type + "_" + str(key))
        formatted_data_string += (INDENT * indent_level + "}")
        if indent_level > 0:
            formatted_data_string += ",\n"

    else:
        formatted_data_string = data

    return formatted_data_string


def match_method(record: logging.LogRecord, method: object) -> bool:
    """
    Check if a log record wast produced by a particular function.
    :param record: The log record to be checked.
    :param method: The method to be checked.
    :return: True if filename and function name of record and method match.
    """
    return record.filename == get_filename(method) and record.funcName == method.__name__


class SovrinLogHandler(logging.FileHandler):
    def emit(self, record: logging.LogRecord):
        try:
            return self._emit(record)
        except:
            traceback.print_exc()

    def _emit(self, record: logging.LogRecord):
        if record.filename == __file__:
            super().emit(record)
            return

        if SHOW_UNFORMATTED_LOG:
            saved_msg = record.msg
            record.msg = apply_colour(record.msg, Colours.GREY)
            super().emit(record)
            record.msg = saved_msg

        msg = record.msg.replace(":null,", ":'null',")

        # Replace NYM encoded using X85 strings by friendly strings
        for method in [Node.processClientInBox,
                       ZStack.handlePingPong,
                       ZStack.sendPingPong,
                       LedgerManager.processLedgerStatus,
                       Walleted.handleEndpointMessage,
                       Node.processClientInBox,
                       Propagator.propagate,
                       ]:
            if match_method(record, method):
                search_result = re.search("b'([{}]{{40}})'".format(Z85_CHARACTERS), msg)
                if search_result:
                    friendly_public_key = rawToFriendly(search_result.group(1).encode())
                    msg = msg.replace(search_result.group(0), friendly_public_key)
                    break

                search_result = re.search("([{}]{{40}})$".format(Z85_CHARACTERS), msg)
                if search_result:
                    friendly_public_key = rawToFriendly(search_result.group(1).encode())
                    msg = msg.replace(search_result.group(1), friendly_public_key)
                    break

        # Replace other NYM encoded using X85 (those without the b'...' strings by friendly strings
        for method in [Node.send,
                       Node.handleOneNodeMsg,
                       Node.validateNodeMsg,
                       Node.postToNodeInBox
                       ]:
            if match_method(record, method):
                search_result = re.search("'{}': '([{}]+?)'".format(f.SENDER_CLIENT.nm, Z85_CHARACTERS), msg)
                if search_result:
                    friendly_public_key = rawToFriendly(search_result.group(1).encode())
                    msg = msg.replace(search_result.group(1), friendly_public_key)
                    break

        # Replace other encoded strings
        for method in [KITZStack.transmit
                       ]:
            if match_method(record, method):
                search_result = re.search("b'([{}]+?)'".format(B58_CHARACTERS), msg)
                if search_result:
                    msg = msg.replace(search_result.group(0), search_result.group(1))
                    break

        # Find dictionary data structure and expand over multiple lines
        if f.MSGS.nm in msg:  # and BATCH in msg ?
            msg = msg.replace("'{", "{")
            msg = msg.replace("}'", "}")
            first_index = msg.find("[")
            last_index = msg.rfind("]")
        elif re.search("Message sent \(.+?\): OrderedDict", msg):
            first_index = msg.find("OrderedDict")
            last_index = len(msg) - 1
        else:
            first_index = msg.find("{")
            last_index = msg.rfind("}")

        if 0 <= first_index < last_index:
            formatted_message = format_data(msg[first_index:last_index + 1])
            msg = "\n" + msg[:first_index] + "\n" + formatted_message + "\n" + msg[last_index + 1:]
            if msg[len(msg) - 1] != "\n":
                msg += "\n"

        # Replace unique identifier with friendly name
        for uid, name in uid_names.items():
            friendly_name = format_random_value(name, uid)
            msg = msg.replace(uid, friendly_name)
        record.msg = msg

        super().emit(record)


class SovrinLogMessageFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            return self._filter(record)
        except:
            traceback.print_exc()

    def _filter(self, record: logging.LogRecord) -> bool:

        # #######################################################
        # Look for unique identifiers (NYMs, public keys, nonces)
        if match_method(record, ZStack.setupOwnKeysIfNeeded):
            search_result = re.search("keys were not found for ([{}]{{44}})\.".format(B58_CHARACTERS), record.msg)
            if search_result:
                add_uid_to_dictionary(search_result.group(1), Roles.CLIENT)

        elif match_method(record, ZStack.handlePingPong) or \
                match_method(record, Propagator.propagate) or \
                match_method(record, Node.processClientInBox):
            # 'Node3C processing b\\'ML+Jsg@ao:WtwrJQT*l2V.xzF&ZKr%ku9o$my%a0\\' request LEDGER_STATUS
            # 'Node1 propagating CaKm3SP1dA9mePKKGT9HrW request 1498122067640921 from client b\\'Oq.j*T01mpi2.ESP45oPDPH^m8C2adi1WFzqpzpj\\''
            # TODO: Find better regular expression and try to merge with next if statements
            search_result = re.search("b?'?([{}]{{40}})'?".format(Z85_CHARACTERS), record.msg)
            if search_result:
                friendly_public_key = rawToFriendly(search_result.group(1).encode())
                add_uid_to_dictionary(friendly_public_key, Roles.CLIENT)

            # 'Node2 propagating R23qboDUA2NmwtNcnqboR2 request 1498122962642415 from client f%x2eJ!a9R7^&#Lo24^I?7<BDbo.-wlpuFNL[dFL'
            search_result = re.search(" ([{}]{{40}})$".format(Z85_CHARACTERS), record.msg)
            if search_result:
                friendly_public_key = rawToFriendly(search_result.group(1).encode())
                add_uid_to_dictionary(friendly_public_key, Roles.CLIENT)

        elif match_method(record, Node.handleOneNodeMsg) or \
                match_method(record, Node.send) or \
                match_method(record, Node.validateNodeMsg) or \
                match_method(record, Node.postToNodeInBox):
            search_result = re.search("'{}': '([{}]+?)'".format(f.SENDER_CLIENT.nm, Z85_CHARACTERS), record.msg)
            if search_result:
                friendly_public_key = rawToFriendly(search_result.group(1).encode())
                add_uid_to_dictionary(friendly_public_key, Roles.CLIENT)

        elif record.filename == get_filename(Agent) and record.funcName == "_send":
            search_result1 = re.search("'{}': '(.+?)',".format(VERKEY), record.msg)
            search_result2 = re.search("'{}': '(.+?)'".format(IDENTIFIER), record.msg)
            if search_result1 and search_result2:
                if search_result2.group(1) in uid_names:
                    add_uid_to_dictionary(search_result1.group(1), uid_names[search_result2.group(1)] + " " + VERKEY)

        elif match_method(record, Walleted.accept_invitation):
            search_result = re.search("(.+?) accepting invitation from (.+?) with id (.+?)$", record.msg)
            if search_result and len(search_result.groups()) == 3:
                add_uid_to_dictionary(search_result.group(3),
                                      "{} ID with {}".format(search_result.group(1), search_result.group(2)))

            search_result = re.search("nonce (.+?) from id (.+?)$", record.msg)
            if search_result and len(search_result.groups()) == 2:
                if search_result.group(2) not in uid_names:
                    add_uid_to_dictionary(search_result.group(2), Roles.CLIENT)
                add_uid_to_dictionary(search_result.group(1), "Nonce for {}".format(uid_names[search_result.group(2)]))

        elif match_method(record, Client.submitReqs):
            search_result = re.search("'{}': {{(.+?)}}".format(OPERATION), record.msg)
            if search_result:
                sub_msg = search_result.group(1)
                search_result = re.search("'{}': '(.+?)'".format(ROLE), sub_msg)
                if search_result:
                    try:
                        role_value = Roles(search_result.group(1))
                    except KeyError:
                        role_value = Roles.CLIENT
                else:
                    role_value = Roles.CLIENT

                search_result = re.search("'{}': '(.+?)'".format(TARGET_NYM), sub_msg)
                if search_result:
                    add_uid_to_dictionary(search_result.group(1), role_value)

        else:
            pass

        # ################
        # Do the filtering
        for method in functions_to_keep:
            if match_method(record, method):
                return True

        if record.filename in files_to_ignore:
            return False

        for method in functions_to_ignore:
            if match_method(record, method):
                return False

        if (record.filename == get_filename(Node) and not record.msg.startswith("Node1")) or \
                (match_method(record, Client.handleOneNodeMsg) and ("got msg from node Node1C:" not in record.msg)):
            # Same messages are sent by other nodes so only keep Node1
            return False

        return True


def add_wallet_uids(wallet: Wallet, agent_name: str) -> None:
    """
    Add various unique identifiers related to a Sovrin wallet, to the local database mapping those
    random looking values to friendly names
    :param wallet: An instance of the Wallet class.
    :param agent_name: Name of the agent who ows the wallet.
    """
    i = 0
    for identifier in wallet.identifiers:
        add_uid_to_dictionary(identifier, "{} {}{}".format(agent_name, IDENTIFIER, i if i else ""), True)
        i += 1
    for _, signer in wallet.idsToSigners.items():
        # noinspection PyUnresolvedReferences
        add_uid_to_dictionary(signer.verkey, "{} {}".format(agent_name, VERKEY, i if i else ""), True)


def add_agent_uids(agents: [WalletedAgent]) -> None:
    """
    Add various unique identifiers related to an agent from a list of agents, to the local database mapping those
    random looking values to friendly names.
    :param agents: List of instances of the WalletedAgent class.
    """
    logging.info("Start adding unique identifiers from agents {}".format([agent.name for agent in agents]))
    for agent in agents:
        add_uid_to_dictionary(agent.client.name, "{} {}".format(agent.name, "agent"), True)
        add_uid_to_dictionary(agent.client.alias, "{} {}".format(agent.name, "agent alias"), True)
        add_wallet_uids(agent.wallet, agent.name)
    logging.info("Finished adding unique identifiers from agents {}".format([agent.name for agent in agents]))


def add_steward_uids(steward: Steward) -> None:
    """
    Add various unique identifiers related to a Sovrin steward, to the local database mapping those
    random looking values to friendly names
    :param steward: An instance of the Steward class.
    """
    add_uid_to_dictionary(steward.nym, steward.name, True)
    add_wallet_uids(steward.wallet, steward.name)
    add_uid_to_dictionary(steward.node.verkey, steward.node.name)


# noinspection PyProtectedMember
def add_pool_uids(pool: LocalPool, stewards: [Steward]) -> None:
    """
    Add the various unique identifiers created for the local pool and stewards demo.
    :param pool: Local pool created by getting_started_future.create_local_pool
    :param stewards: List of stewards created by getting_started_future.create_local_pool
    """
    logging.info("Start adding unique identifiers from pool")
    add_agent_uids([pool._steward_agent])

    for steward in stewards:
        add_steward_uids(steward)

    for i in range(0, 4):
        add_uid_to_dictionary(pool.genesis_transactions[i * 2][TARGET_NYM], "Node{}".format(i + 1), True)
        add_uid_to_dictionary(pool.genesis_transactions[i * 2][VERKEY], "Node{} verkey".format(i + 1), True)
        add_uid_to_dictionary(pool.genesis_transactions[i * 2 + 1][TARGET_NYM], "Node{}C".format(i + 1), True)
    logging.info("Finished adding unique identifiers from pool")


def setup_message_logging() -> None:
    """
    Delete existing logging-file and set-up logging handler, filter and formatter.
    """
    log_filter = SovrinLogMessageFilter()

    if os.path.exists(LOG_FILE_NAME):
        os.remove(LOG_FILE_NAME)

    file_handler = SovrinLogHandler(LOG_FILE_NAME)

    file_handler.setLevel(LOGGING_LEVEL)
    file_handler.addFilter(log_filter)
    file_handler.formatter = logging.Formatter(fmt=getConfig().logFormat,
                                               style=getConfig().logFormatStyle)

    logging.root.addHandler(file_handler)


def print_log_uid_database() -> None:
    """
    Print-out and log the list of NYM's, verkey's and other unique identifiers collected
    together with their friendly name.
    """
    message = "List of identifiers found:\n"
    print("List of identifiers found:")
    for nym, name in uid_names.items():
        message += INDENT + "{}: {}\n".format(apply_colour(name, Colours.RED), nym)

    logging.info(message)
    print(message)
