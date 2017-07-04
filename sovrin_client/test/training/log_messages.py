# !/usr/bin/python3
# -*- coding: utf-8 -*-
"""
A set of functions to filter and reformat Sovrin log entries in order to make them more easily readable and
facilitate understanding of the communication protocol happening between various nodes and agents on the Sovrin network.

Given the relevant Sovrin logs come from various libraries (sovrin*, plenum, anoncreds, zstack, etc.), they are
not all consistent in their initial formatting, and the code below has many it/then tests to cater for various cases.
It might not work for all but performs reasonably well with the test_getting_started_guide.py script.
"""

import ast
import inspect
import json
import logging
import os
import re
import time
import traceback
from binascii import unhexlify
from collections import OrderedDict, Counter
from enum import Enum, unique

from anoncreds.protocol.utils import shorten, serializeToStr
from base58 import alphabet
from ledger.util import F
from plenum.client.client import Client
from plenum.common.constants import TXN_TIME, IDENTIFIER
from plenum.common.ledger_manager import LedgerManager
from plenum.common.member.steward import Steward
from plenum.common.types import f, OPERATION
from plenum.common.util import rawToFriendly
from plenum.server.node import Node
from plenum.server.propagator import Propagator
from sovrin_common.config import agentLoggingLevel
from sovrin_common.config_util import getConfig
from sovrin_common.constants import ROLE, ATTR_NAMES, TXN_TYPE, TARGET_NYM, VERKEY, REVOCATION, PRIMARY
from sovrin_common.roles import Roles as SovrinRoles
from sovrin_common.transactions import SovrinTransactions
from stp_zmq.zstack import ZStack
from zmq.utils.z85 import Z85CHARS, decode as z85decode

from sovrin_client.agent.agent import Agent
from sovrin_client.agent.msg_constants import CLAIM_REQ_FIELD
from sovrin_client.agent.walleted import Walleted, Wallet
from sovrin_client.agent.walleted_agent import WalletedAgent
from sovrin_node.pool.local_pool import LocalPool

LOGGING_LEVEL = logging.DEBUG
if agentLoggingLevel != LOGGING_LEVEL:
    print("Change log level of agents (sovrin_common.config.agentLoggingLevel) to {}.".format(LOGGING_LEVEL))
    exit(0)

APPLY_FILTERING = False  # Does not filter log messages, except the ones repeated for nodes
SHOW_RANDOM = True  # False, replace random value with a comment, else add the comment before the random number.
USE_COLOURS = True  # If True, use colours to improve readability of output.

SHOW_UNFORMATTED_LOG = True  # Mostly for debugging purpose
SHOW_FIELD_TYPE = False  # Mostly for debugging purpose

# Default name of the logfile that is created
LOG_FILE_NAME = "sovrin_messages.log"

Z85_CHARACTERS = re.escape(Z85CHARS.decode())
B58_CHARACTERS = re.escape(alphabet)

SPACE = " "
INDENT = SPACE * 4
SEPARATOR = "\n"

# Track number of times a particular role was used in order to properly increment friendly names
role_instances = Counter()

# Map between unique identifiers (NYM's, verkey's, Nonces) and friendly names
uid_names = OrderedDict()

# List of methods whose log record must be kept (exception to files_to_ignore)
functions_to_keep = [
    ZStack.setupOwnKeysIfNeeded,
    ZStack.sendPingPong,
    ZStack.transmit
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
    "message_processor.py",
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
    Client.__init__,
]

# List of messages explaining the meaning of some fields found in logs.
field_explanation = {
    "signature$": "Message signature",

    # anoncreds.protocol.types.PublicKey
    PRIMARY + "_[Nn]$": "p*q",
    PRIMARY + "_[Rr]ms$": "Random number - S^random mod n",
    PRIMARY + "_[Rr]ctxt$": "Random number - S^random mod n",
    PRIMARY + "_[Rr]_.+?$": "Random number",  # See anoncreds.protocol.primary.primary_claim_issuer.genKeys
    PRIMARY + "_[Ss]$": "Random quadratic number",
    PRIMARY + "_[Zz]$": "Random number - S^random mod n",
    # seqId

    # anoncreds.protocol.types.RevocationPublicKey
    REVOCATION + "_qr$": "Order of group",
    REVOCATION + "_g$": "Random element of group G1",
    REVOCATION + "_h$": "Random element of group G1",
    REVOCATION + "_h0$": "Random element of group G1",
    REVOCATION + "_h1$": "Random element of group G1",
    REVOCATION + "_h2$": "Random element of group G1",
    REVOCATION + "_htilde$": "Random element of group G1",
    REVOCATION + "_u$": "Random element of group G1",
    REVOCATION + "_pk$": "q^sk  (where sk is secret key)",
    REVOCATION + "_y$": "h^x",
    REVOCATION + "_x$": "Random element of group ZR",
    # seqId

    # anoncreds.protocol.types.ClaimRequest
    CLAIM_REQ_FIELD + "_[Uu]$": "See section 5/6 of https://tinyurl.com/ydep46yx",
    CLAIM_REQ_FIELD + "_[Uu]r$": "See section 5/6 of https://tinyurl.com/ydep46yx",

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
    GREY = "\033[90m"  # '<font color="grey">'
    RED = "\033[91m"  # '<font color="red">'
    GREEN = "\033[92m"  # '<font color="green">'
    YELLOW = "\033[93m"  # '<font color="yellow">'
    BLUE = "\033[94m"  # '<font color="blue">'
    MAGENTA = "\033[95m"  # '<font color="magenta">'
    CYAN = "\033[96m"  # '<font color="cyan">'
    WHITE = "\033[97m"  # '<font color="white">'
    ENDC = "\033[0m"  # '</font>
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


@unique
class UIDNames(Enum):
    """
    Define some default names based on Sovrin roles and Plenum names for the various unique identifiers found in logs.
    """
    TRUSTEE = SovrinRoles.TRUSTEE.name
    STEWARD = SovrinRoles.STEWARD.name
    TGB = SovrinRoles.TGB.name
    TRUST_ANCHOR = SovrinRoles.TRUST_ANCHOR.name
    CLIENT = "CLIENT"  # New default name
    ROOT_HASH = F.rootHash.name
    MERKLE_ROOT = f.MERKLE_ROOT.nm
    TXN_ROOT_HASH = f.TXN_ROOT.nm
    STATE_ROOT_HASH = f.STATE_ROOT.nm
    DIGEST = f.DIGEST.nm


    def __str__(self):
        return self.name

    @classmethod
    def has_value(cls, value: str) -> bool:
        return any(value == item.value for item in cls)


class SovrinLogMessageFilter(logging.Filter):
    """
    Logging filter that is used to extract unique identifiers from Sovrin log messages and to filter
    messages to be shown.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            return self._filter(record)
        except:
            traceback.print_exc()

    def _filter(self, record: logging.LogRecord) -> bool:

        msg = record.msg
        # ###############################################################
        # Look for unique identifiers (NYMs, public keys, hashes, nonces)

        # X85-encoded unique identifiers
        for (_, decoded_uid) in find_z85_uid_in_record(record):
            add_uid_to_dictionary(decoded_uid, UIDNames.CLIENT)

        # B58 encoded unique identifiers
        for uid in find_b58_uid_in_record(record):
            add_uid_to_dictionary(uid, UIDNames.CLIENT)
        for (hash_value, key) in find_hashes_in_record(record):
            add_uid_to_dictionary(hash_value, key)

        # From _send declared within Agent.sendMessage
        # logger.debug("Message sent (to -> {}): {}".format(ha, msg))
        if record.filename == get_filename(Agent) and record.funcName == "_send":
            search_result1 = re.search("'{}': '(.+?)',".format(VERKEY), msg)
            search_result2 = re.search("'{}': '(.+?)'".format(IDENTIFIER), msg)
            # The verification key corresponds to the identifier
            if search_result1 and search_result2:
                if search_result2.group(1) in uid_names:
                    add_uid_to_dictionary(search_result1.group(1), uid_names[search_result2.group(1)][0] + " " + VERKEY)

        # From  Walleted.accept_invitation
        # logger.debug("{} accepting invitation from {} with id {}".format(self.name, link.name, link.localIdentifier))
        # logger.info('Accepting invitation with nonce {} from id {}'.format(link.invitationNonce, link.localIdentifier))
        if match_method(record, Walleted.accept_invitation):
            search_result = re.search("(.+?) accepting invitation from (.+?) with id (.+?)$", msg)
            if search_result and len(search_result.groups()) == 3:
                add_uid_to_dictionary(search_result.group(3),
                                      "{} ID with {}".format(search_result.group(1), search_result.group(2)))

            search_result = re.search("nonce (.+?) from id (.+?)$", msg)
            if search_result and len(search_result.groups()) == 2:
                if search_result.group(2) not in uid_names:
                    add_uid_to_dictionary(search_result.group(2), UIDNames.CLIENT)
                add_uid_to_dictionary(search_result.group(1),
                                      "Nonce for {}".format(uid_names[search_result.group(2)][0]))

        # From Client.submitReqs
        # logger.debug('Client {} sending request {}'.format(self, request))
        if match_method(record, Client.submitReqs):
            search_result = re.search("'{}': {{(.+?)}}".format(OPERATION), msg)
            if search_result:
                sub_msg = search_result.group(1)
                search_result = re.search("'{}': '(.+?)'".format(ROLE), sub_msg)
                if search_result:
                    try:
                        role_value = UIDNames(SovrinRoles(search_result.group(1)).name)
                    except KeyError:
                        role_value = UIDNames.CLIENT
                else:
                    role_value = UIDNames.CLIENT

                search_result = re.search("'{}': '(.+?)'".format(TARGET_NYM), sub_msg)
                if search_result:
                    add_uid_to_dictionary(search_result.group(1), role_value)

        # ################
        # Do the filtering

        # Same messages are sent by all nodes so only keep Node1 and always filters the other ones.
        if (record.filename == get_filename(Node) and not msg.startswith("Node1")) or \
                (match_method(record, Client.handleOneNodeMsg) and ("got msg from node Node1C:" not in msg)) or \
                (match_method(record, Node.handleOneNodeMsg) and (
                        re.search("Node[0-9] msg.+?Node[0-9]'\)$", msg))) or \
                (match_method(record, ZStack.transmit) and (not msg.endswith("to Node1C"))) or \
                (match_method(record, ZStack.sendPingPong) and (not msg.endswith("from Node1C"))):
            return False

        if not APPLY_FILTERING:
            return True

        for method in functions_to_keep:
            if match_method(record, method):
                return True

        if record.filename in files_to_ignore:
            return False

        for method in functions_to_ignore:
            if match_method(record, method):
                return False

        return True


class SovrinLogHandler(logging.FileHandler):
    """
    Logging handler that reformat Sovrin log message to a more human readable form. It replaces unique identifiers
    found by the logging filter by more friendly names.
    """

    def emit(self, record: logging.LogRecord):
        try:
            return self._emit(record)
        except:
            traceback.print_exc()

    def _emit(self, record: logging.LogRecord):
        if record.filename == __file__:
            super().emit(record)
            return
        msg = record.msg

        if SHOW_UNFORMATTED_LOG:
            record.msg = apply_colour(record.msg, Colours.GREY)
            super().emit(record)
            record.msg = msg

        # Handle the case when the log contains an encoded message
        if match_method(record, ZStack.transmit):
            search_result = re.search("(^.+?transmitting message )(b'.+?')( to.+?)$", msg)
            if search_result:
                decoded_message = eval(search_result.group(2)).decode()
                try:
                    decoded_message = json.loads(decoded_message)
                    formatted_message = format_data(decoded_message, 1)
                    msg = search_result.group(1) + formatted_message + search_result.group(3)
                    if msg[len(msg) - 1] != SEPARATOR:
                        msg += SEPARATOR
                except json.JSONDecodeError:
                    pass
        else:
            # Replace Z85 encoded NYMs by ASCII values. This is needed for further parsing.
            for (raw_id, decoded_id) in find_z85_uid_in_record(record):
                msg = msg.replace(raw_id, decoded_id)

            if re.search("Message sent \(.+?\): OrderedDict", msg):
                first_index = msg.find("OrderedDict")
                _, last_index = find_matching_bracket(msg[first_index:], "(", ")")
                last_index += first_index
            else:
                first_index, last_index = find_matching_bracket(msg, "{", "}")

            if 0 <= first_index < last_index:
                formatted_message = format_data(msg[first_index:last_index + 1])
                msg = SEPARATOR + msg[:first_index] + SEPARATOR + formatted_message + SEPARATOR + msg[last_index + 1:]
                if msg[len(msg) - 1] != SEPARATOR:
                    msg += SEPARATOR

        # Replace unique identifier with friendly name
        for uid, name in uid_names.items():
            friendly_name = format_random_value(name[0], uid)
            msg = msg.replace(uid, friendly_name)

        if re.search("###.*###", msg):
            msg = apply_colour(msg, Colours.RED)

        record.msg = msg

        super().emit(record)


def find_matching_bracket(msg: str, opening: str, closing: str) -> (int, int):
    i = first_index = msg.find(opening)
    if first_index >= 0:
        count = 1
        while count:
            i += 1
            if i < len(msg):
                if msg[i] == opening:
                    count += 1
                if msg[i] == closing:
                    count -= 1
            else:
                break
        if count:
            last_index = -1
        else:
            last_index = i
    else:
        last_index = -1
    return first_index, last_index


def get_filename(obj: object) -> str:
    return os.path.split(inspect.getsourcefile(obj))[1]


def make_friendly_name(role: UIDNames = UIDNames.CLIENT) -> str:
    """
    Make a friendly name from a role by maintaining a usage counter for each available role name.
    :param role: A valid role.
    :return: A name made from the role and its usage counter (e.g. trustee_1).
    """
    role_instances[role] += 1
    return "{}{}".format(role.value, role_instances[role])


def add_uid_to_dictionary(nym: str, name: [str, UIDNames], update: bool = False) -> None:
    """
    Maintains a list of NYM's and verkey's with a friendly name. Also keep the history of those names when updated.
    :param nym: NYM or verkey to be added to the dictionary.
    :param name: Friendly name or role of the NYM.
    :param update: If True and the nym already a key in the dictionary, then update the corresponding value.
    """
    if nym not in uid_names:
        if isinstance(name, UIDNames):
            name = make_friendly_name(name)
        logging.info("Adding NYM/verkey/hash ({}) to database as {}".format(nym, apply_colour(name, Colours.BOLD)))
        uid_names[nym] = ["{}".format(name)]
    else:
        if update:
            if isinstance(name, UIDNames):
                name = make_friendly_name(name)
            logging.info("Updating NYM/verkey/hash ({}) in database from {} to {}".format(nym, uid_names[nym][0],
                                                                                          apply_colour(name,
                                                                                                       Colours.BOLD)))
            uid_names[nym] = ["{}".format(name)] + uid_names[nym]


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
        return "None," + SEPARATOR

    if type(data) == bytes:
        data = data.decode()

    if type(data) == str:
        data = eval_string(data)

    if type(data) in [str, int, float, tuple]:
        value = data
        if field_type != "":
            if field_type.endswith(OPERATION + "_" + TXN_TYPE) or \
                    field_type.endswith("result" + "_" + TXN_TYPE) or \
                    field_type.endswith(OPERATION + "_" + f.RESULT.nm):
                value = (SovrinTransactions(str(data)).name if data else "")

            elif field_type.endswith(OPERATION + "_" + ROLE):
                value = (SovrinRoles(str(data)).name if data else "")

            elif field_type.endswith(ATTR_NAMES):
                value = (data.replace(",", ", "))

            elif field_type.endswith(TXN_TIME) or field_type.endswith(f.PP_TIME.nm):
                try:
                    value = time.ctime(float(data))
                except ValueError:
                    value = str(data)

            elif field_type.endswith(ROLE):
                if UIDNames.has_value(str(data)):
                    value = UIDNames(str(data)).name

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
            formatted_data_string += "{} ({}),{}".format(value, field_type, SEPARATOR)
        else:
            formatted_data_string += "{},{}".format(value, SEPARATOR)

    elif type(data) in [list, set, tuple]:
        formatted_data_string += SEPARATOR + (INDENT * indent_level) + "[" + SEPARATOR
        for element in data:
            formatted_data_string += INDENT * (indent_level + 1) + format_data(element, indent_level + 1, field_type)
        formatted_data_string += (INDENT * indent_level) + "]"
        if indent_level > 0:
            formatted_data_string += "," + SEPARATOR

    elif isinstance(data, dict):
        formatted_data_string += SEPARATOR + (INDENT * indent_level) + "{" + SEPARATOR
        for key, value in data.items():
            formatted_data_string += INDENT * (indent_level + 1) + apply_colour("'{}': ".format(key), Colours.RED)
            formatted_data_string += format_data(value, indent_level + 2, field_type + "_" + str(key))
        formatted_data_string += (INDENT * indent_level + "}")
        if indent_level > 0:
            formatted_data_string += "," + SEPARATOR

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


def find_b58_uid_in_record(record: logging.LogRecord) -> [str]:
    """
    Generate list of B58 encoded unique identifiers found in some messages.
    :param record: Log record under consideration.
    :return: List string of unique identifiers found.
    """
    matches = []
    for (method, search_string) in [
        (Client.handleOneNodeMsg, "'{}': '([{}]+?)'".format(IDENTIFIER, B58_CHARACTERS)),
        (Client.handleOneNodeMsg, "'{}': '([{}]+?)'".format(TARGET_NYM, B58_CHARACTERS)),
        (Client.handleOneNodeMsg, "'{}': '(~?[{}]+?)'".format(VERKEY, B58_CHARACTERS)),
        (Node.handleOneNodeMsg, "'{}': '([{}]+?)'".format(IDENTIFIER, B58_CHARACTERS)),
        (Node.handleOneNodeMsg, "'{}': '([{}]+?)'".format(TARGET_NYM, B58_CHARACTERS)),
        (Node.handleOneNodeMsg, "'{}': '(~?[{}]+?)'".format(VERKEY, B58_CHARACTERS)),
        (Node.send, "'{}': '([{}]{{60}})'".format(f.SENDER_CLIENT.nm, B58_CHARACTERS)),
        (Node.processClientInBox, "'{}': '([{}]+?)'".format(IDENTIFIER, B58_CHARACTERS)),
        (Node.processClientInBox, "'{}': '([{}]+?)'".format(TARGET_NYM, B58_CHARACTERS)),
        (Node.processClientInBox, "'{}': '(~?[{}]+?)'".format(VERKEY, B58_CHARACTERS)),
        (ZStack.setupOwnKeysIfNeeded,
         "Signing and Encryption keys were not found for ([{}]{{44}})\.".format(B58_CHARACTERS)),
    ]:
        if match_method(record, method):
            search_result = re.search(search_string, record.msg)
            if search_result:
                matches.append(search_result.group(1))

    return matches


def find_hashes_in_record(record: logging.LogRecord) -> [(str, UIDNames)]:
    """
    Generate list of hashes found in some messages.
    :param record: Log record to be analysed.
    :return: List of (hash, hash type) pairs
    """
    matches = []
    for method in [
        Client.handleOneNodeMsg,
        Node.handleOneClientMsg,
        Node.handleOneNodeMsg,
        Node.postToNodeInBox,
        Node.processClientInBox,
        Node.validateNodeMsg,
        Node.validateClientMsg,
        Node.send
    ]:
        if match_method(record, method):
            for key in [
                UIDNames.ROOT_HASH,
                UIDNames.MERKLE_ROOT,
                UIDNames.TXN_ROOT_HASH,
                UIDNames.STATE_ROOT_HASH,
                UIDNames.DIGEST
            ]:
                # Some hashes are B58 encoded, others are hexadecimal
                search_result = re.search("'{}': '(.+?)'".format(key.value), record.msg)
                if search_result:
                    matches.append((search_result.group(1), key))

    return matches


def find_z85_uid_in_record(record: logging.LogRecord) -> [(str, str)]:
    """
    Generate a list of z85 encoded unique identifiers.
    :param record: Log record to be analysed.
    :return: List of pairs of the original string with the decoded string.
    """
    matches = []
    for (method, search_string) in [
        (LedgerManager.processLedgerStatus, "(b'[{}]{{40}}')".format(Z85_CHARACTERS)),
        (Node.processClientInBox, "processing (b'[{}]{{40}}') request".format(Z85_CHARACTERS)),
        (Node.handleOneNodeMsg, "'{}': '([{}]{{40}})'".format(f.SENDER_CLIENT.nm, Z85_CHARACTERS)),
        (Node.send, "'{}': '([{}]+?)'".format(f.SENDER_CLIENT.nm, Z85_CHARACTERS)),
        (Node.validateNodeMsg, "'{}': '([{}]{{40}})'".format(f.SENDER_CLIENT.nm, Z85_CHARACTERS)),
        (Node.postToNodeInBox, "'{}': '([{}]{{40}})'".format(f.SENDER_CLIENT.nm, Z85_CHARACTERS)),
        (Node.processClientInBox, "processing (b'[{}]{{40}}') request".format(Z85_CHARACTERS)),
        (Node.processRequest, "from (b'[{}]{{40}}')$".format(Z85_CHARACTERS)),
        (Node.processPropagate, "'{}': '([{}]{{40}})'".format(f.SENDER_CLIENT.nm, Z85_CHARACTERS)),
        (Node.processPropagate, "from (b'[{}]{{40}}')$".format(f.SENDER_CLIENT.nm, Z85_CHARACTERS)),
        (Propagator.propagate, "from client ([{}]{{40}})$".format(Z85_CHARACTERS)),
        (Propagator.propagate, "from client (b'[{}]{{40}}')$".format(Z85_CHARACTERS)),
        (Walleted.handleEndpointMessage, "(b'[{}]{{40}}')".format(Z85_CHARACTERS)),
        (ZStack.handlePingPong, "got ping from (b'[{}]{{40}}')".format(Z85_CHARACTERS)),
        (ZStack.sendPingPong, "(b'[{}]{{40}}')".format(Z85_CHARACTERS))
    ]:
        if match_method(record, method):
            search_result = re.search(search_string, record.msg)
            if search_result:
                if search_result.group(1).startswith("b'"):
                    friendly_public_key = rawToFriendly(z85decode(search_result.group(1)[2:42]))
                else:
                    friendly_public_key = rawToFriendly(z85decode(search_result.group(1)))
                assert not friendly_public_key.startswith("b'")
                matches.append((search_result.group(1), friendly_public_key))

    return matches


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
        add_uid_to_dictionary(agent.client.name, "{} {}".format(agent.name, "client name"), True)
        add_uid_to_dictionary(agent.client.alias, "{} {}".format(agent.name, "client alias"), True)
        # Note that agent.client.nodestack.name == rawToFriendly(agent.client.nodestack.verKeyRaw)
        add_uid_to_dictionary(agent.client.nodestack.name, "{} {}".format(agent.name, "client nodestack verkey"), True)
        add_uid_to_dictionary(rawToFriendly(agent.client.nodestack.publicKeyRaw),
                              "{} {}".format(agent.name, "client nodestack pubkey"), True)
        if agent.endpoint:
            add_uid_to_dictionary(rawToFriendly(agent.endpoint.verKeyRaw),
                                  "{} {}".format(agent.name, "endpoint verkey"), True)
            add_uid_to_dictionary(rawToFriendly(agent.endpoint.publicKeyRaw),
                                  "{} {}".format(agent.name, "endpoint pubkey"), True)
            add_uid_to_dictionary(rawToFriendly(z85decode(agent.endpoint.sigKey)),
                                  "{} {}".format(agent.name, "endpoint sigkey"), True)
        add_wallet_uids(agent.wallet, agent.name)
    logging.info("Finished adding unique identifiers from agents {}".format([agent.name for agent in agents]))


def add_steward_uids(steward: Steward) -> None:
    """
    Add various unique identifiers related to a Sovrin steward, to the local database mapping those
    random looking values to friendly names
    :param steward: An instance of the Steward class.
    """
    add_uid_to_dictionary(steward.nym, "{} {}".format(steward.name, "NYM"), True)
    add_wallet_uids(steward.wallet, steward.name)
    add_uid_to_dictionary(rawToFriendly(unhexlify(steward.node.verkey)),
                          "{} {}".format(steward.node.name, "verkey"), True)  # See ZStack.initLocalKeys


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
        add_uid_to_dictionary(pool.genesis_transactions[i * 2 + 1][TARGET_NYM], "Node{}C verkey".format(i + 1), True)
    logging.info("Finished adding unique identifiers from pool")


def setup_message_logging(base_dir: str) -> None:
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


    # if os.path.exists("unfiltered_" + LOG_FILE_NAME):
    #     os.remove("unfiltered_" + LOG_FILE_NAME)
    # unfiltered_file_handler = SovrinLogHandler("unfiltered_" + LOG_FILE_NAME)
    #
    # unfiltered_file_handler.setLevel(LOGGING_LEVEL)
    # unfiltered_file_handler.formatter = logging.Formatter(fmt=getConfig().logFormat,
    #                                                       style=getConfig().logFormatStyle)
    #
    # logging.root.addHandler(unfiltered_file_handler)3

    logging.info("### Base directory is: {} ###".format(base_dir))


def print_log_uid_database() -> None:
    """
    Print-out and log the list of NYM's, verkey's and other unique identifiers collected
    together with their friendly name.
    """
    message = "List of identifiers found:\n"
    print("List of identifiers found:")
    for nym, names in uid_names.items():
        message += INDENT + "['{}'".format(apply_colour(names[0], Colours.RED))
        for name in names[1:]:
            message += " was '{}'".format(apply_colour(name, Colours.GREY))
        message += "]: {}\n".format(nym)
    logging.info(message)
    print(message)
