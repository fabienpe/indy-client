from typing import Dict

from anoncreds.protocol.types import AttribDef

from sovrin_client.agent.backend import BackendSystem


class MockBackendSystem(BackendSystem):

    def __init__(self, attrDef):
        self._attrDef = attrDef
        self._attrs = {}  # type: Dict[int, AttribDef]

    def add_record(self, internal_id, **vals):
        self._attrs[internal_id] = self._attrDef.attribs(**vals)

    def update_record(self, internal_id: int, attribute_name: str, attribute_value: any) -> None:
        current_record = self.get_record_by_internal_id(internal_id)

        # TODO: anoncreds.protocol.types.Attribs should support __setitem__
        # noinspection PyProtectedMember
        current_record._vals[attribute_name] = attribute_value

    def get_record_by_internal_id(self, internal_id) -> AttribDef:
        return self._attrs[internal_id]
