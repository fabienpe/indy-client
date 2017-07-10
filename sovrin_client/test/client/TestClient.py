from plenum.test.test_stack import StackedTester, TestStack
from sovrin_common.test.helper import TempStorage
from stp_core.common.log import getlogger

from sovrin_client.client.client import Client

logger = getlogger()


class TestClientStorage(TempStorage):
    def __init__(self, name, baseDir):
        self.name = name
        self.baseDir = baseDir

    def cleanupDataLocation(self):
        self.cleanupDirectory(self.dataLocation)


@spyable(methods=[Client.handleOneNodeMsg])
class TestClient(Client, StackedTester, TestClientStorage):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        TestClientStorage.__init__(self, self.name, self.basedirpath)

    @staticmethod
    def stackType():
        return TestStack

    def onStopping(self, *args, **kwargs):
        # TODO: Why we needed following line?
        # self.cleanupDataLocation()
        super().onStopping(*args, **kwargs)
