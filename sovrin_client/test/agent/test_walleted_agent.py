from plenum.test.testable import spyable
from sovrin_client.agent.walleted_agent import WalletedAgent
from sovrin_client.agent.runnable_agent import RunnableAgent


# @spyable(
#     methods=[WalletedAgent._handlePing, WalletedAgent._handlePong])
class TestWalletedAgent(WalletedAgent, RunnableAgent):
    pass
