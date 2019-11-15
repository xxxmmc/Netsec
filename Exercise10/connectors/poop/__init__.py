import playground
from .protocol import PassthroughClientFactory,PassthroughServerFactory

passthroughConnector = playground.Connector(protocolStack=(
    PassthroughClientFactory(),
    PassthroughServerFactory()))
playground.setConnector("poop", passthroughConnector)
#playground.setConnector("mystack", PassthroughConnector)
#playground.setConnector("passthrough",PassthroughConnector)
