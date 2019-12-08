import playground
from .protocol import SecureClientFactory,SecureServerFactory
secureConnector = playground.Connector(protocolStack=(SecureClientFactory(),SecureServerFactory()))

playground.setConnector("crap",secureConnector)
#playground.setConnector("mystack", PassthroughConnector)
#playground.setConnector("passthrough",PassthroughConnector)
