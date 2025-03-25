import idaapi

from mcp import Server

class IDACode(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "IDA MCP Plugin"
    help = "IDA MCP"
    wanted_name = "IDA MCP"
    wanted_hotkey = "Ctrl-Shift-M"

    def init(self):
        self.server = Server()
        print("[IDACode] Plugin loaded, use Edit -> Plugins -> IDA MCP to start the server")
        return idaapi.PLUGIN_KEEP

    def run(self, args):
        self.server.start()

    def term(self):
        self.server.stop()
