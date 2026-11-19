return {
  api_version = 1,
  settings = {
    {
      name = "daemon_url",
      type = "url",
      label = "Monero node",
      help = "The RPC address of the node the server scans the chain with. It trusts its node, so "
        .. "it is the node on this device; the server has no internet access of its own.",
      required = true,
      default = "$(monero-daemon.public_rpc_url)",
      validate = function(url)
        return nodo.matches(url, "^http://(127\\.0\\.0\\.1|localhost|\\[::1\\]):[0-9]+/?$"),
          "must be a node on this device, http://127.0.0.1:<port>"
      end,
    },
    {
      name = "create",
      type = "enum",
      label = "New wallets",
      help = "auto: a wallet that logs in with create_account gets an account at once. off: "
        .. "nobody new gets one (--create).",
      choices = { "auto", "off" },
      default = "auto",
    },
    {
      name = "import",
      type = "enum",
      label = "Scans from block 0",
      help = "auto: a wallet's request to scan its whole history is granted at once, which keeps "
        .. "the scanner busy for a while. approve: requests wait for the admin API, which this "
        .. "package does not offer yet, so they are in effect refused (--import).",
      choices = { "approve", "auto" },
      default = "approve",
    },
  },
}
