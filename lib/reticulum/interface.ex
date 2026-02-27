defmodule Reticulum.Interface do
  @moduledoc """
  Contract for Reticulum runtime interfaces.

  Interfaces provide raw frame ingress/egress for node runtime services.
  """

  @typedoc "Interface server reference"
  @type server :: GenServer.server()

  @typedoc "Interface start options"
  @type start_opts :: keyword()

  @typedoc "Send options"
  @type send_opts :: keyword()

  @callback start_link(start_opts()) :: GenServer.on_start()
  @callback send_frame(server(), iodata(), send_opts()) :: :ok | {:error, term()}
end
