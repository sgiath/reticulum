defmodule Reticulum.TestSupport.TestInterface do
  @moduledoc false

  @behaviour Reticulum.Interface

  @loopback {127, 0, 0, 1}

  @impl true
  def init(opts) do
    {:ok,
     %{
       name: Keyword.fetch!(opts, :name),
       test_pid: Keyword.fetch!(opts, :test_pid),
       adapter_status: :up
     }, %{kind: :test}}
  end

  @impl true
  def send_frame(payload, opts, state) do
    send(state.test_pid, {:test_interface_sent, state.name, payload, opts})
    {:ok, state, {Keyword.get(opts, :ip, @loopback), Keyword.get(opts, :port, 0)}}
  end

  @impl true
  def prepare_outbound(payload, _opts, state), do: {:ok, %{payload: payload, ifac: :open}, state}

  @impl true
  def normalize_inbound(payload, state), do: {:ok, %{payload: payload, ifac: :open}, state}

  @impl true
  def handle_info({:inject_inbound, payload, endpoint}, state) do
    {:noreply, state, [{:inbound_frame, payload, endpoint}]}
  end

  def handle_info({:adapter_status, status}, state) do
    {:noreply, %{state | adapter_status: status}}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def health(state), do: %{adapter_status: state.adapter_status}
end
