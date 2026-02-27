defmodule Reticulum.Node.Ownership do
  @moduledoc false

  alias Reticulum.Node.Config

  @doc "Claims shared-instance ownership for startup config and owner process."
  def claim_shared_instance(%Config{shared_instance: false}, _owner_pid), do: :ok

  def claim_shared_instance(
        %Config{shared_instance: true, storage_path: storage_path},
        owner_pid
      )
      when is_pid(owner_pid) do
    lock_name =
      storage_path
      |> lock_name()

    case :global.register_name(lock_name, owner_pid) do
      :yes -> :ok
      :no -> {:error, :shared_instance_already_running}
    end
  end

  defp lock_name(storage_path) do
    {__MODULE__, :shared_instance, Path.expand(storage_path)}
  end
end
