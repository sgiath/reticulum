defmodule Reticulum.Node.StartupLifecycleTest do
  use ExUnit.Case, async: false

  alias Reticulum.Node

  defmodule RecorderLifecycle do
    @behaviour Reticulum.Node.StartupLifecycle

    @impl true
    def cold_start(config, node_pid) do
      send(self(), {:startup_lifecycle, :cold, config.name, node_pid})
      :ok
    end

    @impl true
    def warm_restore(config, node_pid) do
      send(self(), {:startup_lifecycle, :warm_restore, config.name, node_pid})
      :ok
    end
  end

  defmodule FailingLifecycle do
    @behaviour Reticulum.Node.StartupLifecycle

    @impl true
    def cold_start(_config, _node_pid), do: {:error, :cold_start_failed}

    @impl true
    def warm_restore(_config, _node_pid), do: {:error, :warm_restore_failed}
  end

  test "invokes cold_start hook for cold startup mode" do
    node_name = Reticulum.Node.StartupLifecycleCold

    assert {:ok, pid} =
             Node.start_link(
               name: node_name,
               storage_path: unique_storage_path("startup-lifecycle-cold"),
               startup_mode: :cold,
               startup_lifecycle: RecorderLifecycle
             )

    on_exit(fn -> maybe_stop(pid) end)

    assert_receive {:startup_lifecycle, :cold, ^node_name, ^pid}, 1_000
    refute_receive {:startup_lifecycle, :warm_restore, ^node_name, ^pid}, 50
  end

  test "invokes warm_restore hook for warm startup mode" do
    node_name = Reticulum.Node.StartupLifecycleWarm

    assert {:ok, pid} =
             Node.start_link(
               name: node_name,
               storage_path: unique_storage_path("startup-lifecycle-warm"),
               startup_mode: :warm_restore,
               startup_lifecycle: RecorderLifecycle
             )

    on_exit(fn -> maybe_stop(pid) end)

    assert_receive {:startup_lifecycle, :warm_restore, ^node_name, ^pid}, 1_000
    refute_receive {:startup_lifecycle, :cold, ^node_name, ^pid}, 50
  end

  test "invokes warm_restore hook for config-driven startup mode" do
    node_name = Reticulum.Node.StartupLifecycleConfigWarm

    config_path =
      write_config!("""
      [node]
      storage_path = "#{unique_storage_path("startup-lifecycle-config")}" 
      startup_mode = "warm_restore"
      """)

    assert {:ok, pid} =
             Node.start_from_config(config_path,
               name: node_name,
               startup_lifecycle: RecorderLifecycle
             )

    on_exit(fn -> maybe_stop(pid) end)

    assert_receive {:startup_lifecycle, :warm_restore, ^node_name, ^pid}, 1_000
    refute_receive {:startup_lifecycle, :cold, ^node_name, ^pid}, 50
  end

  test "rolls back startup when startup lifecycle hook fails" do
    node_name = Reticulum.Node.StartupLifecycleFailure

    assert Node.start_link(
             name: node_name,
             storage_path: unique_storage_path("startup-lifecycle-failure"),
             startup_mode: :warm_restore,
             startup_lifecycle: FailingLifecycle
           ) == {:error, :warm_restore_failed}

    assert node_name
           |> Node.state_server()
           |> :global.whereis_name() == :undefined

    assert node_name
           |> Node.transport_server()
           |> :global.whereis_name() == :undefined

    assert node_name
           |> Node.interface_supervisor()
           |> :global.whereis_name() == :undefined
  end

  defp write_config!(contents) do
    path =
      Path.join(
        System.tmp_dir!(),
        "reticulum-startup-lifecycle-#{System.unique_integer([:positive])}.toml"
      )

    :ok = File.write(path, contents)
    path
  end

  defp unique_storage_path(prefix) do
    Path.join(System.tmp_dir!(), "reticulum-#{prefix}-#{System.unique_integer([:positive])}")
  end

  defp maybe_stop(pid) when is_pid(pid) do
    if Process.alive?(pid) do
      Process.unlink(pid)

      try do
        _ = Supervisor.stop(pid)
      catch
        :exit, _reason -> :ok
      end
    end

    :ok
  end
end
