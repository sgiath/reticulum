defmodule Reticulum.Node.Config do
  @moduledoc """
  Runtime configuration for `Reticulum.Node`.

  This struct intentionally starts small and focuses on options needed for
  bootstrapping the node process.

  `storage_path` is currently reserved for future persistence work. Runtime
  tables are ETS-backed and start empty on each node restart.
  """

  @default_storage_path Path.expand("~/.reticulum")

  @typedoc "Runtime node configuration"
  @type t :: %__MODULE__{
          name: atom(),
          storage_path: String.t(),
          transport_enabled: boolean(),
          use_implicit_proof: boolean(),
          shared_instance: boolean(),
          startup_mode: :cold | :warm_restore,
          startup_lifecycle: module(),
          path_ttl_seconds: pos_integer(),
          path_gc_interval_seconds: pos_integer(),
          receipt_timeout_seconds: pos_integer(),
          receipt_retention_seconds: pos_integer(),
          ratchet_expiry_seconds: pos_integer()
        }

  @enforce_keys [
    :name,
    :storage_path,
    :transport_enabled,
    :use_implicit_proof,
    :shared_instance,
    :startup_mode,
    :startup_lifecycle,
    :path_ttl_seconds,
    :path_gc_interval_seconds,
    :receipt_timeout_seconds,
    :receipt_retention_seconds,
    :ratchet_expiry_seconds
  ]
  defstruct [
    :name,
    :storage_path,
    :transport_enabled,
    :use_implicit_proof,
    :shared_instance,
    :startup_mode,
    :startup_lifecycle,
    :path_ttl_seconds,
    :path_gc_interval_seconds,
    :receipt_timeout_seconds,
    :receipt_retention_seconds,
    :ratchet_expiry_seconds
  ]

  @doc "Builds and validates a node config from keyword options."
  def new(opts \\ [])

  def new(opts) when is_list(opts) do
    with :ok <- validate_keys(opts),
         {:ok, name} <- validate_name(Keyword.get(opts, :name, Reticulum.Node)),
         {:ok, storage_path} <-
           validate_storage_path(Keyword.get(opts, :storage_path, @default_storage_path)),
         {:ok, transport_enabled} <-
           validate_boolean(Keyword.get(opts, :transport_enabled, false), :transport_enabled),
         {:ok, use_implicit_proof} <-
           validate_boolean(Keyword.get(opts, :use_implicit_proof, true), :use_implicit_proof),
         {:ok, shared_instance} <-
           validate_boolean(Keyword.get(opts, :shared_instance, false), :shared_instance),
         {:ok, startup_mode} <- validate_startup_mode(Keyword.get(opts, :startup_mode, :cold)),
         {:ok, startup_lifecycle} <-
           validate_startup_lifecycle(
             Keyword.get(opts, :startup_lifecycle, Reticulum.Node.StartupLifecycle.Default)
           ),
         {:ok, path_ttl_seconds} <-
           validate_positive_integer(Keyword.get(opts, :path_ttl_seconds, 300), :path_ttl_seconds),
         {:ok, path_gc_interval_seconds} <-
           validate_positive_integer(
             Keyword.get(opts, :path_gc_interval_seconds, 5),
             :path_gc_interval_seconds
           ),
         {:ok, receipt_timeout_seconds} <-
           validate_positive_integer(
             Keyword.get(opts, :receipt_timeout_seconds, 10),
             :receipt_timeout_seconds
           ),
         {:ok, receipt_retention_seconds} <-
           validate_positive_integer(
             Keyword.get(opts, :receipt_retention_seconds, 60),
             :receipt_retention_seconds
           ),
         {:ok, ratchet_expiry_seconds} <-
           validate_positive_integer(
             Keyword.get(opts, :ratchet_expiry_seconds, 2_592_000),
             :ratchet_expiry_seconds
           ) do
      {:ok,
       %__MODULE__{
         name: name,
         storage_path: storage_path,
         transport_enabled: transport_enabled,
         use_implicit_proof: use_implicit_proof,
         shared_instance: shared_instance,
         startup_mode: startup_mode,
         startup_lifecycle: startup_lifecycle,
         path_ttl_seconds: path_ttl_seconds,
         path_gc_interval_seconds: path_gc_interval_seconds,
         receipt_timeout_seconds: receipt_timeout_seconds,
         receipt_retention_seconds: receipt_retention_seconds,
         ratchet_expiry_seconds: ratchet_expiry_seconds
       }}
    end
  end

  def new(_opts), do: {:error, :invalid_options}

  defp validate_keys(opts) do
    unknown_keys =
      opts
      |> Keyword.keys()
      |> Enum.reject(
        &(&1 in [
            :name,
            :storage_path,
            :transport_enabled,
            :use_implicit_proof,
            :shared_instance,
            :startup_mode,
            :startup_lifecycle,
            :path_ttl_seconds,
            :path_gc_interval_seconds,
            :receipt_timeout_seconds,
            :receipt_retention_seconds,
            :ratchet_expiry_seconds
          ])
      )

    case unknown_keys do
      [] -> :ok
      _ -> {:error, :unknown_option}
    end
  end

  defp validate_name(name) when is_atom(name), do: {:ok, name}
  defp validate_name(_name), do: {:error, :invalid_node_name}

  defp validate_storage_path(path) when is_binary(path) and path != "" do
    {:ok, Path.expand(path)}
  end

  defp validate_storage_path(_path), do: {:error, :invalid_storage_path}

  defp validate_boolean(value, _field) when is_boolean(value), do: {:ok, value}
  defp validate_boolean(_value, :transport_enabled), do: {:error, :invalid_transport_enabled}
  defp validate_boolean(_value, :use_implicit_proof), do: {:error, :invalid_use_implicit_proof}
  defp validate_boolean(_value, :shared_instance), do: {:error, :invalid_shared_instance}

  defp validate_startup_mode(:cold), do: {:ok, :cold}
  defp validate_startup_mode(:warm_restore), do: {:ok, :warm_restore}
  defp validate_startup_mode("cold"), do: {:ok, :cold}
  defp validate_startup_mode("warm_restore"), do: {:ok, :warm_restore}
  defp validate_startup_mode(_value), do: {:error, :invalid_startup_mode}

  defp validate_startup_lifecycle(module) when is_atom(module) do
    if Code.ensure_loaded?(module) and function_exported?(module, :cold_start, 2) and
         function_exported?(module, :warm_restore, 2) do
      {:ok, module}
    else
      {:error, :invalid_startup_lifecycle}
    end
  end

  defp validate_startup_lifecycle(_module), do: {:error, :invalid_startup_lifecycle}

  defp validate_positive_integer(value, _field) when is_integer(value) and value > 0,
    do: {:ok, value}

  defp validate_positive_integer(_value, :path_ttl_seconds),
    do: {:error, :invalid_path_ttl_seconds}

  defp validate_positive_integer(_value, :path_gc_interval_seconds),
    do: {:error, :invalid_path_gc_interval_seconds}

  defp validate_positive_integer(_value, :receipt_timeout_seconds),
    do: {:error, :invalid_receipt_timeout_seconds}

  defp validate_positive_integer(_value, :receipt_retention_seconds),
    do: {:error, :invalid_receipt_retention_seconds}

  defp validate_positive_integer(_value, :ratchet_expiry_seconds),
    do: {:error, :invalid_ratchet_expiry_seconds}
end
