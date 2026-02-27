defmodule Reticulum.Bootstrap.Parser.TOML do
  @moduledoc """
  TOML bootstrap parser with schema validation.
  """

  alias Reticulum.Bootstrap.Config

  @doc "Parses TOML config file into bootstrap runtime mapping."
  def parse_file(path) when is_binary(path) and path != "" do
    with :ok <- ensure_config_file(path),
         {:ok, decoded} <- decode_file(path),
         {:ok, %Config{} = config} <- Config.new(decoded) do
      {:ok, config}
    end
  end

  def parse_file(_path), do: {:error, :invalid_config_path}

  defp ensure_config_file(path) do
    if File.regular?(path) do
      :ok
    else
      {:error, :config_file_not_found}
    end
  end

  defp decode_file(path) do
    case Toml.decode_file(path) do
      {:ok, decoded} when is_map(decoded) ->
        {:ok, decoded}

      {:ok, _decoded} ->
        {:error, :invalid_bootstrap_config}

      {:error, {:invalid_toml, _line_and_column}} ->
        {:error, :invalid_toml}

      {:error, reason} ->
        {:error, {:invalid_toml, reason}}
    end
  end
end
