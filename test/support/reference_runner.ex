defmodule Reticulum.ReferenceRunner do
  @moduledoc false

  @project_root Path.expand("../..", __DIR__)
  @script Path.expand("../reference/reticulum_reference.py", __DIR__)

  def run!(command, args \\ []) do
    %{output: output, status: status} = run(command, args)

    if status == 0 do
      output
    else
      raise "reference command failed (#{command}): #{output}"
    end
  end

  def run(command, args \\ []) do
    python = System.get_env("PYTHON") || "python3"

    {output, status} =
      System.cmd(python, [@script, command | args],
        cd: @project_root,
        stderr_to_stdout: true
      )

    %{status: status, output: String.trim(output)}
  end

  def parse_kv_lines(output) do
    output
    |> String.split("\n", trim: true)
    |> Enum.reduce(%{}, fn line, acc ->
      case String.split(line, "=", parts: 2) do
        [key, value] -> Map.put(acc, key, value)
        _ -> acc
      end
    end)
  end
end
