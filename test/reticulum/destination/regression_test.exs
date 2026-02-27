defmodule Reticulum.DestinationRegressionTest do
  use ExUnit.Case, async: true

  describe "Reticulum.Destination" do
    test "outbound non-plain destination requires identity" do
      assert Reticulum.Destination.new(:out, :single, "app") == {:error, :missing_identity}
    end
  end
end
