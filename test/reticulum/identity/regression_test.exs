defmodule Reticulum.IdentityRegressionTest do
  use ExUnit.Case, async: true

  describe "Reticulum.Identity" do
    test "new/1 with gen_keys: false does not crash" do
      identity = Reticulum.Identity.new(gen_keys: false)

      assert identity.enc_pub == nil
      assert identity.sig_pub == nil
      assert identity.hash == nil
    end

    test "hash is derived from full public key material" do
      identity = Reticulum.Identity.new()

      <<expected::binary-size(16), _::binary>> =
        :crypto.hash(:sha256, identity.enc_pub <> identity.sig_pub)

      assert identity.hash == expected
    end
  end
end
