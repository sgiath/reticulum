defmodule Reticulum.FernetRegressionTest do
  use ExUnit.Case, async: true
  import Bitwise

  alias Reticulum.Crypto.Fernet

  describe "Reticulum.Crypto.Fernet" do
    test "key layout follows signing key then encryption key" do
      key = bin_range(1..32)
      fernet = Fernet.new(key)

      assert fernet.sig_key == binary_part(key, 0, 16)
      assert fernet.enc_key == binary_part(key, 16, 16)
    end

    test "supports 64-byte keys" do
      key = bin_range(1..64)
      fernet = Fernet.new(key)

      assert fernet.sig_key == binary_part(key, 0, 32)
      assert fernet.enc_key == binary_part(key, 32, 32)
    end

    test "encrypt/decrypt round-trip is stable for binary payloads" do
      key = :crypto.strong_rand_bytes(32)
      fernet = Fernet.new(key)

      for _ <- 1..25 do
        plain_text = :crypto.strong_rand_bytes(64)
        cipher_text = Fernet.encrypt(fernet, plain_text)

        assert Fernet.sig_valid?(fernet, cipher_text)
        assert Fernet.decrypt(fernet, cipher_text) == {:ok, plain_text}
      end
    end

    test "rejects tampered tokens" do
      key = :crypto.strong_rand_bytes(32)
      fernet = Fernet.new(key)
      plain_text = "payload"
      cipher_text = Fernet.encrypt(fernet, plain_text)

      prefix_size = byte_size(cipher_text) - 1
      <<prefix::binary-size(prefix_size), last::integer-size(8)>> = cipher_text
      tampered = prefix <> <<bxor(last, 0x01)>>

      refute Fernet.sig_valid?(fernet, tampered)
      assert Fernet.decrypt(fernet, tampered) == {:error, :invalid_signature}
    end
  end

  defp bin_range(range) do
    range
    |> Enum.to_list()
    |> :binary.list_to_bin()
  end
end
