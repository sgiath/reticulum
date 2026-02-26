defmodule ReticulumRegressionTest do
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

  describe "Reticulum.Destination" do
    test "outbound non-plain destination requires identity" do
      assert Reticulum.Destination.new(:out, :single, "app") == {:error, :missing_identity}
    end
  end

  describe "Reticulum.Packet" do
    test "accepts integer context when encoding" do
      address = <<0::128>>

      packet = %Reticulum.Packet{
        ifac: :open,
        propagation: :broadcast,
        destination: :single,
        type: :data,
        hops: 1,
        addresses: [address],
        context: 1,
        data: <<2, 3>>
      }

      encoded = Reticulum.Packet.encode(packet)
      decoded = Reticulum.Packet.decode(encoded)

      assert decoded.context == <<1>>
      assert decoded.addresses == [address]
      assert decoded.data == <<2, 3>>
    end

    test "rejects address lists outside wire format" do
      base_packet = %Reticulum.Packet{
        ifac: :open,
        propagation: :broadcast,
        destination: :single,
        type: :data,
        hops: 1,
        context: <<0>>,
        data: <<>>
      }

      assert_raise FunctionClauseError, fn ->
        Reticulum.Packet.encode(%{base_packet | addresses: []})
      end

      address = <<0::128>>

      assert_raise FunctionClauseError, fn ->
        Reticulum.Packet.encode(%{base_packet | addresses: [address, address, address]})
      end
    end
  end

  defp bin_range(range) do
    range
    |> Enum.to_list()
    |> :binary.list_to_bin()
  end
end
