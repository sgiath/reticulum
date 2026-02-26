defmodule Reticulum.MalformedReferenceVectorsTest do
  use ExUnit.Case, async: true

  alias Reticulum.Crypto.Fernet
  alias Reticulum.Destination
  alias Reticulum.Identity
  alias Reticulum.ReferenceRunner

  describe "Token/Fernet malformed vectors" do
    test "invalid token material fails in both implementations" do
      key = bin_range(1..32)
      iv = bin_range(201..216)
      plain_text = <<1, 2, 3, 4>>
      fernet = Fernet.new(key)

      token =
        ReferenceRunner.run!("token_encrypt_fixed_iv", [hex(key), hex(plain_text), hex(iv)])
        |> dehex()

      tampered = tamper_last_byte(token)

      reference_tampered = ReferenceRunner.run("token_decrypt", [hex(key), hex(tampered)])
      assert reference_tampered.status == 1
      assert String.contains?(reference_tampered.output, "invalid")

      assert {:error, :invalid_signature} == Fernet.decrypt(fernet, tampered)

      reference_short = ReferenceRunner.run("token_decrypt", [hex(key), "001122"])
      assert reference_short.status == 1
      assert String.contains?(reference_short.output, "Cannot verify HMAC")

      assert {:error, :invalid_signature} == Fernet.decrypt(fernet, <<0x00, 0x11, 0x22>>)
    end

    test "invalid key size is rejected" do
      reference = ReferenceRunner.run("token_decrypt", ["0011", "001122"])
      assert reference.status == 1
      assert String.contains?(reference.output, "Token key must be")

      assert_raise FunctionClauseError, fn ->
        Fernet.new(<<0x00, 0x11>>)
      end
    end
  end

  describe "Identity malformed vectors" do
    test "decrypt returns explicit error for malformed ciphertext like reference" do
      private_key = deterministic_private_key()
      fixture = reference_identity_fixture(private_key)

      identity =
        %Identity{}
        |> Map.put(:enc_sec, dehex(fixture["enc_sec"]))
        |> Map.put(:enc_pub, dehex(fixture["enc_pub"]))
        |> Map.put(:sig_sec, dehex(fixture["sig_sec"]))
        |> Map.put(:sig_pub, dehex(fixture["sig_pub"]))
        |> Identity.update_hash()

      assert ReferenceRunner.run!("identity_decrypt", [hex(private_key), "001122"]) == "none"
      assert Identity.decrypt(identity, <<0x00, 0x11, 0x22>>) == {:error, :invalid_ciphertext}

      ciphertext =
        ReferenceRunner.run!("identity_encrypt", [fixture["public_key"], "01020304", "-"])
        |> dehex()

      tampered = tamper_last_byte(ciphertext)

      assert ReferenceRunner.run!("identity_decrypt", [hex(private_key), hex(tampered)]) == "none"
      assert Identity.decrypt(identity, tampered) == {:error, :invalid_ciphertext}
    end

    test "validate returns false for malformed signature" do
      private_key = deterministic_private_key()
      fixture = reference_identity_fixture(private_key)

      identity =
        %Identity{}
        |> Map.put(:enc_sec, dehex(fixture["enc_sec"]))
        |> Map.put(:enc_pub, dehex(fixture["enc_pub"]))
        |> Map.put(:sig_sec, dehex(fixture["sig_sec"]))
        |> Map.put(:sig_pub, dehex(fixture["sig_pub"]))
        |> Identity.update_hash()

      assert ReferenceRunner.run!("identity_validate", [fixture["public_key"], "00", "00"]) ==
               "false"

      refute Identity.validate(identity, <<0x00>>, <<0x00>>)
    end

    test "decrypt without private key returns explicit error" do
      assert Identity.decrypt(%Identity{}, <<0x00>>) == {:error, :missing_private_key}
    end
  end

  describe "Destination malformed vectors" do
    test "rejects dots in app names" do
      reference = ReferenceRunner.run("destination_name", ["-", "chat.bad", "inbox"])
      assert reference.status == 1
      assert String.contains?(reference.output, "Dots can't be used in app names")

      assert Destination.hash(nil, "chat.bad", ["inbox"]) == {:error, :dots_in_app_name}

      assert Destination.new(:in, :plain, "chat.bad", nil, ["inbox"]) ==
               {:error, :dots_in_app_name}
    end

    test "rejects dots in aspects" do
      reference = ReferenceRunner.run("destination_name", ["-", "chat", "in.box"])
      assert reference.status == 1
      assert String.contains?(reference.output, "Dots can't be used in aspects")

      assert Destination.hash(nil, "chat", ["in.box"]) == {:error, :dots_in_aspects}

      assert Destination.new(:in, :plain, "chat", nil, ["in.box"]) ==
               {:error, :dots_in_aspects}
    end

    test "rejects invalid identity hash material" do
      reference = ReferenceRunner.run("destination_hash", ["0011", "chat", "-"])
      assert reference.status == 1

      assert String.contains?(
               reference.output,
               "Invalid material supplied for destination hash calculation"
             )

      assert Destination.hash(<<0x00, 0x11>>, "chat", []) == {:error, :invalid_hash_material}
    end

    test "rejects unknown direction and type" do
      bad_direction = ReferenceRunner.run("destination_new", ["99", "2", "chat", "-"])
      assert bad_direction.status == 1
      assert String.contains?(bad_direction.output, "Unknown destination direction")

      assert Destination.new(:sideways, :plain, "chat") ==
               {:error, :unknown_destination_direction}

      bad_type = ReferenceRunner.run("destination_new", ["17", "9", "chat", "-"])
      assert bad_type.status == 1
      assert String.contains?(bad_type.output, "Unknown destination type")

      assert Destination.new(:in, :invalid, "chat") == {:error, :unknown_destination_type}
    end
  end

  defp reference_identity_fixture(private_key) do
    private_key
    |> hex()
    |> then(&ReferenceRunner.run!("identity_fixture", [&1]))
    |> ReferenceRunner.parse_kv_lines()
  end

  defp deterministic_private_key, do: bin_range(1..64)

  defp tamper_last_byte(binary) when byte_size(binary) > 0 do
    prefix_size = byte_size(binary) - 1
    <<prefix::binary-size(prefix_size), last::integer-size(8)>> = binary
    prefix <> <<Bitwise.bxor(last, 0x01)>>
  end

  defp hex(data), do: Base.encode16(data, case: :lower)
  defp dehex(data), do: Base.decode16!(data, case: :mixed)

  defp bin_range(range) do
    range
    |> Enum.to_list()
    |> :binary.list_to_bin()
  end
end
