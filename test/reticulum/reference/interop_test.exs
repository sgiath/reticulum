defmodule Reticulum.Reference.InteropTest do
  use ExUnit.Case, async: true

  alias Reticulum.Crypto.Fernet
  alias Reticulum.ReferenceRunner

  describe "HKDF vectors" do
    test "matches reference outputs" do
      vectors = [
        %{
          length: 32,
          derive_from: bin_range(1..32),
          salt: <<>>,
          context: <<>>
        },
        %{
          length: 64,
          derive_from: bin_range(10..41),
          salt: bin_range(100..131),
          context: "reticulum-interop"
        }
      ]

      for vector <- vectors do
        expected_hex =
          ReferenceRunner.run!("hkdf", [
            Integer.to_string(vector.length),
            hex(vector.derive_from),
            hex_or_dash(vector.salt),
            hex_or_dash(vector.context)
          ])

        derived =
          Reticulum.Crypto.hkdf(
            vector.derive_from,
            vector.salt,
            vector.context,
            vector.length
          )

        assert hex(derived) == expected_hex
      end
    end
  end

  describe "Token/Fernet interop" do
    test "decrypts deterministic reference tokens" do
      iv = bin_range(201..216)
      plaintext = <<0, 255, 1, 2, 3, 10, 20, 30, 40, 50>>

      for key <- [
            bin_range(1..32),
            bin_range(1..64)
          ] do
        token_hex =
          ReferenceRunner.run!("token_encrypt_fixed_iv", [
            hex(key),
            hex(plaintext),
            hex(iv)
          ])

        token = dehex(token_hex)
        fernet = Fernet.new(key)

        assert Fernet.sig_valid?(fernet, token)
        assert Fernet.decrypt(fernet, token) == {:ok, plaintext}
      end
    end

    test "reference decrypts tokens encrypted by Elixir" do
      plaintext = <<6, 7, 8, 9, 0, 255, 10, 11, 12, 13>>

      for key <- [
            bin_range(1..32),
            bin_range(1..64)
          ] do
        token = Fernet.new(key) |> Fernet.encrypt(plaintext)

        decrypted_hex =
          ReferenceRunner.run!("token_decrypt", [
            hex(key),
            hex(token)
          ])

        assert dehex(decrypted_hex) == plaintext
      end
    end
  end

  describe "Identity interop" do
    test "matches reference key material and hash for deterministic private key" do
      private_key = deterministic_private_key()
      fixture = reference_identity_fixture(private_key)

      identity =
        %Reticulum.Identity{}
        |> Map.put(:enc_sec, dehex(fixture["enc_sec"]))
        |> Map.put(:enc_pub, dehex(fixture["enc_pub"]))
        |> Map.put(:sig_sec, dehex(fixture["sig_sec"]))
        |> Map.put(:sig_pub, dehex(fixture["sig_pub"]))
        |> Reticulum.Identity.update_hash()

      assert hex(identity.enc_pub) == fixture["enc_pub"]
      assert hex(identity.sig_pub) == fixture["sig_pub"]
      assert hex(identity.hash) == fixture["hash"]
    end

    test "cross-validates signatures with reference" do
      private_key = deterministic_private_key()
      fixture = reference_identity_fixture(private_key)
      message = "reticulum interoperability"

      identity =
        %Reticulum.Identity{}
        |> Map.put(:enc_sec, dehex(fixture["enc_sec"]))
        |> Map.put(:enc_pub, dehex(fixture["enc_pub"]))
        |> Map.put(:sig_sec, dehex(fixture["sig_sec"]))
        |> Map.put(:sig_pub, dehex(fixture["sig_pub"]))
        |> Reticulum.Identity.update_hash()

      signature = Reticulum.Identity.sign(identity, message)

      assert ReferenceRunner.run!("identity_validate", [
               fixture["public_key"],
               hex(message),
               hex(signature)
             ]) ==
               "true"

      reference_signature =
        ReferenceRunner.run!("identity_sign", [hex(private_key), hex(message)])
        |> dehex()

      assert Reticulum.Identity.validate(identity, message, reference_signature)
    end

    test "encrypt/decrypt works both directions with reference" do
      private_key = deterministic_private_key()
      fixture = reference_identity_fixture(private_key)

      receiver =
        %Reticulum.Identity{}
        |> Map.put(:enc_sec, dehex(fixture["enc_sec"]))
        |> Map.put(:enc_pub, dehex(fixture["enc_pub"]))
        |> Map.put(:sig_sec, dehex(fixture["sig_sec"]))
        |> Map.put(:sig_pub, dehex(fixture["sig_pub"]))
        |> Reticulum.Identity.update_hash()

      receiver_public = %Reticulum.Identity{enc_pub: receiver.enc_pub, hash: receiver.hash}
      plaintext = <<1, 2, 3, 4, 5, 200, 201, 202>>

      elixir_ciphertext = Reticulum.Identity.encrypt(receiver_public, plaintext)

      assert ReferenceRunner.run!("identity_decrypt", [hex(private_key), hex(elixir_ciphertext)]) ==
               hex(plaintext)

      reference_ciphertext =
        ReferenceRunner.run!("identity_encrypt", [fixture["public_key"], hex(plaintext), "-"])
        |> dehex()

      assert Reticulum.Identity.decrypt(receiver, reference_ciphertext) == {:ok, plaintext}
    end
  end

  describe "Destination naming interop" do
    test "destination name matches reference" do
      private_key = deterministic_private_key()
      fixture = reference_identity_fixture(private_key)
      app_name = "chat"
      aspects = ["inbox", "messages"]

      expected_name =
        ReferenceRunner.run!("destination_name", [
          fixture["hash"],
          app_name,
          Enum.join(aspects, ",")
        ])

      {:ok, destination} =
        Reticulum.Destination.new(
          :out,
          :single,
          app_name,
          %Reticulum.Identity{hash: dehex(fixture["hash"])},
          aspects
        )

      assert destination.name == expected_name
    end

    test "destination hash matches reference" do
      private_key = deterministic_private_key()
      fixture = reference_identity_fixture(private_key)
      app_name = "chat"
      aspects = ["inbox", "messages"]

      expected_hash =
        ReferenceRunner.run!("destination_hash", [
          fixture["hash"],
          app_name,
          Enum.join(aspects, ",")
        ])

      identity_hash = fixture["hash"] |> dehex()
      {:ok, hash} = Reticulum.Destination.hash(identity_hash, app_name, aspects)
      assert hex(hash) == expected_hash
    end
  end

  defp deterministic_private_key do
    1..64
    |> Enum.to_list()
    |> :binary.list_to_bin()
  end

  defp bin_range(range) do
    range
    |> Enum.to_list()
    |> :binary.list_to_bin()
  end

  defp reference_identity_fixture(private_key) do
    private_key
    |> hex()
    |> then(&ReferenceRunner.run!("identity_fixture", [&1]))
    |> ReferenceRunner.parse_kv_lines()
  end

  defp hex(data), do: Base.encode16(data, case: :lower)
  defp dehex(data), do: Base.decode16!(data, case: :mixed)
  defp hex_or_dash(<<>>), do: "-"
  defp hex_or_dash(data), do: hex(data)
end
