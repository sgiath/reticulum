defmodule Reticulum.Reference.ProofVectorsTest do
  use ExUnit.Case, async: true

  alias Reticulum.Packet
  alias Reticulum.ReferenceRunner
  alias Reticulum.Transport.Proofs

  test "validates explicit and implicit proof vectors against reference signatures" do
    private_key = deterministic_private_key()
    fixture = reference_identity_fixture(private_key)
    public_key = dehex(fixture["public_key"])
    packet_hash = :crypto.strong_rand_bytes(32)

    signature =
      ReferenceRunner.run!("identity_sign", [hex(private_key), hex(packet_hash)])
      |> dehex()

    assert ReferenceRunner.run!("identity_validate", [
             fixture["public_key"],
             hex(packet_hash),
             hex(signature)
           ]) ==
             "true"

    explicit_packet = %Packet{
      type: :proof,
      addresses: [binary_part(packet_hash, 0, 16)],
      data: packet_hash <> signature
    }

    implicit_packet = %Packet{
      type: :proof,
      addresses: [binary_part(packet_hash, 0, 16)],
      data: signature
    }

    assert {:ok, explicit_proof} = Proofs.parse_proof_packet(explicit_packet)
    assert explicit_proof.mode == :explicit
    assert :ok = Proofs.validate_proof(explicit_proof, public_key, packet_hash)

    assert {:ok, implicit_proof} = Proofs.parse_proof_packet(implicit_packet)
    assert implicit_proof.mode == :implicit
    assert :ok = Proofs.validate_proof(implicit_proof, public_key, packet_hash)
  end

  test "rejects proof edge cases with deterministic vectors" do
    private_key = deterministic_private_key()
    fixture = reference_identity_fixture(private_key)
    public_key = dehex(fixture["public_key"])
    packet_hash = :crypto.strong_rand_bytes(32)

    signature =
      ReferenceRunner.run!("identity_sign", [hex(private_key), hex(packet_hash)])
      |> dehex()

    mismatched_destination_packet = %Packet{
      type: :proof,
      addresses: [:crypto.strong_rand_bytes(16)],
      data: packet_hash <> signature
    }

    assert {:error, :proof_destination_hash_mismatch} =
             Proofs.parse_proof_packet(mismatched_destination_packet)

    explicit_packet = %Packet{
      type: :proof,
      addresses: [binary_part(packet_hash, 0, 16)],
      data: packet_hash <> signature
    }

    assert {:ok, explicit_proof} = Proofs.parse_proof_packet(explicit_packet)

    assert {:error, :proof_packet_hash_mismatch} =
             Proofs.validate_proof(explicit_proof, public_key, :crypto.strong_rand_bytes(32))

    assert {:error, :invalid_proof_length} =
             Proofs.parse_proof_packet(%Packet{
               type: :proof,
               addresses: [binary_part(packet_hash, 0, 16)],
               data: <<1, 2, 3>>
             })
  end

  defp deterministic_private_key do
    1..64
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
end
