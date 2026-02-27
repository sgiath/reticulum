defmodule Reticulum.Transport.ProofsTest do
  use ExUnit.Case, async: true

  alias Reticulum.Identity
  alias Reticulum.Transport.Proofs

  test "builds and parses implicit proof packets by default" do
    identity = Identity.new()
    proved_packet_hash = :crypto.strong_rand_bytes(32)

    assert {:ok, packet} = Proofs.build_proof_packet(proved_packet_hash, identity)
    assert packet.type == :proof
    assert packet.destination == :single
    assert packet.addresses == [binary_part(proved_packet_hash, 0, 16)]
    assert byte_size(packet.data) == 64

    assert {:ok, parsed} = Proofs.parse_proof_packet(packet)
    assert parsed.mode == :implicit
    assert parsed.proved_packet_hash == nil
    assert parsed.proof_destination_hash == binary_part(proved_packet_hash, 0, 16)
  end

  test "builds and parses explicit proof packets" do
    identity = Identity.new()
    proved_packet_hash = :crypto.strong_rand_bytes(32)

    assert {:ok, packet} =
             Proofs.build_proof_packet(proved_packet_hash, identity, implicit: false)

    assert byte_size(packet.data) == 96

    assert {:ok, parsed} = Proofs.parse_proof_packet(packet)
    assert parsed.mode == :explicit
    assert parsed.proved_packet_hash == proved_packet_hash
    assert parsed.proof_destination_hash == binary_part(proved_packet_hash, 0, 16)
  end

  test "validates both implicit and explicit proof signatures" do
    proving_identity = Identity.new()
    wrong_identity = Identity.new()
    proved_packet_hash = :crypto.strong_rand_bytes(32)

    public_key = proving_identity.enc_pub <> proving_identity.sig_pub
    wrong_public_key = wrong_identity.enc_pub <> wrong_identity.sig_pub

    assert {:ok, implicit_packet} =
             Proofs.build_proof_packet(proved_packet_hash, proving_identity)

    assert {:ok, parsed_implicit} = Proofs.parse_proof_packet(implicit_packet)

    assert :ok = Proofs.validate_proof(parsed_implicit, public_key, proved_packet_hash)

    assert {:error, :invalid_proof_signature} =
             Proofs.validate_proof(parsed_implicit, wrong_public_key, proved_packet_hash)

    assert {:ok, explicit_packet} =
             Proofs.build_proof_packet(proved_packet_hash, proving_identity, implicit: false)

    assert {:ok, parsed_explicit} = Proofs.parse_proof_packet(explicit_packet)
    assert :ok = Proofs.validate_proof(parsed_explicit, public_key, proved_packet_hash)

    assert {:error, :proof_packet_hash_mismatch} =
             Proofs.validate_proof(parsed_explicit, public_key, :crypto.strong_rand_bytes(32))
  end

  test "rejects malformed proof lengths" do
    assert {:error, :invalid_proof_length} =
             Proofs.parse_proof_packet(%Reticulum.Packet{
               type: :proof,
               addresses: [:crypto.strong_rand_bytes(16)],
               data: :crypto.strong_rand_bytes(65)
             })
  end
end
