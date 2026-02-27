defmodule Reticulum.Transport.ProofsTest do
  use ExUnit.Case, async: true

  alias Reticulum.Identity
  alias Reticulum.Transport.Proofs

  test "builds and parses explicit proof packets" do
    identity = Identity.new()
    proved_packet_hash = :crypto.strong_rand_bytes(32)

    assert {:ok, packet} = Proofs.build_explicit_proof_packet(proved_packet_hash, identity)
    assert packet.type == :proof
    assert packet.destination == :single
    assert packet.addresses == [binary_part(proved_packet_hash, 0, 16)]
    assert byte_size(packet.data) == 96

    assert {:ok, parsed} = Proofs.parse_explicit_proof_packet(packet)
    assert parsed.proved_packet_hash == proved_packet_hash
    assert parsed.proof_destination_hash == binary_part(proved_packet_hash, 0, 16)
  end

  test "validates explicit proof signatures" do
    proving_identity = Identity.new()
    wrong_identity = Identity.new()
    proved_packet_hash = :crypto.strong_rand_bytes(32)

    assert {:ok, packet} =
             Proofs.build_explicit_proof_packet(proved_packet_hash, proving_identity)

    assert {:ok, parsed} = Proofs.parse_explicit_proof_packet(packet)

    public_key = proving_identity.enc_pub <> proving_identity.sig_pub
    wrong_public_key = wrong_identity.enc_pub <> wrong_identity.sig_pub

    assert :ok = Proofs.validate_explicit_proof(parsed, public_key)

    assert {:error, :invalid_proof_signature} =
             Proofs.validate_explicit_proof(parsed, wrong_public_key)
  end
end
